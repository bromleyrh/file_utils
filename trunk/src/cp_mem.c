/*
 * cp_mem.c
 */

#define _GNU_SOURCE

#include <alloca.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

struct dest {
    int     fd;
    off_t   bufsize;
    char    *buf;
    size_t  blksize;
    char    *zeroblock;
    int     hugetlbfs;
};

static const char **srcs;
static const char *dst;
static int dstdir;
static int hugetlbfs;
static int numsrcs;
static int verbose;

static int parse_cmdline(int, char **);

static int dest_init(int, off_t, int, struct dest *);
static int dest_buf_resize(off_t, struct dest *);
static void dest_free(struct dest *);

static int do_ftruncate(int, off_t);
static ssize_t do_read(int, void *, size_t);
static int do_write(struct dest *, const void *, size_t, off_t);

static int do_copy(int, int, int);
static int copy_mode(int, int);
static int do_link(int, const char *);

static int copy(int);

static int
parse_cmdline(int argc, char **argv)
{
    int i;
    int numopts;

    if (argc < 3) {
        error(0, 0, "Must specify a source file and destination");
        return -1;
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0)
            hugetlbfs = 1;
        else if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else
            break;
    }
    numopts = i - 1;

    numsrcs = argc - numopts - 2;
    srcs = (const char **)&argv[1+numopts];
    dst = argv[argc-1];

    return 0;
}

static int
dest_init(int fd, off_t bufsize, int hugetlbfs, struct dest *dst)
{
    if (dst == NULL)
        return -1;

    dst->fd = fd;

    dst->bufsize = bufsize;
    dst->buf = (char *)mmap(0, dst->bufsize, PROT_READ | PROT_WRITE, MAP_SHARED,
                            fd, 0);
    if (dst->buf == MAP_FAILED) {
        error(0, errno, "Memory mapping destination file failed");
        return -1;
    }

    if (ioctl(dst->fd, FIGETBSZ, &dst->blksize) == -1) {
        error(0, errno, "Couldn't get destination filesystem block size");
        goto err;
    }

    dst->zeroblock = malloc(dst->blksize);
    if (dst->zeroblock == NULL) {
        error(0, 0, "Out of memory");
        goto err;
    }
    memset(dst->zeroblock, 0, dst->blksize);

    dst->hugetlbfs = hugetlbfs;

    return 0;

err:
    munmap(dst->buf, dst->bufsize);
    return -1;
}

static int
dest_buf_resize(off_t bufsize, struct dest *dst)
{
    if (dst == NULL)
        return -1;

    if (!dst->hugetlbfs && (do_ftruncate(dst->fd, bufsize) == -1))
        goto err;

    munmap(dst->buf, dst->bufsize);
    dst->buf = (char *)mmap(0, bufsize, PROT_READ | PROT_WRITE, MAP_SHARED,
                            dst->fd, 0);
    if (dst->buf == MAP_FAILED)
        goto err;

/*  dst->buf = mremap(dst->buf, dst->bufsize, bufsize, MREMAP_MAYMOVE);
    if (dst->buf == MAP_FAILED)
        goto err;
*/
    dst->bufsize = bufsize;

    return 0;

err:
    error(0, errno, "Couldn't extend destination file");
    return -1;
}

static void
dest_free(struct dest *dst)
{
    if (dst != NULL) {
        munmap(dst->buf, dst->bufsize);
        free(dst->zeroblock);
    }
}

static int
do_ftruncate(int fd, off_t length)
{
    while (ftruncate(fd, length) == -1) {
        if (errno != EINTR)
            return -1;
    }

    return 0;
}

static ssize_t
do_read(int fd, void *buf, size_t count)
{
    size_t bytesread;
    ssize_t ret;

    for (bytesread = 0; bytesread < count; bytesread += ret) {
        ret = read(fd, buf + bytesread, count - bytesread);
        if (ret > 0)
            continue;
        if (ret == 0)
            break;
        /* ret == -1 */
        if (errno == EINTR) {
            ret = 0;
            continue;
        }
        break;
    }

    if (ret == -1)
        return -1;
    return bytesread;
}

static int
do_write(struct dest *dst, const void *buf, size_t count, off_t offset)
{
    size_t blockbytes, byteswritten;

    if (dst == NULL)
        return -1;

    for (byteswritten = 0; byteswritten < count; byteswritten += blockbytes) {
        if (count - byteswritten < (size_t)dst->blksize)
            blockbytes = count - byteswritten;
        else {
            blockbytes = dst->blksize;
            if (memcmp(buf + byteswritten, dst->zeroblock, dst->blksize) == 0)
                continue;
        }
        memcpy(dst->buf + offset + byteswritten, buf + byteswritten,
               blockbytes);
    }

    return 0;
}

#define BUFSIZE (1024 * 1024)

static int
do_copy(int fd1, int fd2, int hugetlbfs)
{
    off_t off;
    ssize_t num_read;
    struct dest dsts;

    if (dest_init(fd2, BUFSIZE, hugetlbfs, &dsts) == -1)
        return -1;

    for (off = 0;; off += num_read) {
        char buf[BUFSIZE];

        if (dest_buf_resize(off + sizeof(buf), &dsts) == -1)
            goto err;

        num_read = do_read(fd1, buf, sizeof(buf));
        if (num_read == 0)
            break;
        if (num_read == -1) {
            error(0, errno, "Couldn't read source file");
            goto err;
        }
        if (do_write(&dsts, buf, num_read, off) == -1) {
            error(0, 0, "Couldn't write destination file");
            goto err;
        }
    }

    dest_free(&dsts);

    if (!hugetlbfs && (do_ftruncate(fd2, off) == -1)) {
        error(0, errno, "Couldn't truncate destination file");
        return -1;
    }

    return 0;

err:
    dest_free(&dsts);
    return -1;
}

#undef BUFSIZE

static int
copy_mode(int fd1, int fd2)
{
    struct stat srcsb;

    if (fstat(fd1, &srcsb) == -1) {
        error(0, errno, "Couldn't stat source file");
        return -1;
    }
    if (fchmod(fd2, srcsb.st_mode) == -1) {
        error(0, errno, "Couldn't set mode of destination file");
        return -1;
    }

    return 0;
}

static int
do_link(int fd, const char *name)
{
    const char *oldpath;

    if (asprintf((char **)&oldpath, "/proc/self/fd/%d", fd) == -1) {
        error(0, 0, "Out of memory");
        return -1;
    }

    if (linkat(fd, oldpath, 0, name, AT_SYMLINK_FOLLOW) == -1) {
        error(0, errno, "Couldn't link %s", name);
        free((void *)oldpath);
        return -1;
    }

    free((void *)oldpath);

    return 0;
}

static int
copy(int n)
{
    const char *srcfile, *dstfile;
    int fd1, fd2;

    srcfile = srcs[n];

    if (dstdir) {
        if (asprintf((char **)&dstfile, "%s/%s", dst,
                     basename(strdupa(srcfile))) == -1) {
            error(0, 0, "Out of memory");
            return -1;
        }
    } else
        dstfile = dst;

    if (strcmp("-", srcfile) == 0)
        fd1 = STDIN_FILENO;
    else {
        fd1 = open(srcfile, O_RDONLY);
        if (fd1 == -1) {
            error(0, errno, "Couldn't open %s", srcfile);
            return -1;
        }
    }

    if (hugetlbfs)
        fd2 = open(dstfile, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    else {
        fd2 = open(dirname(strdupa(dstfile)), O_RDWR | O_TMPFILE,
                   S_IRUSR | S_IWUSR);
    }
    if (fd2 == -1) {
        error(0, errno, "Couldn't open %s", dstfile);
        goto err1;
    }

    if (do_copy(fd1, fd2, hugetlbfs) == -1)
        goto err2;
    if (copy_mode(fd1, fd2) == -1)
        goto err2;

    close(fd1);
    if (!hugetlbfs)
        do_link(fd2, dstfile);
    if (close(fd2) == -1) {
        error(0, errno, "Couldn't close %s", dstfile);
        return -1;
    }

    if (verbose)
        fprintf(stderr, "%s -> %s\n", srcfile, dstfile);
    return 0;

err2:
    close(fd2);
err1:
    close(fd1);
    return -1;
}

int
main(int argc, char **argv)
{
    int err = 0;
    int i;
    struct stat dstsb;

    if (parse_cmdline(argc, argv) == -1)
        return EXIT_FAILURE;

    if ((numsrcs > 1) || ((stat(dst, &dstsb) == 0) && S_ISDIR(dstsb.st_mode))) {
        size_t slen = strlen(dst);

        if (dst[slen-1] == '/')
            *((char *)dst+slen-1) = '\0';
        dstdir = 1;
    }

    for (i = 0; i < numsrcs; i++) {
        if (copy(i) == -1) {
            err = 1;
            error(0, 0, "Error copying %s", srcs[i]);
        }
    }

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
