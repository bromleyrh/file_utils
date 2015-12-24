/*
 * cp_mem.c
 */

#define _GNU_SOURCE

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BLKSIZE 512

static const char **srcs;
static const char *dst;
static int dstdir;
static int hugetlbfs;
static int numsrcs;
static int verbose;

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
    srcs = malloc(numsrcs * sizeof(char *));
    if (srcs == NULL) {
        error(0, 0, "Out of memory");
        return -1;
    }
    for (i = 0; i < numsrcs; i++)
        srcs[i] = argv[1+numopts+i];
    dst = argv[argc-1];

    return 0;
}

#define BUFSIZE (1024 * 1024)

static int
do_copy(int fd1, int fd2, int hugetlbfs)
{
    char *dest;
    int err = 0;
    off_t off;
    struct stat srcsb;

    (void)hugetlbfs;

    if (fstat(fd1, &srcsb) == -1) {
        error(0, errno, "Couldn't stat source file");
        return -1;
    }

    if (ftruncate(fd2, srcsb.st_size) == -1) {
        error(0, errno, "Couldn't extend destination file");
        return -1;
    }

    dest = (char *)mmap(0, srcsb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                        fd2, 0);
    if (dest == MAP_FAILED) {
        error(0, errno, "Memory mapping destination file failed");
        return -1;
    }

    for (off = 0; off < srcsb.st_size; off += BUFSIZE) {
        char buf[BUFSIZE];
        size_t blockbytes, bytesread, to_read;
        ssize_t ret;
        static char zeroblock[BLKSIZE];

        to_read = srcsb.st_size - off;
        if (to_read > sizeof(buf))
            to_read = sizeof(buf);

        for (bytesread = 0; bytesread < to_read; bytesread += ret) {
            ret = read(fd1, buf + bytesread, to_read - bytesread);
            if (ret == 0)
                goto end;
            if (ret == -1) {
                error(0, errno, "Couldn't read source file");
                err = -1;
                goto end;
            }
        }
        for (bytesread = 0; bytesread < to_read; bytesread += blockbytes) {
            if (to_read - bytesread < BLKSIZE)
                blockbytes = to_read - bytesread;
            else {
                blockbytes = BLKSIZE;
                if (memcmp(buf + bytesread, zeroblock, BLKSIZE) == 0)
                    continue;
            }
            memcpy(dest + off + bytesread, buf + bytesread, blockbytes);
        }
    }

end:
    munmap(dest, srcsb.st_size);
    return err;
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

    fd1 = open(srcfile, O_RDONLY);
    if (fd1 == -1) {
        error(0, errno, "Couldn't open %s", srcfile);
        return -1;
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
