/*
 * cp_mem.c
 */

#define _FILE_OFFSET_BITS 64

#include "common.h"
#include "sys_dep.h"

#include <files/acc_ctl.h>
#include <files/util.h>

#include <option_parsing.h>
#include <strings_ext.h>

#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

struct buf {
    off_t   off;
    off_t   size;
    char    *buf;
};

struct dest {
    int         fd;
    struct buf  buf;
    size_t      blksize;
    int         hugetlbfs;
};

static char **srcs;
static char *dst;
static int dstdir;
static int hugetlbfs;
static int numsrcs;
static int verbose;

static volatile sig_atomic_t bus_err;
static sigjmp_buf env;

static void buserr_handler(int);

static int set_sigbus_handler(void);
static int parse_cmdline(int, char **);

static int saprintf(char **, const char *, ...);

static int is_on_fs_of_type(const char *, uint64_t);
static int get_dest_info(char *);

static off_t get_hugepage_size(int);
static off_t get_page_offset(off_t, int);

static int dest_init(int, int, struct dest *);
static int dest_buf_reposition(off_t, off_t, struct dest *);
static void dest_free(struct dest *);

static int do_ftruncate(int, off_t);
static int do_memcpy(void *, const void *, size_t);
static ssize_t do_read(int, void *, size_t);
static int do_write(struct dest *, const void *, size_t);

static int do_copy(int, int, int);
static int copy_mode(int, int);
#ifdef SYS_DEP_OPENAT_TMPFILE
static int do_link(int, const char *);
#endif

static int copy(int);

static void
buserr_handler(int signum)
{
    (void)signum;

    bus_err = 1;
    siglongjmp(env, -1);
}

static int
set_sigbus_handler()
{
    struct sigaction sa;

    omemset(&sa, 0);
    sa.sa_handler = &buserr_handler;

    return sigaction(SIGBUS, &sa, NULL);
}

static int
parse_cmdline(int argc, char **argv)
{
    int numopts;

    GET_OPTIONS(argc, argv, "tv") {
    case 't':
        hugetlbfs = 1;
        break;
    case 'v':
        verbose = 1;
        break;
    default:
        return -1;
    } END_GET_OPTIONS;
    numopts = optind - 1;

    if (argc - numopts < 3) {
        error(0, 0, "Must specify a source file and destination");
        return -1;
    }

    numsrcs = argc - numopts - 2;
    srcs = &argv[1+numopts];
    dst = argv[argc-1];

    return 0;
}

static int
saprintf(char **strp, const char *format, ...)
{
    char *ret;
    int n, res;
    va_list ap;

    va_start(ap, format);
    n = vsnprintf(NULL, 0, format, ap);
    va_end(ap);
    if (n < 0) {
        errno = EINVAL;
        return -1;
    }
    ++n;

    ret = malloc(n);
    if (ret == NULL)
        return -1;

    va_start(ap, format);
    res = vsnprintf(ret, n, format, ap);
    va_end(ap);
    if (res < 0) {
        res = EINVAL;
        goto err;
    }
    if (res >= n) {
        res = EIO;
        goto err;
    }

    *strp = ret;
    return res;

err:
    free(ret);
    errno = res;
    return -1;
}

static int
is_on_fs_of_type(const char *pathname, uint64_t fstype)
{
    struct fs_stat buf;

    while (get_fs_stat_path(pathname, &buf) == -1) {
        if (errno != EINTR)
            return -1;
    }

    return buf.f_type == fstype;
}

static int
get_dest_info(char *pathname)
{
    char buf[PATH_MAX];
    const char *dirpath;
    int dst_on_hugetlbfs;

    if (numsrcs > 1)
        dstdir = 1;
    else {
        struct stat dstsb;

        if (stat(pathname, &dstsb) == -1) {
            if (errno != ENOENT)
                goto err;
        } else if (S_ISDIR(dstsb.st_mode))
            dstdir = 1;
    }

    if (dstdir) {
        size_t slen = strlen(pathname);

        if (pathname[slen-1] == '/')
            *(pathname+slen-1) = '\0';
    }

    dirpath = dstdir ? pathname : dirname_safe(pathname, buf, sizeof(buf));

    dst_on_hugetlbfs = is_on_fs_of_type(dirpath, HUGETLBFS_MAGIC);
    if (dst_on_hugetlbfs == -1)
        goto err;
    if (dst_on_hugetlbfs)
        hugetlbfs = 1;

    return 0;

err:
    error(0, errno, "Couldn't get status of destination file");
    return -1;
}

static off_t
get_hugepage_size(int fd)
{
    struct stat sb;

    if (fstat(fd, &sb) == -1)
        return -1;

    return sb.st_blksize;
}

static inline off_t
get_page_offset(off_t off, int hugetlbfs_fd)
{
    static int pagesize = -1;

    if (pagesize == -1) {
        pagesize = hugetlbfs_fd == -1 ? sysconf(_SC_PAGESIZE)
                   : get_hugepage_size(hugetlbfs_fd);
        if (pagesize == -1)
            return -1;
    }

    return off / pagesize * pagesize;
}

static int
dest_init(int fd, int on_hugetlbfs, struct dest *dst)
{
    int blksize;

    if (dst == NULL)
        return -1;

    dst->fd = fd;

    dst->buf.buf = NULL;

    if (get_bsz(dst->fd, &blksize) == -1) {
        error(0, errno, "Couldn't get destination file system block size");
        return -1;
    }
    dst->blksize = blksize;

    dst->hugetlbfs = on_hugetlbfs;

    return 0;
}

static int
dest_buf_reposition(off_t offset, off_t bufsize, struct dest *dst)
{
    off_t pgoff;

    if (dst == NULL)
        return -1;

    pgoff = get_page_offset(offset, dst->hugetlbfs ? dst->fd : -1);
    if (pgoff == -1)
        return -1;

    if (!dst->hugetlbfs && do_ftruncate(dst->fd, offset + bufsize) == -1)
        goto err;

    if (dst->buf.buf != NULL)
        munmap(dst->buf.buf, dst->buf.size);
    dst->buf.off = offset;
    dst->buf.size = bufsize;
    dst->buf.buf = mmap(0, dst->buf.off - pgoff + dst->buf.size,
                        PROT_READ | PROT_WRITE, MAP_SHARED, dst->fd, pgoff);
    if (dst->buf.buf == MAP_FAILED)
        goto err;
    dst->buf.buf += dst->buf.off - pgoff;

    return 0;

err:
    error(0, errno, "Couldn't extend destination file");
    return -1;
}

static void
dest_free(struct dest *dst)
{
    if (dst == NULL)
        return;

    if (dst->buf.buf != NULL)
        munmap(dst->buf.buf, dst->buf.size);
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

static int
do_memcpy(void *dest, const void *src, size_t n)
{
    if (sigsetjmp(env, 1) != 0)
        return -1;

    memcpy(dest, src, n);

    return 0;
}

static ssize_t
do_read(int fd, void *buf, size_t count)
{
    size_t bytesread;
    ssize_t ret;

    assert(count > 0);

    for (bytesread = 0; bytesread < count; bytesread += ret) {
        ret = read(fd, (char *)buf + bytesread, count - bytesread);
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
do_write(struct dest *dst, const void *buf, size_t count)
{
    size_t blockbytes, byteswritten;

    if (dst == NULL)
        return -1;

    for (byteswritten = 0; byteswritten < count; byteswritten += blockbytes) {
        if (count - byteswritten < dst->blksize)
            blockbytes = count - byteswritten;
        else {
            blockbytes = dst->blksize;
            if (memcchr((const char *)buf + byteswritten, '\0', dst->blksize)
                == NULL)
                continue;
        }
        if (do_memcpy(dst->buf.buf + byteswritten,
                      (const char *)buf + byteswritten, blockbytes) == -1)
            return -1;
    }

    return 0;
}

#define BUFSIZE (1024 * 1024)

static int
do_copy(int fd1, int fd2, int on_hugetlbfs)
{
    off_t off;
    ssize_t num_read;
    struct dest dsts;

    if (dest_init(fd2, on_hugetlbfs, &dsts) == -1)
        return -1;

    for (off = 0;; off += num_read) {
        char buf[BUFSIZE];

        if (dest_buf_reposition(off, sizeof(buf), &dsts) == -1)
            goto err;

        num_read = do_read(fd1, buf, sizeof(buf));
        if (num_read == 0)
            break;
        if (num_read == -1) {
            error(0, errno, "Couldn't read source file");
            goto err;
        }
        if (do_write(&dsts, buf, num_read) == -1) {
            error(0, 0, "Couldn't write destination file");
            goto err;
        }
    }

    dest_free(&dsts);

    if (!on_hugetlbfs && do_ftruncate(fd2, off) == -1) {
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
        error(0, errno, "Couldn't get status of source file");
        return -1;
    }
    if (fchmod(fd2, srcsb.st_mode) == -1) {
        error(0, errno, "Couldn't set mode of destination file");
        return -1;
    }

    return 0;
}

#ifdef SYS_DEP_OPENAT_TMPFILE
static int
do_link(int fd, const char *name)
{
    char *path;

    if (saprintf(&path, "/proc/self/fd/%d", fd) < 0) {
        error(0, 0, "Out of memory");
        return -1;
    }

    if (linkat(AT_FDCWD, path, AT_FDCWD, name, AT_SYMLINK_FOLLOW) == -1) {
        error(0, errno, "Couldn't link %s", name);
        free(path);
        return -1;
    }

    free(path);

    return 0;
}

#endif
static int
copy(int n)
{
    char *srcfile, *dstfile;
    int fd1, fd2;

    srcfile = srcs[n];

    if (dstdir) {
        if (saprintf(&dstfile, "%s/%s", dst, basename_safe(srcfile)) == -1) {
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
            goto err1;
        }
    }

#ifdef SYS_DEP_OPENAT_TMPFILE
    if (hugetlbfs)
        fd2 = open(dstfile, O_CREAT | O_RDWR, ACC_MODE_DEFAULT);
    else {
        char buf[PATH_MAX];

        fd2 = openat_tmpfile(AT_FDCWD, dirname_safe(dstfile, buf, sizeof(buf)),
                             O_RDWR, ACC_MODE_DEFAULT);
    }
#else
    fd2 = open(dstfile, O_CREAT | O_RDWR, ACC_MODE_DEFAULT);
#endif
    if (fd2 == -1) {
        error(0, errno, "Couldn't open %s", dstfile);
        goto err2;
    }

    if (do_copy(fd1, fd2, hugetlbfs) == -1)
        goto err3;
    if (copy_mode(fd1, fd2) == -1)
        goto err3;

    close(fd1);
#ifdef SYS_DEP_OPENAT_TMPFILE
    if (!hugetlbfs)
        do_link(fd2, dstfile);
#endif
    if (close(fd2) == -1) {
        error(0, errno, "Couldn't close %s", dstfile);
        goto err1;
    }

    if (verbose)
        infomsgf("%s -> %s\n", srcfile, dstfile);

    if (dstdir)
        free(dstfile);

    return 0;

err3:
    close(fd2);
err2:
    close(fd1);
err1:
    if (dstdir)
        free(dstfile);
    return -1;
}

int
main(int argc, char **argv)
{
    int err = 0;
    int i;

    if (set_sigbus_handler() == -1)
        error(EXIT_FAILURE, errno, "Couldn't set signal handler");

    if (parse_cmdline(argc, argv) == -1)
        return EXIT_FAILURE;

    if (get_dest_info(dst) == -1)
        return EXIT_FAILURE;

    for (i = 0; i < numsrcs; i++) {
        if (copy(i) == -1) {
            err = 1;
            error(0, 0, "Error copying %s", srcs[i]);
        }
    }

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
