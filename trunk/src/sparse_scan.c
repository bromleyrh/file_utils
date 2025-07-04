/*
 * sparse_scan.c
 */

#define _FILE_OFFSET_BITS 64

#include "sys_dep.h"

#define MIN_MAX_MACROS
#include "common.h"
#undef MIN_MAX_MACROS

#include <option_parsing.h>
#include <strings_ext.h>

#include <files/util.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#define BLKSIZE 4096

struct file_info {
    int         fd;
    struct stat *s;
};

static volatile sig_atomic_t quit;

static int create_holes;
static int preserve_times;

static uint64_t totbytes;

static void print_usage(const char *);
static int parse_cmdline(int, char **, const char **);

static int do_create_holes(struct file_info *, uint64_t, uint64_t);

static int process_block_range(struct file_info *, int64_t, int64_t);

static int scan_data(struct file_info *, const char *, size_t, off_t, int *);

static int do_zero_block_scan(struct file_info *);

static int block_scan_cb(int, int, const char *, const char *, struct stat *,
                         int, void *);

static void int_handler(int);
static int set_signal_handlers(void);

static void
print_usage(const char *progname)
{
    printf("Usage: %s [options] <path>\n"
           "\n"
           "    -H replace blocks of zeros in files with holes\n"
           "    -h output help\n"
           "    -p if \"-H\" given, preserve files' timestamps\n",
           progname);
}

static void
print_version()
{
#include <myutil/version.h>
    puts("libutil version " LIBUTIL_VERSION);
}

static int
parse_cmdline(int argc, char **argv, const char **path)
{
    static const struct option longopts[] = {
        {"help", 0, NULL, 'h'},
        {"version", 0, NULL, '.'},
        {NULL, 0, NULL, 0}
    };

    GET_LONG_OPTIONS(argc, argv, "Hhp.", longopts) {
    case 'H':
        create_holes = 1;
        break;
    case 'h':
        print_usage(argv[0]);
        return -2;
    case 'p':
        preserve_times = 1;
        break;
    case '.':
        print_version();
        return -2;
    default:
        return -1;
    } END_GET_LONG_OPTIONS;

    if (optind != argc - 1) {
        error(0, 0, optind >= argc
                    ? "Must specify file" : "Unrecognized arguments");
        return -1;
    }
    *path = argv[optind];

    return 0;
}

static int
do_create_holes(struct file_info *fi, uint64_t begin, uint64_t end)
{
    int err = 0;

    if (file_punch(fi->fd, begin * BLKSIZE, (end + 1 - begin) * BLKSIZE,
                   FILE_PUNCH_KEEP_SIZE)
        == -1) {
        error(0, errno, "Error creating hole in file");
        if (errno != EINTR)
            return errno;
        err = EINTR;
    }

    if (preserve_times) {
        struct timespec times[2];

        times[0] = fi->s->st_atim;
        times[1] = fi->s->st_mtim;
        if (futimens(fi->fd, times) == -1) {
            error(0, errno, "Error changing file's timestamps");
            return errno;
        }
    }

    return err;
}

static int
process_block_range(struct file_info *fi, int64_t begin, int64_t end)
{
    int err;
    int64_t numblk;
    int64_t last, start;

    start = begin + 1;
    numblk = end - start;

    if (numblk > 0) {
        last = end - 1;

        if (numblk == 1)
            printf("Block %" PRIi64 "\n", start);
        else
            printf("Blocks %" PRIi64 " - %" PRIi64 "\n", start, last);

        if (create_holes) {
            err = do_create_holes(fi, start, last);
            if (err)
                return err;
        }

        totbytes += numblk * BLKSIZE;
    }

    return 0;
}

static int
scan_data(struct file_info *fi, const char *buf, size_t len, off_t off,
          int *lastnonzero)
{
    int err = 0;
    int nonzero1, nonzero2;
    int64_t nextblk;
    size_t cmplen1, cmplen2;

    nextblk = (off + BLKSIZE) / BLKSIZE;
    cmplen1 = MIN((int64_t)len, nextblk * BLKSIZE - off);
    cmplen2 = len - cmplen1;
    nonzero1 = nonzero2 = 1;
    if (memcchr(buf, 0, cmplen1) == NULL)
        nonzero1 = 0;
    if (cmplen2 == 0 || memcchr(buf + cmplen1, 0, cmplen2) == NULL)
        nonzero2 = 0;

    if (nonzero1) {
        int nonzero = off / BLKSIZE;

        err = process_block_range(fi, *lastnonzero, nonzero);
        if (err)
            goto end;
        *lastnonzero = nonzero2 ? nextblk : nonzero;
    } else if (nonzero2) {
        err = process_block_range(fi, *lastnonzero, nextblk);
        if (err)
            goto end;
        *lastnonzero = nextblk;
    }

end:
    return err;
}

static int
do_zero_block_scan(struct file_info *fi)
{
    int err;
    int lastnonzero = -1;
    off_t off = 0;

    for (;;) {
        char buf[BLKSIZE];
        ssize_t ret;

        if (quit) {
            err = EINTR;
            goto end;
        }

        ret = read(fi->fd, buf, sizeof(buf));
        if (ret < 1) {
            if (ret != 0)
                return -errno;
            break;
        }

        err = scan_data(fi, buf, ret, off, &lastnonzero);
        if (err)
            goto end;
        off += ret;
    }

    err = process_block_range(fi, lastnonzero, off / BLKSIZE);

end:
    return err;
}

static int
block_scan_cb(int fd, int dirfd, const char *name, const char *path,
              struct stat *s, int flags, void *ctx)
{
    int err;
    struct file_info fi;

    (void)flags;
    (void)ctx;

    if (quit)
        return EINTR;

    if (!S_ISREG(s->st_mode))
        return 0;

    puts(path);

    fi.s = s;

    if (!create_holes) {
        fi.fd = fd;
        return do_zero_block_scan(&fi);
    }

    fi.fd = openat(dirfd, name, O_NOCTTY | O_RDWR);
    if (fi.fd == -1)
        return -errno;

    err = do_zero_block_scan(&fi);
    if (err) {
        close(fi.fd);
        return err;
    }

    return close(fi.fd) == 0 ? 0 : -errno;
}

static void
int_handler(int signum)
{
    (void)signum;

    quit = 1;
}

static int
set_signal_handlers()
{
    size_t i;
    struct sigaction sa;

    static const int intsignals[] = {SIGINT, SIGTERM};

    omemset(&sa, 0);
    sa.sa_handler = &int_handler;
    sa.sa_flags = SA_RESETHAND;

    for (i = 0; i < ARRAY_SIZE(intsignals); i++) {
        if (sigaction(intsignals[i], &sa, NULL) == -1)
            return -errno;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    const char *path;
    int acc;
    int fd;
    int ret;
    struct stat s;

    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
        return EXIT_FAILURE;

    ret = parse_cmdline(argc, argv, &path);
    if (ret != 0)
        return ret == -1 ? EXIT_FAILURE : EXIT_SUCCESS;

    acc = create_holes ? O_RDWR : O_RDONLY;
    for (;;) {
        fd = open(path, acc | O_NOCTTY);
        if (fd >= 0)
            break;
        if (errno != EISDIR || acc == O_RDONLY)
            error(EXIT_FAILURE, errno, "Error opening %s", path);
        acc = O_RDONLY;
    }

    if (fstat(fd, &s) == -1) {
        error(0, errno, "Error getting status of %s", path);
        goto err2;
    }

    if (set_signal_handlers() != 0)
        goto err2;

    if (S_ISDIR(s.st_mode))
        ret = dir_walk_fd(fd, &block_scan_cb, DIR_WALK_ALLOW_ERR, NULL);
    else {
        struct file_info fi;

        fi.fd = fd;
        fi.s = &s;
        ret = do_zero_block_scan(&fi);
    }

    close(fd);

    if (ret != 0)
        goto err1;

    printf("Up to %" PRIu64 " byte%s %s freed\n", totbytes,
           totbytes == 1 ? "" : "s", create_holes ? "were" : "can be");

    return EXIT_SUCCESS;

err2:
    close(fd);
err1:
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
