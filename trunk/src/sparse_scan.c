/*
 * sparse_scan.c
 */

#define _FILE_OFFSET_BITS 64

#include <strings_ext.h>

#include <files/util.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BLKSIZE 4096

static void print_block_range(int64_t, int64_t);
static void scan_data(const char *, size_t, off_t, int *);

static int do_zero_block_scan(int);

static int block_scan_cb(int, int, const char *, const char *, struct stat *,
                         void *);

static void
print_block_range(int64_t begin, int64_t end)
{
    int64_t numblk, start;

    start = begin + 1;
    numblk = end - start;

    if (numblk > 1)
        printf("Blocks %" PRIi64 " - %" PRIi64 "\n", start, end - 1);
    else if (numblk == 1)
        printf("Block %" PRIi64 "\n", start);
}

static void
scan_data(const char *buf, size_t len, off_t off, int *lastnonzero)
{
    int nonzero1, nonzero2;
    int64_t nextblk;
    size_t cmplen1, cmplen2;

    nextblk = (off + BLKSIZE) / BLKSIZE;
    cmplen1 = MIN(len, nextblk * BLKSIZE - off);
    cmplen2 = len - cmplen1;
    nonzero1 = nonzero2 = 1;
    if (memcchr(buf, 0, cmplen1) == NULL)
        nonzero1 = 0;
    if ((cmplen2 == 0) || (memcchr(buf + cmplen1, 0, cmplen2) == NULL))
        nonzero2 = 0;

    if (nonzero1) {
        int nonzero = off / BLKSIZE;

        print_block_range(*lastnonzero, nonzero);
        *lastnonzero = nonzero2 ? nextblk : nonzero;
    } else if (nonzero2) {
        print_block_range(*lastnonzero, nextblk);
        *lastnonzero = nextblk;
    }
}

static int
do_zero_block_scan(int fd)
{
    int lastnonzero = -1;
    off_t off = 0;

    for (;;) {
        char buf[BLKSIZE];
        ssize_t ret;

        ret = read(fd, buf, sizeof(buf));
        if (ret < 1) {
            if (ret != 0)
                return -errno;
            break;
        }

        scan_data(buf, ret, off, &lastnonzero);
        off += ret;
    }

    print_block_range(lastnonzero, off / BLKSIZE);

    return 0;
}

static int
block_scan_cb(int fd, int dirfd, const char *name, const char *path,
              struct stat *s, void *ctx)
{
    (void)dirfd;
    (void)name;
    (void)ctx;

    if (!S_ISREG(s->st_mode))
        return 0;

    puts(path);

    return do_zero_block_scan(fd);
}

int
main(int argc, char **argv)
{
    const char *path;
    int err;
    int fd;
    struct stat s;

    setlinebuf(stdout);

    if (argc < 2) {
        fprintf(stderr, "Must specify file\n");
        return EXIT_FAILURE;
    }
    path = argv[1];

    fd = open(path, O_NOCTTY | O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Error opening %s: %s\n", path, strerror(errno));
        return EXIT_FAILURE;
    }

    if (fstat(fd, &s) == -1) {
        fprintf(stderr, "Error getting stats of %s: %s\n", path,
                strerror(errno));
        close(fd);
        return EXIT_FAILURE;
    }

    if (S_ISDIR(s.st_mode))
        err = dir_walk_fd(fd, &block_scan_cb, DIR_WALK_ALLOW_ERR, NULL);
    else
        err = do_zero_block_scan(fd);

    close(fd);

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
