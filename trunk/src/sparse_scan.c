/*
 * sparse_scan.c
 */

#define _FILE_OFFSET_BITS 64

#define _GNU_SOURCE

#include <strings_ext.h>

#include <files/util.h>

#include <errno.h>
#include <error.h>
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

static int do_create_holes(int, uint64_t, uint64_t);
static int process_block_range(int, int64_t, int64_t);

static int scan_data(int, const char *, size_t, off_t, int *);

static int do_zero_block_scan(int);

static int block_scan_cb(int, int, const char *, const char *, struct stat *,
                         void *);

static int create_holes;

static uint64_t totbytes;

static int
do_create_holes(int fd, uint64_t begin, uint64_t end)
{
    if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                  begin * BLKSIZE, (end + 1 - begin) * BLKSIZE) == -1) {
        error(0, errno, "Error creating hole in file");
        return errno;
    }

    return 0;
}

static int
process_block_range(int fd, int64_t begin, int64_t end)
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
            err = do_create_holes(fd, start, last);
            if (err)
                return err;
        }

        totbytes += numblk * BLKSIZE;
    }

    return 0;
}

static int
scan_data(int fd, const char *buf, size_t len, off_t off, int *lastnonzero)
{
    int err = 0;
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

        err = process_block_range(fd, *lastnonzero, nonzero);
        if (err)
            goto end;
        *lastnonzero = nonzero2 ? nextblk : nonzero;
    } else if (nonzero2) {
        err = process_block_range(fd, *lastnonzero, nextblk);
        if (err)
            goto end;
        *lastnonzero = nextblk;
    }

end:
    return err;
}

static int
do_zero_block_scan(int fd)
{
    int err;
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

        err = scan_data(fd, buf, ret, off, &lastnonzero);
        if (err)
            goto end;
        off += ret;
    }

    err = process_block_range(fd, lastnonzero, off / BLKSIZE);

end:
    return err;
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
    int acc;
    int err;
    int fd;
    struct stat s;

    setlinebuf(stdout);

    if (argc < 2) {
        fprintf(stderr, "Must specify file\n");
        return EXIT_FAILURE;
    }
    if ((argc > 2) && (strcmp("-H", argv[1]) == 0)) {
        create_holes = 1;
        path = argv[2];
        acc = O_RDWR;
    } else {
        path = argv[1];
        acc = O_RDONLY;
    }

    for (;;) {
        fd = open(path, acc | O_NOCTTY);
        if (fd >= 0)
            break;
        if ((errno != EISDIR) || (acc == O_RDONLY)) {
            fprintf(stderr, "Error opening %s: %s\n", path, strerror(errno));
            return EXIT_FAILURE;
        }
        acc = O_RDONLY;
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

    if (err)
        return EXIT_FAILURE;

    printf("Up to %" PRIu64 " byte%s %s freed\n", totbytes,
           (totbytes == 1) ? "" : "s", create_holes ? "were" : "can be");

    return EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
