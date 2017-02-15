/*
 * sparse_scan.c
 */

#include <strings_ext.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BLKSIZE 512

static void print_block_range(int, int);
static void scan_data(const char *, size_t, size_t, int *);

static int do_zero_block_scan(int);

static void
print_block_range(int begin, int end)
{
    int numblk, start;

    start = begin + 1;
    numblk = end - start;

    if (numblk > 1)
        printf("%d - %d\n", start, end - 1);
    else if (numblk == 1)
        printf("%d\n", start);
}

static void
scan_data(const char *buf, size_t len, size_t off, int *lastnonzero)
{
    int nextblk;
    int nonzero1, nonzero2;
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

int
main(int argc, char **argv)
{
    const char *path;
    int err;
    int fd;

    if (argc < 2) {
        fprintf(stderr, "Must specify file\n");
        return EXIT_FAILURE;
    }
    path = argv[1];

    fd = open(path, O_NOCTTY | O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Error opening %s\n", path);
        return EXIT_FAILURE;
    }

    err = do_zero_block_scan(fd);

    close(fd);

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
