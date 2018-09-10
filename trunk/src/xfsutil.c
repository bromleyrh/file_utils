/*
 * xfsutil.c
 */

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

typedef off_t off64_t;
#include <xfs/xfs.h>

static int print_dioattrs(FILE *, int);

static int
print_dioattrs(FILE *outf, int fd)
{
    struct dioattr dioattrs;

    if (xfsctl(NULL, fd, XFS_IOC_DIOINFO, &dioattrs) == -1) {
        error(0, errno, "Error getting XFS information");
        return -errno;
    }

    fprintf(outf,
            "     Memory alignment: %" PRIu32 " bytes\n"
            "        Transfer unit: %" PRIu32 " bytes\n"
            "Maximum transfer size: %" PRIu32 " bytes\n",
            dioattrs.d_mem, dioattrs.d_miniosz, dioattrs.d_maxiosz);

    return 0;
}

static int
test_dio(int fd)
{
    int err;
    int fl;
    struct dioattr dioattrs;
    void *buf;

    if (xfsctl(NULL, fd, XFS_IOC_DIOINFO, &dioattrs) == -1) {
        error(0, errno, "Error getting XFS information");
        return -errno;
    }

    err = posix_memalign(&buf, dioattrs.d_mem, dioattrs.d_miniosz);
    if (err)
        return err;

    fl = fcntl(fd, F_GETFL);
    if (fl == -1)
        goto err;
    if (fcntl(fd, F_SETFL, fl | O_DIRECT) == -1)
        goto err;

    if (pread(fd, buf, dioattrs.d_miniosz, 0) == -1) {
        error(0, errno, "Error reading");
        goto err;
    }

    free(buf);

    return 0;

err:
    free(buf);
    return -errno;
}

int
main(int argc, char **argv)
{
    const char *file, *mode;
    int fd;
    int ret = EXIT_SUCCESS;

    if (argc < 3)
        error(EXIT_FAILURE, 0, "Must specify file and mode");
    file = argv[1];
    mode = argv[2];

    if (mode[0] != '-')
        error(EXIT_FAILURE, 0, "Invalid mode %s", mode);

    fd = open(file, O_NONBLOCK | O_RDONLY);
    if (fd == -1)
        error(EXIT_FAILURE, errno, "Error opening %s", file);

    if (!platform_test_xfs_fd(fd)) {
        error(0, 0, "%s does not reside on an XFS file system", file);
        close(fd);
        return EXIT_FAILURE;
    }

    switch (mode[1]) {
    case 'd':
        printf("Direct I/O parameters for %s:\n", file);
        if (print_dioattrs(stdout, fd) != 0)
            ret = EXIT_FAILURE;
        break;
    case 't':
        if (test_dio(fd) != 0)
            ret = EXIT_FAILURE;
        break;
    default:
        error(0, 0, "Invalid mode %s", mode);
        ret = EXIT_FAILURE;
    }

    close(fd);
    return ret;
}

/* vi: set expandtab sw=4 ts=4: */
