/*
 * fastcp.c
 */

#include <files/util.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

static void print_usage(const char *);

static void
print_usage(const char *progname)
{
    printf("Usage: %s [options] <source_path> <destination_path>\n"
           "\n"
           "    -h output help\n",
           progname);
}

int
main(int argc, char **argv)
{
    const char *dst, *src;
    int fd1, fd2;
    int ret;

    if (argc > 3) {
        if (strcmp("-h", argv[1]) == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        src = argv[2];
        dst = argv[3];
    } else if (argc == 3) {
        src = argv[1];
        dst = argv[2];
    } else {
        if ((argc > 1) && (strcmp("-h", argv[1]) == 0)) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        error(EXIT_FAILURE, 0, "Must specify source and destination paths");
    }

    fd1 = open(src, O_RDONLY);
    if (fd1 == -1)
        error(EXIT_FAILURE, errno, "Error opening %s", src);

    fd2 = open(dst, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR);
    if (fd2 == -1) {
        error(0, errno, "Error opening %s", dst);
        goto err1;
    }

    ret = file_copy_fd(fd1, fd2, 0);
    if (ret != 0) {
        error(0, -ret, "Error copying file");
        goto err2;
    }

    close(fd1);
    if (close(fd2) == -1)
        error(EXIT_FAILURE, errno, "Error closing file");

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;

err2:
    close(fd2);
err1:
    close(fd1);
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
