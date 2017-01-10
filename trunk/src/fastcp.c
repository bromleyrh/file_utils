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
    printf("Usage: %s <path> <mode_and_arguments> \n"
           "Modes:\n"
           "    -c <path>         copy file identified by first path to new "
           "file identified\n"
           "                      by second path\n"
           "    -h                output help\n",
           progname);
}

int
main(int argc, char **argv)
{
    char mode;
    const char *src;
    int ret;

    if (argc < 3) {
        if ((argc > 1) && (strcmp("-h", argv[1]) == 0)) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        error(EXIT_FAILURE, 0, "Must specify path and mode");
    }
    src = argv[1];
    if ((*argv[2] != '-') || (argv[2][1] == '\0') || (argv[2][2] != '\0'))
        error(EXIT_FAILURE, 0, "Invalid mode %s", argv[2]);
    mode = argv[2][1];

    switch (mode) {
    case 'c':
        {
            const char *dst;
            int fd1, fd2;

            if (argc < 4)
                error(EXIT_FAILURE, 0, "Too few arguments given");
            dst = argv[3];

            fd1 = open(src, O_RDONLY);
            if (fd1 == -1)
                error(EXIT_FAILURE, errno, "Error opening %s", src);
            fd2 = open(dst, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR);
            if (fd2 == -1) {
                error(0, errno, "Error opening %s", dst);
                close(fd1);
                return EXIT_FAILURE;
            }

            ret = file_copy_fd(fd1, fd2, 0);
            if (ret != 0) {
                error(0, -ret, "Error copying file");
                close(fd1);
                close(fd2);
                break;
            }

            close(fd1);
            if (close(fd2) == -1)
                error(EXIT_FAILURE, errno, "Error closing file");

            break;
        }
    default:
        return EXIT_FAILURE;
    }

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
