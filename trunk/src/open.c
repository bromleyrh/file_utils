/*
 * open.c
 */

#define _GNU_SOURCE

#define _FILE_OFFSET_BITS 64

#include <err.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

int
main(int argc, char **argv)
{
    char *file, *prog;
    char **args;
    int direct;
    int err;
    int fd;

    if (argc < 2)
        error(EXIT_FAILURE, 0, "No file specified");

    if (strcmp(argv[1], "-d") == 0) {
        direct = 1;
        if (argc < 3)
            error(EXIT_FAILURE, 0, "No file specified");
        if (argc < 4)
            error(EXIT_FAILURE, 0, "No program specified");
        file = argv[2];
        prog = argv[3];
        args = &argv[3];
    } else {
        direct = 0;
        if (argc < 3)
            error(EXIT_FAILURE, 0, "No program specified");
        file = argv[1];
        prog = argv[2];
        args = &argv[2];
    }

    fd = open(file, (direct ? O_DIRECT : 0) | O_RDONLY);
    if (fd == -1)
        error(EXIT_FAILURE, errno, "Could not open %s", file);

    if (dup2(fd, STDIN_FILENO) == -1) {
        err = errno;
        close(fd);
        error(EXIT_FAILURE, err, "Could not duplicate file descriptor");
    }

    close(fd);

    if ((strcmp(basename(argv[0]), "delete_input") == 0)
        && (unlink(file) == -1))
        warn("Could not remove %s", file);

    execvp(prog, args);
    error(EXIT_FAILURE, errno, "Could not execute %s", prog);

    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
