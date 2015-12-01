/*
 * open_pipes.c
 */

#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <unistd.h>

#define BASE_FD 3

int
main(int argc, char **argv)
{
    int pipe1[2], pipe2[2];

    if (argc < 2)
        error(EXIT_FAILURE, 0, "Must specify command");

    if ((pipe(pipe1) == -1) || (pipe(pipe2) == -1))
        error(EXIT_FAILURE, errno, "Error opening pipe");

    if ((dup2(pipe1[0], BASE_FD) == -1)
        || (dup2(pipe1[1], BASE_FD + 1) == -1)
        || (dup2(pipe2[0], BASE_FD + 2) == -1)
        || (dup2(pipe2[1], BASE_FD + 3) == -1)) {
        error(0, errno, "Error duplicating file descriptor");
        goto err;
    }

    if (execvp(argv[1], &argv[1]) == -1)
        error(0, errno, "Error executing %s", argv[0]);

err:
    close(pipe1[0]);
    close(pipe1[1]);
    close(pipe2[0]);
    close(pipe2[1]);
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
