/*
 * open_pipes.c
 */

#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_PIPEFDS ((int []){5, 6, 7, 8})

struct pipe_data {
    int npipes;
    int *pipefds;
};

static int
parse_cmdline(int argc, char **argv, char ***cmd, struct pipe_data *pd)
{
    int i;
    int npipefds;

    if (argc < 2) {
        error(0, 0, "Must specify command");
        return -1;
    }

    if (strcmp(argv[1], "-d") != 0) {
        *cmd = &argv[1];
        return 0;
    }

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            ++i;
            break;
        }
    }

    if (i == argc) {
        error(0, 0, "Must specify command");
        return -1;
    }
    *cmd = &argv[i];

    if ((i-3) % 2 != 0) {
        error(0, 0, "Must specify 2 FDs per pipe");
        return -1;
    }
    pd->npipes = (i-3) / 2;
    npipefds = pd->npipes * 2;
    pd->pipefds = malloc(npipefds * sizeof(int));
    if (pd->pipefds == NULL) {
        error(0, 0, "Out of memory");
        return -1;
    }
    for (i = 0; i < npipefds; i++)
        pd->pipefds[i] = atoi(argv[2+i]);

    return 0;
}

static int
open_pipes(struct pipe_data *pd)
{
    int i;
    int (*pipes)[2];

    pipes = calloc(pd->npipes, sizeof(pipes[0]));
    if (pipes == NULL) {
        error(0, 0, "Out of memory");
        return -1;
    }

    for (i = 0; i < pd->npipes; i++) {
        if (pipe(pipes[i]) == -1) {
            error(0, errno, "Error opening pipe");
            break;
        }
        if ((dup2(pipes[i][0], pd->pipefds[2*i]) == -1)
            || (dup2(pipes[i][1], pd->pipefds[2*i+1]) == -1)) {
            error(0, errno, "Error duplicating file descriptor");
            close(pipes[i][0]);
            close(pipes[i][1]);
            break;
        }

        close(pipes[i][0]);
        close(pipes[i][1]);
    }
    if (i != pd->npipes) {
        int j;

        for (j = 0; j <= i; j++) {
            close(pd->pipefds[2*i]);
            close(pd->pipefds[2*i+1]);
        }
        return -1;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    char **cmd;
    struct pipe_data pd = {
        .npipes = sizeof(DEFAULT_PIPEFDS) / sizeof(DEFAULT_PIPEFDS[0]),
        .pipefds = DEFAULT_PIPEFDS
    };

    if (parse_cmdline(argc, argv, &cmd, &pd) == -1)
        return EXIT_FAILURE;

    if (open_pipes(&pd) == -1)
        return EXIT_FAILURE;

    execvp(cmd[0], cmd);
    error(0, errno, "Error executing %s", cmd[0]);

    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
