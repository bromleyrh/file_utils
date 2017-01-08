/*
 * mkmanifest.c
 */

#include <proc_ext.h>

#include <errno.h>
#include <error.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <sys/wait.h>

static int set_signal_handlers(void);

static int
set_signal_handlers()
{
    size_t i;
    struct sigaction sa;

    static const int intsignals[] = {SIGINT, SIGTERM};

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESETHAND;

    for (i = 0; i < sizeof(intsignals)/sizeof(intsignals[0]); i++) {
        if (sigaction(intsignals[i], &sa, NULL) == -1)
            return -errno;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    int err;

    static char *const cmd1[] = {"verify", NULL};
    static char *const cmd2[] = {"osort", "-k3", NULL};

    struct proc cmds[] = {
        {.file = "verify", .argv = cmd1},
        {.file = "osort", .argv = cmd2}
    };
    static const int ncmds = (int)(sizeof(cmds)/sizeof(cmds[0]));

    (void)argc;
    (void)argv;

    if (set_signal_handlers() != 0)
        return EXIT_FAILURE;

    err = pipeline(cmds, ncmds);
    if (err)
        error(EXIT_FAILURE, -err, "Error executing");

    for (;;) {
        int status;

        if (wait(&status) == -1) {
            if (errno == ECHILD)
                break;
            error(EXIT_FAILURE, errno, "Error");
        }
        if (!err && (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)))
            err = -EIO;
    }

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
