/*
 * backup_util.c
 */

#include "backup.h"
#include "backup_util.h"

#include <strings_ext.h>

#include <errno.h>
#include <error.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/wait.h>

int backup_debug = 0;

void
debug_print(const char *fmt, ...)
{
    if (backup_debug) {
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fputc('\n', stderr);
    }
}

int
run_cmd(const char *cmd)
{
    char **argv;
    int err = 0;
    int i;
    int status;
    pid_t pid;

    if (strwords(&argv, cmd, " \t", '"', '\\') == (size_t)-1)
        return -errno;

    pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        error(EXIT_FAILURE, errno, "Error executing %s", argv[0]);
        return -EIO;
    }
    if (pid == -1) {
        err = -errno;
        goto end;
    }

    while (waitpid(pid, &status, 0) == -1) {
        if (errno != EINTR) {
            err = -errno;
            goto end;
        }
    }

    if (!WIFEXITED(status)) {
        err = -EIO;
        goto end;
    }
    err = WEXITSTATUS(status);

end:
    for (i = 0; argv[i] != NULL; i++)
        free(argv[i]);
    free(argv);
    return err;
}

/* vi: set expandtab sw=4 ts=4: */
