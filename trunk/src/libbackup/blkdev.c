/*
 * blkdev.c
 */

#include "libbackup.h"

#include <strings_ext.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

static int run_cmd(const char *);

static int
run_cmd(const char *cmd)
{
    char **argv;
    int err = 0;
    int i;
    int status;
    pid_t pid;

    argv = strwords(cmd, " \t", '"', '\\');
    if (argv == NULL)
        return -errno;

    pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        error(EXIT_FAILURE, errno, "Error executing %s", argv[0]);
        return EXIT_FAILURE;
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

int
blkdev_set_read_only(const char *path, int read_only, int *prev_read_only)
{
    int fd;
    int prev;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        error(0, errno, "Error opening %s", path);
        goto err1;
    }

    if (ioctl(fd, BLKROGET, &prev) == -1) {
        error(0, errno, "Error setting %s read-only", path);
        goto err2;
    }

    if ((prev != read_only) && (ioctl(fd, BLKROSET, &read_only) == -1)) {
        error(0, errno, "Error setting %s read-only", path);
        goto err2;
    }

    close(fd);

    if (prev_read_only != NULL)
        *prev_read_only = prev;
    return 0;

err2:
    close(fd);
err1:
    return -errno;
}

int
blkdev_format(const char *path, const char *cmd)
{
    const char *fullcmd;
    int err;

    debug_print("Formatting device %s", path);

    fullcmd = strsub(cmd, FORMAT_CMD_DEST_SPECIFIER, path);
    if (fullcmd == NULL)
        return -errno;

    debug_print("Running \"%s\"", fullcmd);
    err = run_cmd(fullcmd);

    free((void *)fullcmd);

    return err;
}

/* vi: set expandtab sw=4 ts=4: */
