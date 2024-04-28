/*
 * blkdev.c
 */

#include "backup.h"
#include "backup_util.h"

#include <strings_ext.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/fs.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

int
blkdev_set_read_only(const char *path, int read_only, int *prev_read_only)
{
    int err;
    int fd;
    int prev;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        err = -errno;
        error(0, errno, "Error opening %s", path);
        return err;
    }

    if (ioctl(fd, BLKROGET, &prev) == -1) {
        error(0, errno, "Error setting %s read-only", path);
        goto err;
    }

    if (prev != read_only && ioctl(fd, BLKROSET, &read_only) == -1) {
        error(0, errno, "Error setting %s read-only", path);
        goto err;
    }

    close(fd);

    if (prev_read_only != NULL)
        *prev_read_only = prev;
    return 0;

err:
    err = -errno;
    close(fd);
    return err;
}

int
blkdev_format(const char *path, const char *cmd, const char *dest_specifier)
{
    char *fullcmd;
    int err;

    debug_print("Formatting device %s", path);

    fullcmd = strsub(cmd, dest_specifier, path);
    if (fullcmd == NULL)
        return -errno;

    debug_print("Running \"%s\"", fullcmd);
    err = run_cmd(fullcmd);

    free(fullcmd);

    return err;
}

/* vi: set expandtab sw=4 ts=4: */
