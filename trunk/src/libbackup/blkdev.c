/*
 * blkdev.c
 */

#include "backup.h"
#include "util.h"

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
blkdev_format(const char *path, const char *cmd, const char *dest_specifier)
{
    const char *fullcmd;
    int err;

    debug_print("Formatting device %s", path);

    fullcmd = strsub(cmd, dest_specifier, path);
    if (fullcmd == NULL)
        return -errno;

    debug_print("Running \"%s\"", fullcmd);
    err = run_cmd(fullcmd);

    free((void *)fullcmd);

    return err;
}

/* vi: set expandtab sw=4 ts=4: */
