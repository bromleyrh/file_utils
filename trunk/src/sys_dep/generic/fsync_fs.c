/*
 * fsync_fs.c
 */

#include "sys_dep.h"

#include <errno.h>

int
fsync_fs(int fd)
{
    (void)fd;

    errno = ENOTSUP;
    return -1;
}

/* vi: set expandtab sw=4 ts=4: */
