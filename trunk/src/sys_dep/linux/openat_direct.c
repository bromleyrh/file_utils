/*
 * openat_direct.c
 */

#define _GNU_SOURCE

#include "sys_dep.h"

#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>

int
openat_direct(int dirfd, const char *pathname, int flags, mode_t mode)
{
    int fl;

    fl = flags | O_DIRECT;
    return flags & O_CREAT
           ? openat(dirfd, pathname, fl, mode) : openat(dirfd, pathname, fl);
}

int
fcntl_setfl_direct(int fd)
{
    int fl;

    fl = fcntl(fd, F_GETFL);
    return fl == -1 ? -1 : fcntl(fd, F_SETFL, fl | O_DIRECT);
}

/* vi: set expandtab sw=4 ts=4: */
