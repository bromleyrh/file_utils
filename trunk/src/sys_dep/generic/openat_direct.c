/*
 * openat_direct.c
 */

#include "sys_dep.h"

#include <errno.h>

#include <sys/types.h>

int
openat_direct(int dirfd, const char *pathname, int flags, mode_t mode)
{
    (void)dirfd;
    (void)pathname;
    (void)flags;
    (void)mode;

    errno = ENOTSUP;
    return -1;
}

int
fcntl_setfl_direct(int fd)
{
    (void)fd;

    errno = ENOTSUP;
    return -1;
}

/* vi: set expandtab sw=4 ts=4: */
