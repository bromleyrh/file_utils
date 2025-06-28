/*
 * file_punch.c
 */

#include "sys_dep.h"

#include <errno.h>
#include <stdint.h>

int
file_punch(int fd, int64_t offset, int64_t len, unsigned flags)
{
    (void)fd;
    (void)offset;
    (void)len;
    (void)flags;

    errno = ENOTSUP;
    return -1;
}

/* vi: set expandtab sw=4 ts=4: */
