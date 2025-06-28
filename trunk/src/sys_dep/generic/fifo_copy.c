/*
 * fifo_copy.c
 */

#include "sys_dep.h"

#include <errno.h>
#include <stddef.h>

#include <sys/types.h>

ssize_t
fifo_copy(int fd_in, int fd_out, size_t len, unsigned partial)
{
    (void)fd_in;
    (void)fd_out;
    (void)len;
    (void)partial;

    errno = ENOTSUP;
    return -1;
}

/* vi: set expandtab sw=4 ts=4: */
