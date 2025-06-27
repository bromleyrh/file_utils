/*
 * fifo_transfer.c
 */

#include "sys_dep.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>

ssize_t
fifo_transfer(int fd_in, int64_t *off_in, int fd_out, int64_t *off_out,
              size_t len, unsigned partial)
{
    (void)fd_in;
    (void)off_in;
    (void)fd_out;
    (void)off_out;
    (void)len;
    (void)partial;

    errno = ENOTSUP;
    return -1;
}

/* vi: set expandtab sw=4 ts=4: */
