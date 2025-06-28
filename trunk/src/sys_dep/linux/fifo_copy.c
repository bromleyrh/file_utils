/*
 * fifo_copy.c
 */

#define _GNU_SOURCE

#include "sys_dep.h"

#include <fcntl.h>
#include <stddef.h>

#include <sys/types.h>

ssize_t
fifo_copy(int fd_in, int fd_out, size_t len, unsigned partial)
{
    return tee(fd_in, fd_out, len, partial ? SPLICE_F_MORE : 0);
}

/* vi: set expandtab sw=4 ts=4: */
