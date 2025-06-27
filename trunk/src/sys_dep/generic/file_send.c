/*
 * file_send.c
 */

#include "sys_dep.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>

ssize_t
file_send(int out_fd, int in_fd, int64_t *offset, size_t count)
{
    (void)out_fd;
    (void)in_fd;
    (void)offset;
    (void)count;

    errno = ENOTSUP;
    return -1;
}

/* vi: set expandtab sw=4 ts=4: */
