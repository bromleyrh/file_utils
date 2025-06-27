/*
 * fifo_transfer.c
 */

#define _GNU_SOURCE

#include "sys_dep.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>

ssize_t
fifo_transfer(int fd_in, int64_t *off_in, int fd_out, int64_t *off_out,
              size_t len, unsigned partial)
{
    loff_t offset_in, offset_out;
    loff_t *offset_in_p, *offset_out_p;
    ssize_t ret;

    if (off_in == NULL)
        offset_in_p = NULL;
    else {
        offset_in = *off_in;
        offset_in_p = &offset_in;
    }
    if (off_out == NULL)
        offset_out_p = NULL;
    else {
        offset_out = *off_out;
        offset_out_p = &offset_out;
    }

    ret = splice(fd_in, offset_in_p, fd_out, offset_out_p, len,
                 partial ? SPLICE_F_MORE : 0);

    if (ret > 0) {
        if (off_in != NULL)
            *off_in = offset_in;
        if (off_out != NULL)
            *off_out = offset_out;
    }

    return ret;
}

/* vi: set expandtab sw=4 ts=4: */
