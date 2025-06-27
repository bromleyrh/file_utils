/*
 * file_send.c
 */

#define _FILE_OFFSET_BITS 64

#include "sys_dep.h"

#include <stddef.h>
#include <stdint.h>

#include <sys/sendfile.h>
#include <sys/types.h>

ssize_t
file_send(int out_fd, int in_fd, int64_t *offset, size_t count)
{
    return sendfile(out_fd, in_fd, offset, count);
}

/* vi: set expandtab sw=4 ts=4: */
