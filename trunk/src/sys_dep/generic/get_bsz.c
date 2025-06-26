/*
 * get_bsz.c
 */

#include "sys_dep.h"

#include <errno.h>

int
get_bsz(int fd, int *bsz)
{
    (void)fd;
    (void)bsz;

    errno = ENOTSUP;
    return -1;
}

/* vi: set expandtab sw=4 ts=4: */
