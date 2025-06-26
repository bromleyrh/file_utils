/*
 * get_bsz.c
 */

#include "sys_dep.h"

#include <sys/ioctl.h>

#include <linux/fs.h>

int
get_bsz(int fd, int *bsz)
{
    return ioctl(fd, FIGETBSZ, bsz);
}

/* vi: set expandtab sw=4 ts=4: */
