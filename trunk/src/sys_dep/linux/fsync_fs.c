/*
 * fsync_fs.c
 */

#define _GNU_SOURCE

#include "sys_dep.h"

#include <unistd.h>

int
fsync_fs(int fd)
{
    return syncfs(fd);
}

/* vi: set expandtab sw=4 ts=4: */
