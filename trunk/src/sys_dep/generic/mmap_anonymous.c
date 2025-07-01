/*
 * mmap_anonymous.c
 */

#include "sys_dep.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/mman.h>

void *
mmap_anonymous(void *addr, size_t length, int prot, int flags, int fd,
               int64_t offset)
{
    (void)addr;
    (void)length;
    (void)prot;
    (void)flags;
    (void)fd;
    (void)offset;

    errno = ENOTSUP;
    return MAP_FAILED;
}

/* vi: set expandtab sw=4 ts=4: */
