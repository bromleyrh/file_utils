/*
 * mmap_anonymous.c
 */

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#include "sys_dep.h"

#include <stddef.h>
#include <stdint.h>

#include <sys/mman.h>
#include <sys/types.h>

void *
mmap_anonymous(void *addr, size_t length, int prot, int flags, int fd,
               int64_t offset)
{
    return mmap(addr, length, prot, flags | MAP_ANONYMOUS, fd, offset);
}

/* vi: set expandtab sw=4 ts=4: */
