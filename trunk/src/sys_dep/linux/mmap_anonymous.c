/*
 * mmap_anonymous.c
 */

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#include "sys_dep.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/mman.h>
#include <sys/types.h>

void *
mmap_anonymous(void *addr, size_t length, int prot, int flags,
               unsigned huge_pages, int fd, int64_t offset)
{
    if (huge_pages) {
#ifdef HAVE_MAP_HUGETLB
        flags |= MAP_HUGETLB;
#else
        errno = ENOTSUP;
        return MAP_FAILED;
#endif
    }
    flags |= MAP_ANONYMOUS;

    return mmap(addr, length, prot, flags, fd, offset);
}

/* vi: set expandtab sw=4 ts=4: */
