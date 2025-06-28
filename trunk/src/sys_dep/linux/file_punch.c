/*
 * file_punch.c
 */

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#include "common.h"
#include "sys_dep.h"

#include <fcntl.h>
#include <stdint.h>

int
file_punch(int fd, int64_t offset, int64_t len, unsigned flags)
{
    int fl;
    int i;

    static const struct ent {
        int src;
        int dst;
    } flmap[] = {
        {FILE_PUNCH_KEEP_SIZE, FALLOC_FL_KEEP_SIZE}
    };

    fl = 0;
    for (i = 0; i < (int)ARRAY_SIZE(flmap); i++) {
        const struct ent *ent = &flmap[i];

        if (flags & ent->src)
            fl |= ent->dst;
    }

    return fallocate(fd, FALLOC_FL_PUNCH_HOLE | fl, offset, len);
}

/* vi: set expandtab sw=4 ts=4: */
