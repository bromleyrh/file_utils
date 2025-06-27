/*
 * sys_dep.h
 */

#ifndef _SYS_DEP_H
#define _SYS_DEP_H

#include "config.h"

#include "common.h"

#include <stdint.h>

#ifdef HAVE_LINUX_MAGIC_H
#include <linux/magic.h>

#endif
typedef struct {
    int64_t val[2];
} fs_id_t;

struct fs_stat {
    uint64_t    f_type;     /* type of file system */
    uint64_t    f_bsize;    /* file system fragment size */
    uint64_t    f_blocks;   /* total data blocks in file system */
    uint64_t    f_bfree;    /* free blocks in file system */
    uint64_t    f_files;    /* total file nodes in file system */
    fs_id_t     f_fsid;     /* file system ID */
    uint64_t    f_flags;    /* mount flags of file system */
};

EXPORTED int get_fs_stat_path(const char *path, struct fs_stat *buf);

EXPORTED int get_fs_stat(int fd, struct fs_stat *buf);

#endif

/* vi: set expandtab sw=4 ts=4: */
