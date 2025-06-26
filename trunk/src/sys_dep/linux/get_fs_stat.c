/*
 * get_fs_stat.c
 */

#include "sys_dep.h"

#include <sys/vfs.h>

struct fsid {
    int val[2];
};

static int return_fs_stat(int, struct fs_stat *, const struct statfs *);

static int
return_fs_stat(int ret, struct fs_stat *dst, const struct statfs *src)
{
    if (ret == 0) {
        const struct fsid *fsid = (const struct fsid *)&src->f_fsid;

        dst->f_type = src->f_type;
        dst->f_bsize = src->f_frsize;
        dst->f_blocks = src->f_blocks;
        dst->f_bfree = src->f_bfree;
        dst->f_files = src->f_files;
        dst->f_fsid.val[0] = fsid->val[0];
        dst->f_fsid.val[1] = fsid->val[1];
        dst->f_flags = src->f_flags;
    }

    return ret;
}

int
get_fs_stat_path(const char *path, struct fs_stat *buf)
{
    struct statfs fs;

    return return_fs_stat(statfs(path, &fs), buf, &fs);
}

int
get_fs_stat(int fd, struct fs_stat *buf)
{
    struct statfs fs;

    return return_fs_stat(fstatfs(fd, &fs), buf, &fs);
}

/* vi: set expandtab sw=4 ts=4: */
