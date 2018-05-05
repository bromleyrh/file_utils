/*
 * mount.c
 */

#define _GNU_SOURCE

#include "config.h"

#include "backup.h"
#include "util.h"

#include <libmount/libmount.h>

#include <avl_tree.h>
#include <strings_ext.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <sched.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

static int do_fs_cmp(struct libmnt_fs *, struct libmnt_fs *);
#ifdef HAVE_MNT_TABLE_UNIQ_FS
static int mnt_cmp(struct libmnt_table *, struct libmnt_fs *,
                   struct libmnt_fs *);
#endif
static int fs_cmp(const void *, const void *, void *);

static int uniq_fs(struct libmnt_table *, struct libmnt_iter *);
static int keep_mnt(const char *);

static int
do_fs_cmp(struct libmnt_fs *fs1, struct libmnt_fs *fs2)
{
    const char *target1, *target2;

    if (((target1 = mnt_fs_get_target(fs1)) == NULL)
        || ((target2 = mnt_fs_get_target(fs2)) == NULL))
        return -1;

    return strcmp(target1, target2);
}

#ifdef HAVE_MNT_TABLE_UNIQ_FS
static int
mnt_cmp(struct libmnt_table *tbl, struct libmnt_fs *fs1, struct libmnt_fs *fs2)
{
    (void)tbl;

    return do_fs_cmp(fs1, fs2);
}

#endif
static int
fs_cmp(const void *k1, const void *k2, void *ctx)
{
    struct libmnt_fs *fs1 = (struct libmnt_fs *)k1;
    struct libmnt_fs *fs2 = (struct libmnt_fs *)k2;

    (void)ctx;

    return do_fs_cmp(fs1, fs2);
}

static int
uniq_fs(struct libmnt_table *tbl, struct libmnt_iter *itr)
{
    int ret;
    struct avl_tree *fs_set;

    ret = avl_tree_new(&fs_set, sizeof(struct libmnt_fs *), &fs_cmp, 0, NULL,
                       NULL, NULL);
    if (ret != 0)
        return ret;

    mnt_reset_iter(itr, -1);

    for (;;) {
        struct libmnt_fs *fs;

        ret = mnt_table_next_fs(tbl, itr, &fs);
        if (ret != 0) {
            if (ret == 1)
                break;
            goto err;
        }
        ret = avl_tree_insert(fs_set, &fs);
        if (ret != 0) {
            if (ret == -EADDRINUSE) {
                ret = mnt_table_remove_fs(tbl, fs);
                if (ret != 0)
                    goto err;
            } else
                goto err;
        }
    }

    mnt_reset_iter(itr, -1);

    avl_tree_free(fs_set);

    return 0;

err:
    avl_tree_free(fs_set);
    return -EIO;
}

#define MNT(target) {target, sizeof(target) - 1}

static int
keep_mnt(const char *target)
{
    size_t i;

    static const struct {
        const char  *target;
        size_t      len;
    } keep[] = {
        MNT("/dev"),
        MNT("/proc"),
        MNT("/run"),
        MNT("/sys"),
        MNT("/tmp")
    }, *mnt;

    if (strcmp("/", target) == 0)
        return 1;

    for (i = 0; i < sizeof(keep)/sizeof(keep[0]); i++) {
        mnt = &keep[i];

        if ((strncmp(target, mnt->target, mnt->len) == 0)
            && ((target[mnt->len] == '\0') || (target[mnt->len] == '/')))
            return 1;
    }

    return 0;
}

#undef MNT

int
mount_ns_unshare()
{
    int ret;
    struct libmnt_context *mntctx;
    struct libmnt_fs *fs;
    struct libmnt_iter *itr;
    struct libmnt_table *tbl;

    /* requires CAP_SYS_ADMIN */
    if (unshare(CLONE_NEWNS) == -1) {
        error(0, errno, "Error unsharing namespace");
        return -errno;
    }

    tbl = mnt_new_table();
    if (tbl == NULL)
        return -ENOMEM;
    itr = mnt_new_iter(MNT_ITER_FORWARD);
    if (itr == NULL) {
        mnt_free_table(tbl);
        return -ENOMEM;
    }
    mntctx = mnt_new_context();
    if (mntctx == NULL) {
        mnt_free_table(tbl);
        mnt_free_iter(itr);
        return -ENOMEM;
    }
    if (mnt_context_disable_mtab(mntctx, 1) != 0)
        goto err;

    if (mnt_table_parse_mtab(tbl, NULL) != 0)
        goto err;

#ifdef HAVE_MNT_TABLE_UNIQ_FS
    if (mnt_table_uniq_fs(tbl, 0, &mnt_cmp) != 0)
#else
    if (uniq_fs(tbl, itr) != 0)
#endif
        goto err;

    for (;;) {
        const char *target;

        target = mnt_fs_get_target(fs);
        if (target == NULL)
            goto err;

        if (!keep_mnt(target)) {
            debug_print("Unmounting %s in private namespace", target);
            if ((mnt_reset_context(mntctx) != 0)
                || (mnt_context_set_fs(mntctx, fs) != 0)
                || (mnt_context_umount(mntctx) != 0))
                goto err;
        }

        ret = mnt_table_next_fs(tbl, itr, &fs);
        if (ret != 0) {
            if (ret == 1)
                break;
            goto err;
        }
    }

    mnt_free_context(mntctx);
    mnt_free_iter(itr);
    mnt_free_table(tbl);

    return 0;

err:
    error(0, 0, "Error parsing /etc/mtab");
    mnt_free_context(mntctx);
    mnt_free_iter(itr);
    mnt_free_table(tbl);
    return -EIO;
}

int
mount_filesystem(const char *devpath, const char *mntpath, int flags)
{
    int mflags;
    int ret;
    struct libmnt_context *mntctx;

    debug_print("Mounting %s", devpath ? devpath : mntpath);

    mntctx = mnt_new_context();
    if (mntctx == NULL)
        return -ENOMEM;

    mflags = MS_NODEV | MS_NOEXEC;
    if (flags == MNT_FS_READ)
        mflags |= MS_RDONLY;

    if (mnt_context_set_mflags(mntctx, mflags) != 0)
        goto err1;

    if ((flags == MNT_FS_FORCE_WRITE)
        && (mnt_context_set_options(mntctx, "rw") != 0))
        goto err1;

    if (devpath != NULL) {
        if (mnt_context_set_source(mntctx, devpath) != 0)
            goto err1;
    } else if (mnt_context_set_target(mntctx, mntpath) != 0)
        goto err1;

    /* requires CAP_SYS_ADMIN */
    ret = mnt_context_mount(mntctx);
    if (ret != 0)
        goto err2;

    /* open root directory to provide a handle for subsequent operations */
    ret = open(mntpath, O_DIRECTORY | O_RDONLY);
    if (ret == -1) {
        ret = -errno;
        unmount_filesystem(mntpath, -1);
        goto err2;
    }

    return ret;

err2:
    mnt_free_context(mntctx);
    return (ret > 0) ? -ret : ret;

err1:
    mnt_free_context(mntctx);
    return -EIO;
}

int
unmount_filesystem(const char *path, int rootfd)
{
    int ret;
    struct libmnt_context *mntctx;

    debug_print("Unmounting %s", path);

    mntctx = mnt_new_context();
    if (mntctx == NULL)
        return -ENOMEM;

    if (mnt_context_set_target(mntctx, path) != 0) {
        mnt_free_context(mntctx);
        return -EIO;
    }

    if (rootfd >= 0) {
        /* explicitly synchronize filesystem for greater assurance of data
           integrity if filesystem is writable */
#ifdef HAVE_SYNCFS
        syncfs(rootfd);
#else
        sync();
#endif
        close(rootfd);
    }

    /* requires CAP_SYS_ADMIN */
    ret = mnt_context_umount(mntctx);

    mnt_free_context(mntctx);

    return (ret > 0) ? -ret : ret;
}

int
check_filesystem(const char *path, const char *cmd, const char *src_specifier)
{
    const char *fullcmd;
    int err;

    debug_print("Checking filesystem on %s", path);

    fullcmd = strsub(cmd, src_specifier, path);
    if (fullcmd == NULL)
        return -errno;

    debug_print("Running \"%s\"", fullcmd);
    err = run_cmd(fullcmd);

    free((void *)fullcmd);

    return err;
}

/* vi: set expandtab sw=4 ts=4: */
