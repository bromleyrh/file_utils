/*
 * backup.h
 */

#ifndef _BACKUP_H
#define _BACKUP_H

#define _LIBBACKUP_H_INTERNAL
#include <backup/libbackup_common.h>
#undef _LIBBACKUP_H_INTERNAL

#ifdef __cplusplus
extern "C" {
#endif

#define MNT_FS_WRITE 0
#define MNT_FS_FORCE_WRITE 1
#define MNT_FS_READ 2

extern LIBBACKUP_EXPORTED int backup_debug;

LIBBACKUP_EXPORTED int blkdev_set_read_only(const char *path, int read_only,
                                            int *prev_read_only);

LIBBACKUP_EXPORTED int blkdev_format(const char *path, const char *cmd,
                                     const char *dest_specifier);

LIBBACKUP_EXPORTED int mount_ns_unshare(void);

LIBBACKUP_EXPORTED int mount_filesystem(const char *devpath,
                                        const char *mntpath, int flags);
LIBBACKUP_EXPORTED int unmount_filesystem(const char *path, int rootfd);
LIBBACKUP_EXPORTED int check_filesystem(const char *path, const char *cmd,
                                        const char *src_specifier);

#ifdef __cplusplus
}
#endif

#endif

/* vi: set expandtab sw=4 ts=4: */
