/*
 * sys_dep.h
 */

#ifndef _SYS_DEP_H
#define _SYS_DEP_H

#include "config.h"

#include "common.h"

#include <stddef.h>
#include <stdint.h>

#ifdef HAVE_LINUX_MAGIC_H
#include <linux/magic.h>

#endif
#include <sys/types.h>

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

#define CONTEXT_FILE_TAB        1
#define CONTEXT_FS_ATTRS        2
#define CONTEXT_HOST            4
#define CONTEXT_NET             8
#define CONTEXT_NS              16
#define CONTEXT_NS_IPC          32
#define CONTEXT_PROC_TAB        64
#define CONTEXT_RESOURCES       128
#define CONTEXT_SEM_UNDO_LIST   256
#define CONTEXT_USERS           512

#define FILE_PUNCH_KEEP_SIZE 1

EXPORTED int context_new(int flags);

EXPORTED int _setresuid(uid_t ruid, uid_t euid, uid_t suid);

EXPORTED int get_fs_stat_path(const char *path, struct fs_stat *buf);

EXPORTED int get_fs_stat(int fd, struct fs_stat *buf);

EXPORTED int get_bsz(int fd, int *bsz);

EXPORTED int openat_direct(int dirfd, const char *pathname, int flags,
                           mode_t mode);

EXPORTED int openat_directory(int dirfd, const char *pathname, int flags,
                              int nofollow);

EXPORTED int openat_tmpfile(int dirfd, const char *pathname, int flags,
                            mode_t mode);

EXPORTED int fcntl_setfl_direct(int fd);

EXPORTED ssize_t file_send(int out_fd, int in_fd, int64_t *offset,
                           size_t count);

EXPORTED int file_punch(int fd, int64_t offset, int64_t len, unsigned flags);

EXPORTED ssize_t fifo_transfer(int fd_in, int64_t *off_in, int fd_out,
                               int64_t *off_out, size_t len, unsigned partial);

EXPORTED ssize_t fifo_copy(int fd_in, int fd_out, size_t len, unsigned partial);

EXPORTED int fsync_fs(int fd);

#endif

/* vi: set expandtab sw=4 ts=4: */
