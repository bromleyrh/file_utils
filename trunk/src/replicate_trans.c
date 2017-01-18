/*
 * replicate_trans.c
 */

#include "replicate_common.h"
#include "replicate_trans.h"

#include <strings_ext.h>

#include <files/util.h>

#include <errno.h>
#include <error.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/statvfs.h>

struct copy_ctx {
    off_t       fsbytesused;
    off_t       bytescopied;
    off_t       lastoff;
    ino_t       lastino;
    const char  *lastpath;
};

volatile sig_atomic_t quit;

static int copy_cb(int, int, const char *, const char *, struct stat *, void *);

static int copy_fn(void *);

static int
copy_cb(int fd, int dirfd, const char *name, const char *path, struct stat *s,
        void *ctx)
{
    struct dir_copy_ctx *dcpctx = (struct dir_copy_ctx *)ctx;

    (void)fd;
    (void)dirfd;
    (void)name;
    (void)path;
    (void)s;

    if (dcpctx->off >= 0) {
        struct copy_ctx *cctx = (struct copy_ctx *)(dcpctx->ctx);

        if (s->st_ino != cctx->lastino) {
            if (debug && (cctx->lastpath != NULL)) {
                fprintf(stderr, " (copied %s)\n", cctx->lastpath);
                free((void *)(cctx->lastpath));
            }
            cctx->bytescopied += dcpctx->off;
            cctx->lastino = s->st_ino;
            cctx->lastpath = strdup(path);
        } else
            cctx->bytescopied += dcpctx->off - cctx->lastoff;
        cctx->lastoff = dcpctx->off;

        if (debug) {
            fprintf(stderr, "\rProgress: %.6f%%",
                    (double)100 * cctx->bytescopied / cctx->fsbytesused);
        }
    }

    return quit ? -EINTR : 0;
}

static int
copy_fn(void *arg)
{
    int fl;
    int ret;
    struct copy_args *cargs = (struct copy_args *)arg;
    struct copy_ctx cctx;
    struct statvfs s;

    if ((cargs->gid != (gid_t)-1) && (setegid(cargs->gid) == -1)) {
        error(0, errno, "Error changing group");
        return errno;
    }
    if ((cargs->uid != (uid_t)-1) && (seteuid(cargs->uid) == -1)) {
        error(0, errno, "Error changing user");
        return errno;
    }

    if (fstatvfs(cargs->srcfd, &s) == -1)
        return errno;
    cctx.fsbytesused = (s.f_blocks - s.f_bfree) * s.f_frsize;
    cctx.bytescopied = 0;
    cctx.lastino = 0;
    cctx.lastpath = NULL;

    fl = DIR_COPY_CALLBACK | DIR_COPY_PHYSICAL | DIR_COPY_TMPFILE;
    if (!(cargs->keep_cache))
        fl |= DIR_COPY_DISCARD_CACHE;

    umask(0);
    ret = dir_copy_fd(cargs->srcfd, cargs->dstfd, fl, &copy_cb, &cctx);
    if (debug)
        fputc('\n', stderr);
    if (cctx.lastpath != NULL)
        free((void *)(cctx.lastpath));

    return ret;
}

int
do_copy(struct copy_args *copy_args)
{
    int ret;

    debug_print("Performing copy");

    ret = -copy_fn(copy_args);
    if (ret != 0) {
        int tmp; /* silence compiler warnings */

        tmp = seteuid(0);
        tmp = setegid(0);
        (void)tmp;

        return ret;
    }

    return ((seteuid(0) == 0) && (setegid(0) == 0)) ? 0 : -errno;
}

/* vi: set expandtab sw=4 ts=4: */
