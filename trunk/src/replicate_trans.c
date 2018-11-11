/*
 * replicate_trans.c
 */

#include "replicate_common.h"
#include "replicate_trans.h"
#include "util.h"

#include <dbus/dbus.h>

#include <strings_ext.h>
#include <time_ext.h>

#include <files/util.h>

#include <errno.h>
#include <error.h>
#include <fenv.h>
#include <grp.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/capability.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

struct copy_ctx {
    struct timespec starttm;
    DBusConnection  *busconn;
    off_t           fsbytesused;
    off_t           bytescopied;
    off_t           lastoff;
    ino_t           lastino;
    const char      *lastpath;
};

volatile sig_atomic_t quit;

static int getsgids(gid_t **);
static int check_creds(uid_t, gid_t, uid_t, gid_t);

static int broadcast_progress(DBusConnection *, double);
static int copy_cb(int, int, const char *, const char *, struct stat *, int,
                   void *);

static int copy_fn(void *);

static int
getsgids(gid_t **sgids)
{
    gid_t *ret;
    int err;
    int nsgids, tmp;

    nsgids = getgroups(0, NULL);
    if (nsgids == -1)
        return -errno;

    ret = do_malloc(nsgids * sizeof(*ret));
    if (ret == NULL)
        return -errno;

    tmp = getgroups(nsgids, ret);
    if (tmp != nsgids) {
        err = (tmp == -1) ? -errno : -EIO;
        free(ret);
        return err;
    }

    *sgids = ret;
    return nsgids;
}

static int
check_creds(uid_t ruid, gid_t rgid, uid_t uid, gid_t gid)
{
    if ((ruid == 0) || (ruid == uid))
        return 0;

    return ((rgid == gid) || group_member(gid)) ? 0 : -EPERM;
}

static int
broadcast_progress(DBusConnection *busconn, double pcnt)
{
    DBusMessage *msg;
    DBusMessageIter msgargs;
    dbus_uint32_t serial;

    msg = dbus_message_new_signal("/replicate/signal/progress",
                                  "replicate.signal.Progress", "Progress");
    if (msg == NULL)
        goto err1;

    dbus_message_iter_init_append(msg, &msgargs);
    if (dbus_message_iter_append_basic(&msgargs, DBUS_TYPE_DOUBLE, &pcnt)
        == 0)
        goto err2;

    if (dbus_connection_send(busconn, msg, &serial) == 0)
        goto err2;

    dbus_message_unref(msg);

    return 0;

err2:
    dbus_message_unref(msg);
err1:
    return -ENOMEM;
}

static int
copy_cb(int fd, int dirfd, const char *name, const char *path, struct stat *s,
        int flags, void *ctx)
{
    double pcnt;
    struct dir_copy_ctx *dcpctx = (struct dir_copy_ctx *)ctx;

    (void)fd;
    (void)dirfd;
    (void)name;
    (void)path;
    (void)s;
    (void)flags;

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

        pcnt = (double)100 * cctx->bytescopied / cctx->fsbytesused;
        if (debug) {
            double throughput;
            struct timespec curtm, difftm;

            clock_gettime(CLOCK_MONOTONIC_RAW, &curtm);
            timespec_diff(&curtm, &cctx->starttm, &difftm);
            throughput = cctx->bytescopied
                         / (difftm.tv_sec + difftm.tv_nsec * 0.000000001)
                         / (1024 * 1024);
            fprintf(stderr, "\rProgress: %.6f%% (%.6f MiB/s)", pcnt,
                    throughput);
        }
        broadcast_progress(cctx->busconn, pcnt);
    }

    return quit ? -EINTR : 0;
}

static int
copy_fn(void *arg)
{
    int fexcepts = 0;
    int fl;
    int ret;
    struct copy_args *cargs = (struct copy_args *)arg;
    struct copy_ctx cctx;
    struct statvfs s;

    if (fstatvfs(cargs->srcfd, &s) == -1) {
        ret = errno;
        error(0, errno, "Error getting file system statistics");
        return ret;
    }
    cctx.busconn = cargs->busconn;
    cctx.fsbytesused = (s.f_blocks - s.f_bfree) * s.f_frsize;
    cctx.bytescopied = 0;
    cctx.lastino = 0;
    cctx.lastpath = NULL;

    fl = DIR_COPY_CALLBACK | DIR_COPY_PHYSICAL | DIR_COPY_PRESERVE_LINKS
         | DIR_COPY_SYNC | DIR_COPY_TMPFILE;
    if (!(cargs->keep_cache))
        fl |= DIR_COPY_DISCARD_CACHE;

    umask(0);

    if (debug) {
        /* disable floating-point traps from calculations for debugging
           output */
        fexcepts = fedisableexcept(FE_ALL_EXCEPT);
        if (fexcepts == -1) {
            TRACE(0, "fedisableexcept()");
            return EIO;
        }
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &cctx.starttm);

    ret = -dir_copy_fd(cargs->srcfd, cargs->dstfd, fl, &copy_cb, &cctx);
    if (debug) {
        feenableexcept(fexcepts);
        fputc('\n', stderr);
    }
    if (cctx.lastpath != NULL)
        free((void *)(cctx.lastpath));

    return ret;
}

int
do_copy(struct copy_args *copy_args)
{
    cap_t caps;
    gid_t egid, *sgids = NULL;
    int nsgids;
    int ret, tmp;
    static const cap_value_t capval_fsetid = CAP_FSETID;
    uid_t euid;

    ret = check_creds(ruid, rgid, copy_args->uid, copy_args->gid);
    if (ret != 0) {
        error(0, 0, "Credentials invalid");
        return ret;
    }

    nsgids = getsgids(&sgids);
    if (nsgids < 0) {
        error(0, -nsgids, "Error getting groups");
        return -nsgids;
    }
    if (setgroups(0, NULL) == -1) {
        ret = errno;
        error(0, errno, "Error setting groups");
        free(sgids);
        return ret;
    }

    egid = getegid();
    if ((copy_args->gid != (gid_t)-1) && (setegid(copy_args->gid) == -1)) {
        ret = errno;
        error(0, errno, "Error changing group");
        goto err1;
    }
    euid = geteuid();
    if ((copy_args->uid != (uid_t)-1) && (seteuid(copy_args->uid) == -1)) {
        ret = errno;
        error(0, errno, "Error changing user");
        goto err2;
    }

    /* allow preservation of set-group-ID mode bits */
    caps = cap_get_proc();
    if (caps == NULL) {
        ret = errno;
        goto err3;
    }
    if ((cap_set_flag(caps, CAP_EFFECTIVE, 1, &capval_fsetid, CAP_SET) == -1)
        || (cap_set_proc(caps) == -1)) {
        ret = errno;
        error(0, errno, "Error setting process privileges");
        goto err3;
    }
    cap_free(caps);

    debug_print("Performing copy");

    ret = -copy_fn(copy_args);
    if (ret != 0)
        goto err3;

    ret = ((seteuid(euid) == 0) && (setegid(egid) == 0)
           && (setgroups(nsgids, sgids) == 0))
          ? 0 : -errno;

    free(sgids);

    return ret;

err3:
    tmp = seteuid(euid);
    (void)tmp;
err2:
    tmp = setegid(egid);
    (void)tmp;
err1:
    setgroups(nsgids, sgids);
    free(sgids);
    return ret;
}

/* vi: set expandtab sw=4 ts=4: */
