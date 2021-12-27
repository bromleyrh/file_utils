/*
 * replicate_trans.c
 */

#include "replicate_common.h"
#include "replicate_fs.h"
#include "replicate_trans.h"
#include "util.h"

#include <dbus/dbus.h>

#include <strings_ext.h>
#include <time_ext.h>

#include <files/util.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <fenv.h>
#include <grp.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/magic.h>

#include <sys/capability.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>

struct copy_ctx {
    struct timespec starttm;
    DBusConnection  *busconn;
    off_t           fsbytesused;
    off_t           bytescopied;
    off_t           lastoff;
    dev_t           lastdev;
    ino_t           lastino;
    uint64_t        filesprocessed;
    const char      *lastpath;
    const char      *hookbin;
    int             hookfd;
    mode_t          hookumask;
};

volatile sig_atomic_t quit;

static int fs_supports_tmpfile(__fsword_t);

static int check_protected_hard_links(void);

static int getsgids(gid_t **);
static int check_creds(uid_t, gid_t, uid_t, gid_t);

static int broadcast_progress(DBusConnection *, double);

static int execute_hook(int, const char *, const char *, mode_t);

static int do_execute_hook(struct copy_ctx *, const char *);

static int copy_cb(int, int, const char *, const char *, struct stat *, int,
                   void *);

static int copy_fn(void *);

#define ENTRY(t) [LINUX_FS_TYPE_HASH(t)] = {.type = (t), .valid = 1}

static int
fs_supports_tmpfile(__fsword_t type)
{
    static const struct {
        __fsword_t  type;
        int         valid;
    } typemap[256] = {
#define X(type) ENTRY(type),
        LIST_LINUX_TMPFILE_FS_TYPES()
#undef X
    }, *e;

    e = &typemap[LINUX_FS_TYPE_HASH(type)];

    return e->valid && (e->type == type);
}

#undef ENTRY

static int
check_protected_hard_links()
{
    char buf[32];
    int err;
    int fd;
    size_t len;
    ssize_t ret;

    fd = open("/proc/sys/fs/protected_hardlinks", O_RDONLY);
    if (fd == -1)
        return -errno;

    for (len = 0; len < sizeof(buf) - 1; len += ret) {
        ret = read(fd, buf + len, sizeof(buf) - 1 - len);
        if (ret == -1) {
            if (errno != EINTR) {
                err = -errno;
                goto err;
            }
            ret = 0;
            continue;
        }
        if (ret == 0)
            break;
    }
    buf[len] = '\0';

    close(fd);

    return ((buf[0] != '\0')
            && ((buf[0] != '0') || ((buf[1] != '\n') && (buf[1] != '\0'))));

err:
    close(fd);
    return err;
}

static int
getsgids(gid_t **sgids)
{
    gid_t *ret;
    int nsgids, tmp;

    nsgids = getgroups(0, NULL);
    if (nsgids == -1)
        return -errno;

    ret = do_malloc(nsgids * sizeof(*ret));
    if (ret == NULL)
        return -errno;

    tmp = getgroups(nsgids, ret);
    if (tmp != nsgids) {
        tmp = (tmp == -1) ? -errno : -EIO;
        free(ret);
        return tmp;
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
execute_hook(int fd, const char *bin, const char *path, mode_t mask)
{
    int err, status;
    pid_t pid;

    pid = fork();
    if (pid == 0) {
        char arg0[PATH_MAX], arg1[PATH_MAX];
        char *argv[3];
        extern char **environ;

        umask(mask);

        strlcpy(arg0, bin, sizeof(arg0));
        strlcpy(arg1, path, sizeof(arg1));
        argv[0] = arg0;
        argv[1] = arg1;
        argv[2] = NULL;

        fexecve(fd, argv, environ);
        error(0, errno, "Error executing %s", bin);
        _exit(EXIT_FAILURE);
    }
    if (pid == -1)
        return -errno;

    if (waitpid(pid, &status, 0) == -1) {
        err = -errno;
        goto err;
    }
    if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
        err = -EIO;
        goto err;
    }

    return 0;

err:
    error(0, -err, "Error executing %s", bin);
    return err;
}

static int
do_execute_hook(struct copy_ctx *cctx, const char *path)
{
    return (cctx->hookfd == -1)
           ? 0
           : execute_hook(cctx->hookfd, cctx->hookbin, path, cctx->hookumask);
}

static int
copy_cb(int fd, int dirfd, const char *name, const char *path, struct stat *s,
        int flags, void *ctx)
{
    double pcnt;
    int ret;
    int new_file;
    struct copy_ctx *cctx;
    struct dir_copy_ctx *dcpctx = (struct dir_copy_ctx *)ctx;

    (void)fd;
    (void)dirfd;
    (void)name;
    (void)flags;

    cctx = (struct copy_ctx *)(dcpctx->ctx);

    new_file = ((s->st_ino != cctx->lastino) || (s->st_dev != cctx->lastdev));
    if (new_file)
        ++(cctx->filesprocessed);

    if (dcpctx->off < 0) {
        ret = do_execute_hook(cctx, path);
        if (ret)
            return ret;
        goto end;
    }

    if (new_file) {
        if (cctx->lastpath != NULL) {
            ret = do_execute_hook(cctx, cctx->lastpath);
            if (ret)
                return ret;
            if (debug)
                fprintf(stderr, " (copied %s)\n", cctx->lastpath);
            free((void *)(cctx->lastpath));
        }
        cctx->bytescopied += dcpctx->off;
        cctx->lastdev = s->st_dev;
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
        fprintf(stderr, "\rProgress: %.6f%% (%11.6f MiB/s)", pcnt,
                throughput);
    }
    broadcast_progress(cctx->busconn, pcnt);

end:
    return quit ? -EINTR : 0;
}

static int
copy_fn(void *arg)
{
    extern uint64_t nfilesproc;
    int fexcepts = 0;
    int fl;
    int ret;
    struct copy_args *cargs = (struct copy_args *)arg;
    struct copy_ctx cctx;
    struct statfs ds, ss;

    if ((fstatfs(cargs->srcfd, &ss) == -1)
        || (fstatfs(cargs->dstfd, &ds) == -1)) {
        ret = errno;
        error(0, errno, "Error getting file system statistics");
        return ret;
    }
    cctx.busconn = cargs->busconn;
    cctx.fsbytesused = (ss.f_blocks - ss.f_bfree) * ss.f_frsize;
    cctx.bytescopied = 0;
    cctx.lastdev = 0;
    cctx.lastino = 0;
    cctx.filesprocessed = 0;
    cctx.lastpath = NULL;
    cctx.hookbin = cargs->hookbin;
    cctx.hookfd = cargs->hookfd;

    fl = DIR_COPY_CALLBACK | DIR_COPY_PHYSICAL | DIR_COPY_PRESERVE_LINKS
         | DIR_COPY_SYNC;
    if (!(cargs->keep_cache))
        fl |= DIR_COPY_DISCARD_CACHE;
    if (fs_supports_tmpfile(ds.f_type))
        fl |= DIR_COPY_TMPFILE;

    cctx.hookumask = umask(0);

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
    if (ret == 0)
        nfilesproc = cctx.filesprocessed;
    else if (ret == EPERM) {
        error(0, 0, "Permissions error encountered while copying");
        error(0, 0, "It may be necessary to ensure fs.protected_hardlinks is "
                    "set to 0");
    }

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

    if (check_protected_hard_links() == 1) {
        fputs("Warning: fs.protected_hardlinks is nonzero: permissions errors "
              "may occur\n", stderr);
    }

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
