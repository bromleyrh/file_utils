/*
 * replicate.c
 */

#include "replicate_common.h"
#include "replicate_conf.h"
#include "replicate_trans.h"

#include <dbus/dbus.h>

#include <libmount/libmount.h>

#include <backup.h>

#include <forensics.h>
#include <option_parsing.h>
#include <strings_ext.h>

#include <files/acc_ctl.h>
#include <files/util.h>

#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <mcheck.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <wordexp.h>

#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

#define MTRACE_FILE "mtrace.txt"

#define CONFIG_PATH "\"$HOME/.replicate.conf\""
#define VAR_PATH "/var/replicate"

int debug = 0;
int log_transfers = 0;
int tracing = 0;

uid_t ruid;
gid_t rgid;

static int enable_debugging_features(int);

static int set_capabilities(void);
static int init_privs(void);

static void print_usage(const char *);
static void print_version(void);
static int parse_cmdline(int, char **, const char **, int *);

static int get_conf_path(const char *, const char **);

static void int_handler(int);

static int set_signal_handlers(void);

static int init_dbus(DBusConnection **);
static void end_dbus(DBusConnection *);

static int get_sess_path(const char *, const char *, char *, size_t);

static int sess_init(int, char *, size_t);
static int sess_end(const char *);
static int sess_is_complete(const char *, const char *);
static int sess_record_complete(const char *, const char *);

void
trace(const char *file, const char *func, int line, int err, const char *fmt,
      ...)
{
    if (debug && tracing) {
#ifdef ENABLE_TRACE
        const char **bt;
        int n;
        static const char sep[] = "--------------------------------\n";
#endif
        char fmtbuf[1024];
        int old_errno = errno;
        va_list ap;

#ifdef ENABLE_TRACE
        fputs(sep, stderr);

        bt = (const char **)get_backtrace(&n);
        if (bt != NULL) {
            int i;

            for (i = n - 1; i > 2; i--)
                fprintf(stderr, "%s()\n", bt[i]);
            free_backtrace((char **)bt);
        }

#endif
        if (err) {
            char errbuf[128];

            snprintf(fmtbuf, sizeof(fmtbuf), "%s(), %s:%d: %s (%s)\n", func,
                     file, line, fmt, strerror_r(err, errbuf, sizeof(errbuf)));
        } else {
            snprintf(fmtbuf, sizeof(fmtbuf), "%s(), %s:%d: %s\n", func, file,
                     line, fmt);
        }

        va_start(ap, fmt);
        vfprintf(stderr, fmtbuf, ap);
        va_end(ap);

#ifdef ENABLE_TRACE
        fputs(sep, stderr);

#endif
        errno = old_errno;
    }
}

void
debug_print(const char *fmt, ...)
{
    if (debug) {
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fputc('\n', stderr);
    }
}

void
log_print(int priority, const char *fmt, ...)
{
    if (log_transfers) {
        va_list ap;

        va_start(ap, fmt);
        vsyslog(priority, fmt, ap);
        va_end(ap);
    }
}

static int
enable_debugging_features(int trace)
{
    const struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY
    };
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;

    sa.sa_sigaction = sigaction_segv_diag;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        goto sig_err;
    sa.sa_sigaction = sigaction_bus_diag;
    if (sigaction(SIGBUS, &sa, NULL) == -1)
        goto sig_err;

    if (setrlimit(RLIMIT_CORE, &rlim) == -1) {
        error(0, errno, "Couldn't set resource limit");
        return -errno;
    }

    if (trace) {
        if ((setenv("MALLOC_CHECK_", "7", 1) == -1)
            || (setenv("MALLOC_TRACE", MTRACE_FILE, 1) == -1)) {
            error(0, errno, "Couldn't set environment variable");
            return -errno;
        }
        mtrace();
    }

    return 0;

sig_err:
    error(0, errno, "Error setting signal handler");
    return -errno;
}

static int
set_capabilities()
{
    cap_t caps;

    static const cap_value_t capvals[] = {
        CAP_CHOWN,
        CAP_DAC_READ_SEARCH,
        CAP_FSETID,
        CAP_SETGID,
        CAP_SETUID,
        CAP_SYS_ADMIN
    };
    static const int ncapvals = (int)(sizeof(capvals)/sizeof(capvals[0]));

    caps = cap_init();
    if (caps == NULL)
        return -errno;

    if ((cap_set_flag(caps, CAP_PERMITTED, ncapvals, capvals, CAP_SET) == -1)
        || (cap_set_flag(caps, CAP_EFFECTIVE, ncapvals, capvals, CAP_SET)
            == -1)
        || (cap_set_proc(caps) == -1))
        goto err;

    cap_free(caps);

    return 0;

err:
    cap_free(caps);
    return -errno;
}

static int
init_privs()
{
    ruid = getuid();
    rgid = getgid();

    /* FIXME: needed to mount file systems; prevents invoking user from sending
       signals to replicate */
    if ((setresuid(0, 0, 0) == -1) || (setresgid(0, 0, 0) == -1))
        return -errno;

    return set_capabilities();
}

static void
print_usage(const char *progname)
{
    printf("Usage: %s [options]\n"
           "\n"
           "    -c PATH    use specified configuration file\n"
           "    -h         output help\n"
           "    -s INTEGER record information in /var associated with the "
           "given ID allowing\n"
           "               automatic resumption of an interrupted replicate "
           "process\n",
           progname);
}

static void
print_version()
{
#include <myutil/version.h>
#include <json/version.h>
    puts("libutil version " LIBUTIL_VERSION);
    puts("libjson version " LIBJSON_VERSION);
}

static int
parse_cmdline(int argc, char **argv, const char **confpath, int *sessid)
{
    const char *cfpath = NULL;
    int ret;

    static const struct option longopts[] = {
        {"help", 0, NULL, 'h'},
        {"version", 0, NULL, '.'},
        {NULL, 0, NULL, 0}
    };

    GET_LONG_OPTIONS(argc, argv, "c:dhs.", longopts) {
    case 'c':
        if (cfpath != NULL)
            free((void *)cfpath);
        cfpath = strdup(optarg);
        if (cfpath == NULL) {
            error(0, errno, "Couldn't allocate memory");
            return -1;
        }
        break;
    case 'd':
#ifdef ENABLE_TRACE
        tracing = 1;
#endif
        break;
    case 'h':
        print_usage(argv[0]);
        goto exit_success;
    case 's':
        *sessid = atoi(optarg);
        break;
    case '.':
        print_version();
        goto exit_success;
    default:
        ret = -1;
        goto exit;
    } END_GET_LONG_OPTIONS;

    if (cfpath != NULL)
        *confpath = cfpath;
    return 0;

exit_success:
    ret = -2;
exit:
    if (cfpath != NULL)
        free((void *)cfpath);
    return ret;
}

static int
get_conf_path(const char *pathspec, const char **path)
{
    const char *ret;
    wordexp_t words;

    if (wordexp(pathspec, &words, WRDE_NOCMD | WRDE_UNDEF) != 0)
        goto err1;

    if (words.we_wordc != 1)
        goto err2;

    ret = strdup(words.we_wordv[0]);

    wordfree(&words);

    if (ret == NULL)
        return -errno;

    *path = ret;
    return 0;

err2:
    wordfree(&words);
err1:
    return -EIO;
}

static void
int_handler(int signum)
{
    extern volatile sig_atomic_t quit;

    (void)signum;

    /* flag checked in copy_cb() */
    quit = 1;
}

static int
set_signal_handlers()
{
    size_t i;
    struct sigaction sa;

    static const int intsignals[] = {SIGINT, SIGTERM};

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &int_handler;
    sa.sa_flags = SA_RESETHAND;

    for (i = 0; i < sizeof(intsignals)/sizeof(intsignals[0]); i++) {
        if (sigaction(intsignals[i], &sa, NULL) == -1)
            return -errno;
    }

    return 0;
}

static int
init_dbus(DBusConnection **busconn)
{
    DBusConnection *ret;
    DBusError buserr;
    int res;

    dbus_error_init(&buserr);

    ret = dbus_bus_get(DBUS_BUS_SESSION, &buserr);
    if (dbus_error_is_set(&buserr))
        goto err1;
    if (ret == NULL)
        goto err3;

    res = dbus_bus_request_name(ret, "replicate.replicate", 0, &buserr);
    if (dbus_error_is_set(&buserr))
        goto err2;
    if (res != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
        goto err4;

    *busconn = ret;
    return 0;

err4:
    dbus_connection_close(ret);
err3:
    return -EIO;

err2:
    dbus_connection_close(ret);
err1:
    error(0, 0, "Error connecting to session bus: %s", buserr.message);
    dbus_error_free(&buserr);
    return -EIO;
}

static void
end_dbus(DBusConnection *busconn)
{
    dbus_connection_close(busconn);
}

static int
get_sess_path(const char *sesspath, const char *path, char *fullpath,
              size_t len)
{
    const char *newpath;
    int ret;

    newpath = strsub(path, "/", "_");
    if (newpath == NULL)
        return -ENOMEM;

    ret = snprintf(fullpath, len, "%s/%s", sesspath, newpath);

    free((void *)newpath);

    return (ret >= (int)len) ? -ENAMETOOLONG : 0;
}

static int
sess_init(int sessid, char *sesspath, size_t len)
{
    assert(len > 0);

    if (sessid == -1) {
        *sesspath = '\0';
        return 0;
    }

    if ((mkdir(VAR_PATH, ACC_MODE_ACCESS_PERMS) == -1) && (errno != EEXIST))
        return -errno;

    if (snprintf(sesspath, len, VAR_PATH "/%d", sessid) >= (int)len)
        return -ENAMETOOLONG;

    return ((mkdir(sesspath, ACC_MODE_ACCESS_PERMS) == -1) && (errno != EEXIST))
           ? -errno : 0;
}

static int
sess_end(const char *sesspath)
{
    int err;

    if (*sesspath == '\0')
        return 0;

    err = dir_rem(sesspath, 0);
    if (err)
        return err;

    return (rmdir(sesspath) == -1) ? -errno : 0;
}

static int
sess_is_complete(const char *sesspath, const char *path)
{
    char fullpath[PATH_MAX];

    if (*sesspath == '\0')
        return 0;

    if (get_sess_path(sesspath, path, fullpath, sizeof(fullpath)) != 0)
        return 0;

    return (access(fullpath, F_OK) == 0);
}

static int
sess_record_complete(const char *sesspath, const char *path)
{
    char fullpath[PATH_MAX];
    int err;

    if (*sesspath == '\0')
        return 0;

    err = get_sess_path(sesspath, path, fullpath, sizeof(fullpath));
    if (err)
        return err;

    return (mknod(fullpath, S_IFREG | S_IRUSR | S_IRGRP | S_IROTH, 0) == -1)
           ? -errno : 0;
}

int
do_transfers(struct replicate_ctx *ctx, int sessid)
{
    char sesspath[PATH_MAX];
    int err;
    int i;
    struct copy_args ca;
    struct transfer *transfer;

    err = sess_init(sessid, sesspath, sizeof(sesspath));
    if (err)
        return err;

    ca.keep_cache = ctx->keep_cache;
    ca.busconn = ctx->busconn;
    ca.uid = ctx->uid;
    ca.gid = ctx->gid;

    for (i = 0; i < ctx->num_transfers; i++) {
        transfer = &ctx->transfers[i];

        if (sess_is_complete(sesspath, transfer->srcpath))
            continue;

        debug_print("Transfer %d:", i + 1);
        log_print(LOG_INFO, "Starting transfer %d: %s -> %s", i + 1,
                  transfer->srcpath, transfer->dstpath);

        ca.srcfd = mount_filesystem(NULL, transfer->srcpath, MNT_FS_READ);
        if (ca.srcfd < 0) {
            error(0, -ca.srcfd, "Error mounting %s", transfer->srcpath);
            return ca.srcfd;
        }

        if (transfer->setro) {
            err = blkdev_set_read_only(transfer->dstpath, 0, &transfer->setro);
            if (err) {
                error(0, 0, "Error setting block device read-only flag for %s",
                      transfer->dstpath);
                goto err1;
            }
        }

        err = blkdev_format(transfer->dstpath, transfer->format_cmd,
                            FORMAT_CMD_DEST_SPECIFIER);
        if (err) {
            if (err > 0)
                error(0, 0, "Formatting command returned status %d", err);
            goto err2;
        }

        ca.dstfd = mount_filesystem(transfer->dstpath, transfer->dstmntpath,
                                    transfer->force_write
                                    ? MNT_FS_FORCE_WRITE : MNT_FS_WRITE);
        if (ca.dstfd < 0) {
            error(0, -ca.dstfd, "Error mounting %s", transfer->dstpath);
            err = ca.dstfd;
            goto err2;
        }

        /* change ownership of destination root directory if needed */
        if ((ctx->uid != 0) && (fchown(ca.dstfd, ctx->uid, (gid_t)-1) == -1)) {
            error(0, errno, "Error changing ownership of %s",
                  transfer->dstmntpath);
            err = -errno;
            goto err3;
        }

        err = do_copy(&ca);
        if (err) {
            error(0, -err, "Error copying from %s to %s", transfer->srcpath,
                  transfer->dstmntpath);
            goto err3;
        }

        err = unmount_filesystem(transfer->dstmntpath, ca.dstfd);
        if (err) {
            error(0, -err, "Error unmounting %s", transfer->dstmntpath);
            goto err2;
        }

        if (transfer->setro) {
            err = blkdev_set_read_only(transfer->dstpath, 1, NULL);
            if (err) {
                error(0, -err, "Error setting block device read-only flag for "
                               "%s",
                      transfer->dstpath);
                goto err1;
            }
        }

        err = unmount_filesystem(transfer->srcpath, ca.srcfd);
        if (err) {
            error(0, -err, "Error unmounting %s", transfer->srcpath);
            return err;
        }

        log_print(LOG_INFO, "Finished transfer %d: %s -> %s", i + 1,
                  transfer->srcpath, transfer->dstpath);

        sess_record_complete(sesspath, transfer->srcpath);
    }

    sess_end(sesspath);

    return 0;

err3:
    unmount_filesystem(transfer->dstmntpath, ca.dstfd);
err2:
    if (transfer->setro)
        blkdev_set_read_only(transfer->dstpath, 1, NULL);
err1:
    unmount_filesystem(transfer->srcpath, ca.srcfd);
    return err;
}

void
print_transfers(FILE *f, struct transfer *transfers, int num)
{
    int i;

    for (i = 0; i < num; i++) {
        struct transfer *transfer = &transfers[i];

        fprintf(f,
                "Transfer %d:\n"
                "\tSource directory path: %s\n"
                "\tDestination device path: %s\n"
                "\tDestination formatting command: \"%s\"\n"
                "\tSet block device read-only flag: %d\n",
                i + 1,
                transfer->srcpath,
                transfer->dstpath,
                transfer->format_cmd,
                !!(transfer->setro));
    }
}

void
free_transfers(struct transfer *transfers, int num)
{
    int i;

    for (i = 0; i < num; i++) {
        struct transfer *transfer = &transfers[i];

        free((void *)(transfer->srcpath));
        free((void *)(transfer->dstpath));
        free((void *)(transfer->format_cmd));
    }

    free(transfers);
}

int
main(int argc, char **argv)
{
    const char *confpath = NULL;
    int ret;
    int sessid;
    struct replicate_ctx ctx;

    if ((getuid() != 0) && (clearenv() != 0))
        return EXIT_FAILURE;

    setlinebuf(stdout);

    if (enable_debugging_features(0) != 0)
        return EXIT_FAILURE;

    sessid = -1;
    ctx.keep_cache = 0;
    ctx.uid = (uid_t)-1;
    ctx.gid = (gid_t)-1;

    ret = parse_cmdline(argc, argv, &confpath, &sessid);
    if (ret != 0)
        return (ret == -1) ? EXIT_FAILURE : EXIT_SUCCESS;

    if (confpath == NULL) {
        ret = get_conf_path(CONFIG_PATH, &confpath);
        if (ret != 0)
            return EXIT_FAILURE;
    }

    ret = parse_config(confpath, &ctx);
    free((void *)confpath);
    if (ret != 0)
        return EXIT_FAILURE;

    if (debug) {
        print_transfers(stderr, ctx.transfers, ctx.num_transfers);
        fprintf(stderr, "UID: %d\nGID: %d\n", ctx.uid, ctx.gid);
    }

    ret = init_privs();
    if (ret != 0) {
        error(0, -ret, "Error setting process privileges");
        goto end1;
    }

    if (log_transfers)
        openlog(NULL, LOG_PID, LOG_USER);

    ret = mount_ns_unshare();
    if (ret != 0)
        goto end2;

    ret = set_signal_handlers();
    if (ret != 0)
        goto end2;

    ret = init_dbus(&ctx.busconn);
    if (ret != 0)
        goto end2;

    ret = do_transfers(&ctx, sessid);

    end_dbus(ctx.busconn);

end2:
    if (log_transfers) {
        if (ret == 0)
            syslog(LOG_NOTICE, "Transfer process successful");
        else
            syslog(LOG_ERR, "Transfer process returned error status");
        closelog();
    }
end1:
    free_transfers(ctx.transfers, ctx.num_transfers);
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
