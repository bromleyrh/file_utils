/*
 * replicate.c
 */

#include "replicate_common.h"
#include "replicate_conf.h"
#include "replicate_trans.h"

#include <libmount/libmount.h>

#include <backup.h>

#include <strings_ext.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <grp.h>
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
#include <sys/stat.h>
#include <sys/types.h>

#define CONFIG_PATH "\"$HOME/.replicate.conf\""

int debug = 0;
int log_transfers = 0;

static int set_capabilities(void);
static int init_privs(void);

static void print_usage(const char *);
static int parse_cmdline(int, char **, const char **);

static int get_conf_path(const char *, const char **);

static void int_handler(int);

static int set_signal_handlers(void);

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
set_capabilities()
{
    cap_t caps;

    static const cap_value_t capvals[] = {
        CAP_CHOWN,
        CAP_DAC_READ_SEARCH,
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
    return (setgroups(0, NULL) == -1) ? -errno : set_capabilities();
}

static void
print_usage(const char *progname)
{
    printf("Usage: %s [options]\n"
           "\n"
           "    -c PATH use specified configuration file\n"
           "    -h      output help\n",
           progname);
}

static int
parse_cmdline(int argc, char **argv, const char **confpath)
{
    for (;;) {
        int opt = getopt(argc, argv, "c:h");

        if (opt == -1)
            break;

        switch (opt) {
        case 'c':
            *confpath = strdup(optarg);
            if (*confpath == NULL) {
                error(0, errno, "Couldn't allocate memory");
                return -1;
            }
            break;
        case 'h':
            print_usage(argv[0]);
            return -2;
        default:
            return -1;
        }
    }

    return 0;
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

int
do_transfers(struct replicate_ctx *ctx)
{
    int err;
    int i;
    struct copy_args ca;
    struct transfer *transfer;

    for (i = 0; i < ctx->num_transfers; i++) {
        transfer = &ctx->transfers[i];

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
            err = -errno;
            goto err3;
        }

        ca.keep_cache = ctx->keep_cache;
        ca.uid = ctx->uid;
        ca.gid = ctx->gid;
        err = do_copy(&ca);
        if (err)
            goto err3;

        err = unmount_filesystem(transfer->dstmntpath, ca.dstfd);
        if (err)
            goto err2;

        if (transfer->setro) {
            err = blkdev_set_read_only(transfer->dstpath, 1, NULL);
            if (err)
                goto err1;
        }

        err = unmount_filesystem(transfer->srcpath, ca.srcfd);
        if (err)
            return err;

        log_print(LOG_INFO, "Finished transfer %d: %s -> %s", i + 1,
                  transfer->srcpath, transfer->dstpath);
    }

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
    struct replicate_ctx ctx;

    ret = init_privs();
    if (ret != 0)
        error(EXIT_FAILURE, -ret, "Error setting process privileges");

    ctx.keep_cache = 0;
    ctx.uid = (uid_t)-1;
    ctx.gid = (gid_t)-1;

    ret = parse_cmdline(argc, argv, &confpath);
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

    if (log_transfers)
        openlog(NULL, LOG_PID, LOG_USER);

    ret = mount_ns_unshare();
    if (ret != 0)
        goto end;

    ret = set_signal_handlers();
    if (ret != 0)
        goto end;

    ret = do_transfers(&ctx);

end:
    if (log_transfers)
        closelog();
    free_transfers(ctx.transfers, ctx.num_transfers);
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
