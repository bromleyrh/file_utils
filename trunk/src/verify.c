/*
 * verify.c
 */

#include "verify_common.h"
#include "verify_conf.h"
#include "verify_scan.h"

#ifdef ENABLE_TRACE
#include "backtrace.h"
#endif

#include <dbus/dbus.h>

#include <libmount/libmount.h>

#include <backup.h>

#include <radix_tree.h>
#include <strings_ext.h>

#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <mcheck.h>
#include <regex.h>
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

#define CONFIG_PATH "\"$HOME/.verify.conf\""

int debug = 0;
int log_verifs = 0;
int tracing = 0;

uid_t ruid;
gid_t rgid;

static char from_hex(char);

static int scan_chksum(const char *, unsigned char *, unsigned);

static int enable_debugging_features(int);

static int set_capabilities(void);
static int init_privs(void);

static void print_usage(const char *);
static int parse_cmdline(int, char **, const char **, int *);

static int get_conf_path(const char *, const char **);

static int get_regex(regex_t *, const char *);

static void int_handler(int);

static int set_signal_handlers(void);

static int input_data_walk_cb(const char *, void *, void *);

static int scan_input_file(const char *, struct radix_tree **);
static int print_input_data(FILE *, struct radix_tree *);

static int init_dbus(DBusConnection **);
static void end_dbus(DBusConnection *);

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
debug_print(int nl, const char *fmt, ...)
{
    if (debug) {
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        if (nl)
            fputc('\n', stderr);
    }
}

void
log_print(int priority, const char *fmt, ...)
{
    if (log_verifs) {
        va_list ap;

        va_start(ap, fmt);
        vsyslog(priority, fmt, ap);
        va_end(ap);
    }
}

static char
from_hex(char hexchar)
{
    if ((hexchar >= '0') && (hexchar <= '9'))
        return hexchar - '0';
    if ((hexchar >= 'a') && (hexchar <= 'f'))
        return hexchar + 10 - 'a';

    return -1;
}

static int
scan_chksum(const char *str, unsigned char *sum, unsigned sumlen)
{
    unsigned i;

    for (i = 0; i < sumlen; i++) {
        char tmp1, tmp2;

        if (*str == '\0')
            return -EINVAL;
        tmp2 = from_hex(tolower(*(str++)));
        if (tmp2 == -1)
            return -EINVAL;

        if (*str == '\0')
            return -EINVAL;
        tmp1 = from_hex(tolower(*(str++)));
        if (tmp1 == -1)
            return -EINVAL;

        sum[i] = tmp2 * 0x10 + tmp1;
    }

    return 0;
}

static void
print_usage(const char *progname)
{
    printf("Usage: %s [options]\n"
           "\n"
           "    -a      if input file used, do not exit with error on "
           "encountering files\n"
           "            not listed in the input file\n"
           "    -c PATH use specified configuration file\n"
           "    -h      output help\n",
           progname);
}

static int
parse_cmdline(int argc, char **argv, const char **confpath, int *allow_new)
{
    const char *cfpath = NULL;
    int ret;

    for (;;) {
        int opt = getopt(argc, argv, "ac:dh");

        if (opt == -1)
            break;

        switch (opt) {
        case 'a':
            *allow_new = 1;
            break;
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
            ret = -2;
            goto exit;
        default:
            ret = -1;
            goto exit;
        }
    }

    if (cfpath != NULL)
        *confpath = cfpath;
    return 0;

exit:
    if (cfpath != NULL)
        free((void *)cfpath);
    return ret;
}

static int
enable_debugging_features(int trace)
{
    const struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY
    };

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
}

static int
set_capabilities()
{
    cap_t caps;

    static const cap_value_t capvals[] = {
        CAP_CHOWN, /* fchown("/etc/mtab") performed by libmount */
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
    ruid = getuid();
    rgid = getgid();

    /* FIXME: needed to mount filesystems; prevents invoking user from sending
       signals to verify */
    if ((setresuid(0, 0, 0) == -1) || (setresgid(0, 0, 0) == -1))
        return -errno;

    return set_capabilities();
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

#define ERRBUF_INIT_SIZE 128

static int
get_regex(regex_t *reg, const char *regex)
{
    int err;

    err = regcomp(reg, regex, REG_EXTENDED | REG_NOSUB);
    if (err) {
        char *errbuf;
        size_t errbuf_size;

        errbuf = malloc(ERRBUF_INIT_SIZE);
        if (errbuf == NULL)
            return -EIO;

        errbuf_size = regerror(err, reg, errbuf, ERRBUF_INIT_SIZE);
        if (errbuf_size > ERRBUF_INIT_SIZE) {
            free(errbuf);
            errbuf = malloc(errbuf_size);
            if (errbuf == NULL)
                return -EIO;

            regerror(err, reg, errbuf, errbuf_size);
        }
        error(0, 0, "Error compiling regular expression: %s", errbuf);

        free(errbuf);

        return -EIO;
    }

    return 0;
}

#undef ERRBUF_INIT_SIZE

static void
int_handler(int signum)
{
    extern volatile sig_atomic_t quit;

    (void)signum;

    /* flag checked in verif_walk_fn() */
    quit = 1;
}

static int
set_signal_handlers()
{
    size_t i;
    struct sigaction sa;

    static const int intsignals[] = {SIGINT, SIGPIPE, SIGTERM};

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
input_data_walk_cb(const char *str, void *val, void *ctx)
{
    FILE *f = (FILE *)ctx;

    (void)val;

    fprintf(f, "%s\n", str);
    return 0;
}

static int
scan_input_file(const char *path, struct radix_tree **data)
{
    char *ln = NULL;
    FILE *f;
    int linenum;
    int res;
    size_t n;
    struct radix_tree *ret;

    f = fopen(path, "r");
    if (f == NULL) {
        error(0, errno, "Error opening %s", path);
        return -errno;
    }

    res = radix_tree_new(&ret, sizeof(struct verif_record));
    if (res != 0)
        goto err1;

    errno = 0;
    for (linenum = 1;; linenum++) {
        char buf1[16], buf2[256], buf3[256], buf4[PATH_MAX];
        struct verif_record record;

        if (getline(&ln, &n, f) == -1) {
            if (errno != 0) {
                res = -errno;
                goto err2;
            }
            break;
        }
        res = sscanf(ln, "%s\t%s\t%s\t%s", buf1, buf2, buf3, buf4);
        if (res != 4) {
            if ((res != EOF) || !ferror(f)) {
                error(0, 0, "Line %d of %s invalid", linenum, path);
                res = -EINVAL;
                goto err2;
            }
            res = -errno;
            goto err2;
        }
        record.size = strtoll(buf1, NULL, 10);
        if ((scan_chksum(buf2, record.initsum, 20) != 0)
            || (scan_chksum(buf3, record.sum, 20) != 0)) {
            res = -EINVAL;
            goto err2;
        }
        res = radix_tree_insert(ret, buf4, &record);
        if (res != 0)
            goto err2;
    }

    if (ln != NULL)
        free(ln);
    fclose(f);

    *data = ret;
    return 0;

err2:
    if (ln != NULL)
        free(ln);
    radix_tree_free(ret);
err1:
    fclose(f);
    return res;
}

static int
print_input_data(FILE *f, struct radix_tree *input_data)
{
    return radix_tree_walk(input_data, &input_data_walk_cb, (void *)f);
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

    res = dbus_bus_request_name(ret, "verify.verify", 0, &buserr);
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

int
do_verifs(struct verify_ctx *ctx)
{
    int err;
    int i;
    struct verif *verif;
    struct verif_args va;

    if (strcmp("-", ctx->output_file) == 0)
        va.dstf = stdout;
    else {
        va.dstf = fopen(ctx->output_file, "w");
        if (va.dstf == NULL) {
            error(0, errno, "Error opening %s", ctx->output_file);
            return -errno;
        }
    }

    va.reg_excl = ctx->reg_excl;
    va.detect_hard_links = ctx->detect_hard_links;
    va.input_data = ctx->input_data;
    va.allow_new = ctx->allow_new;
    va.busconn = ctx->busconn;
    va.uid = ctx->uid;
    va.gid = ctx->gid;

    for (i = 0; i < ctx->num_verifs; i++) {
        verif = &ctx->verifs[i];

        DEBUG_PRINT("Verification %d:", i + 1);
        log_print(LOG_INFO, "Starting verifcation %d: %s", i + 1,
                  verif->srcpath);

        if (verif->check_cmd != NULL) {
            err = check_filesystem(verif->devpath, verif->check_cmd,
                                   CHECK_CMD_SRC_SPECIFIER);
            if (err) {
                error(0, -err, "Error checking filesystem on %s",
                      verif->devpath);
                goto err1;
            }
        }

        va.srcfd = mount_filesystem(verif->devpath, verif->srcpath,
                                    MNT_FS_READ);
        if (va.srcfd < 0) {
            error(0, -va.srcfd, "Error mounting %s", verif->srcpath);
            err = va.srcfd;
            goto err1;
        }

        va.prefix = verif->srcpath;
        err = do_verif(&va);
        if (err) {
            error(0, -err, "Error verifying %s", verif->srcpath);
            goto err2;
        }

        err = unmount_filesystem(verif->srcpath, va.srcfd);
        if (err) {
            error(0, -err, "Error unmounting %s", verif->srcpath);
            goto err1;
        }

        if ((va.dstf != stdout) && (fsync(fileno(va.dstf)) == -1)) {
            error(0, errno, "Error writing output file %s", ctx->output_file);
            err = -errno;
            goto err1;
        }

        log_print(LOG_INFO, "Finished verifcation %d: %s", i + 1,
                  verif->srcpath);
    }

    if (ctx->input_data != NULL) {
        struct radix_tree_stats s;

        err = radix_tree_stats(ctx->input_data, &s);
        if (err) {
            TRACE(-err, "radix_tree_stats()");
            goto err1;
        }
        if (s.num_info_nodes != 0) {
            error(0, 0, "Verification error: Files removed:");
            print_input_data(stderr, ctx->input_data);
            err = -EIO;
            goto err1;
        }
    }

    if ((va.dstf != stdout) && (fclose(va.dstf) == EOF)) {
        error(0, -errno, "Error closing %s", ctx->output_file);
        return -errno;
    }

    return 0;

err2:
    unmount_filesystem(verif->srcpath, va.srcfd);
err1:
    if (va.dstf != stdout)
        fclose(va.dstf);
    return err;
}

void
print_verifs(FILE *f, struct verif *verifs, int num)
{
    int i;

    for (i = 0; i < num; i++) {
        struct verif *verif = &verifs[i];

        fprintf(f,
                "Verifcation %d:\n"
                "\tDevice path: %s\n"
                "\tSource directory path: %s\n",
                i + 1,
                verif->devpath,
                verif->srcpath);
    }
}

void
free_verifs(struct verif *verifs, int num)
{
    int i;

    for (i = 0; i < num; i++)
        free((void *)(verifs[i].srcpath));

    free(verifs);
}

int
main(int argc, char **argv)
{
    const char *confpath = NULL;
    int ret;
    regex_t reg_excl;
    struct parse_ctx pctx;
    struct verify_ctx *ctx;

    setlinebuf(stdout);

    if (enable_debugging_features(0) != 0)
        return EXIT_FAILURE;

    ret = parse_cmdline(argc, argv, &confpath, &pctx.ctx.allow_new);
    if (ret != 0)
        return (ret == -1) ? EXIT_FAILURE : EXIT_SUCCESS;

    if (confpath == NULL) {
        ret = get_conf_path(CONFIG_PATH, &confpath);
        if (ret != 0)
            return EXIT_FAILURE;
    }

    ctx = &pctx.ctx;
    ctx->base_dir = NULL;
    ctx->detect_hard_links = 1;
    ctx->input_file = NULL;
    ctx->input_data = NULL;
    ctx->uid = (uid_t)-1;
    ctx->gid = (gid_t)-1;

    pctx.regex = pctx.regexcurbr = NULL;
    pctx.regexlen = 0;

    ret = parse_config(confpath, &pctx);
    free((void *)confpath);
    if (ret != 0)
        return EXIT_FAILURE;

    ret = init_privs();
    if (ret != 0) {
        error(0, -ret, "Error setting process privileges");
        goto end1;
    }

    if ((ctx->base_dir != NULL) && (chdir(ctx->base_dir) == -1)) {
        error(0, errno, "Error changing directory to %s", ctx->base_dir);
        ret = -errno;
        goto end1;
    }

    ctx->reg_excl = NULL;
    if (pctx.regex != NULL) {
        ret = get_regex(&reg_excl, pctx.regex);
        free((void *)(pctx.regex));
        if (ret != 0)
            goto end1;
        ctx->reg_excl = &reg_excl;
    }

    if (ctx->input_file != NULL) {
        ret = scan_input_file(ctx->input_file, &ctx->input_data);
        if (ret != 0)
            goto end1;
    }

    if (debug) {
        print_verifs(stderr, ctx->verifs, ctx->num_verifs);
        fprintf(stderr, "UID: %d\nGID: %d\n", ctx->uid, ctx->gid);
    }

    if (log_verifs)
        openlog(NULL, LOG_PID, LOG_USER);

    ret = mount_ns_unshare();
    if (ret != 0)
        goto end2;

    ret = set_signal_handlers();
    if (ret != 0)
        goto end2;

    ret = init_dbus(&ctx->busconn);
    if (ret != 0)
        goto end2;

    ret = do_verifs(ctx);

    end_dbus(ctx->busconn);

end2:
    if (log_verifs) {
        if (ret == 0)
            syslog(LOG_NOTICE, "Verification process successful");
        else
            syslog(LOG_ERR, "Verification process returned error status");
        closelog();
    }
    radix_tree_free(ctx->input_data);
end1:
    if (ctx->base_dir != NULL)
        free((void *)(ctx->base_dir));
    if (ctx->reg_excl != NULL)
        regfree(ctx->reg_excl);
    if (ctx->input_file != NULL)
        free((void *)(ctx->input_file));
    free((void *)(ctx->output_file));
    free_verifs(ctx->verifs, ctx->num_verifs);
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
