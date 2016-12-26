/*
 * verify.c
 */

#define _GNU_SOURCE

#include "verify.h"

#include <json.h>

#include <json/grammar.h>
#include <json/grammar_parse.h>
#include <json/native.h>

#include <libmount/libmount.h>

#include <openssl/evp.h>

#include <hashes.h>
#include <strings_ext.h>

#include <files/util.h>

#include <aio.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <wchar.h>
#include <wordexp.h>

#include <linux/fs.h>

#include <sys/capability.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define CONFIG_PATH "\"$HOME/.verify.conf\""
#define CONFIG_ROOT_ID "conf"

struct ctx {
    struct verif    *verifs;
    int             num_verifs;
    const char      *output_file;
    uid_t           uid;
    gid_t           gid;
};

struct verif {
    const char *srcpath;
};

struct verif_args {
    int         srcfd;
    FILE        *dstf;
    const char  *prefix;
    uid_t       uid;
    gid_t       gid;
};

struct verif_walk_ctx {
    FILE        *dstf;
    const char  *prefix;
};

static int debug;
static int log;

static void debug_print(const char *, ...);
static void log_print(int, const char *, ...);

static int get_gid(const char *, gid_t *);
static int get_uid(const char *, uid_t *);

static void cancel_aio(struct aiocb *);

static int set_capabilities(void);

static int get_conf_path(const char *, const char **);

static int parse_json_config(const char *, const struct json_parser *,
                             json_val_t *);

static int read_creds_opt(json_val_t, void *);
static int read_debug_opt(json_val_t, void *);
static int read_output_file_opt(json_val_t, void *);
static int read_verifs_opt(json_val_t, void *);
static int read_json_config(json_val_t, struct ctx *);

static int parse_config(const char *, struct ctx *);

static int mount_filesystem(const char *);
static int unmount_filesystem(const char *, int);

static int calc_chksums(int, unsigned char *, unsigned char *, unsigned *);

static int verif_walk_fn(int, int, const char *, const char *, struct stat *,
                         void *);

static int verif_fn(void *);

static int do_verif(struct verif_args *);

static int do_verifs(struct ctx *);
static void print_verifs(FILE *, struct verif *, int);
static void free_verifs(struct verif *, int);

static void
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

static void
log_print(int priority, const char *fmt, ...)
{
    if (log) {
        va_list ap;

        va_start(ap, fmt);
        vsyslog(priority, fmt, ap);
        va_end(ap);
    }
}

static int
get_gid(const char *name, gid_t *gid)
{
    char *buf;
    int err;
    size_t bufsize;
    struct group grp, *res;

    bufsize = (size_t)sysconf(_SC_GETGR_R_SIZE_MAX);
    if (bufsize == (size_t)-1)
        bufsize = 1024;

    buf = malloc(bufsize);
    if (buf == NULL)
        return -errno;

    for (;;) {
        char *tmp;

        err = getgrnam_r(name, &grp, buf, bufsize, &res);
        if (!err)
            break;
        if (err != ERANGE)
            goto err;

        bufsize *= 2;
        tmp = realloc(buf, bufsize);
        if (tmp == NULL) {
            err = -errno;
            goto err;
        }
        buf = tmp;
    }
    if (res == NULL) {
        err = -ENOENT;
        goto err;
    }

    *gid = grp.gr_gid;

    free(buf);

    return 0;

err:
    free(buf);
    return err;
}

static int
get_uid(const char *name, uid_t *uid)
{
    char *buf;
    int err;
    size_t bufsize;
    struct passwd pwd, *res;

    bufsize = (size_t)sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == (size_t)-1)
        bufsize = 1024;

    buf = malloc(bufsize);
    if (buf == NULL)
        return -errno;

    for (;;) {
        char *tmp;

        err = getpwnam_r(name, &pwd, buf, bufsize, &res);
        if (!err)
            break;
        if (err != ERANGE)
            goto err;

        bufsize *= 2;
        tmp = realloc(buf, bufsize);
        if (tmp == NULL) {
            err = -errno;
            goto err;
        }
        buf = tmp;
    }
    if (res == NULL) {
        err = -ENOENT;
        goto err;
    }

    *uid = pwd.pw_uid;

    free(buf);

    return 0;

err:
    free(buf);
    return err;
}

static void
cancel_aio(struct aiocb *cb)
{
    int ret;

    ret = aio_cancel(cb->aio_fildes, cb);

    if (ret == AIO_NOTCANCELED) {
        while (aio_suspend((const struct aiocb **)&cb, 1, NULL) == -1) {
            if ((errno != EAGAIN) && (errno != EINTR))
                break;
        }
    }

    aio_return(cb);
}

static int
set_capabilities()
{
    cap_t caps;

    static const cap_value_t capvals[] = {
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

static int
parse_json_config(const char *path, const struct json_parser *parser,
                  json_val_t *config)
{
    char *conf;
    int err;
    int fd;
    struct stat s;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        error(0, errno, "Error opening %s", path);
        return -1;
    }

    if (fstat(fd, &s) == -1) {
        error(0, errno, "Error accessing %s", path);
        goto err;
    }

    conf = mmap(NULL, s.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (conf == MAP_FAILED) {
        error(0, errno, "Error accessing %s", path);
        goto err;
    }
    conf[s.st_size-1] = '\0';

    close(fd);

    err = json_grammar_validate(conf, NULL, NULL, parser, config);

    munmap((void *)conf, s.st_size);

    if (err) {
        error(0, -err, "Error parsing %s", path);
        return -1;
    }

    return 0;

err:
    close(fd);
    return -1;
}

static int
read_creds_opt(json_val_t opt, void *data)
{
    char *buf;
    int err;
    json_object_elem_t elem;
    mbstate_t s;
    struct ctx *ctx = (struct ctx *)data;

    memset(&s, 0, sizeof(s));

    err = json_val_object_get_elem_by_key(opt, L"uid", &elem);
    if (!err) {
        if (awcstombs((char **)&buf, json_val_string_get(elem.value), &s)
            == (size_t)-1)
            return -errno;
        ctx->uid = atoi(buf);
        free(buf);

        err = json_val_object_get_elem_by_key(opt, L"gid", &elem);
        if (err)
            return err;
        memset(&s, 0, sizeof(s));
        if (awcstombs((char **)&buf, json_val_string_get(elem.value), &s)
            == (size_t)-1)
            return -errno;
        ctx->gid = atoi(buf);
        free(buf);
    } else if (err == -EINVAL) {
        err = json_val_object_get_elem_by_key(opt, L"user", &elem);
        if (err)
            return err;
        if (awcstombs((char **)&buf, json_val_string_get(elem.value), &s)
            == (size_t)-1)
            return -errno;
        err = get_uid(buf, &ctx->uid);
        free(buf);
        if (err)
            return err;

        err = json_val_object_get_elem_by_key(opt, L"group", &elem);
        if (err)
            return err;
        memset(&s, 0, sizeof(s));
        if (awcstombs((char **)&buf, json_val_string_get(elem.value), &s)
            == (size_t)-1)
            return -errno;
        if (strcmp(buf, "-") == 0)
            ctx->gid = (gid_t)-1;
        else {
            err = get_gid(buf, &ctx->gid);
            if (err) {
                free(buf);
                return err;
            }
        }
        free(buf);
    } else
        return err;

    return 0;
}

static int
read_debug_opt(json_val_t opt, void *data)
{
    (void)data;

    debug = json_val_boolean_get(opt);

    return 0;
}

static int
read_output_file_opt(json_val_t opt, void *data)
{
    mbstate_t s;
    struct ctx *ctx = (struct ctx *)data;

    memset(&s, 0, sizeof(s));
    return (awcstombs((char **)&ctx->output_file, json_val_string_get(opt), &s)
            == (size_t)-1) ? -errno : 0;
}

static int
read_log_opt(json_val_t opt, void *data)
{
    (void)data;

    log = json_val_boolean_get(opt);

    return 0;
}

#define VERIF_PARAM(param) offsetof(struct verif, param)

static int
read_verifs_opt(json_val_t opt, void *data)
{
    int err;
    int i;
    struct ctx *ctx = (struct ctx *)data;

    static const struct json_scan_spec spec[] = {
        {L"src", JSON_TYPE_STRING, 1, 0, 1, NULL, NULL, NULL,
         VERIF_PARAM(srcpath)}
    };

    ctx->num_verifs = json_val_array_get_num_elem(opt);

    ctx->verifs = calloc(ctx->num_verifs, sizeof(*(ctx->verifs)));
    if (ctx->verifs == NULL)
        return -errno;

    for (i = 0; i < ctx->num_verifs; i++) {
        json_val_t val;

        val = json_val_array_get_elem(opt, i);
        if (val == NULL) {
            err = -EIO;
            goto err;
        }

        err = json_oscanf(&ctx->verifs[i], spec,
                          (int)(sizeof(spec)/sizeof(spec[0])), val);
        if (err)
            goto err;
    }

    return 0;

err:
    free_verifs(ctx->verifs, i);
    return err;
}

#undef VERIF_PARAM

static int
read_json_config(json_val_t config, struct ctx *ctx)
{
    int err;
    int i, numopt;

    static const struct {
        const wchar_t   *opt;
        int             (*fn)(json_val_t, void *);
    } opts[8] = {
        [1] = {L"creds",        &read_creds_opt},
        [2] = {L"debug",        &read_debug_opt},
        [6] = {L"log",          &read_log_opt},
        [7] = {L"output_file",  &read_output_file_opt},
        [3] = {L"verifs",       &read_verifs_opt}
    }, *opt;

    numopt = json_val_object_get_num_elem(config);
    for (i = 0; i < numopt; i++) {
        json_object_elem_t elem;

        err = json_val_object_get_elem_by_idx(config, i, &elem);
        if (err)
            return err;

        opt = &opts[(hash_str(elem.key, -1) >> 1) & 7];
        if ((opt->opt == NULL) || (wcscmp(elem.key, opt->opt) != 0))
            return -EIO;

        err = (*(opt->fn))(elem.value, ctx);
        if (err)
            return err;
    }

    return 0;
}

static int
parse_config(const char *path, struct ctx *ctx)
{
    int err;
    json_val_t config;
    struct json_parser *parser;

    err = json_parser_init(CONFIG_GRAM, CONFIG_ROOT_ID, &parser);
    if (err)
        return err;

    err = parse_json_config(path, parser, &config);
    json_parser_destroy(parser);
    if (err)
        return err;

    err = read_json_config(config, ctx);

    json_val_free(config);

    return err;
}

static int
mount_filesystem(const char *mntpath)
{
    int mflags;
    int ret;
    struct libmnt_context *mntctx;

    debug_print("Mounting %s", mntpath);

    mntctx = mnt_new_context();
    if (mntctx == NULL)
        return -ENOMEM;

    mflags = MS_NODEV | MS_NOEXEC | MS_RDONLY;

    if ((mnt_context_set_mflags(mntctx, mflags) != 0)
        || (mnt_context_set_target(mntctx, mntpath) != 0))
        goto err1;

    /* requires CAP_SYS_ADMIN */
    ret = mnt_context_mount(mntctx);

    mnt_free_context(mntctx);

    if (ret != 0)
        goto err2;

    /* open root directory to provide a handle for subsequent operations */
    ret = open(mntpath, O_DIRECTORY | O_RDONLY);
    if (ret == -1) {
        ret = -errno;
        goto err2;
    }

    return ret;

err2:
    return (ret > 0) ? -ret : ret;

err1:
    mnt_free_context(mntctx);
    return -EIO;
}

static int
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

    close(rootfd);

    /* requires CAP_SYS_ADMIN */
    ret = mnt_context_umount(mntctx);

    mnt_free_context(mntctx);

    return (ret > 0) ? -ret : ret;
}

#define BUFSIZE (1024 * 1024)
#define DISCARD_CACHE_INTERVAL (16 * 1024 * 1024)

static int
calc_chksums(int fd, unsigned char *initsum, unsigned char *sum,
             unsigned *sumlen)
{
    char *buf;
    const struct aiocb *cbp;
    EVP_MD_CTX ctx, initctx;
    int err;
    size_t flen = 0, initrem = 512;
    struct aiocb cb;

    static char buf1[BUFSIZE], buf2[BUFSIZE];

    if ((EVP_DigestInit(&ctx, EVP_sha1()) != 1)
        || (EVP_DigestInit(&initctx, EVP_sha1()) != 1))
        return -EIO;

    memset(&cb, 0, sizeof(cb));
    cb.aio_nbytes = BUFSIZE;
    cb.aio_fildes = fd;
    cb.aio_buf = buf = buf1;
    if (aio_read(&cb) == -1)
        return -errno;
    cbp = &cb;

    for (;;) {
        char *nextbuf;
        size_t len;

        if (aio_suspend(&cbp, 1, NULL) == -1)
            goto err;
        len = aio_return(&cb);
        if (len < 1) {
            if (len != 0)
                goto err;
            break;
        }
        flen += len;

        if ((flen % DISCARD_CACHE_INTERVAL == 0)
            && (posix_fadvise(fd, 0, flen, POSIX_FADV_DONTNEED) == -1))
            goto err;

        cb.aio_offset = flen;
        cb.aio_buf = nextbuf = (buf == buf1) ? buf2 : buf1;
        if (aio_read(&cb) == -1)
            return -errno;

        if (initrem > 0) {
            size_t sz = MIN(initrem, len);

            if (EVP_DigestUpdate(&initctx, buf, sz) != 1)
                goto err;
            initrem -= sz;
        }
        if (EVP_DigestUpdate(&ctx, buf, len) != 1)
            goto err;

        buf = nextbuf;
    }

    if (EVP_DigestFinal(&initctx, initsum, sumlen) != 1)
        return -EIO;

    return (EVP_DigestFinal(&ctx, sum, sumlen) == 1) ? 0 : -EIO;

err:
    err = -((errno == 0) ? EIO : errno);
    cancel_aio(&cb);
    return -err;
}

#undef BUFSIZE
#undef DISCARD_CACHE_INTERVAL

static int
verif_walk_fn(int fd, int dirfd, const char *name, const char *path,
              struct stat *s, void *ctx)
{
    int err;
    struct verif_walk_ctx *wctx = (struct verif_walk_ctx *)ctx;
    unsigned i, sumlen;
    unsigned char initsum[EVP_MAX_MD_SIZE], sum[EVP_MAX_MD_SIZE];

    (void)dirfd;
    (void)name;

    if (!S_ISREG(s->st_mode))
        return 0;

    err = calc_chksums(fd, initsum, sum, &sumlen);
    if (err)
        return err;

    if (fprintf(wctx->dstf, "%zd\t", s->st_size) <= 0)
        goto err1;
    for (i = 0; i < sumlen; i++) {
        if (fprintf(wctx->dstf, "%02x", initsum[i]) <= 0)
            goto err1;
    }
    if (fputc('\t', wctx->dstf) == EOF)
        goto err1;
    for (i = 0; i < sumlen; i++) {
        if (fprintf(wctx->dstf, "%02x", sum[i]) <= 0)
            goto err1;
    }
    if (fprintf(wctx->dstf, "\t%s/%s\n", wctx->prefix, path) <= 0)
        goto err1;

    if (fflush(wctx->dstf) == EOF)
        goto err2;

    if (posix_fadvise(fd, 0, s->st_size, POSIX_FADV_DONTNEED) == -1)
        goto err2;

    return 0;

err1:
    return -EIO;

err2:
    return -errno;
}

static int
verif_fn(void *arg)
{
    struct verif_args *vargs = (struct verif_args *)arg;
    struct verif_walk_ctx wctx;

    if ((vargs->gid != (gid_t)-1) && (setgid(vargs->gid) == -1)) {
        error(0, errno, "Error changing group");
        return errno;
    }
    if ((vargs->uid != (uid_t)-1) && (setuid(vargs->uid) == -1)) {
        error(0, errno, "Error changing user");
        return errno;
    }

    wctx.dstf = vargs->dstf;
    wctx.prefix = vargs->prefix;
    return dir_walk_fd(vargs->srcfd, &verif_walk_fn, DIR_WALK_ALLOW_ERR,
                       (void *)&wctx);
}

static int
do_verif(struct verif_args *verif_args)
{
    int status;
    pid_t pid;

    static char verif_stack[16 * 1024 * 1024];

    debug_print("Performing verification");

    pid = clone(&verif_fn, verif_stack + sizeof(verif_stack), CLONE_FILES,
                verif_args);
    if (pid == -1) {
        error(0, errno, "Error creating process");
        return -errno;
    }

    while (waitpid(pid, &status, __WCLONE) == -1) {
        if (errno != EINTR)
            return errno;
    }

    if (!WIFEXITED(status))
        return -EIO;

    return -WEXITSTATUS(status);
}

static int
do_verifs(struct ctx *ctx)
{
    FILE *dstf;
    int err;
    int i;
    struct verif *verif;
    struct verif_args va;

    dstf = fopen(ctx->output_file, "w");
    if (dstf == NULL) {
        error(0, -errno, "Error opening %s", ctx->output_file);
        return -errno;
    }

    for (i = 0; i < ctx->num_verifs; i++) {
        verif = &ctx->verifs[i];

        debug_print("Verification %d:", i + 1);
        log_print(LOG_INFO, "Starting verifcation %d: %s", i + 1,
                  verif->srcpath);

        va.srcfd = mount_filesystem(verif->srcpath);
        if (va.srcfd < 0) {
            error(0, -va.srcfd, "Error mounting %s", verif->srcpath);
            err = va.srcfd;
            goto err1;
        }

        va.dstf = dstf;
        va.prefix = verif->srcpath;
        va.uid = ctx->uid;
        va.gid = ctx->gid;
        err = do_verif(&va);
        if (err)
            goto err2;

        err = unmount_filesystem(verif->srcpath, va.srcfd);
        if (err)
            goto err1;

        if (fsync(fileno(dstf)) == -1) {
            err = -errno;
            goto err1;
        }

        log_print(LOG_INFO, "Finished verifcation %d: %s", i + 1,
                  verif->srcpath);
    }

    return (fclose(dstf) == EOF) ? -errno : 0;

err2:
    unmount_filesystem(verif->srcpath, va.srcfd);
err1:
    fclose(dstf);
    return err;
}

static void
print_verifs(FILE *f, struct verif *verifs, int num)
{
    int i;

    for (i = 0; i < num; i++) {
        struct verif *verif = &verifs[i];

        fprintf(f,
                "Verifcation %d:\n"
                "\tSource directory path: %s\n",
                i + 1,
                verif->srcpath);
    }
}

static void
free_verifs(struct verif *verifs, int num)
{
    int i;

    for (i = 0; i < num; i++) {
        struct verif *verif = &verifs[i];

        free((void *)(verif->srcpath));
    }

    free(verifs);
}

int
main(int argc, char **argv)
{
    const char *confpath = NULL;
    int ret;
    struct ctx ctx;

    (void)argc;
    (void)argv;

    ret = set_capabilities();
    if (ret != 0)
        error(EXIT_FAILURE, -ret, "Error setting capabilities");

    ctx.uid = (uid_t)-1;
    ctx.gid = (gid_t)-1;

    ret = get_conf_path(CONFIG_PATH, &confpath);
    if (ret != 0)
        return EXIT_FAILURE;

    ret = parse_config(confpath, &ctx);
    free((void *)confpath);
    if (ret != 0)
        return EXIT_FAILURE;

    if (debug) {
        print_verifs(stderr, ctx.verifs, ctx.num_verifs);
        fprintf(stderr, "UID: %d\nGID: %d\n", ctx.uid, ctx.gid);
    }

    if (log)
        openlog(NULL, LOG_PID, LOG_USER);

    /* requires CAP_SYS_ADMIN */
    ret = unshare(CLONE_NEWNS);
    if (ret == -1) {
        error(0, -ret, "Error unsharing namespace");
        goto end;
    }

    ret = do_verifs(&ctx);

end:
    if (log)
        closelog();
    free_verifs(ctx.verifs, ctx.num_verifs);
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
