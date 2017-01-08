/*
 * verify.c
 */

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#include "verify.h"

#include <json.h>

#include <json/grammar.h>
#include <json/grammar_parse.h>
#include <json/native.h>

#include <libmount/libmount.h>

#include <openssl/evp.h>

#include <backup.h>

#include <hashes.h>
#include <radix_tree.h>
#include <strings_ext.h>

#include <files/util.h>

#include <aio.h>
#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
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
#include <wchar.h>
#include <wordexp.h>

#include <rpc/rpc.h>

#include <sys/capability.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define CONFIG_PATH "\"$HOME/.verify.conf\""
#define CONFIG_ROOT_ID "conf"

#define CHECK_CMD_SRC_SPECIFIER "$dev"

#define RPC_PROGNUM 0x20000001
#define RPC_VERSNUM 1
#define RPC_PROCNUM_VERIFY_RECORD 1

#define BUFSIZE (1024 * 1024)

struct ctx {
    struct verif        *verifs;
    int                 num_verifs;
    const char          *base_dir;
    regex_t             *reg_excl;
    const char          *input_file;
    struct radix_tree   *input_data;
    const char          *output_file;
    uid_t               uid;
    gid_t               gid;
};

struct parse_ctx {
    struct ctx  ctx;
    char        *regex;
    char        *regexcurbr;
    size_t      regexlen;
};

struct input_record {
    off_t           size;
    unsigned char   initsum[EVP_MAX_MD_SIZE];
    unsigned char   sum[EVP_MAX_MD_SIZE];
};

struct verify_record_xdr {
    u_long  input_data;
    char    path[PATH_MAX];
    u_long  size_ms;
    u_long  size_ls;
    u_char  initsum[EVP_MAX_MD_SIZE];
    u_char  sum[EVP_MAX_MD_SIZE];
};

struct verif {
    const char *devpath;
    const char *srcpath;
    const char *check_cmd;
};

struct verif_args {
    int                 srcfd;
    FILE                *dstf;
    regex_t             *reg_excl;
    struct radix_tree   *input_data;
    const char          *prefix;
    uid_t               uid;
    gid_t               gid;
};

struct verif_walk_ctx {
    regex_t             *reg_excl;
    struct radix_tree   *input_data;
    char                *buf1;
    char                *buf2;
    EVP_MD_CTX          initsumctx;
    EVP_MD_CTX          sumctx;
    FILE                *dstf;
    const char          *prefix;
};

static volatile sig_atomic_t quit;

static int debug;
static int log;

static void debug_print(const char *, ...);
static void log_print(int, const char *, ...);

static int expand_string(char **, char **, size_t *, size_t);

static char from_hex(char);

static int scan_chksum(const char *, unsigned char *, unsigned);
static int print_chksum(FILE *, unsigned char *, unsigned);

static int get_gid(const char *, gid_t *);
static int get_uid(const char *, uid_t *);

static int set_direct_io(int);

static void cancel_aio(struct aiocb *);

static int svc_run_fn(void *);

static int do_svc_run(void);

static int set_capabilities(void);

static int get_conf_path(const char *, const char **);

static int parse_json_config(const char *, const struct json_parser *,
                             json_val_t *);

static int read_base_dir_opt(json_val_t, void *);
static int read_creds_opt(json_val_t, void *);
static int read_debug_opt(json_val_t, void *);
static int read_exclude_opt(json_val_t, void *);
static int read_input_file_opt(json_val_t, void *);
static int read_output_file_opt(json_val_t, void *);
static int read_verifs_opt(json_val_t, void *);
static int read_json_config(json_val_t, struct parse_ctx *);

static int parse_config(const char *, struct parse_ctx *);

static int get_regex(regex_t *, const char *);

static void int_handler(int);

static int set_signal_handlers(void);

static int input_data_walk_cb(const char *, void *, void *);

static int scan_input_file(const char *, struct radix_tree **);
static int print_input_data(FILE *, struct radix_tree *);

static int calc_chksums_cb(int, off_t);

static int calc_chksums(int, char *, char *, EVP_MD_CTX *, EVP_MD_CTX *,
                        unsigned char *, unsigned char *, unsigned *,
                        int (*)(int, off_t));

static int verify_record_arg_dec(XDR *, void *);
static int verify_record_arg_enc(XDR *, void *);
static int do_verify_record(struct radix_tree *, const char *, off_t,
                            unsigned char *, unsigned char *);
static char *verify_record_proc(char *);

static int verify_record(struct radix_tree *, const char *, const char *, off_t,
                         unsigned char *, unsigned char *, unsigned);
static int output_record(FILE *, off_t, unsigned char *, unsigned char *,
                         unsigned, const char *, const char *);

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
expand_string(char **str, char **dst, size_t *len, size_t minadd)
{
    size_t off = *dst - *str;

    if (off + minadd > *len) {
        char *tmp;
        size_t newlen;

        newlen = MAX(*len + minadd, *len * 2);
        tmp = realloc((void *)*str, newlen + 1);
        if (tmp == NULL)
            return -errno;
        *str = tmp;
        *dst = tmp + off;
        *len = newlen;
    }

    return 0;
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

static int
print_chksum(FILE *f, unsigned char *sum, unsigned sumlen)
{
    unsigned i;

    for (i = 0; i < sumlen; i++) {
        if (fprintf(f, "%02x", sum[i]) <= 0)
            return -EIO;
    }

    return 0;
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

static int
set_direct_io(int fd)
{
    int fl;

    fl = fcntl(fd, F_GETFL);
    if (fl == -1)
        return -errno;

    return (fcntl(fd, F_SETFL, fl | O_DIRECT) == -1) ? -errno : 0;
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
svc_run_fn(void *arg)
{
    (void)arg;

    svc_run();
    return -1;
}

static int
do_svc_run()
{
    static char svc_run_stack[16 * 1024 * 1024];

    if (clone(&svc_run_fn, svc_run_stack + sizeof(svc_run_stack),
              CLONE_SIGHAND | CLONE_THREAD | CLONE_VM, NULL) == -1) {
        error(0, errno, "Error creating process");
        return -errno;
    }

    return 0;
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
read_base_dir_opt(json_val_t opt, void *data)
{
    mbstate_t s;
    struct ctx *ctx = (struct ctx *)data;

    memset(&s, 0, sizeof(s));
    return (awcstombs((char **)&ctx->base_dir, json_val_string_get(opt), &s)
            == (size_t)-1) ? -errno : 0;
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

    debug = backup_debug = json_val_boolean_get(opt);

    return 0;
}

static int
read_exclude_opt(json_val_t opt, void *data)
{
    int err;
    int first;
    int i, numexcl;
    struct parse_ctx *pctx = (struct parse_ctx *)data;

    numexcl = json_val_array_get_num_elem(opt);
    first = (pctx->regexlen == 0);

    for (i = 0; i < numexcl; i++) {
        char *regexbr;
        json_val_t val;
        mbstate_t s;
        size_t brlen;

        val = json_val_array_get_elem(opt, i);
        if (val == NULL)
            return -EIO;

        memset(&s, 0, sizeof(s));
        brlen = awcstombs(&regexbr, json_val_string_get(val), &s);
        if (brlen == (size_t)-1)
            return -errno;

        err = expand_string(&pctx->regex, &pctx->regexcurbr, &pctx->regexlen,
                            brlen + 2);
        if (err)
            return err;
        if (first)
            first = 0;
        else
            *((pctx->regexcurbr)++) = '|';
        pctx->regexcurbr = stpcpy(pctx->regexcurbr, regexbr);

        free(regexbr);
    }

    return 0;
}

static int
read_input_file_opt(json_val_t opt, void *data)
{
    mbstate_t s;
    struct ctx *ctx = (struct ctx *)data;

    memset(&s, 0, sizeof(s));
    return (awcstombs((char **)&ctx->input_file, json_val_string_get(opt), &s)
            == (size_t)-1) ? -errno : 0;
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
        {L"dev", JSON_TYPE_STRING, 1, 0, 1, NULL, NULL, NULL,
         VERIF_PARAM(devpath)},
        {L"src", JSON_TYPE_STRING, 1, 0, 1, NULL, NULL, NULL,
         VERIF_PARAM(srcpath)},
        {L"check_cmd", JSON_TYPE_STRING, 0, 0, 1, NULL, NULL, NULL,
         VERIF_PARAM(check_cmd)}
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

        ctx->verifs[i].check_cmd = NULL;
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
read_json_config(json_val_t config, struct parse_ctx *ctx)
{
    int err;
    int i, numopt;

    static const struct {
        const wchar_t   *opt;
        int             (*fn)(json_val_t, void *);
    } opts[16] = {
        [2]     = {L"base_dir",     &read_base_dir_opt},
        [3]     = {L"creds",        &read_creds_opt},
        [4]     = {L"debug",        &read_debug_opt},
        [5]     = {L"exclude",      &read_exclude_opt},
        [9]     = {L"input_file",   &read_input_file_opt},
        [12]    = {L"log",          &read_log_opt},
        [15]    = {L"output_file",  &read_output_file_opt},
        [6]     = {L"verifs",       &read_verifs_opt}
    }, *opt;

    numopt = json_val_object_get_num_elem(config);
    for (i = 0; i < numopt; i++) {
        json_object_elem_t elem;

        err = json_val_object_get_elem_by_idx(config, i, &elem);
        if (err)
            return err;

        opt = &opts[hash_str(elem.key, -1) & 15];
        if ((opt->opt == NULL) || (wcscmp(elem.key, opt->opt) != 0))
            return -EIO;

        err = (*(opt->fn))(elem.value, ctx);
        if (err)
            return err;
    }

    return 0;
}

static int
parse_config(const char *path, struct parse_ctx *ctx)
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

    res = radix_tree_new(&ret, sizeof(struct input_record));
    if (res != 0)
        goto err1;

    errno = 0;
    for (linenum = 1;; linenum++) {
        char buf1[16], buf2[256], buf3[256], buf4[PATH_MAX];
        struct input_record record;

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
calc_chksums_cb(int fd, off_t flen)
{
    (void)fd;
    (void)flen;

    return quit ? -EINTR : 0;
}

static int
calc_chksums(int fd, char *buf1, char *buf2, EVP_MD_CTX *initsumctx,
             EVP_MD_CTX *sumctx, unsigned char *initsum, unsigned char *sum,
             unsigned *sumlen, int (*cb)(int, off_t))
{
    char *buf;
    const struct aiocb *aiocbp;
    int err;
    off_t flen = 0, initrem = 512;
    struct aiocb aiocb;

    if ((EVP_DigestInit_ex(sumctx, EVP_sha1(), NULL) != 1)
        || (EVP_DigestInit_ex(initsumctx, EVP_sha1(), NULL) != 1))
        return -EIO;

    memset(&aiocb, 0, sizeof(aiocb));
    aiocb.aio_nbytes = BUFSIZE;
    aiocb.aio_fildes = fd;
    aiocb.aio_buf = buf = buf1;
    if (aio_read(&aiocb) == -1)
        return -errno;
    aiocbp = &aiocb;

    for (;;) {
        char *nextbuf;
        size_t len;

        if (aio_suspend(&aiocbp, 1, NULL) == -1)
            goto err;
        len = aio_return(&aiocb);
        if (len < 1) {
            if (len != 0)
                goto err;
            break;
        }
        flen += len;

        err = (*cb)(fd, flen);
        if (err)
            return err;

        aiocb.aio_offset = flen;
        aiocb.aio_buf = nextbuf = (buf == buf1) ? buf2 : buf1;
        if (aio_read(&aiocb) == -1)
            return -errno;

        if (initrem > 0) {
            size_t sz = MIN(initrem, (off_t)len);

            if (EVP_DigestUpdate(initsumctx, buf, sz) != 1)
                goto err;
            initrem -= sz;
        }
        if (EVP_DigestUpdate(sumctx, buf, len) != 1)
            goto err;

        buf = nextbuf;
    }

    return ((EVP_DigestFinal_ex(initsumctx, initsum, sumlen) == 1)
            && (EVP_DigestFinal_ex(sumctx, sum, sumlen) == 1)) ? 0 : -EIO;

err:
    err = -((errno == 0) ? EIO : errno);
    cancel_aio(&aiocb);
    return -err;
}

static int
verify_record_arg_dec(XDR *xdrs, void *obj)
{
    char *path;
    struct verify_record_xdr *vr = (struct verify_record_xdr *)obj;

    if (xdrs->x_op == XDR_FREE)
        return TRUE;

    path = vr->path;

    xdr_u_long(xdrs, &vr->input_data);
    xdr_string(xdrs, &path, sizeof(vr->path));
    xdr_u_long(xdrs, &vr->size_ms);
    xdr_u_long(xdrs, &vr->size_ls);
    xdr_vector(xdrs, (char *)&vr->initsum, sizeof(vr->initsum),
               sizeof(*(vr->initsum)), (xdrproc_t)&xdr_char);
    xdr_vector(xdrs, (char *)&vr->sum, sizeof(vr->sum), sizeof(*(vr->sum)),
               (xdrproc_t)&xdr_char);

    return TRUE;
}

static int
verify_record_arg_enc(XDR *xdrs, void *obj)
{
    char *path;
    struct verify_record_xdr *vr = (struct verify_record_xdr *)obj;

    if (xdrs->x_op == XDR_FREE)
        return TRUE;

    path = vr->path;

    xdr_u_long(xdrs, &vr->input_data);
    xdr_string(xdrs, &path, sizeof(vr->path));
    xdr_u_long(xdrs, &vr->size_ms);
    xdr_u_long(xdrs, &vr->size_ls);
    xdr_vector(xdrs, (char *)&vr->initsum, sizeof(vr->initsum),
               sizeof(*(vr->initsum)), (xdrproc_t)&xdr_char);
    xdr_vector(xdrs, (char *)&vr->sum, sizeof(vr->sum), sizeof(*(vr->sum)),
               (xdrproc_t)&xdr_char);

    return TRUE;
}

static int
do_verify_record(struct radix_tree *input_data, const char *path, off_t size,
                 unsigned char *initsum, unsigned char *sum)
{
    int ret;
    struct input_record record;

    ret = radix_tree_search(input_data, path, &record);
    if (ret != 1) {
        if (ret != 0)
            return ret;
        error(0, 0, "Verification error: %s added", path);
        return -EIO;
    }

    if ((size != record.size) || (memcmp(initsum, record.initsum, 20) != 0)
        || (memcmp(sum, record.sum, 20) != 0)) {
        error(0, 0, "Verification error: %s failed verification", path);
        return -EIO;
    }

    return radix_tree_delete(input_data, path);
}

static char *
verify_record_proc(char *obj)
{
    off_t size;
    static int ret;
    struct verify_record_xdr *vr = (struct verify_record_xdr *)obj;

    size = (((uint64_t)(vr->size_ms)) << 32) | vr->size_ls;

    ret = do_verify_record((struct radix_tree *)(vr->input_data), vr->path,
                           size, vr->initsum, vr->sum);

    return (char *)&ret;
}

static int
output_record(FILE *f, off_t size, unsigned char *initsum, unsigned char *sum,
              unsigned sumlen, const char *prefix, const char *path)
{
    /* print file size */
    if (fprintf(f, "%" PRIu64 "\t", size) <= 0)
        goto err;

    /* print checksum of first min(file_size, 512) bytes of file */
    if ((print_chksum(f, initsum, sumlen) != 0) || (fputc('\t', f) == EOF))
        goto err;

    /* print checksum of file */
    if (print_chksum(f, sum, sumlen) != 0)
        goto err;

    /* print file path */
    if (fprintf(f, "\t%s/%s\n", prefix, path) <= 0)
        goto err;

    return (fflush(f) == EOF) ? -errno : 0;

err:
    return -EIO;
}

static int
verify_record(struct radix_tree *input_data, const char *prefix,
              const char *path, off_t size, unsigned char *initsum,
              unsigned char *sum, unsigned sumlen)
{
    int ret;
    struct verify_record_xdr vr;
    uint64_t usize;

    if (sumlen != 20)
        return -EIO;

    if (snprintf(vr.path, sizeof(vr.path), "%s/%s", prefix, path)
        >= (int)sizeof(vr.path))
        return -EIO;

    usize = (uint64_t)size;
    vr.size_ms = (usize & 0xffffffff00000000) >> 32;
    vr.size_ls = usize & 0xffffffff;

    vr.input_data = (u_long)input_data;
    memcpy(vr.initsum, initsum, EVP_MAX_MD_SIZE);
    memcpy(vr.sum, sum, EVP_MAX_MD_SIZE);

    return (callrpc("localhost", RPC_PROGNUM, RPC_VERSNUM,
                    RPC_PROCNUM_VERIFY_RECORD,
                    (xdrproc_t)&verify_record_arg_enc, (const char *)&vr,
                    (xdrproc_t)&xdr_int, (char *)&ret)
            == 0)
           ? ret : -EIO;
}

static int
verif_walk_fn(int fd, int dirfd, const char *name, const char *path,
              struct stat *s, void *ctx)
{
    int err;
    struct verif_walk_ctx *wctx = (struct verif_walk_ctx *)ctx;
    unsigned sumlen;
    unsigned char initsum[EVP_MAX_MD_SIZE], sum[EVP_MAX_MD_SIZE];

    (void)dirfd;
    (void)name;

    if (quit)
        return -EINTR;

    if (!S_ISREG(s->st_mode))
        return 0;

    if (wctx->reg_excl != NULL) { /* check if file excluded */
        char buf[PATH_MAX];

        if ((snprintf(buf, sizeof(buf), "%s/%s", wctx->prefix, path)
             < (int)sizeof(buf))
            && (regexec(wctx->reg_excl, buf, 0, NULL, 0) == 0)) {
            fprintf(stderr, "%s excluded\n", buf);
            return 0;
        }
    }

    err = set_direct_io(fd);
    if (err)
        return err;

    err = calc_chksums(fd, wctx->buf1, wctx->buf2, &wctx->initsumctx,
                       &wctx->sumctx, initsum, sum, &sumlen, &calc_chksums_cb);
    if (err)
        return err;

    /* FIXME: later, verify first checksum as soon as min(s->st_size, 512) bytes
       read */
    if (wctx->input_data != NULL) {
        err = verify_record(wctx->input_data, wctx->prefix, path, s->st_size,
                            initsum, sum, sumlen);
        if (err)
            return err;
    }

    err = output_record(wctx->dstf, s->st_size, initsum, sum, sumlen,
                        wctx->prefix, path);
    if (err)
        return err;

    return -posix_fadvise(fd, 0, s->st_size, POSIX_FADV_DONTNEED);
}

static int
verif_fn(void *arg)
{
    int err;
    struct verif_args *vargs = (struct verif_args *)arg;
    struct verif_walk_ctx wctx;

    if ((vargs->gid != (gid_t)-1)
        && ((setgroups(0, NULL) == -1) || (setgid(vargs->gid) == -1))) {
        error(0, errno, "Error changing group");
        return errno;
    }
    if ((vargs->uid != (uid_t)-1) && (setuid(vargs->uid) == -1)) {
        error(0, errno, "Error changing user");
        return errno;
    }

    err = posix_memalign((void **)&wctx.buf1, 512, BUFSIZE);
    if (err)
        return err;
    err = posix_memalign((void **)&wctx.buf2, 512, BUFSIZE);
    if (err)
        goto end1;

    if ((EVP_DigestInit(&wctx.sumctx, EVP_sha1()) != 1)
        || (EVP_DigestInit(&wctx.initsumctx, EVP_sha1()) != 1)) {
        err = -EIO;
        goto end2;
    }

    wctx.reg_excl = vargs->reg_excl;
    wctx.input_data = vargs->input_data;
    wctx.dstf = vargs->dstf;
    wctx.prefix = vargs->prefix;

    err = dir_walk_fd(vargs->srcfd, &verif_walk_fn, DIR_WALK_ALLOW_ERR,
                      (void *)&wctx);

    EVP_MD_CTX_cleanup(&wctx.sumctx);
    EVP_MD_CTX_cleanup(&wctx.initsumctx);

end2:
    free(wctx.buf2);
end1:
    free(wctx.buf1);
    return err;
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

    return WIFEXITED(status) ? -WEXITSTATUS(status) : -EIO;
}

static int
do_verifs(struct ctx *ctx)
{
    FILE *dstf;
    int err;
    int i;
    struct verif *verif;
    struct verif_args va;

    if (strcmp("-", ctx->output_file) == 0)
        dstf = stdout;
    else {
        dstf = fopen(ctx->output_file, "w");
        if (dstf == NULL) {
            error(0, errno, "Error opening %s", ctx->output_file);
            return -errno;
        }
    }

    for (i = 0; i < ctx->num_verifs; i++) {
        verif = &ctx->verifs[i];

        debug_print("Verification %d:", i + 1);
        log_print(LOG_INFO, "Starting verifcation %d: %s", i + 1,
                  verif->srcpath);

        if (verif->check_cmd != NULL) {
            err = check_filesystem(verif->devpath, verif->check_cmd,
                                   CHECK_CMD_SRC_SPECIFIER);
            if (err)
                goto err1;
        }

        va.srcfd = mount_filesystem(verif->devpath, verif->srcpath, 1);
        if (va.srcfd < 0) {
            error(0, -va.srcfd, "Error mounting %s", verif->srcpath);
            err = va.srcfd;
            goto err1;
        }

        va.reg_excl = ctx->reg_excl;
        va.input_data = ctx->input_data;
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

        if ((dstf != stdout) && (fsync(fileno(dstf)) == -1)) {
            err = -errno;
            goto err1;
        }

        log_print(LOG_INFO, "Finished verifcation %d: %s", i + 1,
                  verif->srcpath);
    }

    if (ctx->input_data != NULL) {
        struct radix_tree_stats s;

        err = radix_tree_stats(ctx->input_data, &s);
        if (err)
            goto err1;
        if (s.num_info_nodes != 0) {
            error(0, 0, "Verification error: Files removed:");
            print_input_data(stderr, ctx->input_data);
            err = -EIO;
            goto err1;
        }
    }

    return (dstf == stdout) ? 0 : ((fclose(dstf) == EOF) ? -errno : 0);

err2:
    unmount_filesystem(verif->srcpath, va.srcfd);
err1:
    if (dstf != stdout)
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
                "\tDevice path: %s\n"
                "\tSource directory path: %s\n",
                i + 1,
                verif->devpath,
                verif->srcpath);
    }
}

static void
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
    struct ctx *ctx;
    struct parse_ctx pctx;

    (void)argc;
    (void)argv;

    if ((registerrpc(RPC_PROGNUM, RPC_VERSNUM, RPC_PROCNUM_VERIFY_RECORD,
                     &verify_record_proc, &verify_record_arg_dec, &xdr_int)
         == -1)
        || (do_svc_run() != 0)) {
        error(0, 0, "Error initializing");
        return -EIO;
    }

    ret = set_capabilities();
    if (ret != 0)
        error(EXIT_FAILURE, -ret, "Error setting capabilities");

    ret = get_conf_path(CONFIG_PATH, &confpath);
    if (ret != 0)
        return EXIT_FAILURE;

    ctx = &pctx.ctx;
    ctx->base_dir = NULL;
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

    if ((ctx->base_dir != NULL) && (chdir(ctx->base_dir) == -1)) {
        error(0, -errno, "Error changing directory to %s", ctx->base_dir);
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

    if (log)
        openlog(NULL, LOG_PID, LOG_USER);

    ret = mount_ns_unshare();
    if (ret != 0)
        goto end2;

    ret = set_signal_handlers();
    if (ret != 0)
        goto end2;

    ret = do_verifs(ctx);

end2:
    if (log)
        closelog();
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
