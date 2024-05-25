/*
 * verify_conf.c
 */

#include "common.h"
#include "debug.h"
#include "util.h"
#include "verify_common.h"
#include "verify_conf.h"
#include "verify_gram.h"

#include <backup.h>

#include <json.h>

#include <json/filters.h>
#include <json/grammar.h>
#include <json/grammar_parse.h>
#include <json/native.h>

#include <hashes.h>
#include <strings_ext.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#define CONFIG_ROOT_ID "conf"

static int expand_string(char **, char **, size_t *, size_t);

static int get_gid(const char *, gid_t *);
static int get_uid(const char *, uid_t *);

static int open_as_real_user(int *, const char *, int, ...);
static int config_trusted(struct stat *);
static size_t rd_cb(void *, size_t, size_t, void *);

static int read_base_dir_opt(json_value_t, void *);
static int read_creds_opt(json_value_t, void *);
static int read_debug_opt(json_value_t, void *);
static int read_detect_hard_links_opt(json_value_t, void *);
static int read_exclude_opt(json_value_t, void *);
static int read_input_file_opt(json_value_t, void *);
static int read_output_file_opt(json_value_t, void *);
static int read_verifs_opt(json_value_t, void *);

static int parse_json_config(const char *, const struct json_parser *,
                             json_value_t *);
static int read_json_config(json_value_t, struct parse_ctx *);

static int
expand_string(char **str, char **dst, size_t *len, size_t minadd)
{
    size_t off = *dst - *str;

    if (off + minadd > *len) {
        char *tmp;
        size_t newlen;

        newlen = MAX(*len + minadd, *len * 2);
        tmp = do_realloc(*str, newlen + 1);
        if (tmp == NULL)
            return ERR_TAG(errno);
        *str = tmp;
        *dst = tmp + off;
        *len = newlen;
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

    bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (bufsize == (size_t)-1)
        bufsize = 1024;

    buf = do_malloc(bufsize);
    if (buf == NULL)
        return ERR_TAG(errno);

    for (;;) {
        char *tmp;

        err = getgrnam_r(name, &grp, buf, bufsize, &res);
        if (!err)
            break;
        if (err != ERANGE) {
            error(0, err, "Error looking up group information for %s", name);
            err = ERR_TAG(err);
            goto err;
        }

        bufsize *= 2;
        tmp = do_realloc(buf, bufsize);
        if (tmp == NULL) {
            err = ERR_TAG(errno);
            goto err;
        }
        buf = tmp;
    }
    if (res == NULL) {
        err = ERR_TAG(ENOENT);
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

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == (size_t)-1)
        bufsize = 1024;

    buf = do_malloc(bufsize);
    if (buf == NULL)
        return ERR_TAG(errno);

    for (;;) {
        char *tmp;

        err = getpwnam_r(name, &pwd, buf, bufsize, &res);
        if (!err)
            break;
        if (err != ERANGE) {
            error(0, err, "Error looking up user information for %s", name);
            err = ERR_TAG(err);
            goto err;
        }

        bufsize *= 2;
        tmp = do_realloc(buf, bufsize);
        if (tmp == NULL) {
            err = ERR_TAG(errno);
            goto err;
        }
        buf = tmp;
    }
    if (res == NULL) {
        err = ERR_TAG(ENOENT);
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
open_as_real_user(int *fd, const char *path, int flags, ...)
{
    int err, ret;
    uid_t prev_euid;

    prev_euid = geteuid();

    if (seteuid(getuid()) == -1) {
        err = errno;
        error(0, err, "Error accessing %s", path);
        return ERR_TAG(err);
    }

    if (flags & O_CREAT) {
        va_list ap;

        va_start(ap, flags);
        ret = open(path, flags, va_arg(ap, mode_t));
        va_end(ap);
    } else
        ret = open(path, flags);
    if (ret == -1) {
        err = errno;
        error(0, err, "Error opening %s", path);
        (void)(prev_euid = seteuid(prev_euid));
        return ERR_TAG(err);
    }

    if (seteuid(prev_euid) == -1) {
        err = errno;
        error(0, err, "Error accessing %s", path);
        close(ret);
        return ERR_TAG(err);
    }

    *fd = ret;
    return 0;
}

static int
config_trusted(struct stat *s)
{
    mode_t mode;

    if (s->st_uid != 0) {
        error(0, 0, "Configuration file not owned by root");
        return 0;
    }

    mode = s->st_mode;

    if (mode & S_IWGRP && (s->st_gid != 0 || mode & S_IWOTH)) {
        error(0, 0, "Configuration file writable by non-root users");
        return 0;
    }

    return 1;
}

static size_t
rd_cb(void *buf, size_t off, size_t len, void *ctx)
{
    FILE *f = ctx;
    size_t ret;

    (void)off;

    ret = fread(buf, 1, len, f);

    return ret == 0 && !feof(f) ? (size_t)-1 : ret;
}

static int
read_base_dir_opt(json_value_t opt, void *data)
{
    int err;
    mbstate_t s;
    struct verify_ctx *ctx = data;
    wchar_t *str;

    str = json_string_get_value(opt);
    if (str == NULL)
        return ERR_TAG(ENOMEM);

    omemset(&s, 0);
    err = awcstombs(&ctx->base_dir, str, &s) == (size_t)-1 ? ERR_TAG(errno) : 0;
    free(str);
    return err;
}

static int
read_creds_opt(json_value_t opt, void *data)
{
    char *buf;
    int err;
    json_kv_pair_t elm;
    mbstate_t s;
    struct verify_ctx *ctx = data;
    wchar_t *str;

    omemset(&s, 0);

    err = json_object_get(opt, L"uid", &elm);
    if (!err) {
        str = json_string_get_value(elm.v);
        json_value_put(elm.v);
        if (str == NULL)
            return ERR_TAG(ENOMEM);
        err = awcstombs(&buf, str, &s) == (size_t)-1 ? ERR_TAG(errno) : 0;
        free(str);
        if (err)
            return err;
        ctx->uid = atoi(buf);
        free(buf);

        err = json_object_get(opt, L"gid", &elm);
        if (err)
            return ERR_TAG(-err);
        str = json_string_get_value(elm.v);
        json_value_put(elm.v);
        if (str == NULL)
            return ERR_TAG(ENOMEM);
        omemset(&s, 0);
        err = awcstombs(&buf, str, &s) == (size_t)-1 ? ERR_TAG(errno) : 0;
        free(str);
        if (err)
            return err;
        ctx->gid = atoi(buf);
        free(buf);
    } else if (err == -EINVAL) {
        err = json_object_get(opt, L"user", &elm);
        if (err)
            return ERR_TAG(-err);
        str = json_string_get_value(elm.v);
        json_value_put(elm.v);
        if (str == NULL)
            return ERR_TAG(ENOMEM);
        err = awcstombs(&buf, str, &s) == (size_t)-1 ? ERR_TAG(errno) : 0;
        free(str);
        if (err)
            return err;
        err = get_uid(buf, &ctx->uid);
        free(buf);
        if (err)
            return err;

        err = json_object_get(opt, L"group", &elm);
        if (err)
            return ERR_TAG(-err);
        str = json_string_get_value(elm.v);
        json_value_put(elm.v);
        if (str == NULL)
            return ERR_TAG(ENOMEM);
        omemset(&s, 0);
        err = awcstombs(&buf, str, &s) == (size_t)-1 ? ERR_TAG(errno) : 0;
        free(str);
        if (err)
            return err;
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
        return ERR_TAG(-err);

    return 0;
}

static int
read_debug_opt(json_value_t opt, void *data)
{
    (void)data;

    debug = backup_debug = json_boolean_get(opt);

    return 0;
}

static int
read_detect_hard_links_opt(json_value_t opt, void *data)
{
    struct parse_ctx *pctx = data;

    pctx->ctx.detect_hard_links = json_boolean_get(opt);

    return 0;
}

static int
read_exclude_opt(json_value_t opt, void *data)
{
    int err;
    int first;
    int i, numexcl;
    struct parse_ctx *pctx = data;

    numexcl = json_array_get_size(opt);
    first = pctx->regexlen == 0;

    for (i = 0; i < numexcl; i++) {
        char *regexbr;
        json_value_t val;
        mbstate_t s;
        size_t brlen;
        wchar_t *str;

        err = json_array_get_at(opt, i, &val);
        if (err)
            return ERR_TAG(-err);

        str = json_string_get_value(val);
        json_value_put(val);
        if (str == NULL)
            return ERR_TAG(ENOMEM);

        omemset(&s, 0);
        brlen = awcstombs(&regexbr, str, &s);
        err = brlen == (size_t)-1 ? ERR_TAG(errno) : 0;
        free(str);
        if (err)
            return err;

        err = expand_string(&pctx->regex, &pctx->regexcurbr, &pctx->regexlen,
                            brlen + 2);
        if (err) {
            free(regexbr);
            return err;
        }
        if (first)
            first = 0;
        else
            *pctx->regexcurbr++ = '|';
        pctx->regexcurbr = stpcpy(pctx->regexcurbr, regexbr);

        free(regexbr);
    }

    return 0;
}

static int
read_input_file_opt(json_value_t opt, void *data)
{
    int err;
    mbstate_t s;
    struct verify_ctx *ctx = data;
    wchar_t *str;

    str = json_string_get_value(opt);
    if (str == NULL)
        return ERR_TAG(ENOMEM);

    omemset(&s, 0);
    err = awcstombs(&ctx->input_file, str, &s) == (size_t)-1
          ? ERR_TAG(errno) : 0;
    free(str);
    return err;
}

static int
read_output_file_opt(json_value_t opt, void *data)
{
    int err;
    mbstate_t s;
    struct verify_ctx *ctx = data;
    wchar_t *str;

    str = json_string_get_value(opt);
    if (str == NULL)
        return ERR_TAG(ENOMEM);

    omemset(&s, 0);
    err = awcstombs(&ctx->output_file, str, &s) == (size_t)-1
          ? ERR_TAG(errno) : 0;
    free(str);
    return err;
}

static int
read_log_opt(json_value_t opt, void *data)
{
    (void)data;

    log_verifs = json_boolean_get(opt);

    return 0;
}

#define VERIF_PARAM(param) offsetof(struct verif, param)

static int
read_verifs_opt(json_value_t opt, void *data)
{
    int err;
    int i;
    struct verify_ctx *ctx = data;

    static const struct json_unpack_mapping spec[] = {
        {JSON_STRING_T, L"dev", NULL, NULL, NULL, VERIF_PARAM(devpath), 0, 0,
         1},
        {JSON_STRING_T, L"src", NULL, NULL, NULL, VERIF_PARAM(srcpath), 0, 1,
         1},
        {JSON_STRING_T, L"srcmntopts", NULL, NULL, NULL,
         VERIF_PARAM(srcmntopts), 0, 0, 1},
        {JSON_STRING_T, L"check_cmd", NULL, NULL, NULL, VERIF_PARAM(check_cmd),
         0, 0, 1}
    };

    ctx->num_verifs = json_array_get_size(opt);

    if (oecalloc(&ctx->verifs, ctx->num_verifs) == NULL)
        return ERR_TAG(errno);

    for (i = 0; i < ctx->num_verifs; i++) {
        json_value_t val;

        err = json_array_get_at(opt, i, &val);
        if (err) {
            err = ERR_TAG(-err);
            goto err;
        }

        ctx->verifs[i].check_cmd = NULL;
        err = json_unpack(spec, (int)ARRAY_SIZE(spec), val, &ctx->verifs[i], 0);
        if (err) {
            err = ERR_TAG(-err);
            goto err;
        }
    }

    return 0;

err:
    free_verifs(ctx->verifs, i);
    return err;
}

#undef VERIF_PARAM

static int
parse_json_config(const char *path, const struct json_parser *parser,
                  json_value_t *config)
{
    FILE *f;
    int err;
    int fd;
    struct json_in_filter_ctx ctx;
    struct stat s;

    err = open_as_real_user(&fd, path, O_RDONLY);
    if (err)
        return err;

    if (fstat(fd, &s) == -1) {
        err = errno;
        error(0, err, "Error accessing %s", path);
        err = ERR_TAG(err);
        goto err;
    }

    if (!config_trusted(&s)) {
        err = ERR_TAG(EPERM);
        goto err;
    }

    f = fdopen(fd, "r");
    if (f == NULL) {
        err = errno;
        error(0, err, "Error accessing %s", path);
        err = ERR_TAG(err);
        goto err;
    }

    json_in_filter_ctx_init(&ctx);
    ctx.rd_cb = &rd_cb;
    ctx.ctx = f;

    err = -json_parse_text_with_syntax(config, NULL,
                                       &json_in_filter_discard_comments, &ctx,
                                       parser);

    fclose(f);

    if (err) {
        error(0, err, "Error parsing %s", path);
        return ERR_TAG(err);
    }

    return 0;

err:
    close(fd);
    return err;
}

static int
read_json_config(json_value_t config, struct parse_ctx *ctx)
{
    int err;
    int i, numopt;

    static const struct ent {
        const wchar_t   *opt;
        int             (*fn)(json_value_t, void *);
    } opts[64] = {
        [27]    = {L"base_dir",             &read_base_dir_opt},
        [11]    = {L"creds",                &read_creds_opt},
        [57]    = {L"debug",                &read_debug_opt},
        [43]    = {L"detect_hard_links",    &read_detect_hard_links_opt},
        [59]    = {L"exclude",              &read_exclude_opt},
        [23]    = {L"input_file",           &read_input_file_opt},
        [51]    = {L"log",                  &read_log_opt},
        [6]     = {L"output_file",          &read_output_file_opt},
        [15]    = {L"verifs",               &read_verifs_opt}
    };

    numopt = json_object_get_size(config);
    for (i = 0; i < numopt; i++) {
        const struct ent *opt;
        json_kv_pair_t elm;

        err = json_object_get_at(config, i, &elm);
        if (err)
            return ERR_TAG(-err);

        opt = &opts[hash_wcs(elm.k, -1) >> 3 & 63];
        if (opt->opt == NULL || wcscmp(elm.k, opt->opt) != 0) {
            json_value_put(elm.v);
            return ERR_TAG(EIO);
        }

        err = (*opt->fn)(elm.v, ctx);
        json_value_put(elm.v);
        if (err)
            return err;
    }

    return 0;
}

int
parse_config(const char *path, struct parse_ctx *ctx)
{
    int err;
    json_value_t config;
    struct json_parser *parser;

    err = json_parser_generate(CONFIG_GRAM, CONFIG_ROOT_ID, &parser);
    if (err)
        return ERR_TAG(-err);

    err = parse_json_config(path, parser, &config);
    json_parser_destroy(parser);
    if (err)
        return err;

    err = read_json_config(config, ctx);

    json_value_put(config);

    return err;
}

/* vi: set expandtab sw=4 ts=4: */
