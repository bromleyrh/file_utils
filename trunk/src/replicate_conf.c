/*
 * replicate_conf.c
 */

#include "common.h"
#include "debug.h"
#include "replicate_common.h"
#include "replicate_conf.h"
#include "replicate_gram.h"
#include "util.h"

#include <json.h>

#include <json/filters.h>
#include <json/grammar.h>
#include <json/grammar_parse.h>
#include <json/native.h>

#include <backup.h>

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
#include <sys/stat.h>
#include <sys/types.h>

#define CONFIG_ROOT_ID "conf"

static int get_gid(const char *, gid_t *);
static int get_uid(const char *, uid_t *);

static int open_as_real_user(int *, const char *, int, ...);
static int config_trusted(struct stat *);
static size_t read_cb(char *, size_t, size_t, void *);

static int format_cmd_filter(void *, void *, void *);

static int read_copy_creds_opt(json_val_t, void *);
static int read_debug_opt(json_val_t, void *);
static int read_keep_cache_opt(json_val_t, void *);
static int read_transfers_opt(json_val_t, void *);

static int parse_json_config(const char *, const struct json_parser *,
                             json_val_t *);
static int read_json_config(json_val_t, struct replicate_ctx *);

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
read_cb(char *buf, size_t off, size_t len, void *ctx)
{
    FILE *f = ctx;
    size_t ret;

    (void)off;

    ret = fread(buf, 1, len, f);

    return ret == 0 && !feof(f) ? (size_t)-1 : ret;
}

static int
format_cmd_filter(void *src, void *dst, void *arg)
{
    char *tmp;
    const char *format_cmd = *(const char **)src;

    (void)arg;

    tmp = strstr(format_cmd, FORMAT_CMD_DEST_SPECIFIER);
    if (tmp == NULL) {
        error(0, 0, "\"format_cmd\" option missing \"" FORMAT_CMD_DEST_SPECIFIER
              "\"");
        return ERR_TAG(EINVAL);
    }

    tmp = strstr(tmp + sizeof(FORMAT_CMD_DEST_SPECIFIER) - 1,
                 FORMAT_CMD_DEST_SPECIFIER);
    if (tmp != NULL) {
        error(0, 0, "\"format_cmd\" option must contain only one instance of \""
                    FORMAT_CMD_DEST_SPECIFIER "\"");
        return ERR_TAG(EINVAL);
    }

    tmp = strdup(format_cmd);
    if (tmp == NULL)
        return ERR_TAG(errno);

    *(const char **)dst = tmp;
    return 0;
}

static int
read_copy_creds_opt(json_val_t opt, void *data)
{
    char *buf;
    int err;
    json_object_elem_t elem;
    mbstate_t s;
    struct replicate_ctx *ctx = data;

    omemset(&s, 0);

    err = json_val_object_get_elem_by_key(opt, L"uid", &elem);
    if (!err) {
        if (awcstombs(&buf, json_val_string_get(elem.value), &s) == (size_t)-1)
            return ERR_TAG(errno);
        ctx->uid = atoi(buf);
        free(buf);

        err = json_val_object_get_elem_by_key(opt, L"gid", &elem);
        if (err)
            return ERR_TAG(-err);
        omemset(&s, 0);
        if (awcstombs(&buf, json_val_string_get(elem.value), &s) == (size_t)-1)
            return ERR_TAG(errno);
        ctx->gid = atoi(buf);
        free(buf);
    } else if (err == -EINVAL) {
        err = json_val_object_get_elem_by_key(opt, L"user", &elem);
        if (err)
            return ERR_TAG(-err);
        if (awcstombs(&buf, json_val_string_get(elem.value), &s) == (size_t)-1)
            return ERR_TAG(errno);
        err = get_uid(buf, &ctx->uid);
        free(buf);
        if (err)
            return err;

        err = json_val_object_get_elem_by_key(opt, L"group", &elem);
        if (err)
            return ERR_TAG(-err);
        omemset(&s, 0);
        if (awcstombs(&buf, json_val_string_get(elem.value), &s) == (size_t)-1)
            return ERR_TAG(errno);
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
read_debug_opt(json_val_t opt, void *data)
{
    (void)data;

    debug = backup_debug = json_val_boolean_get(opt);

    return 0;
}

static int
read_keep_cache_opt(json_val_t opt, void *data)
{
    struct replicate_ctx *ctx = data;

    ctx->keep_cache = json_val_boolean_get(opt);

    return 0;
}

static int
read_log_opt(json_val_t opt, void *data)
{
    (void)data;

    log_transfers = json_val_boolean_get(opt);

    return 0;
}

#define TRANSFER_PARAM(param) offsetof(struct transfer, param)

static int
read_transfers_opt(json_val_t opt, void *data)
{
    int err;
    int i;
    struct replicate_ctx *ctx = data;

    static const struct json_scan_spec spec[] = {
        {L"src", JSON_TYPE_STRING, 1, 0, 1, NULL, NULL, NULL,
         TRANSFER_PARAM(srcpath)},
        {L"srcmntopts", JSON_TYPE_STRING, 0, 0, 1, NULL, NULL, NULL,
         TRANSFER_PARAM(srcmntopts)},
        {L"dest", JSON_TYPE_STRING, 1, 0, 1, NULL, NULL, NULL,
         TRANSFER_PARAM(dstpath)},
        {L"dstpath", JSON_TYPE_STRING, 1, 0, 1, NULL, NULL, NULL,
         TRANSFER_PARAM(dstmntpath)},
        {L"format_cmd", JSON_TYPE_STRING, 1, 0, 1, &format_cmd_filter, NULL,
         NULL, TRANSFER_PARAM(format_cmd)},
        {L"force_write", JSON_TYPE_BOOLEAN, 0, 0, 1, NULL, NULL, NULL,
         TRANSFER_PARAM(force_write)},
        {L"hook", JSON_TYPE_STRING, 0, 0, 1, NULL, NULL, NULL,
         TRANSFER_PARAM(hook)},
        {L"setro", JSON_TYPE_BOOLEAN, 0, 0, 1, NULL, NULL, NULL,
         TRANSFER_PARAM(setro)}
    };

    ctx->num_transfers = json_val_array_get_num_elem(opt);

    if (oecalloc(&ctx->transfers, ctx->num_transfers) == NULL)
        return ERR_TAG(errno);

    for (i = 0; i < ctx->num_transfers; i++) {
        json_val_t val;
        struct transfer *transfer = &ctx->transfers[i];

        val = json_val_array_get_elem(opt, i);
        if (val == NULL) {
            err = ERR_TAG(EIO);
            goto err;
        }

        transfer->force_write = 1;
        transfer->setro = 0;
        err = json_oscanf(transfer, spec, (int)ARRAY_SIZE(spec), 0, val);
        if (err) {
            err = ERR_TAG(-err);
            goto err;
        }
    }

    return 0;

err:
    free_transfers(ctx->transfers, i);
    return err;
}

#undef TRANSFER_PARAM

static int
read_json_config(json_val_t config, struct replicate_ctx *ctx)
{
    int err;
    int i, numopt;

    static const struct ent {
        const wchar_t   *opt;
        int             (*fn)(json_val_t, void *);
    } opts[16] = {
        [2] = {L"copy_creds",   &read_copy_creds_opt},
        [7] = {L"debug",        &read_debug_opt},
        [0] = {L"keep_cache",   &read_keep_cache_opt},
        [6] = {L"log",          &read_log_opt},
        [1] = {L"transfers",    &read_transfers_opt}
    };

    numopt = json_val_object_get_num_elem(config);
    for (i = 0; i < numopt; i++) {
        const struct ent *opt;
        json_object_elem_t elem;

        err = json_val_object_get_elem_by_idx(config, i, &elem);
        if (err)
            return ERR_TAG(-err);

        opt = &opts[hash_wcs(elem.key, -1) >> 6 & 7];
        if (opt->opt == NULL || wcscmp(elem.key, opt->opt) != 0)
            return ERR_TAG(EIO);

        err = (*opt->fn)(elem.value, ctx);
        if (err)
            return err;
    }

    return 0;
}

static int
parse_json_config(const char *path, const struct json_parser *parser,
                  json_val_t *config)
{
    FILE *f;
    int err;
    int fd;
    struct json_read_cb_ctx ctx;
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

    json_read_cb_ctx_init(&ctx);
    ctx.read_cb = &read_cb;
    ctx.ctx = f;

    err = -json_grammar_validate(NULL, &json_read_cb_strip_comments, &ctx,
                                 parser, config);

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

int
parse_config(const char *path, struct replicate_ctx *ctx)
{
    int err;
    json_val_t config;
    struct json_parser *parser;

    err = json_parser_init(CONFIG_GRAM, CONFIG_ROOT_ID, &parser);
    if (err)
        return ERR_TAG(-err);

    err = parse_json_config(path, parser, &config);
    json_parser_destroy(parser);
    if (err)
        return err;

    err = read_json_config(config, ctx);

    json_val_free(config);

    return err;
}

/* vi: set expandtab sw=4 ts=4: */
