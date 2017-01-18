/*
 * verify_conf.c
 */

#include "verify_common.h"
#include "verify_conf.h"
#include "verify_gram.h"

#include <backup.h>

#include <json.h>

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

static int read_base_dir_opt(json_val_t, void *);
static int read_creds_opt(json_val_t, void *);
static int read_debug_opt(json_val_t, void *);
static int read_detect_hard_links_opt(json_val_t, void *);
static int read_exclude_opt(json_val_t, void *);
static int read_input_file_opt(json_val_t, void *);
static int read_output_file_opt(json_val_t, void *);
static int read_verifs_opt(json_val_t, void *);

static int parse_json_config(const char *, const struct json_parser *,
                             json_val_t *);
static int read_json_config(json_val_t, struct parse_ctx *);

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
read_base_dir_opt(json_val_t opt, void *data)
{
    mbstate_t s;
    struct verify_ctx *ctx = (struct verify_ctx *)data;

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
    struct verify_ctx *ctx = (struct verify_ctx *)data;

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
read_detect_hard_links_opt(json_val_t opt, void *data)
{
    struct parse_ctx *pctx = (struct parse_ctx *)data;

    pctx->ctx.detect_hard_links = json_val_boolean_get(opt);

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
    struct verify_ctx *ctx = (struct verify_ctx *)data;

    memset(&s, 0, sizeof(s));
    return (awcstombs((char **)&ctx->input_file, json_val_string_get(opt), &s)
            == (size_t)-1) ? -errno : 0;
}

static int
read_output_file_opt(json_val_t opt, void *data)
{
    mbstate_t s;
    struct verify_ctx *ctx = (struct verify_ctx *)data;

    memset(&s, 0, sizeof(s));
    return (awcstombs((char **)&ctx->output_file, json_val_string_get(opt), &s)
            == (size_t)-1) ? -errno : 0;
}

static int
read_log_opt(json_val_t opt, void *data)
{
    (void)data;

    log_verifs = json_val_boolean_get(opt);

    return 0;
}

#define VERIF_PARAM(param) offsetof(struct verif, param)

static int
read_verifs_opt(json_val_t opt, void *data)
{
    int err;
    int i;
    struct verify_ctx *ctx = (struct verify_ctx *)data;

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
read_json_config(json_val_t config, struct parse_ctx *ctx)
{
    int err;
    int i, numopt;

    static const struct {
        const wchar_t   *opt;
        int             (*fn)(json_val_t, void *);
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
    }, *opt;

    numopt = json_val_object_get_num_elem(config);
    for (i = 0; i < numopt; i++) {
        json_object_elem_t elem;

        err = json_val_object_get_elem_by_idx(config, i, &elem);
        if (err)
            return err;

        opt = &opts[(hash_wcs(elem.key, -1) >> 3) & 63];
        if ((opt->opt == NULL) || (wcscmp(elem.key, opt->opt) != 0))
            return -EIO;

        err = (*(opt->fn))(elem.value, ctx);
        if (err)
            return err;
    }

    return 0;
}

int
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

/* vi: set expandtab sw=4 ts=4: */
