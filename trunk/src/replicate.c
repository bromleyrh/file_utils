/*
 * replicate.c
 */

#include "replicate.h"

#include <json.h>

#include <json/grammar.h>
#include <json/grammar_parse.h>

#include <hashes.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define CONFIG_PATH "replicate.conf"
#define CONFIG_ROOT_ID "conf"

#define FORMAT_CMD_DEST_SPECIFIER "$dest"

struct ctx {
    struct transfer *transfers;
    int             num_transfers;
};

struct transfer {
    const char *srcpath;
    const char *dstpath;
    const char *format_cmd;
};

static int debug;

static int get_string_value(const wchar_t *, const char **);

static int format_device(struct transfer *);

static int do_transfers(struct transfer *, int);
static void print_transfers(FILE *, struct transfer *, int);
static void free_transfers(struct transfer *, int);

static int parse_json_config(const char *, const struct json_parser *,
                             json_val_t *);

static int read_debug_opt(json_val_t, void *);
static int read_transfers_opt(json_val_t, void *);
static int read_json_config(json_val_t, struct ctx *);

static int parse_config(const char *, struct ctx *);

static int
get_string_value(const wchar_t *wcs, const char **str)
{
    char *buf, *tmp;
    mbstate_t mbs;
    size_t bufsize = 128, len = 0, tmplen;

    memset(&mbs, 0, sizeof(mbs));

    buf = malloc(bufsize);
    if (buf == NULL)
        return -errno;

    for (;;) {
        tmplen = wcsrtombs(buf + len, &wcs, bufsize - len, &mbs);
        if (tmplen == (size_t)-1)
            goto err;
        len += tmplen;
        if (wcs == NULL)
            break;

        bufsize *= 2;
        tmp = realloc(buf, bufsize);
        if (tmp == NULL)
            goto err;
        buf = tmp;
    }

    tmp = realloc(buf, len + 1);
    if (tmp == NULL)
        goto err;

    *str = tmp;
    return 0;

err:
    free(buf);
    return -errno;
}

static int
run_cmd(const char *cmd)
{
    return 0;
}

static int
format_device(struct transfer *transfer)
{
    (void)transfer;

    return 0;
}

static int
do_transfers(struct transfer *transfers, int num)
{
    int i;

    for (i = 0; i < num; i++) {
        struct transfer *transfer = &transfers[i];
    }

    return 0;
}

static void
print_transfers(FILE *f, struct transfer *transfers, int num)
{
    int i;

    for (i = 0; i < num; i++) {
        struct transfer *transfer = &transfers[i];

        fprintf(f,
                "Transfer %d:\n"
                "\tSource directory path: %s\n"
                "\tDestination device path: %s\n"
                "\tDestination formatting command: \"%s\"\n",
                i + 1,
                transfer->srcpath,
                transfer->dstpath,
                transfer->format_cmd);
    }
}

static void
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

    err = json_grammar_validate(conf, parser, config);

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
read_debug_opt(json_val_t opt, void *data)
{
    (void)data;

    debug = json_val_boolean_get(opt);

    return 0;
}

static int
read_transfers_opt(json_val_t opt, void *data)
{
    int err;
    int i;
    struct ctx *ctx = (struct ctx *)data;
    struct transfer *transfer;

    ctx->num_transfers = json_val_array_get_num_elem(opt);

    ctx->transfers = calloc(ctx->num_transfers, sizeof(*(ctx->transfers)));
    if (ctx->transfers == NULL)
        return -errno;

    for (i = 0; i < ctx->num_transfers; i++) {
        char *tmp;
        json_object_elem_t elem;
        json_val_t val;

        val = json_val_array_get_elem(opt, i);
        if (val == NULL) {
            err = -EIO;
            goto err1;
        }

        transfer = &ctx->transfers[i];

        err = json_val_object_get_elem_by_key(val, L"src", &elem);
        if (err)
            goto err1;
        err = get_string_value(json_val_string_get(elem.value),
                               &transfer->srcpath);
        if (err)
            goto err1;

        err = json_val_object_get_elem_by_key(val, L"dest", &elem);
        if (err)
            goto err2;
        err = get_string_value(json_val_string_get(elem.value),
                               &transfer->dstpath);
        if (err)
            goto err2;

        err = json_val_object_get_elem_by_key(val, L"format_cmd", &elem);
        if (err)
            goto err3;
        err = get_string_value(json_val_string_get(elem.value),
                               &transfer->format_cmd);
        if (err)
            goto err3;
        tmp = strstr(transfer->format_cmd, FORMAT_CMD_DEST_SPECIFIER);
        if (tmp == NULL) {
            error(0, 0, "\"format_cmd\" option missing \""
                  FORMAT_CMD_DEST_SPECIFIER "\"");
            err = -EINVAL;
            goto err3;
        }
        tmp = strstr(tmp + sizeof(FORMAT_CMD_DEST_SPECIFIER) - 1,
                     FORMAT_CMD_DEST_SPECIFIER);
        if (tmp != NULL) {
            error(0, 0, "\"format_cmd\" option must contain only one instance "
                  "of \"" FORMAT_CMD_DEST_SPECIFIER "\"");
            err = -EINVAL;
            goto err3;
        }
    }

    return 0;

err3:
    free((void *)(transfer->dstpath));
err2:
    free((void *)(transfer->srcpath));
err1:
    free_transfers(ctx->transfers, i);
    return err;
}

static int
read_json_config(json_val_t config, struct ctx *ctx)
{
    int err;
    int i, numopt;

    static const struct {
        const wchar_t   *opt;
        int             (*fn)(json_val_t, void *);
    } opts[2] = {
        [0] = {L"debug", &read_debug_opt},
        [1] = {L"transfers", &read_transfers_opt}
    }, *opt;

    numopt = json_val_object_get_num_elem(config);
    for (i = 0; i < numopt; i++) {
        json_object_elem_t elem;

        err = json_val_object_get_elem_by_idx(config, i, &elem);
        if (err)
            return err;

        opt = &opts[(hash_str(elem.key, -1) >> 4) & 1];
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

int
main(int argc, char **argv)
{
    int ret;
    struct ctx ctx;

    (void)argc;
    (void)argv;

    ret = parse_config(CONFIG_PATH, &ctx);
    if (ret != 0)
        return EXIT_FAILURE;
    print_transfers(stdout, ctx.transfers, ctx.num_transfers);

    ret = do_transfers(ctx.transfers, ctx.num_transfers);

    free_transfers(ctx.transfers, ctx.num_transfers);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
