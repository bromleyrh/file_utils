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
#include <unistd.h>
#include <wchar.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define CONFIG_PATH "replicate.conf"
#define CONFIG_ROOT_ID "conf"

static int debug;

static int parse_json_config(const char *, const struct json_parser *,
                             json_val_t *);

static int read_debug_opt(json_val_t);
static int read_transfers_opt(json_val_t);
static int read_json_config(json_val_t);

static int parse_config(const char *);

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
read_debug_opt(json_val_t opt)
{
    debug = json_val_boolean_get(opt);
    return 0;
}

static int
read_transfers_opt(json_val_t opt)
{
    int err;
    int i, numtransfers;

    numtransfers = json_val_array_get_num_elem(opt);
    for (i = 0; i < numtransfers; i++) {
        json_object_elem_t elem;
        json_val_t transfer;

        printf("Transfer %d:\n", i);

        transfer = json_val_array_get_elem(opt, i);
        if (transfer == NULL)
            return -EIO;

        err = json_val_object_get_elem_by_key(transfer, L"src", &elem);
        if (err)
            return err;
        printf("src: %ls\n", json_val_string_get(elem.value));

        err = json_val_object_get_elem_by_key(transfer, L"dest", &elem);
        if (err)
            return err;
        printf("dest: %ls\n", json_val_string_get(elem.value));

        err = json_val_object_get_elem_by_key(transfer, L"format_cmd", &elem);
        if (err)
            return err;
        printf("format_cmd: %ls\n", json_val_string_get(elem.value));
    }

    return 0;
}

static int
read_json_config(json_val_t config)
{
    int err;
    int i, numopt;

    static const struct {
        const wchar_t   *opt;
        int             (*fn)(json_val_t);
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

        err = (*(opt->fn))(elem.value);
        if (err)
            return err;
    }

    return 0;
}

static int
parse_config(const char *path)
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

    err = read_json_config(config);

    json_val_free(config);

    return err;
}

int
main(int argc, char **argv)
{
    int ret;

    (void)argc;
    (void)argv;

    ret = parse_config(CONFIG_PATH);
    if (ret != 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
