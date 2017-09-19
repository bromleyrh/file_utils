/*
 * project_db.c
 */

#include "project_db_common.h"
#include "project_db_schema_gram.h"

#include <gdbm.h>

#include <json.h>

#include <json/filters.h>
#include <json/grammar.h>
#include <json/grammar_parse.h>

#include <shell.h>

#include <forensics.h>
#include <hashes.h>
#include <option_parsing.h>
#include <strings_ext.h>

#include <errno.h>
#include <error.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DEFAULT_DB_FILE "project_db.gdbm"

#define DEFAULT_SCHEMA_FILE "project_db_schema.json"

struct data_member {
    size_t      off;
    const char  *name;
};

struct data_definition {
    struct data_member  *members;
    int                 n;
    size_t              tot_size;
};

struct cmd_ctx {
    struct cmdhelp  cmdhelp;
    int             semid;
};

static int debug;

static void debug_print(const char *, ...);

static int enable_debugging_features(void);

static void print_usage(const char *);

static int parse_cmdline(int, char **, char **, const char **);

static size_t read_cb(char *, size_t, size_t, void *);

static int get_string_value(json_val_t, const wchar_t *, const wchar_t **);
static size_t get_member_size(const wchar_t *);

static int get_data_def(json_val_t, const wchar_t *, struct data_definition *);
static void print_data_def(struct data_definition *);
static void free_data_def(struct data_definition *);

static int get_data_defs(json_val_t, struct data_definition *,
                         struct data_definition *);

static int do_parse_schema(const char *, struct data_definition *,
                           struct data_definition *);

static int parse_schema(const char *, struct data_definition *,
                        struct data_definition *);

static int open_db(GDBM_FILE *, char *);
static void close_db(GDBM_FILE);

static int do_shell_loop(GDBM_FILE, struct data_definition *,
                         struct data_definition *);

static void
debug_print(const char *fmt, ...)
{
    if (debug) {
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
}

static int
enable_debugging_features()
{
    struct sigaction sa;

    static const struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY
    };

    if (setrlimit(RLIMIT_CORE, &rlim) == -1)
        return -errno;

    sa.sa_handler = NULL;
    sa.sa_flags = SA_SIGINFO;

    sa.sa_sigaction = sigaction_segv_diag;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        return -errno;

    sa.sa_sigaction = sigaction_bus_diag;
    return (sigaction(SIGBUS, &sa, NULL) == -1) ? -errno : 0;
}

static void
print_usage(const char *progusage)
{
    printf("Usage: %s [options]\n"
           "\n"
           "    -f FILE_NAME Use given database file\n"
           "    -h           Output help\n"
           "    -s FILE_NAME Use given schema file\n",
           progusage);
}

static int
parse_cmdline(int argc, char **argv, char **dbfile, const char **schema_file)
{
    GET_OPTIONS(argc, argv, "f:hs:") {
    case 'f':
        *dbfile = optarg;
        break;
    case 'h':
        print_usage(argv[0]);
        return -2;
    case 's':
        *schema_file = optarg;
        break;
    default:
        return -1;
    } END_GET_OPTIONS;

    return 0;
}

static size_t
read_cb(char *buf, size_t off, size_t len, void *ctx)
{
    FILE *f = (FILE *)ctx;
    size_t ret;

    (void)off;

    ret = fread(buf, 1, len, f);
    return ((ret == 0) && !feof(f)) ? (size_t)-1 : ret;
}

static int
get_string_value(json_val_t member, const wchar_t *key, const wchar_t **str)
{
    const wchar_t *ret;
    int err;
    json_object_elem_t member_field;

    err = json_val_object_get_elem_by_key(member, key, &member_field);
    if (err)
        return err;

    ret = json_val_string_get(member_field.value);

    json_val_free(member_field.value);

    if (str == NULL)
        return -ENOMEM;

    *str = ret;
    return 0;
}

static size_t
get_member_size(const wchar_t *type)
{
    static const size_t sizes[8] = {
        [4] = sizeof(char),
        [2] = sizeof(int),
        [5] = sizeof(unsigned),
        [1] = sizeof(double),
        [7] = (size_t)-1 /* stringz */
    };

    return sizes[hash_wcs(type, (size_t)-1) & 7];
}

static int
get_data_def(json_val_t jval, const wchar_t *key, struct data_definition *def)
{
    int err;
    int i, num;
    json_object_elem_t members;
    json_val_t member;
    size_t off;

    debug_print("\"%ls\" data definition:\n", key);

    err = json_val_object_get_elem_by_key(jval, key, &members);
    if (err)
        return err;

    num = json_val_array_get_num_elem(members.value);

    def->members = malloc(num * sizeof(*(def->members)));
    if (def->members == NULL)
        goto err1;
    def->n = num;

    off = 0;
    for (i = 0; i < num; i++) {
        const wchar_t *str;
        mbstate_t s;
        size_t tmp;

        debug_print("Definition member %d\n", i);

        member = json_val_array_get_elem(members.value, i);

        err = get_string_value(member, L"type", &str);
        if (err)
            goto err2;
        debug_print("Type: %ls\n", str);
        tmp = get_member_size(str);
        free((void *)str);

        def->members[i].off = off;
        off += tmp;

        err = get_string_value(member, L"name", &str);
        if (err)
            goto err2;
        debug_print("Name: %ls\n", str);
        memset(&s, 0, sizeof(s));
        tmp = awcstombs((char **)&def->members[i].name, str, &s);
        free((void *)str);
        if (tmp == (size_t)-1)
            goto err2;

        json_val_free(member);
    }

    json_val_free(members.value);

    def->tot_size = off;

    return 0;

err2:
    json_val_free(member);
    free(def->members);
err1:
    json_val_free(members.value);
    return err;
}

static void
print_data_def(struct data_definition *def)
{
    int i;

    fprintf(stderr, "Total size: %zd\n", def->tot_size);

    for (i = 0; i < def->n; i++) {
        struct data_member *member = &def->members[i];

        fprintf(stderr, "\"%s\": offset %zd\n", member->name, member->off);
    }
}

static void
free_data_def(struct data_definition *def)
{
    int i;

    for (i = 0; i < def->n; i++)
        free((void *)(def->members[i].name));

    free(def->members);
}

static int
get_data_defs(json_val_t jval, struct data_definition *key_def,
              struct data_definition *value_def)
{
    int err;

    err = get_data_def(jval, L"key", key_def);
    if (err)
        return err;

    return get_data_def(jval, L"value", value_def);
}

static int
do_parse_schema(const char *schema_file, struct data_definition *key_def,
                struct data_definition *value_def)
{
    FILE *f;
    int err;
    json_val_t jval;
    struct json_parser *parser;
    struct json_read_cb_ctx ctx;

    err = json_parser_init(SCHEMA_GRAM, "document", &parser);
    if (err)
        return err;

    f = fopen(schema_file, "r");
    if (f == NULL) {
        error(0, errno, "Error opening %s", schema_file);
        goto end1;
    }

    json_read_cb_ctx_init(&ctx);
    ctx.read_cb = &read_cb;
    ctx.ctx = f;

    err = json_grammar_validate(NULL, &json_read_cb_strip_comments, &ctx,
                                parser, &jval);
    if (err) {
        error(0, -err, "Error parsing schema file %s", schema_file);
        goto end2;
    }

    err = get_data_defs(jval, key_def, value_def);

    json_val_free(jval);

end2:
    fclose(f);
end1:
    json_parser_destroy(parser);
    return err;
}

static int
parse_schema(const char *schema_file, struct data_definition *key_def,
             struct data_definition *value_def)
{
    int err;

    err = json_init();
    if (err)
        return err;
    if (atexit(&json_end) != 0) {
        json_end();
        return -EIO;
    }

    return do_parse_schema(schema_file, key_def, value_def);
}

static int
open_db(GDBM_FILE *dbf, char *dbfile)
{
    GDBM_FILE ret;

    ret = gdbm_open(dbfile, 4096, GDBM_WRCREAT, S_IRUSR | S_IWUSR, NULL);
    if (ret == NULL)
        return -((gdbm_errno == 0) ? errno : gdbm_errno);

    *dbf = ret;
    return 0;
}

static void
close_db(GDBM_FILE dbf)
{
    gdbm_close(dbf);
}

static int
do_shell_loop(GDBM_FILE dbf, struct data_definition *key_def,
              struct data_definition *value_def)
{
    int ret;
    struct cmd_ctx cmdctx;
    void *hdl;

    static const struct cmd cmds[] = {
        {.name = "help", .fn = FN_HELP},
        {.name = "quit", .fn = FN_QUIT}
    };

    (void)dbf;
    (void)key_def;
    (void)value_def;

    ret = shell_init(NULL, -1, &hdl);
    if (ret != 0)
        return ret;

    ret = shell_loop(hdl, "project_db command", cmds,
                     (int)(sizeof(cmds)/sizeof(cmds[0])), NULL, NULL, NULL,
                     &cmdctx);

    shell_end(hdl);

    return ret;
}

int
main(int argc, char **argv)
{
    char *dbfile = DEFAULT_DB_FILE;
    const char *schema_file = DEFAULT_SCHEMA_FILE;
    GDBM_FILE dbf = NULL;
    int ret;
    struct data_definition key_def, value_def;

    ret = enable_debugging_features();
    if (ret != 0)
        return EXIT_FAILURE;

    ret = parse_cmdline(argc, argv, &dbfile, &schema_file);
    if (ret != 0)
        return (ret == -1) ? EXIT_FAILURE : EXIT_SUCCESS;

    ret = parse_schema(schema_file, &key_def, &value_def);
    if (ret != 0) {
        error(0, -ret, "Error initializing");
        goto end1;
    }

    fputs("Key data definition:\n", stderr);
    print_data_def(&key_def);
    fputs("Value data definition:\n", stderr);
    print_data_def(&value_def);

    fprintf(stderr, "Database file: %s\n", dbfile);

    ret = open_db(&dbf, dbfile);
    if (ret != 0) {
        error(0, -ret, "Error opening %s", dbfile);
        goto end2;
    }

    ret = do_shell_loop(dbf, &key_def, &value_def);

    close_db(dbf);

end2:
    free_data_def(&key_def);
    free_data_def(&value_def);
end1:
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
