/*
 * verify_common.h
 */

#ifndef _VERIFY_COMMON_H
#define _VERIFY_COMMON_H

#include "verify_plugin.h"

#include <dbus/dbus.h>

#include <openssl/evp.h>

#include <dynamic_array.h>
#include <radix_tree.h>

#include <regex.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#define CHECK_CMD_SRC_SPECIFIER "$dev"

extern int debug;
extern int log_verifs;
extern int tracing;

extern uid_t ruid;
extern gid_t rgid;

struct verif {
    const char  *devpath;
    char        *srcpath;
    const char  *srcmntopts;
    const char  *check_cmd;
};

struct verify_ctx {
    struct verif        *verifs;
    int                 num_verifs;
    DBusConnection      *busconn;
    char                *base_dir;
    regex_t             *reg_excl;
    int                 detect_hard_links;
    char                *input_file;
    int                 allow_new;
    struct radix_tree   *input_data;
    char                *output_file;
    uid_t               uid;
    gid_t               gid;
    struct plugin_list  *plist;
};

struct verif_record {
    off_t           size;
    unsigned char   initsum[EVP_MAX_MD_SIZE];
    unsigned char   sum[EVP_MAX_MD_SIZE];
};

struct plugin {
    char                            *path;
    void                            *hdl;
    void                            *phdl;
    const struct verify_plugin_fns  *fns;
};

struct plugin_list {
    struct dynamic_array *list;
};

#define TRACE(err, ...) trace(__FILE__, __func__, __LINE__, err, __VA_ARGS__)

#define DEBUG_PUTS(str) \
    do { \
        if (debug) \
            fputs(str "\n", stderr); \
    } while (0)

#define _DEBUG_EOL() fputc('\n', stderr)

#define _DEBUG_PRINT(print_suffix, fmt, ...) \
    do { \
        if (debug) { \
            fprintf(stderr, fmt, __VA_ARGS__); \
            print_suffix; \
        } \
    } while (0)

#define DEBUG_PRINT(...) \
    _DEBUG_PRINT(_DEBUG_EOL(), __VA_ARGS__)
#define DEBUG_PRINT_NO_NL(...) \
    _DEBUG_PRINT(, __VA_ARGS__)

#define LOG_PRINT(priority, fmt, ...) \
    do { \
        if (log_verifs) \
            syslog(priority, fmt, __VA_ARGS__); \
    } while (0)

void trace(const char *file, const char *func, int line, int err,
           const char *fmt, ...);

int do_verifs(struct verify_ctx *ctx);
void print_verifs(FILE *f, struct verif *verifs, int num);
void free_verifs(struct verif *verifs, int num);

#endif

/* vi: set expandtab sw=4 ts=4: */
