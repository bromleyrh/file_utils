/*
 * verify_common.h
 */

#ifndef _VERIFY_COMMON_H
#define _VERIFY_COMMON_H

#include <dbus/dbus.h>

#include <openssl/evp.h>

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
    const char *devpath;
    const char *srcpath;
    const char *srcmntopts;
    const char *check_cmd;
};

struct verify_ctx {
    struct verif        *verifs;
    int                 num_verifs;
    DBusConnection      *busconn;
    const char          *base_dir;
    regex_t             *reg_excl;
    int                 detect_hard_links;
    const char          *input_file;
    int                 allow_new;
    struct radix_tree   *input_data;
    const char          *output_file;
    uid_t               uid;
    gid_t               gid;
};

struct verif_record {
    off_t           size;
    unsigned char   initsum[EVP_MAX_MD_SIZE];
    unsigned char   sum[EVP_MAX_MD_SIZE];
};

#define TRACE(err, fmt, ...) \
    trace(__FILE__, __FUNCTION__, __LINE__, err, fmt, ##__VA_ARGS__)

#define DEBUG_PRINT(fmt, ...) \
    debug_print(1, fmt, ##__VA_ARGS__)
#define DEBUG_PRINT_NO_NL(fmt, ...) \
    debug_print(0, fmt, ##__VA_ARGS__)

void trace(const char *file, const char *func, int line, int err,
           const char *fmt, ...);
void debug_print(int nl, const char *fmt, ...);
void log_print(int priority, const char *fmt, ...);

int do_verifs(struct verify_ctx *ctx);
void print_verifs(FILE *f, struct verif *verifs, int num);
void free_verifs(struct verif *verifs, int num);

#endif

/* vi: set expandtab sw=4 ts=4: */
