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

extern uid_t ruid;
extern gid_t rgid;

struct verif {
    const char *devpath;
    const char *srcpath;
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

void debug_print(const char *fmt, ...);
void log_print(int priority, const char *fmt, ...);

int do_verifs(struct verify_ctx *ctx);
void print_verifs(FILE *f, struct verif *verifs, int num);
void free_verifs(struct verif *verifs, int num);

#endif

/* vi: set expandtab sw=4 ts=4: */
