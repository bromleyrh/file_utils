/*
 * replicate_common.h
 */

#ifndef _REPLICATE_COMMON_H
#define _REPLICATE_COMMON_H

#include <dbus/dbus.h>

#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

#define FORMAT_CMD_DEST_SPECIFIER "$dest"

struct transfer {
    char        *srcpath;
    const char  *srcmntopts;
    char        *dstpath;
    const char  *dstmntpath;
    char        *format_cmd;
    const char  *hook;
    int         force_write;
    int         setro;
};

struct replicate_ctx {
    struct transfer *transfers;
    int             num_transfers;
    DBusConnection  *busconn;
    int             keep_cache;
    uid_t           uid;
    gid_t           gid;
};

extern int debug;
extern int log_transfers;
extern int tracing;

extern uid_t ruid;
extern gid_t rgid;

#define TRACE(err, ...) trace(__FILE__, __func__, __LINE__, err, __VA_ARGS__)

#define DEBUG_PUTS(str) \
    do { \
        if (debug) \
            fputs(str "\n", stderr); \
    } while (0)

#define DEBUG_PRINT(fmt, ...) \
    do { \
        if (debug) { \
            fprintf(stderr, fmt, __VA_ARGS__); \
            fputc('\n', stderr); \
        } \
    } while (0)

#define LOG_PRINT(priority, fmt, ...) \
    do { \
        if (log_transfers) \
            syslog(priority, fmt, __VA_ARGS__); \
    } while (0)

void trace(const char *file, const char *func, int line, int err,
           const char *fmt, ...);

int do_transfers(struct replicate_ctx *ctx, int sessid);
void print_transfers(FILE *, struct transfer *transfers, int num);
void free_transfers(struct transfer *transfers, int num);

#endif

/* vi: set expandtab sw=4 ts=4: */
