/*
 * replicate_common.h
 */

#ifndef _REPLICATE_COMMON_H
#define _REPLICATE_COMMON_H

#include <dbus/dbus.h>

#include <stdio.h>
#include <unistd.h>

#define FORMAT_CMD_DEST_SPECIFIER "$dest"

struct transfer {
    const char  *srcpath;
    const char  *srcmntopts;
    const char  *dstpath;
    const char  *dstmntpath;
    const char  *format_cmd;
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

#define TRACE(err, ...) \
    trace(__FILE__, __FUNCTION__, __LINE__, err, __VA_ARGS__)

void trace(const char *file, const char *func, int line, int err,
           const char *fmt, ...);
void debug_print(const char *fmt, ...);
void log_print(int priority, const char *fmt, ...);

int do_transfers(struct replicate_ctx *ctx, int sessid);
void print_transfers(FILE *, struct transfer *transfers, int num);
void free_transfers(struct transfer *transfers, int num);

#endif

/* vi: set expandtab sw=4 ts=4: */
