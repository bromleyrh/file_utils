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
    const char  *dstpath;
    const char  *dstmntpath;
    const char  *format_cmd;
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

extern uid_t ruid;
extern gid_t rgid;

void debug_print(const char *fmt, ...);
void log_print(int priority, const char *fmt, ...);

int do_transfers(struct replicate_ctx *ctx);
void print_transfers(FILE *, struct transfer *transfers, int num);
void free_transfers(struct transfer *transfers, int num);

#endif

/* vi: set expandtab sw=4 ts=4: */
