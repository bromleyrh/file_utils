/*
 * replicate_trans.h
 */

#ifndef _REPLICATE_TRANS_H
#define _REPLICATE_TRANS_H

#include <dbus/dbus.h>

#include <unistd.h>

#include <sys/types.h>

struct copy_args {
    int             srcfd;
    int             dstfd;
    int             keep_cache;
    DBusConnection  *busconn;
    uid_t           uid;
    gid_t           gid;
    const char      *hookbin;
    int             hookfd;
    mode_t          hookumask;
};

int do_copy(struct copy_args *copy_args);

#endif

/* vi: set expandtab sw=4 ts=4: */
