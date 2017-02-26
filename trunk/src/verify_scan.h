/*
 * verify_scan.h
 */

#ifndef _VERIFY_SCAN_H
#define _VERIFY_SCAN_H

#include <dbus/dbus.h>

#include <radix_tree.h>

#include <regex.h>
#include <stdio.h>
#include <unistd.h>

struct verif_args {
    int                 srcfd;
    FILE                *dstf;
    regex_t             *reg_excl;
    int                 detect_hard_links;
    struct radix_tree   *input_data;
    int                 allow_new;
    DBusConnection      *busconn;
    const char          *prefix;
    uid_t               uid;
    gid_t               gid;
};

int do_verif(struct verif_args *verif_args);

#endif

/* vi: set expandtab sw=4 ts=4: */
