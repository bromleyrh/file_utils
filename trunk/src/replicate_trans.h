/*
 * replicate_trans.h
 */

#ifndef _REPLICATE_TRANS_H
#define _REPLICATE_TRANS_H

#include <unistd.h>

struct copy_args {
    int     srcfd;
    int     dstfd;
    int     keep_cache;
    uid_t   uid;
    gid_t   gid;
};

int do_copy(struct copy_args *copy_args);

#endif

/* vi: set expandtab sw=4 ts=4: */
