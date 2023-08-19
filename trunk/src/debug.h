/*
 * debug.h
 */

#ifndef _DEBUG_H
#define _DEBUG_H

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct err_info_bt {
    int         errdes;
    const char  *file;
    int         line;
    char        **bt;
    int         len;
};

#define ERRDES_MIN 128

#define ERR_TAG(errn) err_tag_bt(-(errn))

#define err_tag_bt(errcode) _err_tag_bt(errcode, __FILE__, __LINE__)

int err_tag(int errcode, void *data);

void *err_get(int errdes, int *errcode);

int err_get_code(int errdes);

int err_clear(int errdes);

int err_foreach(int (*cb)(int, void *, void *), void *ctx);

int _err_tag_bt(int errcode, const char *file, int line);

struct err_info_bt *err_get_bt(int *err);

int err_info_free(struct err_info_bt *info, int freeall);

int err_print(FILE *f, int *err);

#endif

/* vi: set expandtab sw=4 ts=4: */
