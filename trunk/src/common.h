/*
 * common.h
 */

#ifndef _COMMON_H
#define _COMMON_H

#include "config.h"

#include <stdio.h>

/* for eliminating false negatives from static analysis tools */
#ifdef ASSERT_MACROS
#include <assert.h>
#include <errno.h>

static _Thread_local int asserttmp;

#define ERRNO (asserttmp = errno, assert(asserttmp > 0), asserttmp)
#define MINUS_ERRNO (asserttmp = -errno, assert(asserttmp < 0), asserttmp)
#endif

#endif

#define _STR(x) #x
#define STR(x) _STR(x)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define PL(val) PL_SUF(val, "", "s")
#define PL_SUF(val, s, p) val, (val) == 1 ? (s) : (p)

#define stderrchr(c) fputc(c, stderr)
#define stderrmsg(msg) fputs(msg, stderr)
#define stderrmsgf(...) fprintf(stderr, __VA_ARGS__)

#define infochr stderrchr
#define infomsg stderrmsg
#define infomsgf stderrmsgf

#define errmsg stderrmsg
#define errmsgf stderrmsgf

#if defined(HAVE_ERROR)
#include <error.h>
#elif defined(HAVE_ERRC) && defined(HAVE_WARNC)
#include <err.h>
#define error(eval, code, ...) \
    do { \
        if ((eval) == 0) \
            warnc(code, __VA_ARGS__); \
        else \
            errc(eval, code, __VA_ARGS__); \
    } while (0)
#else
#include <stdlib.h>
#define error(eval, code, ...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, ": error code %d\n", code); \
        if (eval != 0) \
            exit(eval); \
    } while (0)
#endif

/* vi: set expandtab sw=4 ts=4: */
