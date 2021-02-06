/*
 * common.h
 */

#ifndef _COMMON_H
#define _COMMON_H

#include "config.h"

/* for eliminating false negatives from static analysis tools */
#ifdef ASSERT_MACROS
#include <assert.h>
#include <errno.h>

static __thread int asserttmp;

#define ERRNO (asserttmp = errno, assert(asserttmp > 0), asserttmp)
#define MINUS_ERRNO (asserttmp = -errno, assert(asserttmp < 0), asserttmp)
#endif

#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#if defined(HAVE_ERROR)
#include <error.h>
#elif defined(HAVE_ERRC) && defined(HAVE_WARNC)
#include <err.h>
#define error(eval, code, format, ...) \
    do { \
        if ((eval) == 0) \
            warnc(code, format, ##__VA_ARGS__); \
        else \
            errc(eval, code, format, ##__VA_ARGS__); \
    } while (0)
#else
#include <stdio.h>
#include <stdlib.h>
#define error(eval, code, format, ...) \
    do { \
        fprintf(stderr, format ": error code %d\n", ##__VA_ARGS__, code); \
        if (eval != 0) \
            exit(eval); \
    } while (0)
#endif

/* vi: set expandtab sw=4 ts=4: */
