/*
 * common.h
 */

#ifndef _COMMON_H
#define _COMMON_H

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

/* vi: set expandtab sw=4 ts=4: */
