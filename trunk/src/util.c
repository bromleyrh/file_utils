/*
 * util.c
 */

#include "config.h"

#define ASSERT_MACROS
#include "common.h"
#undef ASSERT_MACROS

#include <malloc_ext.h>

#include <errno.h>
#include <locale.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <strings_ext.h>

#define ASSURE_ERRNO_SET(ret, expr) \
    do { \
        errno = 0; \
        (ret) = (expr); \
        if ((ret) == NULL && errno == 0) \
            errno = ENOMEM; \
    } while (0)

static int get_locale(locale_t *);

static int strerror_lr(int, char *, size_t, locale_t);

static int
get_locale(locale_t *loc)
{
    locale_t ret;

    ret = uselocale((locale_t)0);
    if (ret == (locale_t)0)
        return ERRNO;

    ret = duplocale(ret);
    if (ret == (locale_t)0)
        return ERRNO;

    *loc = ret;
    return 0;
}

static int
strerror_lr(int errnum, char *strerrbuf, size_t buflen, locale_t loc)
{
#ifdef HAVE_STRERROR_L
    char *ret;
    int err, old_errno;

    old_errno = errno;
    errno = 0;
    ret = strerror_l(errnum, loc);
    err = errno;
    errno = old_errno;
    if (ret == NULL)
        return err ? err : EIO;

    return strlcpy(strerrbuf, ret, buflen) < buflen ? err : ERANGE;
#else
    (void)loc;

    return strerror_r(errnum, strerrbuf, buflen);
#endif
}

void *
do_malloc(size_t size)
{
    void *ret;

    ASSURE_ERRNO_SET(ret, malloc(size));
    return ret;
}

void *
do_allocarray(size_t nmemb, size_t size)
{
    void *ret;

    ASSURE_ERRNO_SET(ret, allocarray(nmemb, size));
    return ret;
}

void *
do_calloc(size_t nmemb, size_t size)
{
    void *ret;

    ASSURE_ERRNO_SET(ret, calloc(nmemb, size));
    return ret;
}

void *
do_realloc(void *ptr, size_t size)
{
    void *ret;

    ASSURE_ERRNO_SET(ret, realloc(ptr, size));
    return ret;
}

void *
do_reallocarray(void *ptr, size_t nmemb, size_t size)
{
    void *ret;

    ASSURE_ERRNO_SET(ret, reallocarray(ptr, nmemb, size));
    return ret;
}

int
strerror_rp(int errnum, char *strerrbuf, size_t buflen)
{
    int err;
    locale_t loc;

    err = get_locale(&loc);
    if (!err) {
        err = strerror_lr(errnum, strerrbuf, buflen, loc);
        freelocale(loc);
    }

    return err;
}

char *
strperror_r(int errnum, char *strerrbuf, size_t buflen)
{
#ifdef HAVE_STRERROR_L
    char *ret;
    int err;
    locale_t loc;

    static _Thread_local char buf[32];

    if (get_locale(&loc) != 0) {
        snprintf(buf, sizeof(buf), "%d", errnum);
        return buf;
    }

    err = strerror_lr(errnum, strerrbuf, buflen, loc);
    ret = err ? strerror_l(errnum, loc) : strerrbuf;
    freelocale(loc);
    return ret;
#else
    const char *fmt = "%d";
    int err;
    locale_t loc;

    static _Thread_local char buf[32];

    err = get_locale(&loc);
    if (err)
        goto err;

    err = strerror_lr(errnum, strerrbuf, buflen, loc);
    freelocale(loc);
    if (err) {
        if (err == EINVAL)
            fmt = "Unknown error %d";
        goto err;
    }

    return strerrbuf;

err:
    snprintf(buf, sizeof(buf), fmt, errnum);
    return buf;
#endif
}

/* vi: set expandtab sw=4 ts=4: */
