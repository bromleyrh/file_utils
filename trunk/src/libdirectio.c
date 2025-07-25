/*
 * libdirectio.c
 */

#define _GNU_SOURCE

#include "common.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>

static int (*orig_open)(const char *, int, ...);
static int (*orig_open64)(const char *, int, ...);

#define get_mode_arg(mode) \
    do { \
        va_list args; \
        va_start(args, flags); \
        mode = va_arg(args, int); \
        va_end(args); \
    } while (0); \

static inline int
do_open(int (*open_func)(const char *, int, ...), const char *pathname,
        int flags, mode_t mode)
{
    char rp[PATH_MAX];

    if (realpath(pathname, rp) == NULL
        || (strncmp(rp, _PATH_DEVNULL, sizeof(_PATH_DEVNULL) - 1) != 0
            && strncmp(rp, "/proc/", sizeof("/proc/") - 1) != 0
            && strncmp(rp, "/sys/", sizeof("/sys/") - 1) != 0)) {
        infomsgf("Opening %s with O_DIRECT\n", pathname);
        flags |= O_DIRECT;
    }

    return (*open_func)(pathname, flags, mode);
}

int
open(const char *pathname, int flags, ...)
{
    mode_t mode = 0;

    if (flags & O_CREAT)
        get_mode_arg(mode);

    return do_open(orig_open, pathname, flags, mode);
}

int
__open(const char *pathname, int flags, ...)
{
    mode_t mode = 0;

    if (flags & O_CREAT)
        get_mode_arg(mode);

    return do_open(orig_open, pathname, flags, mode);
}

int
open64(const char *pathname, int flags, ...)
{
    mode_t mode = 0;

    if (flags & O_CREAT)
        get_mode_arg(mode);

    return do_open(orig_open64, pathname, flags, mode);
}

int
__open64(const char *pathname, int flags, ...)
{
    mode_t mode = 0;

    if (flags & O_CREAT)
        get_mode_arg(mode);

    return do_open(orig_open64, pathname, flags, mode);
}

void __attribute__((constructor))
ctor()
{
    infomsg("libdirectio loaded\n");

    orig_open = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
    if (orig_open == NULL) {
        errmsgf("Missing open() symbol\n");
        exit(EXIT_FAILURE);
    }

    orig_open64 = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open64");
    if (orig_open64 == NULL) {
        errmsgf("Missing open64() symbol\n");
        exit(EXIT_FAILURE);
    }
}

/* vi: set expandtab sw=4 ts=4: */
