/*
 * openat_tmpfile.c
 */

#define _GNU_SOURCE

#include "config.h"

#include "sys_dep.h"

#include <errno.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>

int
openat_tmpfile(int dirfd, const char *pathname, int flags, mode_t mode)
{
#ifdef HAVE_O_TMPFILE
    return openat(dirfd, pathname, flags | O_TMPFILE, mode);
#else
    (void)dirfd;
    (void)pathname;
    (void)flags;
    (void)mode;

    errno = ENOTSUP;
    return -1;
#endif
}

/* vi: set expandtab sw=4 ts=4: */
