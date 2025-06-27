/*
 * openat_directory.c
 */

#include "sys_dep.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

int
openat_directory(int dfd, const char *pathname, int flags, int nofollow)
{
    int ret;
#ifndef O_DIRECTORY
    int old_errno;
    struct stat s;
#endif

#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#else
    /* O_NONBLOCK required to prevent blocking if e.d_name references a FIFO not
       open in any other process */
    flags |= O_NOCTTY | O_NONBLOCK;
#endif
    if (nofollow)
        flags |= O_NOFOLLOW;

    ret = openat(dfd, pathname, flags);
#ifndef O_DIRECTORY
    if (ret == -1)
        return -1;

    if (fstat(ret, &s) == -1)
        goto err;
    if (!S_ISDIR(s.st_mode)) {
        close(ret);
        errno = ENOTDIR;
        return -1;
    }

    if (fcntl(ret, F_SETFL, flags & ~O_NONBLOCK) == -1)
        goto err;

#endif
    return ret;
#ifndef O_DIRECTORY

err:
    old_errno = errno;
    close(ret);
    errno = old_errno;
    return -1;
#endif
}

/* vi: set expandtab sw=4 ts=4: */
