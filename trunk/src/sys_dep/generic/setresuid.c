/*
 * setresuid.c
 */

#include "sys_dep.h"

#include <errno.h>

#include <sys/types.h>

int
_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    (void)ruid;
    (void)euid;
    (void)suid;

    errno = ENOTSUP;
    return -1;
}

/* vi: set expandtab sw=4 ts=4: */
