/*
 * setresuid.c
 */

#include "sys_dep.h"

#include <errno.h>
#include <stddef.h>

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

int
_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
    (void)rgid;
    (void)egid;
    (void)sgid;

    errno = ENOTSUP;
    return -1;
}

int
_setgroups(size_t size, const gid_t *list)
{
    (void)size;
    (void)list;

    errno = ENOTSUP;
    return -1;
}

/* vi: set expandtab sw=4 ts=4: */
