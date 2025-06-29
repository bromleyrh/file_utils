/*
 * setresuid.c
 */

#define _GNU_SOURCE

#include "sys_dep.h"

#include <grp.h>
#include <stddef.h>
#include <unistd.h>

#include <sys/types.h>

int
_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    return setresuid(ruid, euid, suid);
}

int
_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
    return setresgid(rgid, egid, sgid);
}

int
_setgroups(size_t size, const gid_t *list)
{
    return setgroups(size, list);
}

/* vi: set expandtab sw=4 ts=4: */
