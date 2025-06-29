/*
 * setresuid.c
 */

#define _GNU_SOURCE

#include "sys_dep.h"

#include <unistd.h>

#include <sys/types.h>

int
_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    return setresuid(ruid, euid, suid);
}

/* vi: set expandtab sw=4 ts=4: */
