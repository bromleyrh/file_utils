/*
 * context_new.c
 */

#include "common.h"
#include "sys_dep.h"

#include <errno.h>

EXPORTED int
context_new(int flags)
{
    (void)flags;

    errno = ENOTSUP;
    return -1;
}

/* vi: set expandtab sw=4 ts=4: */
