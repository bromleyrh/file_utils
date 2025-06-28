/*
 * context_new.c
 */

#define _GNU_SOURCE

#include "common.h"
#include "sys_dep.h"

#include <sched.h>

EXPORTED int
context_new(int flags)
{
    int fl;
    int i;

    static const struct ent {
        int src;
        int dst;
    } flmap[] = {
        {CONTEXT_FILE_TAB,      CLONE_FILES},
        {CONTEXT_FS_ATTRS,      CLONE_FS},
        {CONTEXT_HOST,          CLONE_NEWUTS},
        {CONTEXT_NET,           CLONE_NEWNET},
        {CONTEXT_NS,            CLONE_NEWNS},
        {CONTEXT_NS_IPC,        CLONE_NEWIPC},
        {CONTEXT_PROC_TAB,      CLONE_NEWPID},
        {CONTEXT_RESOURCES,     CLONE_NEWCGROUP},
        {CONTEXT_SEM_UNDO_LIST, CLONE_SYSVSEM},
        {CONTEXT_USERS,         CLONE_NEWUSER}
    };

    fl = 0;
    for (i = 0; i < (int)ARRAY_SIZE(flmap); i++) {
        const struct ent *ent = &flmap[i];

        if (flags & ent->src)
            fl |= ent->dst;
    }

    return unshare(fl);
}

/* vi: set expandtab sw=4 ts=4: */
