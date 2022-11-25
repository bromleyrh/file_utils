/*
 * verify_plugin.h
 */

#ifndef _VERIFY_PLUGIN_H
#define _VERIFY_PLUGIN_H

#include <stddef.h>

struct verify_plugin_fns {
    int (*load)(void **);
    int (*unload)(void *);
    int (*handle_file_start)(void *, const char *, const char *);
    int (*handle_file_end)(void *);
    int (*handle_file_data)(void *, const void *, size_t);
};

#define PLUGIN_FNS_SUFFIX "_fns"

#endif

/* vi: set expandtab sw=4 ts=4: */
