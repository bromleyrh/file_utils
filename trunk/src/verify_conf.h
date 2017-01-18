/*
 * verify_conf.h
 */

#ifndef _VERIFY_CONF_H
#define _VERIFY_CONF_H

#include "verify_common.h"

#include <stddef.h>

struct parse_ctx {
    struct verify_ctx   ctx;
    char                *regex;
    char                *regexcurbr;
    size_t              regexlen;
};

int parse_config(const char *path, struct parse_ctx *ctx);

#endif

/* vi: set expandtab sw=4 ts=4: */
