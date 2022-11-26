/*
 * verify_mkv_plugin.c
 */

#define _FILE_OFFSET_BITS 64

#include "verify_plugin.h"

#include <matroska.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#include <sys/param.h>
#include <sys/types.h>

struct mkv_ctx {
    matroska_hdl_t  hdl;
    const char      *buf;
    size_t          off;
    size_t          sz;
    off_t           file_off;
    int             mkv_open;
    int             err;
    ucontext_t      verify_ctx;
    ucontext_t      read_ctx;
};

#define EXPORTED __attribute__((__visibility__("default")))

#define MKV_EXT ".mkv"
#define MKV_EXT_LEN (sizeof(MKV_EXT) - 1)

#define READ_STACK_SZ (2 * 1024 * 1024)

static struct mkv_ctx *mkv_ctx;

static matroska_metadata_cb_t metadata_cb;

static int buf_open(void **, void *);
static int buf_close(void *);
static int buf_read(void *, void *, ssize_t *);
static int buf_get_fpos(void *, off_t *);

static void read_proc(void);

static int load(void **);
static int unload(void *);
static int handle_file_start(void *, const char *, const char *);
static int handle_file_end(void *);
static int handle_file_data(void *, const void *, size_t);

EXPORTED const struct verify_plugin_fns libverify_mkv_plugin_fns = {
    .load               = &load,
    .unload             = &unload,
    .handle_file_start  = &handle_file_start,
    .handle_file_end    = &handle_file_end,
    .handle_file_data   = &handle_file_data
};

static matroska_io_fns_t io_fns = {
    .open       = &buf_open,
    .close      = &buf_close,
    .read       = &buf_read,
    .get_fpos   = &buf_get_fpos
};

static int
metadata_cb(const char *id, matroska_metadata_t *val, size_t len, int flags,
            void *ctx)
{
    (void)val;
    (void)len;
    (void)flags;
    (void)ctx;

    fprintf(stderr, "Matroska file: %s element\n", id);

    return 0;
}

static int
buf_open(void **ctx, void *args)
{
    struct mkv_ctx *mctx = args;

    mctx->file_off = 0;
    mctx->err = 0;

    *ctx = mctx;
    return 0;
}

static int
buf_close(void *ctx)
{
    (void)ctx;

    return 0;
}

static int
buf_read(void *ctx, void *buf, ssize_t *nbytes)
{
    size_t toread;
    struct mkv_ctx *mctx = ctx;

    if (mctx->off == mctx->sz
        && swapcontext(&mctx->read_ctx, &mctx->verify_ctx) == -1)
        return -errno;

    toread = MIN(*nbytes, mctx->sz - mctx->off);
    memcpy(buf, mctx->buf + mctx->off, toread);
    mctx->off += toread;
    mctx->file_off += toread;

    *nbytes = toread;
    return 0;
}

static int
buf_get_fpos(void *ctx, off_t *offset)
{
    struct mkv_ctx *mctx = ctx;

    *offset = mctx->file_off;
    return 0;
}

static void
read_proc()
{
    mkv_ctx->err = matroska_read(NULL, mkv_ctx->hdl);
    if (mkv_ctx->err == 0)
        mkv_ctx->mkv_open = -1;
}

static int
load(void **hdl)
{
    struct mkv_ctx *ret;

    fputs("libverify_mkv_plugin.so loaded\n", stderr);

    ret = malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    ret->hdl = NULL;
    ret->mkv_open = 0;

    *hdl = ret;
    return 0;
}

static int
unload(void *hdl)
{
    int err = 0;
    struct mkv_ctx *ctx = hdl;

    if (ctx->hdl != NULL) {
        err = matroska_close(ctx->hdl);
        free(ctx->read_ctx.uc_stack.ss_sp);
    }

    free(ctx);

    return err;
}

static int
handle_file_start(void *hdl, const char *name, const char *path)
{
    size_t namelen;
    struct mkv_ctx *ctx = hdl;

    (void)path;

    fprintf(stderr, "libverify_mkv_plugin.so: start of %s\n", name);

    namelen = strlen(name);
    if (namelen >= MKV_EXT_LEN
        && strcmp(name + namelen - MKV_EXT_LEN, MKV_EXT) == 0)
        ctx->mkv_open = 1;

    return 0;
}

static int
handle_file_end(void *hdl)
{
    int err = 0;
    struct mkv_ctx *ctx = hdl;

    fputs("libverify_mkv_plugin.so: end\n", stderr);

    if (ctx->hdl != NULL) {
        err = matroska_close(ctx->hdl);
        ctx->hdl = NULL;
        free(ctx->read_ctx.uc_stack.ss_sp);
    }

    ctx->mkv_open = 0;

    return err;
}

static int
handle_file_data(void *hdl, const void *buf, size_t count)
{
    int err;
    struct mkv_ctx *ctx = hdl;
    ucontext_t *read_ctx;

    if (ctx->mkv_open != 1)
        return 0;

    fprintf(stderr, "libverify_mkv_plugin.so: %zu bytes of data\n", count);

    read_ctx = &ctx->read_ctx;

    if (ctx->hdl == NULL) {
        stack_t *read_stk;

        err = matroska_open(&ctx->hdl, &io_fns, &metadata_cb, NULL, ctx, ctx);
        if (err)
            return err;

        if (getcontext(read_ctx) == -1) {
            err = -errno;
            goto err;
        }

        read_stk = &read_ctx->uc_stack;
        read_stk->ss_size = READ_STACK_SZ;
        read_stk->ss_sp = malloc(read_stk->ss_size);
        if (read_stk->ss_sp == NULL) {
            err = -errno;
            goto err;
        }

        read_ctx->uc_link = NULL;

        mkv_ctx = ctx;
        makecontext(read_ctx, &read_proc, 0);
    }

    ctx->buf = buf;
    ctx->off = 0;
    ctx->sz = count;

    if (swapcontext(&ctx->verify_ctx, read_ctx) == -1)
        return -errno;

    return ctx->err;

err:
    matroska_close(ctx->hdl);
    return err;
}

/* vi: set expandtab sw=4 ts=4: */
