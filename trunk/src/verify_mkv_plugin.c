/*
 * verify_mkv_plugin.c
 */

#define _FILE_OFFSET_BITS 64

#include "verify_plugin.h"

#include <matroska.h>

#include <avl_tree.h>

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#include <sys/param.h>
#include <sys/types.h>

struct track_data {
    uint64_t trackno;
    uint64_t type;
};

struct mkv_ctx {
    matroska_hdl_t      hdl;
    const char          *buf;
    size_t              off;
    size_t              sz;
    off_t               file_off;
    struct avl_tree     *tdata;
    struct track_data   cur_tdata;
    int                 state;
    uint64_t            nframes;
    uint64_t            tot_nframes;
    int16_t             prev_ts;
    int                 mkv_open;
    int                 incomplete_line_output;
    int                 err;
    ucontext_t          verify_ctx;
    ucontext_t          read_ctx;
};

#define EXPORTED __attribute__((__visibility__("default")))

#define PLUGIN_NAME "libverify_mkv_plugin.so"

#define MKV_EXT ".mkv"
#define MKV_EXT_LEN (sizeof(MKV_EXT) - 1)

#define READ_STACK_SZ (2 * 1024 * 1024)

#define ENAME_SEP " -> "

static struct mkv_ctx *mkv_ctx;

static int track_data_cmp(const void *, const void *, void *);

static matroska_metadata_cb_t metadata_cb;

static matroska_bitstream_cb_t bitstream_cb;

static int buf_open(void **, void *);
static int buf_close(void *);
static int buf_read(void *, void *, ssize_t *);
static int buf_get_fpos(void *, off_t *);

static void read_proc(void);

static int load(void **);
static int unload(void *);
static int handle_file_start(void *, const char *, const char *);
static int handle_file_end(void *);
static int handle_file_data(void *, const void *, size_t, int);

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
track_data_cmp(const void *k1, const void *k2, void *ctx)
{
    const struct track_data *tdata1 = k1;
    const struct track_data *tdata2 = k2;

    (void)ctx;

    return (tdata1->trackno > tdata2->trackno)
           - (tdata1->trackno < tdata2->trackno);
}

static int
metadata_cb(const char *id, matroska_metadata_t *val, size_t len, size_t hdrlen,
            int flags, void *ctx)
{
    const char *ename;
    int block;
    struct mkv_ctx *mctx = ctx;

    (void)val;
    (void)len;
    (void)hdrlen;
    (void)flags;

    ename = strstr(id, ENAME_SEP);
    if (ename == NULL)
        return -EIO;
    ename += sizeof(ENAME_SEP) - 1;

    if (strcmp(ename, "Cluster") == 0) {
        mctx->prev_ts = 0;
        return 0;
    }

    if (strcmp(ename, "TrackNumber") == 0) {
        mctx->cur_tdata.trackno = val->uinteger;
        mctx->state |= 1;
    } else if (strcmp(ename, "TrackType") == 0) {
        mctx->cur_tdata.type = val->uinteger;
        mctx->state |= 2;
    }
    if (mctx->state == 3) {
        mctx->state = 0;
        return avl_tree_insert(mctx->tdata, &mctx->cur_tdata);
    }

    block = strcmp(ename, "SimpleBlock") == 0 || strcmp(ename, "Block") == 0;
    if (block)
        mctx->state = 4;
    else {
        fprintf(stderr, "%sMatroska file: %s element\n",
                mctx->incomplete_line_output ? "\n" : "", ename);
        mctx->incomplete_line_output = 0;
    }

    return 0;
}

static int
bitstream_cb(uint64_t trackno, const void *buf, size_t len, size_t framelen,
             size_t totlen, size_t hdrlen, size_t num_logical_bytes, off_t off,
             int16_t ts, int new_frame, int keyframe, void *ctx)
{
    int res;
    struct mkv_ctx *mctx = ctx;

    (void)buf;
    (void)len;
    (void)framelen;
    (void)totlen;
    (void)hdrlen;
    (void)num_logical_bytes;
    (void)off;
    (void)new_frame;
    (void)keyframe;

    if (mctx->state == 4) {
        struct track_data e;

        e.trackno = trackno;
        res = avl_tree_search(mctx->tdata, &e, &e);
        if (res != 1)
            return res == 0 ? -EILSEQ : res;

        if (e.type == 1 && ts != mctx->prev_ts) {
            ++mctx->nframes;
            mctx->prev_ts = ts;
            fprintf(stderr, "\rTrack %" PRIu64 ": %" PRIu64 " frame%s",
                    trackno, mctx->nframes, mctx->nframes == 1 ? "" : "s");
            mctx->incomplete_line_output = 1;
        }

        mctx->state = 0;
    }

    return 0;
}

static int
buf_open(void **ctx, void *args)
{
    struct mkv_ctx *mctx = args;

    mctx->file_off = 0;
    mctx->state = 0;
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
    mkv_ctx->err = matroska_read(NULL, mkv_ctx->hdl, 0);
    if (mkv_ctx->err == 0)
        mkv_ctx->mkv_open = -1;
}

static int
load(void **hdl)
{
    struct mkv_ctx *ret;

    fputs(PLUGIN_NAME " loaded\n", stderr);

    ret = malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    ret->hdl = NULL;
    ret->tot_nframes = 0;
    ret->mkv_open = 0;

    *hdl = ret;
    return 0;
}

static int
unload(void *hdl)
{
    int err = 0;
    struct mkv_ctx *ctx = hdl;

    fprintf(stderr, PLUGIN_NAME ": %" PRIu64 " frame%s\n",
            ctx->tot_nframes, ctx->tot_nframes == 1 ? "" : "s");

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
    int err;
    size_t namelen;
    struct mkv_ctx *ctx = hdl;

    (void)path;

    fprintf(stderr, PLUGIN_NAME ": start of %s\n", name);

    namelen = strlen(name);
    if (namelen >= MKV_EXT_LEN
        && strcmp(name + namelen - MKV_EXT_LEN, MKV_EXT) == 0) {
        err = avl_tree_new(&ctx->tdata, sizeof(struct track_data),
                           &track_data_cmp, 0, NULL, NULL, NULL);
        if (err)
            return err;
        ctx->nframes = 0;
        ctx->mkv_open = 1;
    }

    return 0;
}

static int
handle_file_end(void *hdl)
{
    int err = 0;
    struct mkv_ctx *ctx = hdl;

    fputs(PLUGIN_NAME ": end", stderr);
    if (ctx->mkv_open == 1) {
        avl_tree_free(ctx->tdata);
        ctx->tot_nframes += ctx->nframes;
        fprintf(stderr, " (%" PRIu64 " frame%s)",
                ctx->nframes, ctx->nframes == 1 ? "" : "s");
    }
    fputc('\n', stderr);

    if (ctx->hdl != NULL) {
        err = matroska_close(ctx->hdl);
        ctx->hdl = NULL;
        free(ctx->read_ctx.uc_stack.ss_sp);
    }

    ctx->mkv_open = 0;

    return err;
}

static int
handle_file_data(void *hdl, const void *buf, size_t count,
                 int incomplete_line_output)
{
    int err;
    struct mkv_ctx *ctx = hdl;
    ucontext_t *read_ctx;

    if (ctx->mkv_open != 1)
        return 0;

    fprintf(stderr, "%s" PLUGIN_NAME ": %zu bytes of data\n",
            incomplete_line_output ? "\n" : "", count);

    read_ctx = &ctx->read_ctx;

    if (ctx->hdl == NULL) {
        stack_t *read_stk;

        err = matroska_open(&ctx->hdl, &io_fns, &metadata_cb, &bitstream_cb,
                            ctx, ctx);
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
    ctx->incomplete_line_output = 0;

    if (swapcontext(&ctx->verify_ctx, read_ctx) == -1)
        ctx->err = -errno;

    if (ctx->incomplete_line_output)
        fputc('\n', stderr);

    return ctx->err;

err:
    matroska_close(ctx->hdl);
    return err;
}

/* vi: set expandtab sw=4 ts=4: */
