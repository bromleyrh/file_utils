/*
 * simpledb.c
 */

#include "util.h"

#define ASSERT_MACROS
#include "common.h"
#undef ASSERT_MACROS

#include <dbm_high_level.h>
#include <strings_ext.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/param.h>
#include <sys/types.h>

#define NBWD (sizeof(uint64_t) * NBBY)

struct db_key_ctx {
    void    *last_key;
    int     last_key_valid;
};

struct db_ctx {
    struct dbh          *dbh;
    size_t              key_size;
    db_hl_key_cmp_t     key_cmp;
    struct db_key_ctx   *key_ctx;
};

struct db_iter {
    db_hl_iter_t    iter;
    void            *srch_key;
    int             srch_status;
    struct db_ctx   *dbctx;
};

enum db_obj_type {
    TYPE_HEADER = 1,
    TYPE_INTERNAL,      /* look up by id */
    TYPE_EXTERNAL,      /* look up by key */
    TYPE_FREE_ID        /* look up by id */
};

#define KEY_MAX 255

struct db_key {
    enum db_obj_type    type;
    uint64_t            id;
    char                key[KEY_MAX+1];
};

#define FMT_VERSION 1

struct db_obj_header {
    uint64_t    version;
    uint64_t    numobj;
    uint8_t     reserved[112];
} __attribute__((packed));

#define FREE_ID_RANGE_SZ 2048

#define FREE_ID_LAST_USED 1 /* values in all following ranges are free */

struct db_obj_free_id {
    uint64_t    used_id[FREE_ID_RANGE_SZ/NBWD];
    uint8_t     flags;
} __attribute__((packed));

static int uint64_cmp(uint64_t, uint64_t);

static int db_key_cmp(const void *, const void *, void *);

static int get_next_elem(void *, void *, size_t *, const void *,
                         struct db_ctx *);

static int do_db_hl_create(struct db_ctx **, const char *, mode_t, size_t,
                           db_hl_key_cmp_t);
static int do_db_hl_open(struct db_ctx **, const char *, size_t,
                         db_hl_key_cmp_t);
static int do_db_hl_close(struct db_ctx *);

static int do_db_hl_insert(struct db_ctx *, const void *, const void *, size_t);
static int do_db_hl_replace(struct db_ctx *, const void *, const void *,
                            size_t);
static int do_db_hl_look_up(struct db_ctx *, const void *, void *, void *,
                            size_t *, int);
static int do_db_hl_delete(struct db_ctx *, const void *);

static int do_db_hl_walk(struct db_ctx *, db_hl_walk_cb_t, void *);

static int do_db_hl_iter_new(struct db_iter **, struct db_ctx *);
static int do_db_hl_iter_free(struct db_iter *);
static int do_db_hl_iter_get(struct db_iter *, void *, void *, size_t *);
static int do_db_hl_iter_next(struct db_iter *);
static int do_db_hl_iter_search(struct db_iter *, const void *);

static int do_db_hl_trans_new(struct db_ctx *);
static int do_db_hl_trans_abort(struct db_ctx *);
static int do_db_hl_trans_commit(struct db_ctx *);

static void used_id_set(uint64_t *, uint64_t, uint64_t, int);
static uint64_t free_id_find(uint64_t *, uint64_t);
static int get_id(struct db_ctx *, uint64_t *);
static int release_id(struct db_ctx *, uint64_t, uint64_t);

static int
uint64_cmp(uint64_t n1, uint64_t n2)
{
    return (n1 > n2) - (n1 < n2);
}

static int
db_key_cmp(const void *k1, const void *k2, void *key_ctx)
{
    int cmp;
    struct db_key *key1 = (struct db_key *)k1;
    struct db_key *key2 = (struct db_key *)k2;

    if (key_ctx != NULL) {
        struct db_key_ctx *ctx = (struct db_key_ctx *)key_ctx;

        memcpy(ctx->last_key, k2, sizeof(struct db_key));
        ctx->last_key_valid = 1;
    }

    cmp = uint64_cmp(key1->type, key2->type);
    if ((cmp != 0) || (key1->type == TYPE_HEADER))
        return cmp;

    return uint64_cmp(key1->id, key2->id);
}

static int
get_next_elem(void *retkey, void *retdata, size_t *retdatasize, const void *key,
              struct db_ctx *dbctx)
{
    db_hl_iter_t iter;
    int res;
    size_t datalen;

    if (retdatasize == NULL)
        retdatasize = &datalen;

    res = db_hl_iter_new(&iter, dbctx->dbh);
    if (res != 0)
        return res;

    res = db_hl_iter_search(iter, key);
    if (res != 1) {
        if (res == 0)
            res = -ENOENT;
        goto end;
    }

    res = db_hl_iter_next(iter);
    if (res != 0)
        goto end;

    res = db_hl_iter_get(iter, retkey, retdata, retdatasize);

end:
    db_hl_iter_free(iter);
    return res;
}

static int
do_db_hl_create(struct db_ctx **dbctx, const char *pathname, mode_t mode,
                size_t key_size, db_hl_key_cmp_t key_cmp)
{
    int err;
    struct db_ctx *ret;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return MINUS_ERRNO;
    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    ret->key_ctx = do_malloc(sizeof(*(ret->key_ctx)));
    if (ret->key_ctx == NULL) {
        err = MINUS_ERRNO;
        goto err1;
    }

    ret->key_ctx->last_key = do_malloc(key_size);
    if (ret->key_ctx->last_key == NULL) {
        err = MINUS_ERRNO;
        goto err2;
    }
    ret->key_ctx->last_key_valid = 0;

    err = db_hl_create(&ret->dbh, pathname, mode, key_size, key_cmp,
                       ret->key_ctx, 0);
    if (err)
        goto err3;

    *dbctx = ret;
    return 0;

err3:
    free(ret->key_ctx->last_key);
err2:
    free(ret->key_ctx);
err1:
    free(ret);
    return err;
}

static int
do_db_hl_open(struct db_ctx **dbctx, const char *pathname, size_t key_size,
              db_hl_key_cmp_t key_cmp)
{
    int err;
    struct db_ctx *ret;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return MINUS_ERRNO;
    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    ret->key_ctx = do_malloc(sizeof(*(ret->key_ctx)));
    if (ret->key_ctx == NULL) {
        err = MINUS_ERRNO;
        goto err1;
    }

    ret->key_ctx->last_key = do_malloc(key_size);
    if (ret->key_ctx->last_key == NULL) {
        err = MINUS_ERRNO;
        goto err2;
    }
    ret->key_ctx->last_key_valid = 0;

    err = db_hl_open(&ret->dbh, pathname, key_size, key_cmp, ret->key_ctx, 0);
    if (err)
        goto err3;

    *dbctx = ret;
    return 0;

err3:
    free(ret->key_ctx->last_key);
err2:
    free(ret->key_ctx);
err1:
    free(ret);
    return err;
}

static int
do_db_hl_close(struct db_ctx *dbctx)
{
    int err;

    err = db_hl_close(dbctx->dbh);

    free(dbctx->key_ctx->last_key);

    free(dbctx->key_ctx);

    free(dbctx);

    return err;
}

static int
do_db_hl_insert(struct db_ctx *dbctx, const void *key, const void *data,
                size_t datasize)
{
    return db_hl_insert(dbctx->dbh, key, data, datasize);
}

static int
do_db_hl_replace(struct db_ctx *dbctx, const void *key, const void *data,
                 size_t datasize)
{
    return db_hl_replace(dbctx->dbh, key, data, datasize);
}

static int
do_db_hl_look_up(struct db_ctx *dbctx, const void *key, void *retkey,
                 void *retdata, size_t *retdatasize, int look_up_nearest)
{
    int res;
    size_t datalen;

    if (retdatasize == NULL)
        retdatasize = &datalen;

    dbctx->key_ctx->last_key_valid = 0;

    res = db_hl_search(dbctx->dbh, key, retkey, retdata, retdatasize);

    if (look_up_nearest && (res == 0) && dbctx->key_ctx->last_key_valid) {
        int cmp;

        cmp = (*(dbctx->key_cmp))(dbctx->key_ctx->last_key, key, NULL);
        if (cmp > 0) {
            res = db_hl_search(dbctx->dbh, dbctx->key_ctx->last_key, retkey,
                               retdata, retdatasize);
            assert(res != 0);
            return (res == 1) ? 2 : res;
        }
        res = get_next_elem(retkey, retdata, retdatasize,
                            dbctx->key_ctx->last_key, dbctx);
        if (res != 0)
            return (res == -EADDRNOTAVAIL) ? 0 : res;
        return 2;
    }

    return res;
}

static int
do_db_hl_delete(struct db_ctx *dbctx, const void *key)
{
    return db_hl_delete(dbctx->dbh, key);
}

static int
do_db_hl_walk(struct db_ctx *dbctx, db_hl_walk_cb_t fn, void *wctx)
{
    return db_hl_walk(dbctx->dbh, fn, wctx);
}

static int
do_db_hl_iter_new(struct db_iter **iter, struct db_ctx *dbctx)
{
    int err;
    struct db_iter *ret;

    ret = do_malloc(sizeof(*ret));
    if (ret == NULL)
        return MINUS_ERRNO;

    err = db_hl_iter_new(&ret->iter, dbctx->dbh);
    if (err)
        goto err1;

    ret->dbctx = dbctx;

    ret->srch_key = do_malloc(dbctx->key_size);
    if (ret->srch_key == NULL)
        goto err2;
    ret->srch_status = -EINVAL;

    *iter = ret;
    return 0;

err2:
    db_hl_iter_free(ret->iter);
err1:
    free(ret);
    return err;
}

static int
do_db_hl_iter_free(struct db_iter *iter)
{
    int err;

    free(iter->srch_key);

    err = db_hl_iter_free(iter->iter);

    free(iter);

    return err;
}

static int
do_db_hl_iter_get(struct db_iter *iter, void *retkey, void *retdata,
                  size_t *retdatasize)
{
    db_hl_iter_t dbiter;
    int res;
    size_t datalen;
    struct db_ctx *dbctx;

    dbiter = iter->iter;
    dbctx = iter->dbctx;

    if (retdatasize == NULL)
        retdatasize = &datalen;

    if (iter->srch_status == 0) {
        assert(dbctx->key_ctx->last_key_valid);

        res = db_hl_iter_search(dbiter, dbctx->key_ctx->last_key);
        assert(res != 0);
        if (res < 0)
            return res;

        if ((*(dbctx->key_cmp))(dbctx->key_ctx->last_key, iter->srch_key, NULL)
            < 0) {
            res = db_hl_iter_next(dbiter);
            if (res != 0)
                return res;
        }
    }

    return db_hl_iter_get(dbiter, retkey, retdata, retdatasize);
}

static int
do_db_hl_iter_next(struct db_iter *iter)
{
    int err;

    err = db_hl_iter_next(iter->iter);

    iter->srch_status = err ? err : 1;

    return err;
}

static int
do_db_hl_iter_search(struct db_iter *iter, const void *key)
{
    struct db_ctx *dbctx;

    dbctx = iter->dbctx;

    dbctx->key_ctx->last_key_valid = 0;

    iter->srch_status = db_hl_iter_search(iter->iter, key);

    if (iter->srch_status == 0)
        memcpy(iter->srch_key, key, dbctx->key_size);

    return iter->srch_status;
}

static int
do_db_hl_trans_new(struct db_ctx *dbctx)
{
    return db_hl_trans_new(dbctx->dbh);
}

static int
do_db_hl_trans_abort(struct db_ctx *dbctx)
{
    return db_hl_trans_abort(dbctx->dbh);
}

static int
do_db_hl_trans_commit(struct db_ctx *dbctx)
{
    return db_hl_trans_commit(dbctx->dbh);
}

static void
used_id_set(uint64_t *used_id, uint64_t base, uint64_t id, int val)
{
    int idx, wordidx;
    uint64_t mask;

    idx = id - base;
    wordidx = idx / NBWD;
    mask = 1ull << (idx % NBWD);

    if (val)
        used_id[wordidx] |= mask;
    else
        used_id[wordidx] &= ~mask;
}

static uint64_t
free_id_find(uint64_t *used_id, uint64_t base)
{
    int idx;
    int maxidx;
    uint64_t id;
    static const uint64_t filled = ~(uint64_t)0;
    uint64_t word;

    maxidx = FREE_ID_RANGE_SZ / NBWD - 1;
    for (idx = 0;; idx++) {
        if (used_id[idx] != filled)
            break;
        if (idx == maxidx)
            return 0;
    }
    id = base + idx * NBWD;
    word = ~(used_id[idx]);

    idx = 0;
    if (!(word & 0xffffffff)) {
        word >>= 32;
        idx += 32;
    }
    if (!(word & 0xffff)) {
        word >>= 16;
        idx += 16;
    }
    if (!(word & 0xff)) {
        word >>= 8;
        idx += 8;
    }
    if (!(word & 0x3)) {
        word >>= 2;
        idx += 2;
    }
    if (!(word & 0x1))
        idx += 1;

    return id + idx;
}

static int
get_id(struct db_ctx *dbctx, uint64_t *id)
{
    int res;
    struct db_iter *iter;
    struct db_key k;
    struct db_obj_free_id freeid;
    struct db_obj_header hdr;
    uint64_t ret;

    res = do_db_hl_iter_new(&iter, dbctx);
    if (res != 0)
        return res;

    k.type = TYPE_FREE_ID;
    k.id = 0;
    res = do_db_hl_iter_search(iter, &k);
    if (res < 0) {
        do_db_hl_iter_free(iter);
        return res;
    }

    res = do_db_hl_iter_get(iter, &k, &freeid, NULL);
    do_db_hl_iter_free(iter);
    if (res != 0)
        return (res == -EADDRNOTAVAIL) ? -ENOSPC : res;
    if (k.type != TYPE_FREE_ID)
        return -ENOSPC;

    ret = free_id_find(freeid.used_id, k.id);
    if (ret == 0) {
        if (!(freeid.flags & FREE_ID_LAST_USED))
            return -EILSEQ;
        if (ULONG_MAX - k.id < FREE_ID_RANGE_SZ)
            return -ENOSPC;

        res = do_db_hl_delete(dbctx, &k);
        if (res != 0)
            return res;

        k.id += FREE_ID_RANGE_SZ;
        memset(freeid.used_id, 0, sizeof(freeid.used_id));
        used_id_set(freeid.used_id, k.id, k.id, 1);
        freeid.flags = FREE_ID_LAST_USED;
        res = do_db_hl_insert(dbctx, &k, &freeid, sizeof(freeid));
        if (res != 0)
            return res;

        *id = k.id;
        return 0;
    }

    used_id_set(freeid.used_id, k.id, ret, 1);
    res = ((memcchr(freeid.used_id, 0xff, sizeof(freeid.used_id)) == NULL)
           && !(freeid.flags & FREE_ID_LAST_USED))
          ? do_db_hl_delete(dbctx, &k)
          : do_db_hl_replace(dbctx, &k, &freeid, sizeof(freeid));
    if (res != 0)
        return res;

    k.type = TYPE_HEADER;
    res = do_db_hl_look_up(dbctx, &k, NULL, &hdr, NULL, 0);
    if (res != 1)
        return (res == 0) ? -EILSEQ : res;

    ++(hdr.numobj);
    res = do_db_hl_replace(dbctx, &k, &hdr, sizeof(hdr));
    if (res != 0)
        return res;

    *id = ret;
    return 0;
}

static int
release_id(struct db_ctx *dbctx, uint64_t root_id, uint64_t id)
{
    int res;
    struct db_key k;
    struct db_obj_free_id freeid;
    struct db_obj_header hdr;

    k.type = TYPE_FREE_ID;
    k.id = (id - root_id) / FREE_ID_RANGE_SZ * FREE_ID_RANGE_SZ + root_id;
    res = do_db_hl_look_up(dbctx, &k, &k, &freeid, NULL, 0);
    if (res != 1) {
        if (res != 0)
            return res;

        /* insert new free ID information object */
        memset(freeid.used_id, 0xff, sizeof(freeid.used_id));
        used_id_set(freeid.used_id, k.id, id, 0);
        freeid.flags = 0;
        res = do_db_hl_insert(dbctx, &k, &freeid, sizeof(freeid));
        if (res != 0)
            return res;
    } else {
        used_id_set(freeid.used_id, k.id, id, 0);
        res = do_db_hl_replace(dbctx, &k, &freeid, sizeof(freeid));
        if (res != 0)
            return res;
    }

    k.type = TYPE_HEADER;
    res = do_db_hl_look_up(dbctx, &k, NULL, &hdr, NULL, 0);
    if (res != 1)
        return (res == 0) ? -EILSEQ : res;

    --(hdr.numobj);
    return do_db_hl_replace(dbctx, &k, &hdr, sizeof(hdr));
}

int
main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    return EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
