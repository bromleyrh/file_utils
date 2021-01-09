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
#include <error.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/types.h>

#define NBWD (sizeof(uint64_t) * NBBY)

enum op {
    OP_INSERT = 1,
    OP_LOOK_UP,
    OP_DELETE
};

enum key_type {
    KEY_INTERNAL = 1,
    KEY_EXTERNAL
};

#define ROOT_ID 1

#define KEY_MAX 255

struct key {
    enum key_type   type;
    uint64_t        id;
    const char      *key;
};

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

#define DEFAULT_PATHNAME "db.db"

#define MAX_READ 4096

struct db_obj_free_id {
    uint64_t    used_id[FREE_ID_RANGE_SZ/NBWD];
    uint8_t     flags;
} __attribute__((packed));

static int parse_cmdline(int, char **, const char **, enum op *, struct key *);

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

/*static int do_db_hl_walk(struct db_ctx *, db_hl_walk_cb_t, void *);
*/
static int do_db_hl_iter_new(struct db_iter **, struct db_ctx *);
static int do_db_hl_iter_free(struct db_iter *);
static int do_db_hl_iter_get(struct db_iter *, void *, void *, size_t *);
/*static int do_db_hl_iter_next(struct db_iter *);*/
static int do_db_hl_iter_search(struct db_iter *, const void *);

static int do_db_hl_trans_new(struct db_ctx *);
static int do_db_hl_trans_abort(struct db_ctx *);
static int do_db_hl_trans_commit(struct db_ctx *);

static void used_id_set(uint64_t *, uint64_t, uint64_t, int);
static uint64_t free_id_find(uint64_t *, uint64_t);

static int get_id(struct db_ctx *, uint64_t *);
static int release_id(struct db_ctx *, uint64_t, uint64_t);

static int do_read_data(const char **, size_t *, int);
static int do_write_data(const char *, size_t, int);

static int
get_str_arg(const char **str)
{
    if (*str != NULL)
        free((void *)*str);

    *str = strdup(optarg);

    return (*str == NULL) ? -1 : 0;
}

static void
print_usage(const char *prognm)
{
    printf("Usage: %s [options]\n"
           "\n"
           "    -d         delete specified entry\n"
           "    -f PATH    perform operation in specified database file\n"
           "    -h         output help\n"
           "    -i         insert specified entry\n"
           "    -k STRING  operate on entry specified by given external key\n"
           "    -l         look up specified entry\n"
           "    -n INTEGER operate on entry specified by given internal key\n",
           prognm);
}

static int
parse_cmdline(int argc, char **argv, const char **pathname, enum op *op,
              struct key *key)
{
    for (;;) {
        int opt = getopt(argc, argv, "df:hik:ln:");

        if (opt == -1)
            break;

        switch (opt) {
        case 'd':
            *op = OP_DELETE;
            break;
        case 'f':
            if (get_str_arg(pathname) == -1)
                return -1;
            break;
        case 'h':
            print_usage(argv[0]);
            return -2;
        case 'i':
            *op = OP_INSERT;
            break;
        case 'k':
            if (get_str_arg(&key->key) == -1)
                return -1;
            key->type = KEY_EXTERNAL;
            break;
        case 'l':
            *op = OP_LOOK_UP;
            break;
        case 'n':
            key->id = strtoull(optarg, NULL, 10);
            key->type = KEY_INTERNAL;
            break;
        default:
            return -1;
        }
    }

    if (optind != argc) {
        fputs("Unrecognized arguments\n", stderr);
        return -1;
    }

    return 0;
}

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

    return (key1->type == TYPE_EXTERNAL)
           ? strcmp(key1->key, key2->key)
           : uint64_cmp(key1->id, key2->id);
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

/*static int
do_db_hl_walk(struct db_ctx *dbctx, db_hl_walk_cb_t fn, void *wctx)
{
    return db_hl_walk(dbctx->dbh, fn, wctx);
}
*/
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
    if (ret->srch_key == NULL) {
        err = MINUS_ERRNO;
        goto err2;
    }
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

/*static int
do_db_hl_iter_next(struct db_iter *iter)
{
    int err;

    err = db_hl_iter_next(iter->iter);

    iter->srch_status = err ? err : 1;

    return err;
}
*/
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
    if (!(word & 0xf)) {
        word >>= 4;
        idx += 4;
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
    struct db_iter *iter = NULL;
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

static int
do_read_data(const char **data, size_t *datalen, int fd)
{
    char *ret, *tmp;
    int err;
    size_t len, sz;

    sz = MAX_READ;
    ret = do_malloc(sz);
    if (ret == NULL)
        return MINUS_ERRNO;
    len = 0;

    for (;;) {
        ssize_t numread;

        numread = read(fd, ret + len, MAX_READ);
        if (numread < 1) {
            if (numread == 0)
                break;
            if (errno == EINTR)
                continue;
            goto err;
        }
        len += numread;

        if (len + MAX_READ > sz) {
            sz *= 2;
            tmp = do_realloc(ret, sz);
            if (tmp == NULL)
                goto err;
            ret = tmp;
        }
    }

    tmp = do_realloc(ret, len);
    if (tmp == NULL)
        goto err;

    *data = (const char *)tmp;
    *datalen = len;
    return 0;

err:
    err = MINUS_ERRNO;
    free(ret);
    return err;
}

static int
do_write_data(const char *data, size_t datalen, int fd)
{
    size_t numwritten;
    ssize_t ret;

    for (numwritten = 0; numwritten < datalen; numwritten += ret) {
        ret = write(fd, data + numwritten, datalen - numwritten);
        if (ret < 1) {
            if (ret == 0)
                return -EIO;
            if (errno == EINTR)
                continue;
            return MINUS_ERRNO;
        }
    }

    return 0;
}

static int
do_insert(const char *pathname, struct key *key, int datafd)
{
    const char *d = NULL;
    int alloc_id = 0;
    int err;
    size_t dlen = 0;
    struct db_ctx *dbctx;
    struct db_key k;
    struct db_obj_free_id freeid;
    struct db_obj_header hdr;

    if (key->type == 0) {
        error(0, 0, "Must specify key");
        return -EINVAL;
    }
    if ((key->type == KEY_EXTERNAL) && (strlen(key->key) > KEY_MAX)) {
        error(0, 0, "Key too long");
        return -ENAMETOOLONG;
    }

    err = do_db_hl_open(&dbctx, pathname, sizeof(struct db_key), &db_key_cmp);
    if (err) {
        if (err != -ENOENT) {
            error(0, -err, "Error opening database file %s", pathname);
            return err;
        }

        err = do_db_hl_create(&dbctx, pathname, 0666, sizeof(struct db_key),
                              &db_key_cmp);
        if (err) {
            error(0, -err, "Error creating database file %s", pathname);
            return err;
        }

        k.type = TYPE_HEADER;
        hdr.version = FMT_VERSION;
        hdr.numobj = 0;
        err = do_db_hl_insert(dbctx, &k, &hdr, sizeof(hdr));
        if (err) {
            error(0, -err, "Error creating database file %s", pathname);
            goto err1;
        }

        k.type = TYPE_FREE_ID;
        k.id = ROOT_ID;
        memset(freeid.used_id, 0, sizeof(freeid.used_id));
        freeid.flags = FREE_ID_LAST_USED;
        err = do_db_hl_insert(dbctx, &k, &freeid, sizeof(freeid));
        if (err) {
            error(0, -err, "Error creating database file %s", pathname);
            goto err1;
        }
    }

    err = do_read_data(&d, &dlen, datafd);
    if (err) {
        error(0, -err, "Error reading data");
        goto err1;
    }

    err = do_db_hl_trans_new(dbctx);
    if (err) {
        error(0, -err, "Error inserting into database file %s", pathname);
        goto err2;
    }

    switch (key->type) {
    case KEY_INTERNAL:
        k.type = TYPE_INTERNAL;
        if (key->id == 0) {
            err = get_id(dbctx, &k.id);
            if (err) {
                error(0, -err, "Error allocating ID");
                goto err3;
            }
            alloc_id = 1;
        } else
            k.id = key->id;
        break;
    case KEY_EXTERNAL:
        k.type = TYPE_EXTERNAL;
        strlcpy(k.key, key->key, sizeof(k.key));
        break;
    default:
        abort();
    }

    err = do_db_hl_insert(dbctx, &k, d, dlen);
    if (err) {
        error(0, -err, "Error inserting into database file %s", pathname);
        goto err3;
    }

    free((void *)d);

    err = do_db_hl_trans_commit(dbctx);
    if (err) {
        error(0, -err, "Error inserting into database file %s", pathname);
        do_db_hl_trans_abort(dbctx);
        goto err1;
    }

    if (alloc_id)
        printf("%" PRIu64 "\n", k.id);

    err = do_db_hl_close(dbctx);
    if (err)
        error(0, -err, "Error closing database file %s", pathname);

    return err;

err3:
    do_db_hl_trans_abort(dbctx);
err2:
    free((void *)d);
err1:
    do_db_hl_close(dbctx);
    return err;
}

static int
do_look_up(const char *pathname, struct key *key, int datafd)
{
    char *d;
    int res;
    size_t dlen;
    struct db_ctx *dbctx;
    struct db_key k;

    if (key->type == 0) {
        error(0, 0, "Must specify key");
        return -EINVAL;
    }
    if ((key->type == KEY_EXTERNAL) && (strlen(key->key) > KEY_MAX)) {
        error(0, 0, "Key too long");
        return -ENAMETOOLONG;
    }

    res = do_db_hl_open(&dbctx, pathname, sizeof(struct db_key), &db_key_cmp);
    if (res != 0) {
        error(0, -res, "Error opening database file %s", pathname);
        return res;
    }

    switch (key->type) {
    case KEY_INTERNAL:
        k.type = TYPE_INTERNAL;
        k.id = key->id;
        break;
    case KEY_EXTERNAL:
        k.type = TYPE_EXTERNAL;
        strlcpy(k.key, key->key, sizeof(k.key));
        break;
    default:
        abort();
    }

    res = do_db_hl_look_up(dbctx, &k, NULL, NULL, &dlen, 0);
    if (res != 1) {
        if (res == 0) {
            error(0, 0, "Key not found");
            res = -EADDRNOTAVAIL;
        } else
            error(0, -res, "Error looking up in database file %s", pathname);
        goto err;
    }

    d = do_malloc(dlen);
    if (d == NULL) {
        res = MINUS_ERRNO;
        goto err;
    }

    res = do_db_hl_look_up(dbctx, &k, NULL, d, &dlen, 0);
    if (res != 1) {
        if (res == 0)
            res = -EIO;
        error(0, -res, "Error looking up in database file %s", pathname);
        goto err;
    }

    res = do_db_hl_close(dbctx);
    if (res != 0) {
        error(0, -res, "Error closing database file %s", pathname);
        return res;
    }

    res = do_write_data(d, dlen, datafd);
    if (res != 0) {
        error(0, -res, "Error writing data");
        return res;
    }

    free(d);

    return 0;

err:
    do_db_hl_close(dbctx);
    return res;
}

static int
do_delete(const char *pathname, struct key *key)
{
    int err;
    struct db_ctx *dbctx;
    struct db_key k;

    if (key->type == 0) {
        error(0, 0, "Must specify key");
        return -EINVAL;
    }
    if ((key->type == KEY_EXTERNAL) && (strlen(key->key) > KEY_MAX)) {
        error(0, 0, "Key too long");
        return -ENAMETOOLONG;
    }

    err = do_db_hl_open(&dbctx, pathname, sizeof(struct db_key), &db_key_cmp);
    if (err) {
        error(0, -err, "Error opening database file %s", pathname);
        return err;
    }

    switch (key->type) {
    case KEY_INTERNAL:
        k.type = TYPE_INTERNAL;
        k.id = key->id;
        break;
    case KEY_EXTERNAL:
        k.type = TYPE_EXTERNAL;
        strlcpy(k.key, key->key, sizeof(k.key));
        break;
    default:
        abort();
    }

    err = do_db_hl_trans_new(dbctx);
    if (err) {
        error(0, -err, "Error deleting from database file %s", pathname);
        goto err1;
    }

    err = do_db_hl_delete(dbctx, &k);
    if (err) {
        error(0, -err, "Error deleting from database file %s", pathname);
        goto err2;
    }

    if (k.type == TYPE_INTERNAL) {
        err = release_id(dbctx, ROOT_ID, k.id);
        if (err) {
            error(0, -err, "Error deleting from database file %s", pathname);
            goto err2;
        }
    }

    err = do_db_hl_trans_commit(dbctx);
    if (err) {
        error(0, -err, "Error deleting from database file %s", pathname);
        goto err2;
    }

    err = do_db_hl_close(dbctx);
    if (err)
        error(0, -err, "Error closing database file %s", pathname);

    return err;

err2:
    do_db_hl_trans_abort(dbctx);
err1:
    do_db_hl_close(dbctx);
    return err;
}

int
main(int argc, char **argv)
{
    const char *pathname = NULL;
    enum op op = 0;
    int ret;
    struct key key = {.type = 0};

    static const char default_pathname[] = DEFAULT_PATHNAME;

    ret = parse_cmdline(argc, argv, &pathname, &op, &key);
    if (ret != 0)
        return (ret == -2) ? EXIT_SUCCESS : EXIT_FAILURE;
    if (pathname == NULL)
        pathname = default_pathname;

    switch (op) {
    case OP_INSERT:
        ret = do_insert(pathname, &key, STDIN_FILENO);
        break;
    case OP_LOOK_UP:
        ret = do_look_up(pathname, &key, STDOUT_FILENO);
        break;
    case OP_DELETE:
        ret = do_delete(pathname, &key);
        break;
    default:
        error(0, 0, "Must specify operation");
        ret = -EIO;
    }

    if (pathname != default_pathname)
        free((void *)pathname);
    if (key.key != NULL)
        free((void *)(key.key));

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
