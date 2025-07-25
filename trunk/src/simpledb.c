/*
 * simpledb.c
 */

#define _WITH_DPRINTF

#include "simpledb_obj.h"
#include "util.h"

#define ASSERT_MACROS
#include "common.h"
#undef ASSERT_MACROS

#include <dbm_high_level.h>
#include <packing.h>
#include <strings_ext.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <paths.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#define NBWD (sizeof(uint64_t) * CHAR_BIT)

enum op {
    OP_INIT_TRANS = 1,
    OP_ABORT_TRANS,
    OP_COMMIT_TRANS,
    OP_INSERT,
    OP_UPDATE,
    OP_LOOK_UP,
    OP_LOOK_UP_NEAREST,
    OP_LOOK_UP_NEXT,
    OP_LOOK_UP_PREFIX,
    OP_LOOK_UP_PREV,
    OP_DELETE,
    OP_DUMP
};

enum key_type {
    KEY_INTERNAL = 1,
    KEY_EXTERNAL
};

#define ROOT_ID 1

struct key {
    enum key_type   type;
    uint64_t        id;
    char            *key;
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

#define DEFAULT_PATHNAME "db.db"
#define DEFAULT_SOCK_PATHNAME "db.socket"

#define MAX_READ 4096

static int get_str_arg(char **);

static void print_usage(const char *);

static int parse_cmdline(int, char **, char **, char **, enum op *,
                         struct key *, int *);

static int uint64_cmp(uint64_t, uint64_t);

static int db_key_cmp(const void *, const void *, void *);

static int get_next_elem(void *, void *, size_t *, const void *,
                         struct db_ctx *);

static int do_db_hl_create(struct db_ctx **, const char *, mode_t, size_t,
                           db_hl_key_cmp_t);
static int do_db_hl_open(struct db_ctx **, const char *, size_t,
                         db_hl_key_cmp_t, int);
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
static int do_db_hl_iter_prev(struct db_iter *);
static int do_db_hl_iter_search(struct db_iter *, const void *);

static int do_db_hl_trans_new(struct db_ctx *);
static int do_db_hl_trans_abort(struct db_ctx *);
static int do_db_hl_trans_commit(struct db_ctx *);

static int open_or_create(struct db_ctx **, const char *);

static void used_id_set(uint64_t *, uint64_t, uint64_t, int);
static uint64_t free_id_find(uint64_t *, uint64_t);

static int get_id(struct db_ctx *, uint64_t *);
static int release_id(struct db_ctx *, uint64_t, uint64_t);

static int do_read_data(char **, size_t *, int);
static int do_write_data(const char *, size_t, int);

static int resize_msg_buf(char **, size_t, size_t *, int);

static int read_msg(char **, size_t *, int);
static int read_msg_v(struct iovec *, size_t, int);
static int write_msg(char *, size_t, int);
static int write_msg_v(struct iovec *, size_t, int);

static int open_db(struct db_ctx **, enum op, const char *);
static int return_data(enum op, struct key *, uint64_t, char *, size_t, int);
static int wait_for_client(int);

static int process_trans(const char *, const char *, int);

static int do_init_trans(const char *, const char *);
static int do_update_trans(const char *, enum op, struct key *);

static int do_insert(struct db_ctx *, struct key *, void **, size_t *,
                     uint64_t *, int, int);
static int do_update(struct db_ctx *, struct key *, void **, size_t *, int,
                     int);
static int do_look_up(struct db_ctx *, struct key *, void **, size_t *, int);
static int do_look_up_nearest(struct db_ctx *, struct key *, void **, size_t *,
                              int);
static int do_look_up_next(struct db_ctx *, struct key *, void **, size_t *,
                           int);
static int do_look_up_prefix(struct db_ctx *, struct key *, int);
static int do_look_up_prev(struct db_ctx *, struct key *, void **, size_t *,
                           int);
static int do_delete(struct db_ctx *, struct key *, int);
static int do_dump(struct db_ctx *, int);

static int do_op(struct db_ctx *, enum op, struct key *, void **, size_t *,
                 uint64_t *, int, int, int);

static int
get_str_arg(char **str)
{
    if (*str != NULL)
        free(*str);

    *str = strdup(optarg);

    return *str == NULL ? -1 : 0;
}

static void
print_usage(const char *prognm)
{
    printf("Usage: %s [options]\n"
           "\n"
           "    -a         abort transaction and close named socket\n"
           "    -c         commit transaction and close named socket\n"
           "    -d         delete specified entry\n"
           "    -f PATH    perform operation in specified database file\n"
           "    -h         output help\n"
           "    -i         insert specified entry\n"
           "    -k STRING  operate on entry specified by given external key\n"
           "    -L         look up nearest entry greater than or equal to "
           "given key\n"
           "    -l         look up specified entry\n"
           "    -n INTEGER operate on entry specified by given internal key\n"
           "    -P         output all entries with external keys having the "
           "specified prefix\n"
           "    -p         look up nearest entry less than given existing key\n"
           "    -S PATH    use specified named socket\n"
           "    -s         look up nearest entry greater than given existing "
           "key\n"
           "    -T         create named socket and listen in background\n"
           "    -t         send command through named socket\n"
           "    -u         update specified entry\n"
           "    -w         output contents of database\n",
           prognm);
}

static int
parse_cmdline(int argc, char **argv, char **sock_pathname, char **pathname,
              enum op *op, struct key *key, int *trans)
{
    static const enum op ops[256] = {
        [(unsigned char)'a'] = OP_ABORT_TRANS,
        [(unsigned char)'c'] = OP_COMMIT_TRANS,
        [(unsigned char)'d'] = OP_DELETE,
        [(unsigned char)'i'] = OP_INSERT,
        [(unsigned char)'L'] = OP_LOOK_UP_NEAREST,
        [(unsigned char)'l'] = OP_LOOK_UP,
        [(unsigned char)'P'] = OP_LOOK_UP_PREFIX,
        [(unsigned char)'p'] = OP_LOOK_UP_PREV,
        [(unsigned char)'s'] = OP_LOOK_UP_NEXT,
        [(unsigned char)'T'] = OP_INIT_TRANS,
        [(unsigned char)'u'] = OP_UPDATE,
        [(unsigned char)'w'] = OP_DUMP
    };

    for (;;) {
        enum op operation;
        int opt = getopt(argc, argv, "acdf:hik:Lln:PpS:sTtuw");

        if (opt == -1)
            break;

        operation = ops[(unsigned char)opt];
        if (operation != 0) {
            *op = operation;
            continue;
        }

        switch (opt) {
        case 'f':
            if (get_str_arg(pathname) == -1)
                return -1;
            break;
        case 'h':
            print_usage(argv[0]);
            return -2;
        case 'k':
            if (get_str_arg(&key->key) == -1)
                return -1;
            key->type = KEY_EXTERNAL;
            break;
        case 'n':
            key->id = strtoumax(optarg, NULL, 10);
            key->type = KEY_INTERNAL;
            break;
        case 'S':
            if (get_str_arg(sock_pathname) == -1)
                return -1;
            break;
        case 't':
            *trans = 1;
            break;
        default:
            return -1;
        }
    }

    if (optind != argc) {
        error(0, 0, "Unrecognized arguments");
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
    const struct db_key *key1 = k1;
    const struct db_key *key2 = k2;
    int cmp;
    uint32_t type;

    if (key_ctx != NULL) {
        struct db_key_ctx *ctx = key_ctx;

        memcpy(ctx->last_key, k2, sizeof(struct db_key));
        ctx->last_key_valid = 1;
    }

    type = unpack_u32(db_key, key1, type);

    cmp = uint64_cmp(type, unpack_u32(db_key, key2, type));
    if (cmp != 0 || type == TYPE_HEADER)
        return cmp;

    return type == TYPE_EXTERNAL
           ? strcmp(packed_memb_addr(db_key, key1, key),
                    packed_memb_addr(db_key, key2, key))
           : uint64_cmp(unpack_u64(db_key, key1, id),
                        unpack_u64(db_key, key2, id));
}

static int
db_walk_cb(const void *key, const void *data, size_t datasize, void *ctx)
{
    const struct db_key *k = key;
    int datafd = *(int *)ctx;
    int ret;

    switch (unpack_u32(db_key, k, type)) {
    case TYPE_INTERNAL:
        ret = dprintf(datafd, "%" PRIu64 "\n", unpack_u64(db_key, k, id));
        break;
    case TYPE_EXTERNAL:
        ret = dprintf(datafd, "%s\n", (char *)packed_memb_addr(db_key, k, key));
        break;
    default:
        return 0;
    }
    if (ret == -1) {
        ret = MINUS_ERRNO;
        goto err;
    }

    ret = do_write_data(data, datasize, datafd);
    if (ret != 0)
        goto err;

    return 0;

err:
    error(0, -ret, "Error writing data");
    return ret;
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

    if (oemalloc(&ret) == NULL)
        return MINUS_ERRNO;
    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    if (oemalloc(&ret->key_ctx) == NULL) {
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
              db_hl_key_cmp_t key_cmp, int ro)
{
    int err;
    int fl;
    struct db_ctx *ret;

    if (oemalloc(&ret) == NULL)
        return MINUS_ERRNO;
    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    if (oemalloc(&ret->key_ctx) == NULL) {
        err = MINUS_ERRNO;
        goto err1;
    }

    ret->key_ctx->last_key = do_malloc(key_size);
    if (ret->key_ctx->last_key == NULL) {
        err = MINUS_ERRNO;
        goto err2;
    }
    ret->key_ctx->last_key_valid = 0;

    fl = DB_HL_NDELAY;
    if (ro)
        fl |= DB_HL_RDONLY;

    err = db_hl_open(&ret->dbh, pathname, key_size, key_cmp, ret->key_ctx, fl);
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

    if (look_up_nearest && res == 0 && dbctx->key_ctx->last_key_valid) {
        int cmp;

        cmp = (*dbctx->key_cmp)(dbctx->key_ctx->last_key, key, NULL);
        if (cmp > 0) {
            res = db_hl_search(dbctx->dbh, dbctx->key_ctx->last_key, retkey,
                               retdata, retdatasize);
            assert(res != 0);
            return res == 1 ? 2 : res;
        }
        res = get_next_elem(retkey, retdata, retdatasize,
                            dbctx->key_ctx->last_key, dbctx);
        if (res != 0)
            return res == -EADDRNOTAVAIL ? 0 : res;
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

    if (oemalloc(&ret) == NULL)
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

        if ((*dbctx->key_cmp)(dbctx->key_ctx->last_key, iter->srch_key, NULL)
            < 0) {
            res = db_hl_iter_next(dbiter);
            if (res != 0)
                return res;
        }

        iter->srch_status = 1; /* XXX */
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
do_db_hl_iter_prev(struct db_iter *iter)
{
    int err;

    err = db_hl_iter_prev(iter->iter);

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

static int
open_or_create(struct db_ctx **dbctx, const char *pathname)
{
    int err;
    struct db_ctx *ret;
    struct db_key k;
    struct db_obj_free_id freeid;
    struct db_obj_header hdr;

    err = do_db_hl_open(&ret, pathname, sizeof(struct db_key), &db_key_cmp, 0);
    if (err) {
        if (err != -ENOENT) {
            error(0, -err, "Error opening database file %s", pathname);
            return err;
        }

        err = do_db_hl_create(&ret, pathname, 0666, sizeof(struct db_key),
                              &db_key_cmp);
        if (err) {
            error(0, -err, "Error creating database file %s", pathname);
            return err;
        }

        pack_u32(db_key, &k, type, TYPE_HEADER);
        pack_u64(db_obj_header, &hdr, version, FMT_VERSION);
        pack_u64(db_obj_header, &hdr, numobj, 0);
        err = do_db_hl_insert(ret, &k, &hdr, sizeof(hdr));
        if (err) {
            error(0, -err, "Error creating database file %s", pathname);
            goto err;
        }

        pack_u32(db_key, &k, type, TYPE_FREE_ID);
        pack_u64(db_key, &k, id, ROOT_ID);
        memset(packed_memb_addr(db_obj_free_id, &freeid, used_id), 0,
               packed_memb_size(db_obj_free_id, used_id));
        pack_u8(db_obj_free_id, &freeid, flags, FREE_ID_LAST_USED);
        err = do_db_hl_insert(ret, &k, &freeid, sizeof(freeid));
        if (err) {
            error(0, -err, "Error creating database file %s", pathname);
            goto err;
        }
    }

    *dbctx = ret;
    return 0;

err:
    do_db_hl_close(ret);
    return err;
}

static void
used_id_set(uint64_t *used_id, uint64_t base, uint64_t id, int val)
{
    int idx, wordidx;
    uint64_t mask;

    idx = id - base;
    wordidx = idx / NBWD;
    mask = UINT64_C(1) << idx % NBWD;

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
    static const uint64_t filled = ~UINT64_C(0);
    uint64_t id;
    uint64_t word;

    maxidx = FREE_ID_RANGE_SZ / NBWD - 1;
    for (idx = 0;; idx++) {
        if (used_id[idx] != filled)
            break;
        if (idx == maxidx)
            return 0;
    }
    id = base + idx * NBWD;
    word = ~used_id[idx];

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
    uint64_t *freeid_used_id;
    uint64_t k_id;
    uint64_t ret;

    res = do_db_hl_iter_new(&iter, dbctx);
    if (res != 0)
        return res;

    pack_u32(db_key, &k, type, TYPE_FREE_ID);
    pack_u64(db_key, &k, id, 0);
    res = do_db_hl_iter_search(iter, &k);
    if (res < 0) {
        do_db_hl_iter_free(iter);
        return res;
    }

    res = do_db_hl_iter_get(iter, &k, &freeid, NULL);
    do_db_hl_iter_free(iter);
    if (res != 0)
        return res == -EADDRNOTAVAIL ? -ENOSPC : res;
    if (unpack_u32(db_key, &k, type) != TYPE_FREE_ID)
        return -ENOSPC;

    k_id = unpack_u64(db_key, &k, id);
    freeid_used_id = (uint64_t *)packed_memb_addr(db_obj_free_id, &freeid,
                                                  used_id);

    ret = free_id_find(freeid_used_id, k_id);
    if (ret == 0) {
        if (!(unpack_u8(db_obj_free_id, &freeid, flags) & FREE_ID_LAST_USED))
            return -EILSEQ;
        if (ULONG_MAX - k_id < FREE_ID_RANGE_SZ)
            return -ENOSPC;

        res = do_db_hl_delete(dbctx, &k);
        if (res != 0)
            return res;

        k_id += FREE_ID_RANGE_SZ;
        pack_u64(db_key, &k, id, k_id);
        memset(freeid_used_id, 0, packed_memb_size(db_obj_free_id, used_id));
        used_id_set(freeid_used_id, k_id, k_id, 1);
        pack_u8(db_obj_free_id, &freeid, flags, FREE_ID_LAST_USED);
        res = do_db_hl_insert(dbctx, &k, &freeid, sizeof(freeid));
        if (res != 0)
            return res;

        *id = k_id;
        return 0;
    }

    used_id_set(freeid_used_id, k_id, ret, 1);
    res = memcchr(freeid_used_id, 0xff,
                  packed_memb_size(db_obj_free_id, used_id))
          == NULL
          && !(unpack_u8(db_obj_free_id, &freeid, flags) & FREE_ID_LAST_USED)
          ? do_db_hl_delete(dbctx, &k)
          : do_db_hl_replace(dbctx, &k, &freeid, sizeof(freeid));
    if (res != 0)
        return res;

    pack_u32(db_key, &k, type, TYPE_HEADER);
    res = do_db_hl_look_up(dbctx, &k, NULL, &hdr, NULL, 0);
    if (res != 1)
        return res == 0 ? -EILSEQ : res;

    pack_u64(db_obj_header, &hdr, numobj,
             unpack_u64(db_obj_header, &hdr, numobj) + 1);
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
    uint64_t *freeid_used_id;
    uint64_t k_id;

    k_id = (id - root_id) / FREE_ID_RANGE_SZ * FREE_ID_RANGE_SZ + root_id;
    freeid_used_id = (uint64_t *)packed_memb_addr(db_obj_free_id, &freeid,
                                                  used_id);

    pack_u32(db_key, &k, type, TYPE_FREE_ID);
    pack_u64(db_key, &k, id, k_id);
    res = do_db_hl_look_up(dbctx, &k, &k, &freeid, NULL, 0);
    if (res != 1) {
        if (res != 0)
            return res;

        /* insert new free ID information object */
        memset(freeid_used_id, 0xff, packed_memb_size(db_obj_free_id, used_id));
        used_id_set(freeid_used_id, k_id, id, 0);
        pack_u8(db_obj_free_id, &freeid, flags, 0);
        res = do_db_hl_insert(dbctx, &k, &freeid, sizeof(freeid));
        if (res != 0)
            return res;
    } else {
        used_id_set(freeid_used_id, k_id, id, 0);
        res = do_db_hl_replace(dbctx, &k, &freeid, sizeof(freeid));
        if (res != 0)
            return res;
    }

    pack_u32(db_key, &k, type, TYPE_HEADER);
    res = do_db_hl_look_up(dbctx, &k, NULL, &hdr, NULL, 0);
    if (res != 1)
        return res == 0 ? -EILSEQ : res;

    pack_u64(db_obj_header, &hdr, numobj,
             unpack_u64(db_obj_header, &hdr, numobj) - 1);
    return do_db_hl_replace(dbctx, &k, &hdr, sizeof(hdr));
}

static int
do_read_data(char **data, size_t *datalen, int fd)
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

    if (len > 0) {
        tmp = do_realloc(ret, len);
        if (tmp == NULL)
            goto err;
        *data = tmp;
    } else {
        free(ret);
        *data = NULL;
    }
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
resize_msg_buf(char **buf, size_t len, size_t *sz, int sockfd)
{
    char *tmp;
    ssize_t ret;
    struct iovec iov;
    struct msghdr msghdr;

    for (;;) {
        for (;;) {
            iov.iov_base = *buf + len;
            iov.iov_len = *sz - len;

            omemset(&msghdr, 0);
            msghdr.msg_iov = &iov;
            msghdr.msg_iovlen = 1;

            ret = recvmsg(sockfd, &msghdr, MSG_PEEK);
            if (ret > 0)
                break;
            if (ret == 0)
                return 1;
            if (errno != EINTR)
                return MINUS_ERRNO;
        }

        if ((size_t)ret == *sz - len) {
            *sz *= 2;
            tmp = do_realloc(*buf, *sz);
            if (tmp == NULL)
                return MINUS_ERRNO;
            *buf = tmp;
        }

        if (!(msghdr.msg_flags & MSG_TRUNC))
            break;
    }

    return 0;
}

static int
read_msg(char **msg, size_t *msglen, int sockfd)
{
    char *buf;
    int res;
    size_t len, sz;
    ssize_t ret;
    struct iovec iov;
    struct msghdr msghdr;

    sz = 4096;
    buf = do_malloc(sz);
    if (buf == NULL)
        return MINUS_ERRNO;
    len = 0;

    for (;;) {
        res = resize_msg_buf(&buf, len, &sz, sockfd);
        if (res != 0) {
            if (res != 1)
                goto err;
            goto end;
        }

        for (;;) {
            iov.iov_base = buf + len;
            iov.iov_len = sz - len;

            omemset(&msghdr, 0);
            msghdr.msg_iov = &iov;
            msghdr.msg_iovlen = 1;

            ret = recvmsg(sockfd, &msghdr, 0);
            if (ret > 0)
                break;
            if (ret == 0)
                continue;
            if (errno != EINTR) {
                res = MINUS_ERRNO;
                goto err;
            }
        }

        len += ret;
    }

end:
    if (len == 0) {
        free(buf);
        *msg = NULL;
    } else
        *msg = buf;
    *msglen = len;
    return 0;

err:
    free(buf);
    return res;
}

static int
read_msg_v(struct iovec *iov, size_t iovlen, int sockfd)
{
    struct msghdr msghdr;

    omemset(&msghdr, 0);
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = iovlen;

    return recvmsg(sockfd, &msghdr, 0) == -1 ? MINUS_ERRNO : 0;
}

static int
write_msg(char *msg, size_t msglen, int sockfd)
{
    int fl;
    size_t sent;
    ssize_t ret;

    fl = msglen == 0 ? MSG_EOR : 0;
    sent = 0;
    for (;;) {
        struct iovec iov;
        struct msghdr msghdr;

        iov.iov_base = msg + sent;
        iov.iov_len = msglen - sent;

        omemset(&msghdr, 0);
        msghdr.msg_iov = &iov;
        msghdr.msg_iovlen = 1;

        ret = sendmsg(sockfd, &msghdr, fl);
        if (ret == -1)
            return MINUS_ERRNO;

        sent += ret;
        if (sent == msglen)
            break;
    }

    return 0;
}

/*
 * FIXME: check for short writes by sendmsg()
 */
static int
write_msg_v(struct iovec *iov, size_t iovlen, int sockfd)
{
    int fl;
    struct msghdr msghdr;

    fl = iovlen == 0 ? MSG_EOR : 0;

    omemset(&msghdr, 0);
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = iovlen;

    return sendmsg(sockfd, &msghdr, fl) == -1 ? MINUS_ERRNO : 0;
}

static int
open_db(struct db_ctx **dbctx, enum op op, const char *pathname)
{
    int err;

    /* first operation determines whether database is created if it does
       not exist */
    if (op == OP_INSERT)
        err = open_or_create(dbctx, pathname);
    else {
        err = do_db_hl_open(dbctx, pathname, sizeof(struct db_key), &db_key_cmp,
                            0);
    }

    return err ? -err : do_db_hl_trans_new(*dbctx);
}

static int
return_data(enum op op, struct key *key, uint64_t id, char *buf, size_t len,
            int sockfd)
{
    int err;

    switch (op) {
    case OP_INSERT:
        if (key->type == KEY_INTERNAL) {
            /* send allocated key */
            err = write_msg((char *)&id, sizeof(id), sockfd);
            if (err)
                return err;
            err = write_msg(NULL, 0, sockfd);
            if (err)
                return err;
        }
        break;
    case OP_LOOK_UP_NEAREST:
    case OP_LOOK_UP_NEXT:
    case OP_LOOK_UP_PREV:
        /* send neighbor key */
        if (key->type == KEY_INTERNAL)
            err = write_msg((char *)&key->id, sizeof(key->id), sockfd);
        else
            err = write_msg((char *)key->key, strlen(key->key) + 1, sockfd);
        if (err)
            return err;
        err = write_msg(NULL, 0, sockfd);
        if (err)
            return err;
        /* fallthrough */
    case OP_LOOK_UP:
        /* send data */
        if (len > 0) {
            err = write_msg(buf, len, sockfd);
            if (err)
                return err;
        }
        err = write_msg(NULL, 0, sockfd);
        if (err)
            return err;
    default:
        break;
    }

    return 0;
}

static int
wait_for_client(int sockfd)
{
    struct pollfd pfd;

    omemset(&pfd, 0);
    pfd.fd = sockfd;

    for (;;) {
        while (poll(&pfd, 1, 0) == -1) {
            if (errno != EINTR)
                return MINUS_ERRNO;
        }
        if (pfd.revents & POLLHUP)
            break;
    }

    return 0;
}

static int
process_trans(const char *sock_pathname, const char *pathname, int pipefd)
{
    char *databuf = NULL, *keybuf = NULL;
    int err, tmp;
    int sockfd1, sockfd2;
    ssize_t ret;
    struct db_ctx *dbctx = NULL;
    struct sockaddr_un addr;

    sockfd1 = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sockfd1 == -1) {
        err = MINUS_ERRNO;
        goto err1;
    }

    omemset(&addr, 0);
    addr.sun_family = AF_UNIX;
    strfillbuf(addr.sun_path, sock_pathname);
    if (bind(sockfd1, (const struct sockaddr *)&addr, sizeof(addr)) == -1) {
        err = MINUS_ERRNO;
        goto err2;
    }

    if (listen(sockfd1, 1) == -1) {
        err = MINUS_ERRNO;
        goto err2;
    }

    for (;;) {
        static const unsigned char msg = 1;

        ret = write(pipefd, &msg, 1);
        if (ret == 1)
            break;
        if (ret == -1 && errno != EINTR) {
            err = MINUS_ERRNO;
            goto err2;
        }
    }

    close(pipefd);

    for (;;) {
        char *buf = NULL;
        enum op op;
        int nodata = 0;
        size_t len;
        struct iovec iov[2];
        struct key key;
        uint64_t id;
        void *bufp;

        sockfd2 = accept(sockfd1, NULL, NULL);
        if (sockfd2 == -1) {
            err = MINUS_ERRNO;
            goto err3;
        }

        /* receive operation and key type */
        iov[0].iov_base = &op;
        iov[0].iov_len = sizeof(op);
        iov[1].iov_base = &key.type;
        iov[1].iov_len = sizeof(key.type);
        err = read_msg_v(iov, 2, sockfd2);
        if (err)
            goto err4;

        if (op == OP_COMMIT_TRANS)
            goto end;
        if (op == OP_ABORT_TRANS) {
            err = -ECANCELED;
            goto err4;
        }

        /* receive key */
        err = read_msg(&keybuf, &len, sockfd2);
        if (err)
            goto err3;
        if (key.type == KEY_INTERNAL) {
            if (len != sizeof(key.id)) {
                /* FIXME: return error to client */
                err = -EIO;
                goto err4;
            }
            key.id = *(uint64_t *)keybuf;
            free(keybuf);
            keybuf = NULL;
        } else
            key.key = keybuf;

        switch (op) {
        case OP_INSERT:
        case OP_UPDATE:
            /* receive data */
            err = read_msg(&databuf, &len, sockfd2);
            if (err)
                goto err5;
            buf = databuf;
        default:
            break;
        }

        if (dbctx == NULL) {
            err = open_db(&dbctx, op, pathname);
            if (err < 0)
                goto err5;
        }

        if (!err) {
            bufp = buf;
            err = do_op(dbctx, op, &key, &bufp, &len, &id, -1, -1, 1);
            switch (-err) {
            case 0:
                buf = bufp;
                /* fallthrough */
            case EADDRINUSE:
            case EADDRNOTAVAIL:
            case ENOENT:
                break;
            default:
                goto err5;
            }
            if (key.type == KEY_EXTERNAL)
                keybuf = (char *)key.key;
        } else
            err = -err;

        /* send error status */
        if (err)
            nodata = 1;
        err = write_msg((char *)&err, sizeof(err), sockfd2);
        if (err)
            goto err5;
        err = write_msg(NULL, 0, sockfd2);
        if (err)
            goto err5;

        if (!nodata) {
            err = return_data(op, &key, id, buf, len, sockfd2);
            if (op == OP_LOOK_UP)
                free(buf);
            if (err)
                goto err5;
        }

        if (keybuf != NULL) {
            free(keybuf);
            keybuf = NULL;
        }
        if (databuf != NULL) {
            free(databuf);
            databuf = NULL;
        }

        err = wait_for_client(sockfd2);
        if (err)
            goto err4;

        if (shutdown(sockfd2, SHUT_RDWR) == -1) {
            err = MINUS_ERRNO;
            goto err4;
        }
        close(sockfd2);
    }

end:
    if (shutdown(sockfd2, SHUT_RDWR) == -1
        || shutdown(sockfd1, SHUT_RDWR) == -1) {
        err = MINUS_ERRNO;
        goto err4;
    }
    close(sockfd2);
    close(sockfd1);
    if (dbctx != NULL) {
        err = do_db_hl_trans_commit(dbctx);
        tmp = do_db_hl_close(dbctx);
        if (tmp != 0)
            err = tmp;
        return err;
    }
    return 0;

err5:
    if (keybuf != NULL) {
        free(keybuf);
        keybuf = NULL;
    }
    if (databuf != NULL) {
        free(databuf);
        databuf = NULL;
    }
err4:
    close(sockfd2);
err3:
    close(sockfd1);
    if (dbctx != NULL) {
        do_db_hl_trans_abort(dbctx);
        do_db_hl_close(dbctx);
    }
    return err;

err2:
    close(sockfd1);
err1:
    close(pipefd);
    return err;
}

static int
do_init_trans(const char *sock_pathname, const char *pathname)
{
    int err, status;
    int pipefd[2];
    pid_t pid;
    unsigned char msg;

    if (pipe(pipefd) == -1) {
        err = MINUS_ERRNO;
        error(0, -err, "Error initializing background process");
        return err;
    }

    pid = fork();
    if (pid == -1) {
        err = MINUS_ERRNO;
        error(0, -err, "Error initializing background process");
        close(pipefd[1]);
        goto err1;
    }
    if (pid == 0) {
        int fd;

        close(pipefd[0]);

        fd = open(_PATH_DEVNULL, O_RDWR);
        if (fd == -1) {
            err = MINUS_ERRNO;
            goto err3;
        }

        if (dup2(fd, STDIN_FILENO) == -1
            || dup2(fd, STDOUT_FILENO) == -1
            || dup2(fd, STDERR_FILENO) == -1) {
            err = MINUS_ERRNO;
            close(fd);
            goto err3;
        }

        close(fd);

        return process_trans(sock_pathname, pathname, pipefd[1]);
    }

    close(pipefd[1]);

    for (;;) {
        ssize_t ret;

        ret = read(pipefd[0], &msg, 1);
        if (ret > 0)
            break;
        if (ret == 0) {
            err = -EIO;
            error(0, 0, "Error creating named socket %s", sock_pathname);
            goto err2;
        }
        if (errno != EINTR) {
            err = MINUS_ERRNO;
            goto err2;
        }
    }
    if (msg != 1) {
        err = -EIO;
        goto err2;
    }

    close(pipefd[0]);

    return 0;

err3:
    close(pipefd[1]);
    return err;

err2:
    waitpid(pid, &status, 0);
err1:
    close(pipefd[0]);
    return err;
}

static int
do_update_trans(const char *sock_pathname, enum op op, struct key *key)
{
    char *msg;
    int eof;
    int err;
    int sockfd;
    size_t keylen = 0, len;
    struct iovec iov[2];
    struct sockaddr_un addr;

    if (op != OP_ABORT_TRANS && op != OP_COMMIT_TRANS) {
        if (key->type == 0) {
            error(0, 0, "Must specify key");
            return -EINVAL;
        }
        if (key->type == KEY_EXTERNAL) {
            keylen = strlen(key->key) + 1;
            if (keylen > KEY_MAX) {
                error(0, 0, "Key too long");
                return -ENAMETOOLONG;
            }
        }
    }

    sockfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sockfd == -1) {
        err = MINUS_ERRNO;
        error(0, -err, "Error connecting");
        return err;
    }

    omemset(&addr, 0);
    addr.sun_family = AF_UNIX;
    strfillbuf(addr.sun_path, sock_pathname);
    if (connect(sockfd, (const struct sockaddr *)&addr, sizeof(addr)) == -1) {
        err = MINUS_ERRNO;
        error(0, -err, "Error connecting");
        goto err;
    }

    /* send operation and key type */
    iov[0].iov_base = &op;
    iov[0].iov_len = sizeof(op);
    /* FIXME: skip sending key type for OP_ABORT_TRANS and OP_COMMIT_TRANS */
    iov[1].iov_base = &key->type;
    iov[1].iov_len = sizeof(key->type);
    err = write_msg_v(iov, 2, sockfd);
    if (err)
        goto err;

    if (op == OP_ABORT_TRANS || op == OP_COMMIT_TRANS)
        goto end;

    /* send key */
    err = key->type == KEY_INTERNAL
          ? write_msg((char *)&key->id, sizeof(key->id), sockfd)
          : write_msg((char *)key->key, keylen, sockfd);
    if (err)
        goto err;
    err = write_msg(NULL, 0, sockfd);
    if (err)
        goto err;

    switch (op) {
    case OP_INSERT:
    case OP_UPDATE:
        /* send data */
        eof = 0;
        for (;;) {
            char buf[4096];
            ssize_t ret;

            for (len = 0; len < sizeof(buf); len += ret) {
                ret = read(STDIN_FILENO, buf + len, sizeof(buf) - len);
                if (ret < 1) {
                    if (ret == 0) {
                        eof = 1;
                        break;
                    }
                    if (errno == EINTR)
                        continue;
                    err = MINUS_ERRNO;
                    goto err;
                }
            }

            if (len == 0)
                break;
            err = write_msg(buf, len, sockfd);
            if (err)
                goto err;
            if (eof)
                break;

        }
        err = write_msg(NULL, 0, sockfd);
        if (err)
            goto err;
    default:
        break;
    }

    /* receive error status */
    err = read_msg(&msg, &len, sockfd);
    if (err)
        goto err;
    if (len != sizeof(int)) {
        free(msg);
        goto err;
    }
    err = *(int *)msg;
    free(msg);
    if (err) {
        error(0, -err, "Operation returned error");
        goto err;
    }

    switch (op) {
    case OP_INSERT:
        if (key->type == KEY_INTERNAL) {
            /* receive allocated key */
            err = read_msg(&msg, &len, sockfd);
            if (err)
                goto err;
            if (len != sizeof(uint64_t)) {
                free(msg);
                goto err;
            }
            printf("%" PRIu64 "\n", *(uint64_t *)msg);
            free(msg);
        }
        break;
    case OP_LOOK_UP_NEAREST:
    case OP_LOOK_UP_NEXT:
    case OP_LOOK_UP_PREV:
        /* receive neighbor key */
        err = read_msg(&msg, &len, sockfd);
        if (err)
            goto err;
        if (key->type == KEY_INTERNAL) {
            key->id = *(uint64_t *)msg;
            free(msg);
        } else {
            free(key->key);
            key->key = msg;
        }
        /* fallthrough */
    case OP_LOOK_UP:
        /* receive data */
        err = read_msg(&msg, &len, sockfd);
        if (err)
            goto err;

        if (op != OP_LOOK_UP) {
            if (key->type == KEY_INTERNAL)
                printf("%" PRIu64 "\n", key->id);
            else
                printf("%s\n", key->key);
        }
        err = do_write_data(msg, len, STDOUT_FILENO);
        free(msg);
        if (err)
            goto err;
    default:
        break;
    }

end:
    close(sockfd);
    return 0;

err:
    close(sockfd);
    return err;
}

static int
do_insert(struct db_ctx *dbctx, struct key *key, void **data, size_t *datalen,
          uint64_t *id, int datafd, int notrans)
{
    char *d = NULL;
    int alloc_id = 0;
    int err;
    size_t dlen = 0;
    struct db_key k;
    uint32_t type;

    if (key->type == 0) {
        error(0, 0, "Must specify key");
        return -EINVAL;
    }
    if (key->type == KEY_EXTERNAL && strlen(key->key) > KEY_MAX) {
        error(0, 0, "Key too long");
        return -ENAMETOOLONG;
    }

    if (data == NULL && datafd >= 0) {
        err = do_read_data(&d, &dlen, datafd);
        if (err) {
            error(0, -err, "Error reading data");
            return err;
        }
    } else {
        d = *data;
        dlen = *datalen;
    }

    if (!notrans) {
        err = do_db_hl_trans_new(dbctx);
        if (err) {
            error(0, -err, "Error inserting into database file");
            goto err1;
        }
    }

    switch (key->type) {
    case KEY_INTERNAL:
        type = TYPE_INTERNAL;
        if (key->id == 0) {
            err = get_id(dbctx, &key->id);
            if (err) {
                error(0, -err, "Error allocating ID");
                goto err2;
            }
            alloc_id = 1;
        }
        pack_u64(db_key, &k, id, key->id);
        break;
    case KEY_EXTERNAL:
        type = TYPE_EXTERNAL;
        _strlcpy(packed_memb_addr(db_key, &k, key), key->key,
                 packed_memb_size(db_key, key));
        break;
    default:
        abort();
    }
    pack_u32(db_key, &k, type, type);

    err = do_db_hl_insert(dbctx, &k, d, dlen);
    if (err) {
        error(0, -err, "Error inserting into database file");
        goto err2;
    }

    if (data == NULL && datafd >= 0)
        free(d);

    if (!notrans) {
        err = do_db_hl_trans_commit(dbctx);
        if (err) {
            error(0, -err, "Error inserting into database file");
            do_db_hl_trans_abort(dbctx);
            return err;
        }
    }

    if (alloc_id) {
        if (id == NULL)
            printf("%" PRIu64 "\n", key->id);
        else
            *id = key->id;
    }

    return 0;

err2:
    if (!notrans)
        do_db_hl_trans_abort(dbctx);
err1:
    if (data == NULL && datafd >= 0)
        free(d);
    return err;
}

static int
do_update(struct db_ctx *dbctx, struct key *key, void **data, size_t *datalen,
          int datafd, int notrans)
{
    char *d = NULL;
    int err;
    size_t dlen = 0;
    struct db_key k;
    uint32_t type;

    if (key->type == 0 || (key->type == KEY_INTERNAL && key->id == 0)) {
        error(0, 0, "Must specify key");
        return -EINVAL;
    }
    if (key->type == KEY_EXTERNAL && strlen(key->key) > KEY_MAX) {
        error(0, 0, "Key too long");
        return -ENAMETOOLONG;
    }

    if (data == NULL && datafd >= 0) {
        err = do_read_data(&d, &dlen, datafd);
        if (err) {
            error(0, -err, "Error reading data");
            return err;
        }
    } else {
        d = *data;
        dlen = *datalen;
    }

    if (!notrans) {
        err = do_db_hl_trans_new(dbctx);
        if (err) {
            error(0, -err, "Error inserting into database file");
            goto err1;
        }
    }

    switch (key->type) {
    case KEY_INTERNAL:
        type = TYPE_INTERNAL;
        pack_u64(db_key, &k, id, key->id);
        break;
    case KEY_EXTERNAL:
        type = TYPE_EXTERNAL;
        _strlcpy(packed_memb_addr(db_key, &k, key), key->key,
                 packed_memb_size(db_key, key));
        break;
    default:
        abort();
    }
    pack_u32(db_key, &k, type, type);

    err = do_db_hl_replace(dbctx, &k, d, dlen);
    if (err) {
        error(0, -err, "Error updating database file");
        goto err2;
    }

    if (data == NULL && datafd >= 0)
        free(d);

    if (!notrans) {
        err = do_db_hl_trans_commit(dbctx);
        if (err) {
            error(0, -err, "Error updating database file");
            do_db_hl_trans_abort(dbctx);
            return err;
        }
    }

    return 0;

err2:
    if (!notrans)
        do_db_hl_trans_abort(dbctx);
err1:
    if (data == NULL && datafd >= 0)
        free(d);
    return err;
}

static int
do_look_up(struct db_ctx *dbctx, struct key *key, void **data, size_t *datalen,
           int datafd)
{
    char *d;
    int res;
    size_t dlen;
    struct db_key k;
    uint32_t type;

    if (key->type == 0) {
        error(0, 0, "Must specify key");
        return -EINVAL;
    }
    if (key->type == KEY_EXTERNAL && strlen(key->key) > KEY_MAX) {
        error(0, 0, "Key too long");
        return -ENAMETOOLONG;
    }

    switch (key->type) {
    case KEY_INTERNAL:
        type = TYPE_INTERNAL;
        pack_u64(db_key, &k, id, key->id);
        break;
    case KEY_EXTERNAL:
        type = TYPE_EXTERNAL;
        _strlcpy(packed_memb_addr(db_key, &k, key), key->key,
                 packed_memb_size(db_key, key));
        break;
    default:
        abort();
    }
    pack_u32(db_key, &k, type, type);

    res = do_db_hl_look_up(dbctx, &k, NULL, NULL, &dlen, 0);
    if (res != 1) {
        if (res == 0) {
            error(0, 0, "Key not found");
            res = -EADDRNOTAVAIL;
        } else
            error(0, -res, "Error looking up in database file");
        return res;
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
        error(0, -res, "Error looking up in database file");
        goto err;
    }

    if (data == NULL) {
        res = do_write_data(d, dlen, datafd);
        free(d);
        if (res != 0) {
            error(0, -res, "Error writing data");
            return res;
        }
    } else {
        *data = d;
        *datalen = dlen;
    }

    return 0;

err:
    free(d);
    return res;
}

static int
do_look_up_nearest(struct db_ctx *dbctx, struct key *key, void **data,
                   size_t *datalen, int datafd)
{
    char *d;
    int res;
    size_t dlen;
    struct db_iter *iter;
    struct db_key k;
    uint32_t type;

    if (key->type == 0) {
        error(0, 0, "Must specify key");
        return -EINVAL;
    }
    if (key->type == KEY_EXTERNAL && strlen(key->key) > KEY_MAX) {
        error(0, 0, "Key too long");
        return -ENAMETOOLONG;
    }

    res = do_db_hl_iter_new(&iter, dbctx);
    if (res != 0) {
        error(0, -res, "Error reading database file");
        return res;
    }

    switch (key->type) {
    case KEY_INTERNAL:
        type = TYPE_INTERNAL;
        pack_u64(db_key, &k, id, key->id);
        break;
    case KEY_EXTERNAL:
        type = TYPE_EXTERNAL;
        _strlcpy(packed_memb_addr(db_key, &k, key), key->key,
                 packed_memb_size(db_key, key));
        break;
    default:
        abort();
    }
    pack_u32(db_key, &k, type, type);

    res = do_db_hl_iter_search(iter, &k);
    if (res < 0) {
        error(0, -res, "Error reading database file");
        goto err1;
    }

    res = do_db_hl_iter_get(iter, &k, NULL, &dlen);
    if (res != 0) {
        error(0, -res, "Error reading database file");
        goto err1;
    }
    type = unpack_u32(db_key, &k, type);
    if (type != TYPE_INTERNAL && type != TYPE_EXTERNAL) {
        error(0, 0, "Key not found");
        res = -EADDRNOTAVAIL;
        goto err1;
    }

    d = do_malloc(dlen);
    if (d == NULL) {
        res = MINUS_ERRNO;
        goto err1;
    }

    res = do_db_hl_iter_get(iter, &k, d, &dlen);
    if (res != 0) {
        error(0, -res, "Error reading database file");
        goto err2;
    }

    do_db_hl_iter_free(iter);

    if (data == NULL && datafd >= 0) {
        switch (type) {
        case TYPE_INTERNAL:
            printf("%" PRIu64 "\n", unpack_u64(db_key, &k, id));
            break;
        case TYPE_EXTERNAL:
            printf("%s\n", (char *)packed_memb_addr(db_key, &k, key));
            break;
        default:
            abort();
        }

        res = do_write_data(d, dlen, datafd);
        free(d);
        if (res != 0) {
            error(0, -res, "Error writing data");
            return res;
        }
    } else {
        if (key->type == KEY_INTERNAL)
            key->id = unpack_u64(db_key, &k, id);
        else {
            key->key = strdup(packed_memb_addr(db_key, &k, key));
            if (key->key == NULL)
                return MINUS_ERRNO;
        }
        *data = d;
        *datalen = dlen;
    }

    return 0;

err2:
    free(d);
err1:
    do_db_hl_iter_free(iter);
    return res;
}

static int
do_look_up_next(struct db_ctx *dbctx, struct key *key, void **data,
                size_t *datalen, int datafd)
{
    char *d;
    int res;
    size_t dlen;
    struct db_iter *iter;
    struct db_key k;
    uint32_t type;

    if (key->type == 0) {
        error(0, 0, "Must specify key");
        return -EINVAL;
    }
    if (key->type == KEY_EXTERNAL && strlen(key->key) > KEY_MAX) {
        error(0, 0, "Key too long");
        return -ENAMETOOLONG;
    }

    res = do_db_hl_iter_new(&iter, dbctx);
    if (res != 0) {
        error(0, -res, "Error reading database file");
        return res;
    }

    switch (key->type) {
    case KEY_INTERNAL:
        type = TYPE_INTERNAL;
        pack_u64(db_key, &k, id, key->id);
        break;
    case KEY_EXTERNAL:
        type = TYPE_EXTERNAL;
        _strlcpy(packed_memb_addr(db_key, &k, key), key->key,
                 packed_memb_size(db_key, key));
        break;
    default:
        abort();
    }
    pack_u32(db_key, &k, type, type);

    res = do_db_hl_iter_search(iter, &k);
    if (res != 1) {
        if (res == 0) {
            error(0, 0, "Key not found");
            res = -EADDRNOTAVAIL;
        } else
            error(0, -res, "Error reading database file");
        goto err1;
    }

    res = do_db_hl_iter_next(iter);
    if (res != 0) {
        error(0, -res, "Error reading database file");
        goto err1;
    }

    res = do_db_hl_iter_get(iter, &k, NULL, &dlen);
    if (res != 0) {
        error(0, -res, "Error reading database file");
        goto err1;
    }
    type = unpack_u32(db_key, &k, type);
    if (type != TYPE_INTERNAL && type != TYPE_EXTERNAL) {
        error(0, 0, "Key not found");
        res = -EADDRNOTAVAIL;
        goto err1;
    }

    d = do_malloc(dlen);
    if (d == NULL) {
        res = MINUS_ERRNO;
        goto err1;
    }

    res = do_db_hl_iter_get(iter, &k, d, &dlen);
    if (res != 0) {
        error(0, -res, "Error reading database file");
        goto err2;
    }

    do_db_hl_iter_free(iter);

    if (data == NULL && datafd >= 0) {
        switch (type) {
        case TYPE_INTERNAL:
            printf("%" PRIu64 "\n", unpack_u64(db_key, &k, id));
            break;
        case TYPE_EXTERNAL:
            printf("%s\n", (char *)packed_memb_addr(db_key, &k, key));
            break;
        default:
            abort();
        }

        res = do_write_data(d, dlen, datafd);
        free(d);
        if (res != 0) {
            error(0, -res, "Error writing data");
            return res;
        }
    } else {
        if (key->type == KEY_INTERNAL)
            key->id = unpack_u64(db_key, &k, id);
        else {
            key->key = strdup(packed_memb_addr(db_key, &k, key));
            if (key->key == NULL)
                return MINUS_ERRNO;
        }
        *data = d;
        *datalen = dlen;
    }

    return 0;

err2:
    free(d);
err1:
    do_db_hl_iter_free(iter);
    return res;
}

static int
do_look_up_prefix(struct db_ctx *dbctx, struct key *key, int datafd)
{
    char *d;
    char *keybuf;
    int res;
    size_t dlen;
    size_t keylen;
    struct db_iter *iter;
    struct db_key k;

    if (key->type != KEY_EXTERNAL) {
        error(0, 0, "Must specify external key prefix");
        return -EINVAL;
    }

    res = do_db_hl_iter_new(&iter, dbctx);
    if (res != 0) {
        error(0, -res, "Error reading database file");
        return res;
    }

    keybuf = packed_memb_addr(db_key, &k, key);

    pack_u32(db_key, &k, type, TYPE_EXTERNAL);
    _strlcpy(keybuf, key->key, packed_memb_size(db_key, key));
    res = do_db_hl_iter_search(iter, &k);
    if (res < 0) {
        error(0, -res, "Error reading database file");
        goto err1;
    }

    keylen = strlen(key->key);
    for (;;) {
        res = do_db_hl_iter_get(iter, &k, NULL, &dlen);
        if (res != 0)
            goto err1;

        if (strncmp(key->key, keybuf, keylen) != 0)
            break;

        d = do_malloc(dlen);
        if (d == NULL) {
            res = MINUS_ERRNO;
            goto err1;
        }

        res = do_db_hl_iter_get(iter, &k, d, &dlen);
        if (res != 0)
            goto err1;

        res = dprintf(datafd, "%s\n", keybuf);
        if (res == -1) {
            res = MINUS_ERRNO;
            goto err2;
        }

        res = do_write_data(d, dlen, datafd);
        free(d);
        if (res != 0)
            goto err1;

        res = do_db_hl_iter_next(iter);
        if (res != 0) {
            if (res != -ENOENT)
                goto err1;
            break;
        }
    }

    do_db_hl_iter_free(iter);

    return 0;

err2:
    free(d);
err1:
    do_db_hl_iter_free(iter);
    return res;
}

static int
do_look_up_prev(struct db_ctx *dbctx, struct key *key, void **data,
                size_t *datalen, int datafd)
{
    char *d;
    int res;
    size_t dlen;
    struct db_iter *iter;
    struct db_key k;
    uint32_t type;

    if (key->type == 0) {
        error(0, 0, "Must specify key");
        return -EINVAL;
    }
    if (key->type == KEY_EXTERNAL && strlen(key->key) > KEY_MAX) {
        error(0, 0, "Key too long");
        return -ENAMETOOLONG;
    }

    res = do_db_hl_iter_new(&iter, dbctx);
    if (res != 0) {
        error(0, -res, "Error reading database file");
        return res;
    }

    switch (key->type) {
    case KEY_INTERNAL:
        type = TYPE_INTERNAL;
        pack_u64(db_key, &k, id, key->id);
        break;
    case KEY_EXTERNAL:
        type = TYPE_EXTERNAL;
        _strlcpy(packed_memb_addr(db_key, &k, key), key->key,
                 packed_memb_size(db_key, key));
        break;
    default:
        abort();
    }
    pack_u32(db_key, &k, type, type);

    res = do_db_hl_iter_search(iter, &k);
    if (res != 1) {
        if (res == 0) {
            error(0, 0, "Key not found");
            res = -EADDRNOTAVAIL;
        } else
            error(0, -res, "Error reading database file");
        goto err1;
    }

    res = do_db_hl_iter_prev(iter);
    if (res != 0) {
        error(0, -res, "Error reading database file");
        goto err1;
    }

    res = do_db_hl_iter_get(iter, &k, NULL, &dlen);
    if (res != 0) {
        error(0, -res, "Error reading database file");
        goto err1;
    }
    type = unpack_u32(db_key, &k, type);
    if (type != TYPE_INTERNAL && type != TYPE_EXTERNAL) {
        error(0, 0, "Key not found");
        res = -EADDRNOTAVAIL;
        goto err1;
    }

    d = do_malloc(dlen);
    if (d == NULL) {
        res = MINUS_ERRNO;
        goto err1;
    }

    res = do_db_hl_iter_get(iter, &k, d, &dlen);
    if (res != 0) {
        error(0, -res, "Error reading database file");
        goto err2;
    }

    do_db_hl_iter_free(iter);

    if (data == NULL && datafd >= 0) {
        switch (type) {
        case TYPE_INTERNAL:
            printf("%" PRIu64 "\n", unpack_u64(db_key, &k, id));
            break;
        case TYPE_EXTERNAL:
            printf("%s\n", (char *)packed_memb_addr(db_key, &k, key));
            break;
        default:
            abort();
        }

        res = do_write_data(d, dlen, datafd);
        free(d);
        if (res != 0) {
            error(0, -res, "Error writing data");
            return res;
        }
    } else {
        if (key->type == KEY_INTERNAL)
            key->id = unpack_u64(db_key, &k, id);
        else {
            key->key = strdup(packed_memb_addr(db_key, &k, key));
            if (key->key == NULL)
                return MINUS_ERRNO;
        }
        *data = d;
        *datalen = dlen;
    }

    return 0;

err2:
    free(d);
err1:
    do_db_hl_iter_free(iter);
    return res;
}

static int
do_delete(struct db_ctx *dbctx, struct key *key, int notrans)
{
    int err;
    struct db_key k;
    uint32_t type;

    if (key->type == 0) {
        error(0, 0, "Must specify key");
        return -EINVAL;
    }
    if (key->type == KEY_EXTERNAL && strlen(key->key) > KEY_MAX) {
        error(0, 0, "Key too long");
        return -ENAMETOOLONG;
    }

    switch (key->type) {
    case KEY_INTERNAL:
        type = TYPE_INTERNAL;
        pack_u64(db_key, &k, id, key->id);
        break;
    case KEY_EXTERNAL:
        type = TYPE_EXTERNAL;
        _strlcpy(packed_memb_addr(db_key, &k, key), key->key,
                 packed_memb_size(db_key, key));
        break;
    default:
        abort();
    }
    pack_u32(db_key, &k, type, type);

    if (!notrans) {
        err = do_db_hl_trans_new(dbctx);
        if (err) {
            error(0, -err, "Error deleting from database file");
            goto err;
        }
    }

    err = do_db_hl_delete(dbctx, &k);
    if (err) {
        error(0, -err, "Error deleting from database file");
        goto err;
    }

    if (type == TYPE_INTERNAL) {
        err = release_id(dbctx, ROOT_ID, key->id);
        if (err) {
            error(0, -err, "Error deleting from database file");
            goto err;
        }
    }

    if (!notrans) {
        err = do_db_hl_trans_commit(dbctx);
        if (err) {
            error(0, -err, "Error deleting from database file");
            goto err;
        }
    }

    return 0;

err:
    if (!notrans)
        do_db_hl_trans_abort(dbctx);
    return err;
}

static int
do_dump(struct db_ctx *dbctx, int datafd)
{
    int err;

    err = do_db_hl_walk(dbctx, &db_walk_cb, &datafd);
    if (err)
        error(0, -err, "Error reading database file");

    return err;
}

static int
do_op(struct db_ctx *dbctx, enum op op, struct key *key, void **data,
      size_t *len, uint64_t *id, int infd, int outfd, int notrans)
{
    switch (op) {
    case OP_INSERT:
        return do_insert(dbctx, key, data, len, id, infd, notrans);
    case OP_UPDATE:
        return do_update(dbctx, key, data, len, infd, notrans);
    case OP_LOOK_UP:
        return do_look_up(dbctx, key, data, len, outfd);
    case OP_LOOK_UP_NEAREST:
        return do_look_up_nearest(dbctx, key, data, len, outfd);
    case OP_LOOK_UP_NEXT:
        return do_look_up_next(dbctx, key, data, len, outfd);
    case OP_LOOK_UP_PREFIX:
        return do_look_up_prefix(dbctx, key, outfd);
    case OP_LOOK_UP_PREV:
        return do_look_up_prev(dbctx, key, data, len, outfd);
    case OP_DELETE:
        return do_delete(dbctx, key, notrans);
    case OP_DUMP:
        return do_dump(dbctx, outfd);
    default:
        break;
    }

    return -EIO;
}

int
main(int argc, char **argv)
{
    char *pathname_buf = NULL, *sock_pathname_buf = NULL;
    const char *pathname, *sock_pathname;
    enum op op = 0;
    int ret;
    int trans = 0;
    struct db_ctx *dbctx;
    struct key key = {.type = 0};

    static const char default_sock_pathname[] = DEFAULT_SOCK_PATHNAME;
    static const char default_pathname[] = DEFAULT_PATHNAME;

    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
        return EXIT_FAILURE;

    ret = parse_cmdline(argc, argv, &sock_pathname_buf, &pathname_buf, &op,
                        &key, &trans);
    if (ret != 0)
        return ret == -2 ? EXIT_SUCCESS : EXIT_FAILURE;
    sock_pathname = sock_pathname_buf == NULL
                    ? default_sock_pathname : sock_pathname_buf;
    pathname = pathname_buf == NULL ? default_pathname : pathname_buf;

    if (op == OP_INIT_TRANS) {
        ret = do_init_trans(sock_pathname, pathname);
        if (ret == 0)
            infomsgf("%s: Transaction started\n", argv[0]);
    } else if (op == OP_ABORT_TRANS || op == OP_COMMIT_TRANS
               || (trans && op != OP_LOOK_UP_PREFIX && op != OP_DUMP))
        ret = do_update_trans(sock_pathname, op, &key);
    else {
        switch (op) {
        case OP_INSERT:
            ret = open_or_create(&dbctx, pathname);
            break;
        case OP_UPDATE:
        case OP_DELETE:
            ret = do_db_hl_open(&dbctx, pathname, sizeof(struct db_key),
                                &db_key_cmp, 0);
            break;
        case OP_LOOK_UP:
        case OP_LOOK_UP_NEAREST:
        case OP_LOOK_UP_NEXT:
        case OP_LOOK_UP_PREFIX:
        case OP_LOOK_UP_PREV:
        case OP_DUMP:
            ret = do_db_hl_open(&dbctx, pathname, sizeof(struct db_key),
                                &db_key_cmp, 1);
            break;
        default:
            error(0, 0, "Must specify operation");
            ret = -EIO;
            goto end;
        }
        if (ret != 0) {
            error(0, -ret, "Error opening database %s", pathname);
            goto end;
        }

        ret = do_op(dbctx, op, &key, NULL, NULL, NULL, STDIN_FILENO,
                    STDOUT_FILENO, 0);
        if (ret != 0) {
            do_db_hl_close(dbctx);
            goto end;
        }

        ret = do_db_hl_close(dbctx);
        if (ret != 0)
            error(0, -ret, "Error closing database %s", pathname);
    }

end:
    if (pathname != default_pathname)
        free(pathname_buf);
    if (sock_pathname != default_sock_pathname)
        free(sock_pathname_buf);
    if (key.key != NULL)
        free(key.key);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
