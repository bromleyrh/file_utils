/*
 * simpledb.c
 */

#include <dbm_high_level.h>
#include <strings_ext.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/param.h>

#define NBWD (sizeof(uint64_t) * NBBY)

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

struct db_obj_free_ino {
    uint64_t    used_id[FREE_ID_RANGE_SZ/NBWD];
    uint8_t     flags;
} __attribute__((packed));

static int uint64_cmp(uint64_t, uint64_t);

static int db_key_cmp(const void *, const void *, void *);

static void used_id_set(uint64_t *, uint64_t, uint64_t, int);
static uint64_t free_id_find(uint64_t *, uint64_t);
static int get_id(struct dbh *, uint64_t *);
static int release_id(struct dbh *, uint64_t, uint64_t);

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

    (void)key_ctx;

    cmp = uint64_cmp(key1->type, key2->type);
    if ((cmp != 0) || (key1->type == TYPE_HEADER))
        return cmp;

    return uint64_cmp(key1->id, key2->id);
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
        if (used_ino[idx] != filled)
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

    return ino + idx;
}

static int
get_id(struct dbh *dbh, uint64_t *id)
{
    db_hl_iter_t iter;
    int res;
    struct db_key k;
    struct db_obj_free_id freeid;
    struct db_obj_header hdr;
    uint64_t ret;

    res = do_db_hl_iter_new(&iter, dbh);
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

    ret = free_ino_find(freeid.used_id, k.id);
    if (ret == 0) {
        if (!(freeid.flags & FREE_ID_LAST_USED))
            return -EILSEQ;
        if (ULONG_MAX - k.id < FREE_ID_RANGE_SZ)
            return -ENOSPC;

        res = do_db_hl_delete(dbh, &k);
        if (res != 0)
            return res;

        k.id += FREE_ID_RANGE_SZ;
        memset(freeid.used_id, 0, sizeof(freeid.used_id));
        used_id_set(freeid.used_id, k.id, k.id, 1);
        freeid.flags = FREE_ID_LAST_USED;
        res = do_db_hl_insert(dbh, &k, &freeid, sizeof(freeid));
        if (res != 0)
            return res;

        *id = k.id;
        return 0;
    }

    used_id_set(freeid.used_id, k.id, ret, 1);
    res = ((memcchr(freeid.used_id, 0xff, sizeof(freeid.used_id)) == NULL)
           && !(freeid.flags & FREE_ID_LAST_USED))
          ? do_db_hl_delete(dbh, &k)
          : do_db_hl_replace(dbh, &k, &freeid, sizeof(freeid));
    if (res != 0)
        return res;

    k.type = TYPE_HEADER;
    res = do_db_hl_look_up(dbh, &k, NULL, &hdr, NULL, 0);
    if (res != 1)
        return (res == 0) ? -EILSEQ : res;

    ++(hdr.numobj);
    res = do_db_hl_replace(dbh, &k, &hdr, sizeof(hdr));
    if (res != 0)
        return res;

    *id = ret;
    return 0;
}

static int
release_id(struct dbh *dbh, uint64_t root_id, uint64_t id)
{
    int res;
    struct db_key k;
    struct db_obj_free_id freeid;
    struct db_obj_header hdr;

    k.type = TYPE_FREE_ID;
    k.id = (id - root_id) / FREE_ID_RANGE_SZ * FREE_ID_RANGE_SZ + root_id;
    res = do_db_hl_look_up(dbh, &k, &k, &freeid, NULL, 0);
    if (res != 1) {
        if (res != 0)
            return res;

        /* insert new free ID information object */
        memset(freeid.used_id, 0xff, sizeof(freeid.used_id));
        used_id_set(freeid.used_id, k.id, id, 0);
        freeid.flags = 0;
        res = do_db_hl_insert(dbh, &k, &freeid, sizeof(freeid));
        if (res != 0)
            return res;
    } else {
        used_id_set(freeid.used_id, k.id, id, 0);
        res = do_db_hl_replace(dbh, &k, &freeid, sizeof(freeid));
        if (res != 0)
            return res;
    }

    k.type = TYPE_HEADER;
    res = do_db_hl_look_up(dbh, &k, NULL, &hdr, NULL, 0);
    if (res != 1)
        return (res == 0) ? -EILSEQ : res;

    --(hdr.numobj);
    return do_db_hl_replace(dbh, &k, &hdr, sizeof(hdr));
}

int
main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    return EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
