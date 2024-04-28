/*
 * attr_idx.c
 */

#undef _FILE_OFFSET_BITS

#include "btree.h"
#include "btree_mmap.h"
#include "common.h"
#include "option_parsing.h"

#include "files/acc_ctl.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <fts.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

enum attrtype {
    PERMS = 1
};

enum op {
    GEN = 1,
    LIST,
    CHECK,
    APPLY
};

struct opts {
    enum attrtype   type;
    enum op         op;
    char            *index_file;
    char            **names;
};

struct index_ctx {
    int             read;
    void            *hctx;
    void            *nctx;
    struct btree    *bt;
};

struct attr_key {
    ino_t   ino;
    mode_t  mode;
};

#define INDEX_FILE ".index"

#define MAX_ENTRIES (1024 * 1024)

static int parse_cmdline(int, char **, struct opts *);

static int index_open(const char *, struct index_ctx *);
static int index_close(struct index_ctx *);

static int key_cmp(const void *, const void *, void *);
static int walk_cb(const void *, void *);

static int walk_dir(struct btree *, char *, int);
static int walk_index(struct btree *);

static int gen_index(const char *);
static int list_index(const char *);
static int check_index(const char *);
static int apply_from_index(const char *, char **);

static int
parse_cmdline(int argc, char **argv, struct opts *opts)
{
    static const enum op opmap[256] = {
        ['a'] = APPLY,
        ['c'] = CHECK,
        ['g'] = GEN,
        ['l'] = LIST
    };

    GET_OPTIONS(argc, argv, "i:o:") {
    case 'i':
        opts->index_file = strdup(optarg);
        break;
    case 'o':
        if (optarg[1] != '\0')
            return -1;
        opts->op = opmap[(unsigned char)*optarg];
        break;
    default:
        return -1;
    } END_GET_OPTIONS;

    if (opts->op == APPLY) {
        if (optind >= argc) {
            error(0, 0, "Must specify list of file names");
            return -1;
        }
        opts->names = &argv[optind];
    }

    return 0;
}

static int
index_open(const char *index_file, struct index_ctx *ictx)
{
    int ret;
    struct btree *bt;
    void *hctx, *nctx;

    if (ictx->read) {
        ret = btree_mmap_init_ctx(index_file, MAX_ENTRIES, &hctx, &nctx, 0);
        if (ret != 0) {
            error(0, -ret, "Error reading index");
            return ret;
        }

        ret = btree_read(&bt, BTREE_HADDR_NULL, BTREE_MMAP, hctx, BTREE_MMAP,
                         nctx, &key_cmp, NULL);
        if (ret != 0) {
            error(0, -ret, "Error reading index");
            goto err;
        }
    } else {
        ret = btree_mmap_init_ctx(index_file, MAX_ENTRIES, &hctx, &nctx,
                                  BTREE_MMAP_CREATE, ACC_MODE_DEFAULT);
        if (ret != 0) {
            error(0, -ret, "Error creating index");
            return ret;
        }

        ret = btree_new(&bt, 6, sizeof(struct attr_key), BTREE_MMAP, hctx,
                        BTREE_MMAP, nctx, &key_cmp, NULL);
        if (ret != 0) {
            error(0, -ret, "Error creating index");
            goto err;
        }
    }

    ictx->hctx = hctx;
    ictx->nctx = nctx;
    ictx->bt = bt;
    return 0;

err:
    btree_mmap_destroy_ctx(hctx, nctx);
    return ret;
}

static int
index_close(struct index_ctx *ictx)
{
    int ret;

    btree_close(ictx->bt);

    if (ictx->read) {
        btree_mmap_destroy_ctx(ictx->hctx, ictx->nctx);
        ret = 0;
    } else {
        int tmp;

        ret = btree_mmap_sync(ictx->hctx, ictx->nctx);
        if (ret != 0)
            error(0, -ret, "Error saving index");

        tmp = btree_mmap_destroy_ctx(ictx->hctx, ictx->nctx);
        if (tmp != 0) {
            error(0, -tmp, "Error saving index");
            ret = tmp;
        }
    }

    return ret;
}

static int
key_cmp(const void *k1, const void *k2, void *key_ctx)
{
    const struct attr_key *key1 = k1;
    const struct attr_key *key2 = k2;

    (void)key_ctx;

    return key1->ino - key2->ino;
}

static int
walk_cb(const void *keyval, void *ctx)
{
    const struct attr_key *key = keyval;

    (void)ctx;

    printf("inode %ld: mode %o\n", key->ino, key->mode);
    return 0;
}

static int
walk_dir(struct btree *bt, char *dir, int check)
{
    char *dirs[2];
    FTS *wctx;
    int ncheck = 0;
    int ret;

    dirs[0] = dir;
    dirs[1] = NULL;

    wctx = fts_open(dirs, FTS_PHYSICAL | FTS_SEEDOT, NULL);
    if (wctx == NULL)
        return -errno;

    for (;;) {
        FTSENT *e;
        struct attr_key key;

        e = fts_read(wctx);
        if (e == NULL) {
            if (errno != 0)
                error(0, errno, "Error walking directory");
            ret = -errno;
            break;
        }

        switch (e->fts_info) {
        case FTS_D:
        case FTS_DEFAULT:
        case FTS_DNR:
        case FTS_DOT:
        case FTS_ERR:
        case FTS_NS:
        case FTS_NSOK:
            continue;
        default:
            break;
        }

        key.ino = e->fts_statp->st_ino;

        if (check) {
            mode_t mode = e->fts_statp->st_mode & 07777;
            struct attr_key res;

            ret = btree_search(bt, &key, &res);
            if (ret < 0) {
                error(0, -ret, "Error looking up in index");
                break;
            }
            if (ret == 0)
                continue;

            ++ncheck;
            if (res.mode != mode) {
                printf("%s: inode %ld, mode %o -> mode %o\n", e->fts_path,
                       res.ino, res.mode, mode);
            }
        } else {
            key.mode = e->fts_statp->st_mode & 07777;

            printf("%s: inode %ld, mode %o\n", e->fts_path, key.ino, key.mode);

            ret = btree_insert(bt, &key);
            if (ret != 0) {
                error(0, -ret, "Error adding to index");
                break;
            }
        }
    }

    fts_close(wctx);

    if (check)
        infomsgf("%d files checked\n", ncheck);

    return ret;
}

static int
walk_index(struct btree *bt)
{
    btree_walk_ctx_t wctx = NULL;

    return btree_walk(bt, NULL, &walk_cb, NULL, &wctx);
}

static int
gen_index(const char *index_file)
{
    char dir[PATH_MAX];
    int ret;
    struct index_ctx ictx;

    if (getcwd(dir, sizeof(dir)) == NULL) {
        error(0, errno, "Couldn't get current working directory");
        return -errno;
    }

    ictx.read = 0;
    ret = index_open(index_file, &ictx);
    if (ret != 0)
        return ret;

    ret = walk_dir(ictx.bt, dir, 0);
    if (ret != 0)
        error(0, -ret, "Error creating index");

    return index_close(&ictx);
}

static int
list_index(const char *index_file)
{
    int ret;
    struct index_ctx ictx;

    ictx.read = 1;
    ret = index_open(index_file, &ictx);
    if (ret != 0)
        return ret;

    ret = walk_index(ictx.bt);
    if (ret != 0)
        error(0, -ret, "Error reading index");

    index_close(&ictx);

    return ret;
}

static int
check_index(const char *index_file)
{
    char dir[PATH_MAX];
    int ret;
    struct index_ctx ictx;

    if (getcwd(dir, sizeof(dir)) == NULL) {
        error(0, errno, "Couldn't get current working directory");
        return -errno;
    }

    ictx.read = 1;
    ret = index_open(index_file, &ictx);
    if (ret != 0)
        return ret;

    ret = walk_dir(ictx.bt, dir, 1);
    if (ret != 0)
        error(0, -ret, "Error checking index");

    index_close(&ictx);

    return ret;
}

static int
apply_from_index(const char *index_file, char **names)
{
    int fd;
    int i;
    int ret;
    struct index_ctx ictx;

    ictx.read = 1;
    ret = index_open(index_file, &ictx);
    if (ret != 0)
        return ret;

    for (i = 0; names[i] != NULL; i++) {
        mode_t mode;
        struct attr_key key, res;
        struct stat s;

        fd = open(names[i], O_RDONLY);
        if (fd == -1) {
            error(0, errno, "Error opening %s", names[i]);
            goto err2;
        }

        if (fstat(fd, &s) == -1) {
            error(0, errno, "Error getting status of %s", names[i]);
            goto err2;
        }
        mode = s.st_mode & 07777;

        key.ino = s.st_ino;
        ret = btree_search(ictx.bt, &key, &res);
        if (ret < 0) {
            error(0, -ret, "Error looking up in index");
            goto err1;
        }
        if (ret == 0)
            error(0, 0, "%s not in index", names[i]);
        else if (res.mode != mode) {
            printf("%s: inode %ld, mode %o -> mode %o: correcting to %o\n",
                   names[i], res.ino, res.mode, mode, res.mode);
            if (fchmod(fd, res.mode) == -1) {
                error(0, errno, "Error changing permissions of %s", names[i]);
                goto err2;
            }
        }

        close(fd);
    }

    index_close(&ictx);

    return 0;

err2:
    ret = errno;
err1:
    close(fd);
    index_close(&ictx);
    return ret;
}

int
main(int argc, char **argv)
{
    const char *index_file;
    int ret;

    static struct opts opts = {
        .type       = PERMS,
    };

    ret = parse_cmdline(argc, argv, &opts);
    switch (ret) {
    case -2:
        ret = 0;
    case -1:
        goto end;
    default:
        break;
    }

    if (opts.type != PERMS) {
        error(0, 0, "Mode not implemented");
        goto end;
    }

    index_file = opts.index_file == NULL ? INDEX_FILE : opts.index_file;

    switch (opts.op) {
    case APPLY:
        ret = apply_from_index(index_file, opts.names);
        break;
    case CHECK:
        ret = check_index(index_file);
        break;
    case GEN:
        ret = gen_index(index_file);
        break;
    case LIST:
        ret = list_index(index_file);
        break;
    default:
        ret = -1;
    }

end:
    if (opts.index_file != NULL)
        free(opts.index_file);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
