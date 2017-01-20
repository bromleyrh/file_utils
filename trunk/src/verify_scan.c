/*
 * verify_scan.c
 */

#include "verify_common.h"
#include "verify_scan.h"

#include <backup.h>

#include <openssl/evp.h>

#include <avl_tree.h>
#include <radix_tree.h>

#include <files/util.h>

#include <aio.h>
#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <regex.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#define BUFSIZE (1024 * 1024)

struct verif_record_output {
    dev_t               dev;
    ino_t               ino;
    struct verif_record record;
};

struct verif_walk_ctx {
    off_t               fsbytesused;
    off_t               bytesverified;
    off_t               lastoff;
    regex_t             *reg_excl;
    int                 detect_hard_links;
    struct radix_tree   *input_data;
    char                *buf1;
    char                *buf2;
    EVP_MD_CTX          initsumctx;
    EVP_MD_CTX          sumctx;
    struct avl_tree     *output_data;
    FILE                *dstf;
    const char          *prefix;
};

volatile sig_atomic_t quit;

static int getsgids(gid_t **);
static int check_creds(uid_t, gid_t, uid_t, gid_t);

static int print_chksum(FILE *, unsigned char *, unsigned);

static int64_t get_huge_page_size(void);

static int set_direct_io(int);

static void cancel_aio(struct aiocb *);

static int verif_record_cmp(const void *, const void *, void *);

static int verif_chksums_cb(int, off_t, void *);

static int verif_chksums(int, char *, char *, EVP_MD_CTX *, EVP_MD_CTX *,
                         struct verif_record *, unsigned char *,
                         unsigned char *, unsigned *,
                         int (*)(int, off_t, void *), void *);

static int output_record(FILE *, off_t, unsigned char *, unsigned char *,
                         unsigned, const char *, const char *);

static int verif_walk_fn(int, int, const char *, const char *, struct stat *,
                         void *);

static int verif_fn(void *);

static int
getsgids(gid_t **sgids)
{
    gid_t *ret;
    int nsgids, tmp;

    nsgids = getgroups(0, NULL);
    if (nsgids == -1)
        return -errno;

    ret = malloc(nsgids * sizeof(*ret));
    if (ret == NULL)
        return -errno;

    tmp = getgroups(nsgids, ret);
    if (tmp != nsgids) {
        free(ret);
        return (tmp == -1) ? -errno : -EIO;
    }

    *sgids = ret;
    return nsgids;
}

static int
check_creds(uid_t ruid, gid_t rgid, uid_t uid, gid_t gid)
{
    if ((ruid == 0) || (ruid == uid))
        return 0;

    return ((rgid == gid) || group_member(gid)) ? 0 : -EPERM;
}

static int
print_chksum(FILE *f, unsigned char *sum, unsigned sumlen)
{
    unsigned i;

    for (i = 0; i < sumlen; i++) {
        if (fprintf(f, "%02x", sum[i]) <= 0)
            return -EIO;
    }

    return 0;
}

#define MEMINFO "/proc/meminfo"
#define HUGE_PAGE_SIZE_KEY "Hugepagesize:"

static int64_t
get_huge_page_size()
{
    char unit_prefix;
    char *ln = NULL;
    FILE *f;
    int64_t ret = 0;
    intmax_t num;
    size_t n;

    static const int64_t prefix_map[256] = {
        ['k'] = (int64_t)1 << 10,
        ['M'] = (int64_t)1 << 20,
        ['G'] = (int64_t)1 << 30,
        ['T'] = (int64_t)1 << 40
    };

    f = fopen(MEMINFO, "r");
    if (f == NULL) {
        error(0, errno, "Error opening " MEMINFO);
        return -errno;
    }

    for (;;) {
        errno = 0;
        if (getline(&ln, &n, f) == -1) {
            if (errno != 0)
                ret = errno;
            goto end;
        }
        if (sscanf(ln, HUGE_PAGE_SIZE_KEY " %jd %cB", &num, &unit_prefix) == 2)
            break;
    }

    ret = num * prefix_map[(unsigned char)unit_prefix];

end:
    fclose(f);
    if (ln != NULL)
        free(ln);
    return ret;
}

#undef MEMINFO
#undef HUGE_PAGE_SIZE_KEY

static int
set_direct_io(int fd)
{
    int fl;

    fl = fcntl(fd, F_GETFL);
    return ((fl != -1)
            && ((fcntl(fd, F_SETFL, fl | O_DIRECT) != -1) || (errno == EINVAL)))
           ? 0 : -errno; /* EINVAL from fcntl(F_SETFL, fl | O_DIRECT) means
                            O_DIRECT not supported by filesystem */
}

static void
cancel_aio(struct aiocb *cb)
{
    int ret;

    ret = aio_cancel(cb->aio_fildes, cb);

    if (ret == AIO_NOTCANCELED) {
        while (aio_suspend((const struct aiocb **)&cb, 1, NULL) == -1) {
            if ((errno != EAGAIN) && (errno != EINTR))
                break;
        }
    }

    aio_return(cb);
}

static int
verif_record_cmp(const void *k1, const void *k2, void *ctx)
{
    struct verif_record_output *record1 = (struct verif_record_output *)k1;
    struct verif_record_output *record2 = (struct verif_record_output *)k2;

    (void)ctx;

    if (record1->dev != record2->dev)
        return (record1->dev > record2->dev) - (record1->dev < record2->dev);

    return (record1->ino > record2->ino) - (record1->ino < record2->ino);
}

static int
verif_chksums_cb(int fd, off_t flen, void *ctx)
{
    struct verif_walk_ctx *wctx = (struct verif_walk_ctx *)ctx;

    (void)fd;

    wctx->bytesverified += flen - wctx->lastoff;
    wctx->lastoff = flen;

    if (debug) {
        fprintf(stderr, "\rProgress: %.6f%%",
                (double)100 * wctx->bytesverified / wctx->fsbytesused);
    }

    return quit ? -EINTR : 0;
}

static int
verif_chksums(int fd, char *buf1, char *buf2, EVP_MD_CTX *initsumctx,
              EVP_MD_CTX *sumctx, struct verif_record *record_in,
              unsigned char *initsum, unsigned char *sum, unsigned *sumlen,
              int (*cb)(int, off_t, void *), void *ctx)
{
    char *buf;
    const struct aiocb *aiocbp;
    int err;
    int init_verif = 0;
    off_t flen = 0, initrem = 512;
    size_t len;
    struct aiocb aiocb;

    if ((EVP_DigestInit_ex(sumctx, EVP_sha1(), NULL) != 1)
        || (EVP_DigestInit_ex(initsumctx, EVP_sha1(), NULL) != 1))
        return -EIO;

    memset(&aiocb, 0, sizeof(aiocb));
    aiocb.aio_nbytes = BUFSIZE;
    aiocb.aio_fildes = fd;
    aiocb.aio_buf = buf = buf1;
    if (aio_read(&aiocb) == -1)
        return -errno;
    aiocbp = &aiocb;

    for (;;) {
        char *nextbuf;

        if (aio_suspend(&aiocbp, 1, NULL) == -1)
            goto err;
        len = aio_return(&aiocb);
        if (len < 1) {
            if (len != 0)
                goto err;
            break;
        }
        flen += len;

        err = (*cb)(fd, flen, ctx);
        if (err)
            return err;

        aiocb.aio_offset = flen;
        aiocb.aio_buf = nextbuf = (buf == buf1) ? buf2 : buf1;
        if (aio_read(&aiocb) == -1)
            return -errno;

        if (initrem > 0) {
            size_t sz = MIN(initrem, (off_t)len);

            if (EVP_DigestUpdate(initsumctx, buf, sz) != 1)
                goto err;
            initrem -= sz;
        }
        if (!init_verif && (initrem == 0)) {
            if (EVP_DigestFinal_ex(initsumctx, initsum, sumlen) != 1)
                goto err;
            if ((record_in != NULL)
                && ((*sumlen != 20)
                    || (memcmp(initsum, record_in->initsum, *sumlen) != 0)))
                goto verif_err;
            init_verif = 1;
        }
        if (EVP_DigestUpdate(sumctx, buf, len) != 1)
            goto err;

        buf = nextbuf;
    }

    err = (*cb)(fd, flen + len, ctx);
    if (err)
        return err;

    if (!init_verif) {
        if (EVP_DigestFinal_ex(initsumctx, initsum, sumlen) != 1)
            return -EIO;
        if ((record_in != NULL)
            && ((*sumlen != 20)
                || (memcmp(initsum, record_in->initsum, *sumlen) != 0)))
            return 1;
    }
    if (EVP_DigestFinal_ex(sumctx, sum, sumlen) != 1)
        return -EIO;
    if ((record_in != NULL)
        && ((*sumlen != 20) || (memcmp(sum, record_in->sum, *sumlen) != 0)))
        return 1;

    return 0;

verif_err:
    cancel_aio(&aiocb);
    return 1;

err:
    err = -((errno == 0) ? EIO : errno);
    cancel_aio(&aiocb);
    return -err;
}

static int
output_record(FILE *f, off_t size, unsigned char *initsum, unsigned char *sum,
              unsigned sumlen, const char *prefix, const char *path)
{
    /* print file size */
    if (fprintf(f, "%" PRIu64 "\t", size) <= 0)
        goto err;

    /* print checksum of first min(file_size, 512) bytes of file */
    if ((print_chksum(f, initsum, sumlen) != 0) || (fputc('\t', f) == EOF))
        goto err;

    /* print checksum of file */
    if (print_chksum(f, sum, sumlen) != 0)
        goto err;

    /* print file path */
    if (fprintf(f, "\t%s/%s\n", prefix, path) <= 0)
        goto err;

    return (fflush(f) == EOF) ? -errno : 0;

err:
    return -EIO;
}

static int
verif_walk_fn(int fd, int dirfd, const char *name, const char *path,
              struct stat *s, void *ctx)
{
    char fullpath[PATH_MAX];
    int mult_links;
    int res;
    struct verif_record record_in, *p_record_in;
    struct verif_record_output record;
    struct verif_walk_ctx *wctx = (struct verif_walk_ctx *)ctx;
    unsigned sumlen;

    (void)dirfd;
    (void)name;

    if (quit)
        return -EINTR;

    if (!S_ISREG(s->st_mode))
        return 0;

    if (snprintf(fullpath, sizeof(fullpath), "%s/%s", wctx->prefix, path)
        >= (int)sizeof(fullpath))
        return -EIO;

    if ((wctx->reg_excl != NULL) /* check if excluded */
        && (regexec(wctx->reg_excl, fullpath, 0, NULL, 0) == 0)) {
        fprintf(stderr, "%s excluded\n", fullpath);
        return 0;
    }

    /* if multiple hard links, check if already checksummed */
    mult_links = wctx->detect_hard_links && (s->st_nlink > 1);
    if (mult_links) {
        record.dev = s->st_dev;
        record.ino = s->st_ino;
        res = avl_tree_search(wctx->output_data, &record, &record);
        if (res != 0) {
            if (res < 0)
                return res;
            if (record.record.size != s->st_size)
                return -EIO;
            res = output_record(wctx->dstf, record.record.size,
                                record.record.initsum, record.record.sum, 20,
                                wctx->prefix, path);
            if (res != 0)
                return res;
            goto end;
        }
    }

    if (wctx->input_data != NULL) {
        res = radix_tree_search(wctx->input_data, fullpath, &record_in);
        if (res != 1) {
            if (res != 0)
                return res;
            error(0, 0, "Verification error: %s added", fullpath);
            return -EIO;
        }

        /* verify file size */
        if (s->st_size != record_in.size)
            goto verif_err;

        p_record_in = &record_in;
    } else
        p_record_in = NULL;

    res = set_direct_io(fd);
    if (res != 0)
        return res;

    record.record.size = s->st_size;
    wctx->lastoff = 0;
    res = verif_chksums(fd, wctx->buf1, wctx->buf2, &wctx->initsumctx,
                        &wctx->sumctx, p_record_in, record.record.initsum,
                        record.record.sum, &sumlen, &verif_chksums_cb, wctx);
    if (res != 0) {
        if (debug)
            fputc('\n', stderr);
        if (res == 1)
            goto verif_err;
        return res;
    }
    if (debug)
        fprintf(stderr, " (verified %s/%s)\n", wctx->prefix, path);

    if (wctx->input_data != NULL) {
        res = radix_tree_delete(wctx->input_data, fullpath);
        if (res != 0)
            return res;
    }

    res = output_record(wctx->dstf, record.record.size, record.record.initsum,
                        record.record.sum, sumlen, wctx->prefix, path);
    if (res != 0)
        return res;

    if (mult_links) {
        res = avl_tree_insert(wctx->output_data, &record);
        if (res != 0)
            return res;
    }

end:
    return -posix_fadvise(fd, 0, s->st_size, POSIX_FADV_DONTNEED);

verif_err:
    error(0, 0, "Verification error: %s failed verification", fullpath);
    return -EIO;
}

static int
verif_fn(void *arg)
{
    int err;
    int hugetlbfl;
    int64_t fullbufsize;
    struct statvfs s;
    struct verif_args *vargs = (struct verif_args *)arg;
    struct verif_walk_ctx wctx;

    fullbufsize = get_huge_page_size();
    if (fullbufsize <= 0) {
        hugetlbfl = 0;
        fullbufsize = BUFSIZE;
    } else {
        hugetlbfl = MAP_HUGETLB;
        if (fullbufsize < BUFSIZE) {
            fullbufsize = (BUFSIZE + fullbufsize - 1) / fullbufsize
                          * fullbufsize;
        }
    }

    if (fstatvfs(vargs->srcfd, &s) == -1)
        return errno;
    wctx.fsbytesused = (s.f_blocks - s.f_bfree) * s.f_frsize;
    wctx.bytesverified = 0;

    wctx.buf1 = mmap(NULL, BUFSIZE, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | hugetlbfl, -1, 0);
    if (wctx.buf1 == MAP_FAILED) {
        err = errno;
        goto alloc_err;
    }
    wctx.buf2 = mmap(NULL, BUFSIZE, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | hugetlbfl, -1, 0);
    if (wctx.buf2 == MAP_FAILED) {
        err = errno;
        munmap(wctx.buf1, fullbufsize);
        goto alloc_err;
    }

    if ((EVP_DigestInit(&wctx.sumctx, EVP_sha1()) != 1)
        || (EVP_DigestInit(&wctx.initsumctx, EVP_sha1()) != 1)) {
        err = EIO;
        goto end1;
    }

    err = avl_tree_new(&wctx.output_data, sizeof(struct verif_record_output),
                       &verif_record_cmp, NULL);
    if (err)
        goto end2;

    wctx.reg_excl = vargs->reg_excl;
    wctx.detect_hard_links = vargs->detect_hard_links;
    wctx.input_data = vargs->input_data;
    wctx.dstf = vargs->dstf;
    wctx.prefix = vargs->prefix;

    err = -dir_walk_fd(vargs->srcfd, &verif_walk_fn, DIR_WALK_ALLOW_ERR,
                       (void *)&wctx);

    avl_tree_free(wctx.output_data);

end2:
    EVP_MD_CTX_cleanup(&wctx.sumctx);
    EVP_MD_CTX_cleanup(&wctx.initsumctx);
end1:
    munmap(wctx.buf2, fullbufsize);
    munmap(wctx.buf1, fullbufsize);
    return err;

alloc_err:
    error(0, err, "Couldn't allocate memory%s",
          ((err == ENOMEM) && (hugetlbfl != 0))
          ? " (check /proc/sys/vm/nr_hugepages is at least 2)" : "");
    return err;
}

int
do_verif(struct verif_args *verif_args)
{
    gid_t egid, *sgids = NULL;
    int nsgids;
    int ret, tmp;
    uid_t euid;

    ret = check_creds(ruid, rgid, verif_args->uid, verif_args->gid);
    if (ret != 0) {
        error(0, 0, "Credentials invalid");
        return ret;
    }

    nsgids = getsgids(&sgids);
    if (nsgids == -1) {
        error(0, -nsgids, "Error getting groups");
        return -nsgids;
    }
    if (setgroups(0, NULL) == -1) {
        error(0, errno, "Error setting groups");
        free(sgids);
        return errno;
    }

    egid = getegid();
    if ((verif_args->gid != (gid_t)-1) && (setegid(verif_args->gid) == -1)) {
        ret = errno;
        error(0, ret, "Error changing group");
        goto err1;
    }
    euid = geteuid();
    if ((verif_args->uid != (uid_t)-1) && (seteuid(verif_args->uid) == -1)) {
        ret = errno;
        error(0, ret, "Error changing user");
        goto err2;
    }

    debug_print("Performing verification");

    ret = -verif_fn(verif_args);
    if (ret != 0)
        goto err3;

    ret = ((seteuid(euid) == 0) && (setegid(egid) == 0)
           && (setgroups(nsgids, sgids) == 0))
          ? 0 : -errno;

    free(sgids);

    return ret;

err3:
    tmp = seteuid(euid);
err2:
    tmp = setegid(egid);
    (void)tmp;
err1:
    setgroups(nsgids, sgids);
    free(sgids);
    return ret;
}

/* vi: set expandtab sw=4 ts=4: */
