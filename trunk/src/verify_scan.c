/*
 * verify_scan.c
 */

#include "config.h"

#include "verify_common.h"
#include "verify_io.h"
#include "verify_scan.h"

#include <backup.h>

#include <dbus/dbus.h>

#include <openssl/evp.h>

#include <avl_tree.h>
#include <radix_tree.h>
#include <time_ext.h>

#include <files/util.h>

#include <aio.h>
#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <fenv.h>
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
#include <time.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#ifdef HAVE_XFS_XFS_H
#include <xfs/xfs.h>
#endif

#define BUFSIZE (2 * 1024 * 1024)

#define NR_HUGEPAGES "/proc/sys/vm/nr_hugepages"

struct verif_record_output {
    dev_t               dev;
    ino_t               ino;
    struct verif_record record;
};

struct verif_walk_ctx {
    struct io_state     *io_state;
    size_t              transfer_size;
    off_t               fsbytesused;
    off_t               bytesverified;
    off_t               lastoff;
    regex_t             *reg_excl;
    int                 detect_hard_links;
    struct timespec     starttm;
    struct radix_tree   *input_data;
    int                 allow_new;
    char                *buf1;
    char                *buf2;
    size_t              bufsz;
    EVP_MD_CTX          initsumctx;
    EVP_MD_CTX          sumctx;
    DBusConnection      *busconn;
    struct avl_tree     *output_data;
    FILE                *dstf;
    const char          *prefix;
};

volatile sig_atomic_t quit;

static int getsgids(gid_t **);
static int check_creds(uid_t, gid_t, uid_t, gid_t);

static int print_chksum(FILE *, unsigned char *, unsigned);

static ssize_t get_io_size(int);
static int64_t get_huge_page_size(void);

static int set_direct_io(int);

static void cancel_aio(struct aiocb *);

static int verif_record_cmp(const void *, const void *, void *);

static int insert_ino(struct verif_record_output *, struct verif_walk_ctx *);
static int look_up_ino(struct stat *, struct verif_record_output *,
                       struct verif_walk_ctx *);

static int broadcast_stat(DBusConnection *, double, const char *, const char *,
                          const char *);
static int verif_chksums_cb(int, off_t, void *);

static int verif_chksums(int, char *, char *, size_t, EVP_MD_CTX *,
                         EVP_MD_CTX *, struct verif_record *, unsigned char *,
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

static ssize_t
get_io_size(int rootfd)
{
#ifdef HAVE_XFS_XFS_H
    struct stat s;

    if (1 || !platform_test_xfs_fd(rootfd))
        return BUFSIZE;

    /* FIXME: ensure XFS filesystems are mounted with "largeio" mount option */
    return (fstat(rootfd, &s) == 0) ? s.st_blksize : -errno;
#else
    return BUFSIZE;
#endif
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
insert_ino(struct verif_record_output *record, struct verif_walk_ctx *wctx)
{
    int res;

    res = avl_tree_insert(wctx->output_data, record);
    if (res != 0)
        TRACE(-res, "avl_tree_insert()");

    return res;
}

static int
look_up_ino(struct stat *s, struct verif_record_output *record,
            struct verif_walk_ctx *wctx)
{
    int res;
    struct verif_record_output tmp;

    tmp.dev = s->st_dev;
    tmp.ino = s->st_ino;
    res = avl_tree_search(wctx->output_data, &tmp, record);
    if (res != 0) {
        if (res < 0) {
            TRACE(-res, "avl_tree_search()");
            return res;
        }
        if (record->record.size != s->st_size) {
            TRACE(0, "record->record.size (%" PRIi64 ") != s->st_size (%"
                     PRIi64 ")",
                  record->record.size, s->st_size);
            return -EIO;
        }
    }

    return res;
}

static int
broadcast_stat(DBusConnection *busconn, double stat, const char *path,
               const char *iface, const char *name)
{
    DBusMessage *msg;
    DBusMessageIter msgargs;
    dbus_uint32_t serial;

    msg = dbus_message_new_signal(path, iface, name);
    if (msg == NULL)
        goto err1;

    dbus_message_iter_init_append(msg, &msgargs);
    if (dbus_message_iter_append_basic(&msgargs, DBUS_TYPE_DOUBLE, &stat)
        == 0)
        goto err2;

    if (dbus_connection_send(busconn, msg, &serial) == 0)
        goto err2;

    dbus_message_unref(msg);

    return 0;

err2:
    dbus_message_unref(msg);
err1:
    return -ENOMEM;
}

static int
verif_chksums_cb(int fd, off_t flen, void *ctx)
{
    double pcnt, throughput;
    struct timespec curtm, difftm;
    struct verif_walk_ctx *wctx = (struct verif_walk_ctx *)ctx;

    (void)fd;

    wctx->bytesverified += flen - wctx->lastoff;
    wctx->lastoff = flen;

    pcnt = (double)100 * wctx->bytesverified / wctx->fsbytesused;

    clock_gettime(CLOCK_MONOTONIC_RAW, &curtm);
    timespec_diff(&curtm, &wctx->starttm, &difftm);
    throughput = wctx->bytesverified
                 / (difftm.tv_sec + difftm.tv_nsec * 0.000000001)
                 / (1024 * 1024);
    DEBUG_PRINT_NO_NL("\rProgress: %.6f%% (%.6f MiB/s)", pcnt, throughput);

    broadcast_stat(wctx->busconn, pcnt, "/verify/signal/progress",
                   "verify.signal.Progress", "Progress");
    broadcast_stat(wctx->busconn, throughput, "/verify/signal/throughput",
                   "verify.signal.Throughput", "Throughput");

    wctx->transfer_size = io_state_update(wctx->io_state,
                                          (size_t)(wctx->bytesverified), -1.0);

    return quit ? -EINTR : 0;
}

static int
verif_chksums(int fd, char *buf1, char *buf2, size_t bufsz,
              EVP_MD_CTX *initsumctx, EVP_MD_CTX *sumctx,
              struct verif_record *record_in, unsigned char *initsum,
              unsigned char *sum, unsigned *sumlen,
              int (*cb)(int, off_t, void *), void *ctx)
{
    char *buf;
    const struct aiocb *aiocbp;
    int err;
    int init_verif = 0;
    off_t flen = 0, initrem = 512;
    size_t len;
    struct aiocb aiocb;
    struct verif_walk_ctx *wctx = (struct verif_walk_ctx *)ctx;

    (void)bufsz;

    if ((EVP_DigestInit_ex(sumctx, EVP_sha1(), NULL) != 1)
        || (EVP_DigestInit_ex(initsumctx, EVP_sha1(), NULL) != 1))
        return -EIO;

    memset(&aiocb, 0, sizeof(aiocb));
    aiocb.aio_nbytes = wctx->transfer_size;
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

        aiocb.aio_nbytes = wctx->transfer_size;
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
    err = (errno == 0) ? EIO : errno;
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
        >= (int)sizeof(fullpath)) {
        error(0, 0, "Path name too long");
        return -EIO;
    }

    if ((wctx->reg_excl != NULL) /* check if excluded */
        && (regexec(wctx->reg_excl, fullpath, 0, NULL, 0) == 0)) {
        fprintf(stderr, "%s excluded\n", fullpath);
        return 0;
    }

    /* if multiple hard links, check if already checksummed */
    mult_links = wctx->detect_hard_links && (s->st_nlink > 1);
    if (mult_links) {
        res = look_up_ino(s, &record, wctx);
        if (res != 0) {
            if (res < 0)
                return res;
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
            if (res != 0) {
                TRACE(-res, "radix_tree_search()");
                return res;
            }
            if (!(wctx->allow_new)) {
                error(0, 0, "Verification error: %s added", fullpath);
                return -EIO;
            }
            p_record_in = NULL;
        } else {
            /* verify file size */
            if (s->st_size != record_in.size)
                goto verif_err;

            p_record_in = &record_in;
        }
    } else
        p_record_in = NULL;

    res = set_direct_io(fd);
    if (res != 0) {
        error(0, -res, "Error reading %s", fullpath);
        return res;
    }

    record.record.size = s->st_size;
    wctx->lastoff = 0;
    res = verif_chksums(fd, wctx->buf1, wctx->buf2, wctx->bufsz,
                        &wctx->initsumctx, &wctx->sumctx, p_record_in,
                        record.record.initsum, record.record.sum, &sumlen,
                        &verif_chksums_cb, wctx);
    if (res != 0) {
        if (debug)
            fputc('\n', stderr);
        if (res == 1)
            goto verif_err;
        return res;
    }
    if (debug)
        fprintf(stderr, " (verified %s/%s)\n", wctx->prefix, path);

    if (p_record_in != NULL) {
        res = radix_tree_delete(wctx->input_data, fullpath);
        if (res != 0) {
            TRACE(-res, "radix_tree_delete()");
            return res;
        }
    }

    res = output_record(wctx->dstf, record.record.size, record.record.initsum,
                        record.record.sum, sumlen, wctx->prefix, path);
    if (res != 0)
        return res;

    if (mult_links) {
        res = insert_ino(&record, wctx);
        if (res != 0)
            return res;
    }

end:
    res = posix_fadvise(fd, 0, s->st_size, POSIX_FADV_DONTNEED);
    if (res != 0)
        error(0, res, "Error writing %s", fullpath);
    return -res;

verif_err:
    error(0, 0, "Verification error: %s failed verification", fullpath);
    return -EIO;
}

static int
verif_fn(void *arg)
{
    int err;
    int fexcepts = 0;
    int hugetlbfl, nhugep;
    int64_t fullbufsize;
    ssize_t bufsz;
    struct statvfs s;
    struct verif_args *vargs = (struct verif_args *)arg;
    struct verif_walk_ctx wctx;

    bufsz = get_io_size(vargs->srcfd);
    if (bufsz < 1) {
        err = (bufsz == 0) ? EIO : -bufsz;
        goto stat_err;
    }
    wctx.bufsz = bufsz * 2;

    fullbufsize = get_huge_page_size();
    if (fullbufsize <= 0) {
        hugetlbfl = 0;
        fullbufsize = wctx.bufsz;
    } else {
        hugetlbfl = MAP_HUGETLB;
        nhugep = (wctx.bufsz + fullbufsize - 1) / fullbufsize;
        if ((size_t)fullbufsize < wctx.bufsz)
            fullbufsize *= nhugep;
    }

    if (fstatvfs(vargs->srcfd, &s) == -1) {
        err = errno;
        goto stat_err;
    }
    wctx.fsbytesused = (s.f_blocks - s.f_bfree) * s.f_frsize;
    wctx.bytesverified = 0;

    wctx.buf1 = mmap(NULL, wctx.bufsz, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | hugetlbfl, -1, 0);
    if (wctx.buf1 == MAP_FAILED) {
        err = errno;
        goto alloc_err2;
    }
    wctx.buf2 = wctx.buf1 + wctx.bufsz / 2;

    if ((EVP_DigestInit(&wctx.sumctx, EVP_sha1()) != 1)
        || (EVP_DigestInit(&wctx.initsumctx, EVP_sha1()) != 1)) {
        TRACE(0, "EVP_DigestInit()");
        err = EIO;
        goto end1;
    }

    err = -avl_tree_new(&wctx.output_data, sizeof(struct verif_record_output),
                        &verif_record_cmp, NULL);
    if (err)
        goto alloc_err1;

    wctx.reg_excl = vargs->reg_excl;
    wctx.detect_hard_links = vargs->detect_hard_links;
    wctx.input_data = vargs->input_data;
    wctx.allow_new = vargs->allow_new;
    wctx.busconn = vargs->busconn;
    wctx.dstf = vargs->dstf;
    wctx.prefix = vargs->prefix;

    if (debug) {
        /* disable floating-point traps from calculations for debugging
           output */
        fexcepts = fedisableexcept(FE_ALL_EXCEPT);
        if (fexcepts == -1) {
            TRACE(0, "fedisableexcept()");
            err = EIO;
            goto end2;
        }
    }

    wctx.transfer_size = 512 * 1024;
    err = io_state_init(&wctx.io_state);
    if (err)
        goto end3;

    clock_gettime(CLOCK_MONOTONIC_RAW, &wctx.starttm);

    err = -dir_walk_fd(vargs->srcfd, &verif_walk_fn, DIR_WALK_ALLOW_ERR,
                       (void *)&wctx);

    io_state_free(wctx.io_state);

end3:
    if (debug)
        feenableexcept(fexcepts);
end2:
    avl_tree_free(wctx.output_data);
    EVP_MD_CTX_cleanup(&wctx.sumctx);
    EVP_MD_CTX_cleanup(&wctx.initsumctx);
end1:
    munmap(wctx.buf1, fullbufsize);
    return err;

alloc_err2:
    if ((err != ENOMEM) || (hugetlbfl == 0))
        goto alloc_err1;
    error(0, 0, "Couldn't allocate memory (check " NR_HUGEPAGES " is at least "
          "%d)", nhugep);
    return err;

alloc_err1:
    error(0, err, "Couldn't allocate memory");
    return err;

stat_err:
    error(0, err, "Error getting filesystem stats");
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

    DEBUG_PRINT("Performing verification");

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
    (void)tmp;
err2:
    tmp = setegid(egid);
    (void)tmp;
err1:
    setgroups(nsgids, sgids);
    free(sgids);
    return ret;
}

/* vi: set expandtab sw=4 ts=4: */
