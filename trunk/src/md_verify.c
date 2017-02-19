/*
 * md_verify.c
 */

#define _GNU_SOURCE

#include <radix_tree.h>

#include <files/util.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct md_record {
    struct timespec atim;
    struct timespec mtim;
};

struct ctx {
    const char          *rootdir;
    struct radix_tree   *data;
    int                 err;
};

#define TM_FMT "%Y-%m-%d %H:%M:%S %z"
#define TM_FMT_OUT "%Y-%m-%d %H:%M:%S%nxxxxxxxxxx%z"

static int correct_timestamps;
static int verbose;

static void print_usage(const char *);
static int parse_cmdline(int, char **, const char **, const char ***);

static size_t timestamp_to_str(char *, size_t, const char *, struct timespec *);

static int parse_ns(const char *, long *);
static char *scan_timestamp(char *, char *, struct timespec *);
static int scan_input_file(const char *, struct radix_tree **);

static int input_data_walk_cb(const char *, void *, void *);
static int print_input_data(FILE *, struct radix_tree *);

static int cmp_timestamps(struct md_record *, struct stat *);
static void print_timestamps(struct timespec *, struct timespec *);

static int process_files_cb(int, int, const char *, const char *, struct stat *,
                            void *);

static int process_files(const char **, struct radix_tree *);

static void
print_usage(const char *progname)
{
    printf("Usage: %s [options] <manifest_path> <path>...\n"
           "\n"
           "    -c correct file timestamps differing from those in the "
           "manifest\n"
           "    -h output help\n"
           "    -v increase verbosity\n",
           progname);
}

static int
parse_cmdline(int argc, char **argv, const char **manifest_path,
              const char ***paths)
{
    for (;;) {
        int opt = getopt(argc, argv, "chv");

        if (opt == -1)
            break;

        switch (opt) {
        case 'c':
            correct_timestamps = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return -2;
        case 'v':
            verbose = 1;
            break;
        default:
            return -1;
        }
    }

    if (optind > argc - 2) {
        error(0, 0, "Must specify manifest path and directory path");
        return -1;
    }
    *manifest_path = argv[optind];
    *paths = (const char **)&argv[optind+1];

    return 0;
}

static size_t
timestamp_to_str(char *str, size_t n, const char *fmt, struct timespec *ts)
{
    char *ns;
    int len;
    struct tm tm;

    localtime_r(&ts->tv_sec, &tm);
    len = strftime(str, n, fmt, &tm);
    if (len == 0)
        return 0;

    ns = strchr(str, '\n');
    if (ns == NULL)
        return 0;

    if (snprintf(ns, 11, ".%09ld", ts->tv_nsec) >= 11)
        return 0;
    ns[10] = ' ';

    return len;
}

static int
parse_ns(const char *ns, long *nsec)
{
    char *endptr;
    long ret;

    ret = strtol(ns, &endptr, 10);
    if (endptr != ns + 9)
        return -1;

    *nsec = ret;
    return 0;
}

static char *
scan_timestamp(char *str, char *key, struct timespec *ts)
{
    char *ns, *tz;
    char *ret;
    long nsec;
    struct tm tm;

    ret = strstr(str, key);
    if (ret == NULL)
        return NULL;

    /* parse nanosecond specification */
    ns = strchr(str, '.');
    if (ns == NULL)
        return NULL;
    tz = strchr(ns, ' ');
    if (tz == NULL)
        return NULL;
    if (parse_ns(ns + 1, &nsec) != 0)
        return NULL;
    memmove(ns, tz, strlen(tz) + 1);

    memset(&tm, 0, sizeof(tm));
    ret = strptime(ret + strlen(key), " " TM_FMT, &tm);
    if (ret == NULL)
        return NULL;
    tm.tm_isdst = -1;

    ts->tv_sec = mktime(&tm);
    if (ts->tv_sec == -1)
        return NULL;
    ts->tv_nsec = nsec;

    return ret;
}

static int
scan_input_file(const char *path, struct radix_tree **data)
{
    char *ln = NULL;
    FILE *f;
    int linenum;
    int res;
    size_t n;
    struct radix_tree *ret;

    f = fopen(path, "r");
    if (f == NULL) {
        error(0, errno, "Error opening %s", path);
        return -errno;
    }

    res = radix_tree_new(&ret, sizeof(struct md_record));
    if (res != 0)
        goto err1;

    errno = 0;
    for (linenum = 1;; linenum++) {
        char buf[PATH_MAX];
        char *tmstr;
        int pathlen;
        struct md_record record;

        if (getline(&ln, &n, f) == -1) {
            if (errno != 0) {
                res = -errno;
                goto err2;
            }
            break;
        }

        res = sscanf(ln, "'%[^']'%n", buf, &pathlen);
        if (res != 1) {
            if ((res != EOF) || !ferror(f))
                goto err3;
            res = -errno;
            goto err2;
        }
        tmstr = scan_timestamp(ln + pathlen, "a:", &record.atim);
        if (tmstr == NULL)
            goto err3;
        if (scan_timestamp(tmstr, "m:", &record.mtim) == NULL)
            goto err3;

        res = radix_tree_insert(ret, buf, &record);
        if (res != 0)
            goto err2;
    }

    if (ln != NULL)
        free(ln);
    fclose(f);

    *data = ret;
    return 0;

err3:
    error(0, 0, "Line %d of %s invalid", linenum, path);
    res = -EINVAL;
err2:
    if (ln != NULL)
        free(ln);
    radix_tree_free(ret);
err1:
    fclose(f);
    return res;
}

static int
input_data_walk_cb(const char *str, void *val, void *ctx)
{
    char outstr[PATH_MAX + 256];
    FILE *f = (FILE *)ctx;
    size_t len, tmp;
    struct md_record *record = (struct md_record *)val;

    len = timestamp_to_str(outstr, sizeof(outstr), "a:" TM_FMT_OUT,
                           &record->atim);
    if (len == 0)
        goto err;

    tmp = timestamp_to_str(outstr + len, sizeof(outstr) - len,
                           "\tm:" TM_FMT_OUT, &record->mtim);
    if (tmp == 0)
        goto err;
    len += tmp;

    tmp = sizeof(outstr) - len;
    if (snprintf(outstr + len, tmp, "\t%s\n", str) >= (int)tmp)
        goto err;

    fputs(outstr, f);

    return 0;

err:
    return -ENAMETOOLONG;
}

static int
print_input_data(FILE *f, struct radix_tree *input_data)
{
    return radix_tree_walk(input_data, &input_data_walk_cb, (void *)f);
}

static int
cmp_timestamps(struct md_record *record, struct stat *s)
{
    return ((record->atim.tv_sec == s->st_atim.tv_sec)
            && (record->atim.tv_nsec == s->st_atim.tv_nsec)
            && (record->mtim.tv_sec == s->st_mtim.tv_sec)
            && (record->mtim.tv_nsec == s->st_mtim.tv_nsec))
           ? 0 : -1;
}

static void
print_timestamps(struct timespec *ts1, struct timespec *ts2)
{
    char buf[256];

    timestamp_to_str(buf, sizeof(buf), TM_FMT_OUT, ts1);
    puts(buf);
    timestamp_to_str(buf, sizeof(buf), TM_FMT_OUT, ts2);
    puts(buf);
}

static int
process_files_cb(int fd, int dirfd, const char *name, const char *path,
                 struct stat *s, void *ctx)
{
    char fullpath[PATH_MAX];
    int ret;
    struct ctx *pctx = (struct ctx *)ctx;
    struct md_record record;

    (void)dirfd;
    (void)name;

    if (S_ISDIR(s->st_mode))
        return 0;

    if (snprintf(fullpath, sizeof(fullpath), "%s/%s", pctx->rootdir, path)
        >= (int)sizeof(fullpath)) {
        error(0, 0, "Cannot process file: File name too long");
        pctx->err = 1;
        return 0;
    }

    if (verbose)
        puts(fullpath);

    ret = radix_tree_search(pctx->data, fullpath, &record);
    if (ret != 1) {
        if (ret == 0) {
            if (!verbose)
                puts(fullpath);
            puts("File added");
            pctx->err = 1;
            return 0;
        }
        return ret;
    }

    if (cmp_timestamps(&record, s) != 0) {
        if (!verbose)
            puts(fullpath);
        puts("Incorrect timestamp\nFile timestamps:");
        print_timestamps(&s->st_atim, &s->st_mtim);
        puts("Correct timestamps:");
        print_timestamps(&record.atim, &record.mtim);
        if (correct_timestamps) {
            struct timespec times[2];

            times[0] = record.atim;
            times[1] = record.mtim;
            if (futimens(fd, times) == -1) {
                error(0, errno, "Error changing file's timestamps");
                pctx->err = 1;
            }
        } else
            pctx->err = 1;
    }

    return radix_tree_delete(pctx->data, fullpath);
}

static int
process_files(const char **paths, struct radix_tree *data)
{
    int err;
    struct ctx pctx;
    struct radix_tree_stats s;

    pctx.data = data;
    pctx.err = 0;

    for (; *paths != NULL; paths++) {
        pctx.rootdir = *paths;
        err = dir_walk(*paths, &process_files_cb, DIR_WALK_ALLOW_ERR, &pctx);
        if (err)
            return err;
    }

    err = radix_tree_stats(data, &s);
    if (err)
        return err;
    if (s.num_info_nodes != 0) {
        puts("Files removed:");
        print_input_data(stdout, data);
        return -EIO;
    }

    return pctx.err ? -EIO : 0;
}

int
main(int argc, char **argv)
{
    const char *manifest_path, **paths;
    int ret;
    struct radix_tree *data;

    setlinebuf(stdout);

    ret = parse_cmdline(argc, argv, &manifest_path, &paths);
    if (ret != 0)
        return (ret == -1) ? EXIT_FAILURE : EXIT_SUCCESS;

    if (scan_input_file(manifest_path, &data) != 0)
        return EXIT_FAILURE;

    ret = process_files(paths, data);

    radix_tree_free(data);

    if (ret != 0)
        error(EXIT_FAILURE, -ret, "Error processing files");

    return EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
