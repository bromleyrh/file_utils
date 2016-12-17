/*
 * replicate.c
 */

#define _GNU_SOURCE

#include "replicate.h"

#include <json.h>

#include <json/grammar.h>
#include <json/grammar_parse.h>

#include <libmount/libmount.h>

#include <hashes.h>
#include <strings_ext.h>

#include <files/util.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define CONFIG_PATH "replicate.conf"
#define CONFIG_ROOT_ID "conf"

#define FORMAT_CMD_DEST_SPECIFIER "$dest"

struct ctx {
    struct transfer *transfers;
    int             num_transfers;
    uid_t           uid;
    gid_t           gid;
};

struct transfer {
    const char *srcpath;
    const char *dstpath;
    const char *format_cmd;
};

struct copy_args {
    int     srcfd;
    int     dstfd;
    uid_t   uid;
    gid_t   gid;
};

static int debug;

static void debug_print(const char *, ...);

static int get_gid(const char *, gid_t *);
static int get_uid(const char *, uid_t *);

static int run_cmd(const char *);

static int mount_filesystem(const char *, const char **, int);
static int unmount_filesystem(const char *, int);

static int format_device(const char *, const char *);

static int copy_fn(void *);

static int do_copy(struct copy_args *);

static int do_transfers(struct ctx *);
static void print_transfers(FILE *, struct transfer *, int);
static void free_transfers(struct transfer *, int);

static int parse_json_config(const char *, const struct json_parser *,
                             json_val_t *);

static int read_copy_creds_opt(json_val_t, void *);
static int read_debug_opt(json_val_t, void *);
static int read_transfers_opt(json_val_t, void *);
static int read_json_config(json_val_t, struct ctx *);

static int parse_config(const char *, struct ctx *);

static void
debug_print(const char *fmt, ...)
{
    if (debug) {
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fputc('\n', stderr);
    }
}

static int
get_gid(const char *name, gid_t *gid)
{
    char *buf;
    int err;
    size_t bufsize;
    struct group grp, *res;

    bufsize = (size_t)sysconf(_SC_GETGR_R_SIZE_MAX);
    if (bufsize == (size_t)-1)
        bufsize = 1024;

    buf = malloc(bufsize);
    if (buf == NULL)
        return -errno;

    for (;;) {
        char *tmp;

        err = getgrnam_r(name, &grp, buf, bufsize, &res);
        if (!err)
            break;
        if (err != ERANGE)
            goto err;

        bufsize *= 2;
        tmp = realloc(buf, bufsize);
        if (tmp == NULL) {
            err = -errno;
            goto err;
        }
        buf = tmp;
    }
    if (res == NULL) {
        err = -ENOENT;
        goto err;
    }

    *gid = grp.gr_gid;

    free(buf);

    return 0;

err:
    free(buf);
    return err;
}

static int
get_uid(const char *name, uid_t *uid)
{
    char *buf;
    int err;
    size_t bufsize;
    struct passwd pwd, *res;

    bufsize = (size_t)sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == (size_t)-1)
        bufsize = 1024;

    buf = malloc(bufsize);
    if (buf == NULL)
        return -errno;

    for (;;) {
        char *tmp;

        err = getpwnam_r(name, &pwd, buf, bufsize, &res);
        if (!err)
            break;
        if (err != ERANGE)
            goto err;

        bufsize *= 2;
        tmp = realloc(buf, bufsize);
        if (tmp == NULL) {
            err = -errno;
            goto err;
        }
        buf = tmp;
    }
    if (res == NULL) {
        err = -ENOENT;
        goto err;
    }

    *uid = pwd.pw_uid;

    free(buf);

    return 0;

err:
    free(buf);
    return err;
}

static int
run_cmd(const char *cmd)
{
    char **argv;
    int err = 0;
    int i;
    int status;
    pid_t pid;

    argv = strwords(cmd, " \t", '"', '\\');
    if (argv == NULL)
        return -errno;

    pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        error(EXIT_FAILURE, errno, "Error executing %s", argv[0]);
        return EXIT_FAILURE;
    }
    if (pid == -1) {
        err = -errno;
        goto end;
    }

    while (waitpid(pid, &status, 0) == -1) {
        if (errno != EINTR) {
            err = -errno;
            goto end;
        }
    }

    if (!WIFEXITED(status)) {
        err = -EIO;
        goto end;
    }
    err = WEXITSTATUS(status);

end:
    for (i = 0; argv[i] != NULL; i++)
        free(argv[i]);
    free(argv);
    return err;
}

static int
mount_filesystem(const char *devpath, const char **mntpath, int read)
{
    const char *rootdir;
    int mflags;
    int ret;
    struct libmnt_context *mntctx;

    debug_print("Mounting %s", devpath ? devpath : *mntpath);

    mntctx = mnt_new_context();
    if (mntctx == NULL)
        return -ENOMEM;

    mflags = MS_NODEV | MS_NOEXEC;
    if (read)
        mflags |= MS_RDONLY;

    if (mnt_context_set_mflags(mntctx, mflags) != 0)
        goto err1;

    if (devpath != NULL) {
        if (mnt_context_set_source(mntctx, devpath) != 0)
            goto err2;
        rootdir = mnt_context_get_target(mntctx);
        if (rootdir == NULL)
            goto err2;
        rootdir = strdup(rootdir);
        if (rootdir == NULL)
            goto err2;
    } else {
        if (mnt_context_set_target(mntctx, *mntpath) != 0)
            goto err2;
        rootdir = *mntpath;
    }

    /* requires CAP_SYS_ADMIN */
    ret = mnt_context_mount(mntctx);

    mnt_free_context(mntctx);

    if (ret != 0)
        goto err3;

    /* open root directory to provide a handle for subsequent operations */
    ret = open(rootdir, O_DIRECTORY | O_RDONLY);
    if (ret == -1) {
        ret = -errno;
        goto err3;
    }

    *mntpath = rootdir;
    return ret;

err3:
    if (devpath != NULL)
        free((void *)rootdir);
    return (ret > 0) ? -ret : ret;

err2:
    mnt_free_context(mntctx);
err1:
    return -EIO;
}

static int
unmount_filesystem(const char *path, int rootfd)
{
    int ret;
    struct libmnt_context *mntctx;

    debug_print("Unmounting %s", path);

    mntctx = mnt_new_context();
    if (mntctx == NULL)
        return -ENOMEM;

    if (mnt_context_set_target(mntctx, path) != 0) {
        mnt_free_context(mntctx);
        return -EIO;
    }

    /* explicitly synchronize filesystem for greater assurance of data
       integrity if filesystem is writable */
    syncfs(rootfd);

    close(rootfd);

    /* requires CAP_SYS_ADMIN */
    ret = mnt_context_umount(mntctx);

    mnt_free_context(mntctx);

    return (ret > 0) ? -ret : ret;
}

static int
format_device(const char *path, const char *cmd)
{
    const char *fullcmd;
    int err;

    debug_print("Formatting device %s", path);

    fullcmd = strsub(cmd, FORMAT_CMD_DEST_SPECIFIER, path);
    if (fullcmd == NULL)
        return -errno;

    debug_print("Running \"%s\"", fullcmd);
    err = run_cmd(fullcmd);

    free((void *)fullcmd);

    return err;
}

static int
copy_fn(void *arg)
{
    struct copy_args *cargs = (struct copy_args *)arg;

    if ((cargs->gid > 0) && (setgid(cargs->gid) == -1)) {
        error(0, errno, "Error changing group");
        return errno;
    }
    if ((cargs->uid > 0) && (setuid(cargs->uid) == -1)) {
        error(0, errno, "Error changing user");
        return errno;
    }

    return dir_copy(cargs->srcfd, cargs->dstfd,
                    DIR_COPY_DISCARD_CACHE | DIR_COPY_TMPFILE);
}

static int
do_copy(struct copy_args *copy_args)
{
    int status;
    pid_t pid;

    static char copy_stack[16 * 1024 * 1024];

    pid = clone(&copy_fn, copy_stack + sizeof(copy_stack),
                CLONE_FILES | CLONE_VM, copy_args);
    if (pid == -1) {
        error(0, errno, "Error creating process");
        return -errno;
    }

    while (waitpid(pid, &status, 0) == -1) {
        if (errno != EINTR)
            return errno;
    }

    if (!WIFEXITED(status))
        return -EIO;

    return -WEXITSTATUS(status);
}

static int
do_transfers(struct ctx *ctx)
{
    const char *dstroot;
    int err;
    int i;
    struct copy_args ca;
    struct transfer *transfer;

    for (i = 0; i < ctx->num_transfers; i++) {
        transfer = &ctx->transfers[i];

        debug_print("Transfer %d:", i + 1);

        ca.srcfd = mount_filesystem(NULL, &transfer->srcpath, 1);
        if (ca.srcfd < 0) {
            error(0, -ca.srcfd, "Error mounting %s", transfer->srcpath);
            return ca.srcfd;
        }

        err = format_device(transfer->dstpath, transfer->format_cmd);
        if (err) {
            if (err > 0)
                error(0, 0, "Formatting command returned status %d", err);
            goto err1;
        }

        ca.dstfd = mount_filesystem(transfer->dstpath, &dstroot, 0);
        if (ca.dstfd < 0) {
            error(0, -ca.dstfd, "Error mounting %s", transfer->dstpath);
            err = ca.dstfd;
            goto err1;
        }

        /* change ownership of destination root directory if needed */
        if ((ctx->uid != 0) && (fchown(ca.dstfd, ctx->uid, (gid_t)-1) == -1))
            goto err2;

        ca.uid = ctx->uid;
        ca.gid = ctx->gid;
        err = do_copy(&ca);
        if (err)
            goto err2;

        err = unmount_filesystem(dstroot, ca.dstfd);
        free((void *)dstroot);
        if (err)
            goto err1;

        err = unmount_filesystem(transfer->srcpath, ca.srcfd);
        if (err)
            return err;
    }

    return 0;

err2:
    unmount_filesystem(dstroot, ca.dstfd);
    free((void *)dstroot);
err1:
    unmount_filesystem(transfer->srcpath, ca.srcfd);
    return err;
}

static void
print_transfers(FILE *f, struct transfer *transfers, int num)
{
    int i;

    for (i = 0; i < num; i++) {
        struct transfer *transfer = &transfers[i];

        fprintf(f,
                "Transfer %d:\n"
                "\tSource directory path: %s\n"
                "\tDestination device path: %s\n"
                "\tDestination formatting command: \"%s\"\n",
                i + 1,
                transfer->srcpath,
                transfer->dstpath,
                transfer->format_cmd);
    }
}

static void
free_transfers(struct transfer *transfers, int num)
{
    int i;

    for (i = 0; i < num; i++) {
        struct transfer *transfer = &transfers[i];

        free((void *)(transfer->srcpath));
        free((void *)(transfer->dstpath));
        free((void *)(transfer->format_cmd));
    }

    free(transfers);
}

static int
parse_json_config(const char *path, const struct json_parser *parser,
                  json_val_t *config)
{
    char *conf;
    int err;
    int fd;
    struct stat s;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        error(0, errno, "Error opening %s", path);
        return -1;
    }

    if (fstat(fd, &s) == -1) {
        error(0, errno, "Error accessing %s", path);
        goto err;
    }

    conf = mmap(NULL, s.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (conf == MAP_FAILED) {
        error(0, errno, "Error accessing %s", path);
        goto err;
    }
    conf[s.st_size-1] = '\0';

    close(fd);

    err = json_grammar_validate(conf, NULL, NULL, parser, config);

    munmap((void *)conf, s.st_size);

    if (err) {
        error(0, -err, "Error parsing %s", path);
        return -1;
    }

    return 0;

err:
    close(fd);
    return -1;
}

static int
read_copy_creds_opt(json_val_t opt, void *data)
{
    char *buf;
    int err;
    json_object_elem_t elem;
    mbstate_t s;
    struct ctx *ctx = (struct ctx *)data;

    memset(&s, 0, sizeof(s));

    err = json_val_object_get_elem_by_key(opt, L"uid", &elem);
    if (!err) {
        if (awcstombs((char **)&buf, json_val_string_get(elem.value), &s)
            == (size_t)-1)
            return -errno;
        ctx->uid = atoi(buf);
        free(buf);

        err = json_val_object_get_elem_by_key(opt, L"gid", &elem);
        if (err)
            return err;
        memset(&s, 0, sizeof(s));
        if (awcstombs((char **)&buf, json_val_string_get(elem.value), &s)
            == (size_t)-1)
            return -errno;
        ctx->gid = atoi(buf);
        free(buf);
    } else if (err == -EINVAL) {
        err = json_val_object_get_elem_by_key(opt, L"user", &elem);
        if (err)
            return err;
        if (awcstombs((char **)&buf, json_val_string_get(elem.value), &s)
            == (size_t)-1)
            return -errno;
        err = get_uid(buf, &ctx->uid);
        free(buf);
        if (err)
            return err;

        err = json_val_object_get_elem_by_key(opt, L"group", &elem);
        if (err)
            return err;
        memset(&s, 0, sizeof(s));
        if (awcstombs((char **)&buf, json_val_string_get(elem.value), &s)
            == (size_t)-1)
            return -errno;
        if (strcmp(buf, "-") == 0)
            ctx->gid = (gid_t)-1;
        else {
            err = get_gid(buf, &ctx->gid);
            if (err) {
                free(buf);
                return err;
            }
        }
        free(buf);
    } else
        return err;

    return 0;
}

static int
read_debug_opt(json_val_t opt, void *data)
{
    (void)data;

    debug = json_val_boolean_get(opt);

    return 0;
}

static int
read_transfers_opt(json_val_t opt, void *data)
{
    int err;
    int i;
    struct ctx *ctx = (struct ctx *)data;
    struct transfer *transfer;

    ctx->num_transfers = json_val_array_get_num_elem(opt);

    ctx->transfers = calloc(ctx->num_transfers, sizeof(*(ctx->transfers)));
    if (ctx->transfers == NULL)
        return -errno;

    for (i = 0; i < ctx->num_transfers; i++) {
        char *tmp;
        json_object_elem_t elem;
        json_val_t val;
        mbstate_t s;

        val = json_val_array_get_elem(opt, i);
        if (val == NULL) {
            err = -EIO;
            goto err1;
        }

        transfer = &ctx->transfers[i];

        err = json_val_object_get_elem_by_key(val, L"src", &elem);
        if (err)
            goto err1;
        memset(&s, 0, sizeof(s));
        if (awcstombs((char **)&transfer->srcpath,
                      json_val_string_get(elem.value), &s) == (size_t)-1) {
            err = -errno;
            goto err1;
        }

        err = json_val_object_get_elem_by_key(val, L"dest", &elem);
        if (err)
            goto err2;
        memset(&s, 0, sizeof(s));
        if (awcstombs((char **)&transfer->dstpath,
                      json_val_string_get(elem.value), &s) == (size_t)-1) {
            err = -errno;
            goto err2;
        }

        err = json_val_object_get_elem_by_key(val, L"format_cmd", &elem);
        if (err)
            goto err3;
        memset(&s, 0, sizeof(s));
        if (awcstombs((char **)&transfer->format_cmd,
                      json_val_string_get(elem.value), &s) == (size_t)-1) {
            err = -errno;
            goto err3;
        }
        tmp = strstr(transfer->format_cmd, FORMAT_CMD_DEST_SPECIFIER);
        if (tmp == NULL) {
            error(0, 0, "\"format_cmd\" option missing \""
                  FORMAT_CMD_DEST_SPECIFIER "\"");
            err = -EINVAL;
            goto err3;
        }
        tmp = strstr(tmp + sizeof(FORMAT_CMD_DEST_SPECIFIER) - 1,
                     FORMAT_CMD_DEST_SPECIFIER);
        if (tmp != NULL) {
            error(0, 0, "\"format_cmd\" option must contain only one instance "
                  "of \"" FORMAT_CMD_DEST_SPECIFIER "\"");
            err = -EINVAL;
            goto err3;
        }
    }

    return 0;

err3:
    free((void *)(transfer->dstpath));
err2:
    free((void *)(transfer->srcpath));
err1:
    free_transfers(ctx->transfers, i);
    return err;
}

static int
read_json_config(json_val_t config, struct ctx *ctx)
{
    int err;
    int i, numopt;

    static const struct {
        const wchar_t   *opt;
        int             (*fn)(json_val_t, void *);
    } opts[8] = {
        [0] = {L"copy_creds",   &read_copy_creds_opt},
        [1] = {L"debug",        &read_debug_opt},
        [5] = {L"transfers",    &read_transfers_opt}
    }, *opt;

    numopt = json_val_object_get_num_elem(config);
    for (i = 0; i < numopt; i++) {
        json_object_elem_t elem;

        err = json_val_object_get_elem_by_idx(config, i, &elem);
        if (err)
            return err;

        opt = &opts[(hash_str(elem.key, -1) >> 2) & 7];
        if ((opt->opt == NULL) || (wcscmp(elem.key, opt->opt) != 0))
            return -EIO;

        err = (*(opt->fn))(elem.value, ctx);
        if (err)
            return err;
    }

    return 0;
}

static int
parse_config(const char *path, struct ctx *ctx)
{
    int err;
    json_val_t config;
    struct json_parser *parser;

    err = json_parser_init(CONFIG_GRAM, CONFIG_ROOT_ID, &parser);
    if (err)
        return err;

    err = parse_json_config(path, parser, &config);
    json_parser_destroy(parser);
    if (err)
        return err;

    err = read_json_config(config, ctx);

    json_val_free(config);

    return err;
}

int
main(int argc, char **argv)
{
    int ret;
    struct ctx ctx;

    (void)argc;
    (void)argv;

    ctx.uid = ctx.gid = 0;

    ret = parse_config(CONFIG_PATH, &ctx);
    if (ret != 0)
        return EXIT_FAILURE;
    print_transfers(stdout, ctx.transfers, ctx.num_transfers);
    printf("UID: %d\nGID: %d\n", ctx.uid, ctx.gid);

    /* requires CAP_SYS_ADMIN */
    ret = unshare(CLONE_NEWNS);
    if (ret == -1) {
        error(0, -ret, "Error unsharing namespace");
        goto end;
    }

    ret = do_transfers(&ctx);

end:
    free_transfers(ctx.transfers, ctx.num_transfers);
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
