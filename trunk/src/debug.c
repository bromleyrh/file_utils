/*
 * debug.c
 */

#include "debug.h"
#include "util.h"

#define ASSERT_MACROS
#include "common.h"
#undef ASSERT_MACROS

#include <avl_tree.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>

#if defined(__GLIBC__) || defined(__APPLE__)
#define HAVE_BACKTRACE
#endif

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#endif

#ifdef __linux__
#define HAVE_ADDR2LINE
#endif

struct err_info {
    int     errdes;
    int     errcode;
    void    *data;
};

struct err_info_walk_ctx {
    int     (*cb)(int, void *, void *);
    void    *ctx;
};

static _Thread_local struct err_data {
    int             curr_errdes;
    struct avl_tree *err_info;
} err_data;

#ifdef HAVE_ADDR2LINE
static int close_pipe(int [2]);

#endif
static int err_info_cmp(const void *, const void *, void *);
static int err_info_walk_cb(const void *, void *);

static int init_err_data(struct err_data *);

#ifdef HAVE_ADDR2LINE
static int xlat_addr2line_bt(FILE *, const char *, const char *, unsigned);

#endif

#ifdef HAVE_ADDR2LINE
static int
close_pipe(int pfd[2])
{
    int err;

    err = close(pfd[0]) == -1 ? MINUS_ERRNO : 0;
    return close(pfd[1]) == -1 ? MINUS_ERRNO : err;
}

#endif

static int
err_info_cmp(const void *k1, const void *k2, void *ctx)
{
    const struct err_info *info1 = k1;
    const struct err_info *info2 = k2;

    (void)ctx;

    return (info1->errdes > info2->errdes) - (info1->errdes < info2->errdes);
}

static int
err_info_walk_cb(const void *keyval, void *ctx)
{
    const struct err_info *info = keyval;
    const struct err_info_walk_ctx *ectx = ctx;

    return (*ectx->cb)(info->errcode, info->data, ectx->ctx);
}

static int
init_err_data(struct err_data *err_data)
{
    int err;

    err = avl_tree_new(&err_data->err_info, sizeof(struct err_info),
                       &err_info_cmp, 0, NULL, NULL, NULL);
    if (!err)
        err_data->curr_errdes = ERRDES_MIN;

    return err;
}

#ifdef HAVE_ADDR2LINE
static int
xlat_addr2line_bt(FILE *f, const char *fmt, const char *path, unsigned reloff)
{
    char *str1, *str2;
    FILE *inf, *outf;
    int err, res;
    int inpfd[2], outpfd[2];
    size_t len;
    pid_t pid;

    if (pipe(inpfd) == -1)
        return MINUS_ERRNO;
    if (pipe(outpfd) == -1) {
        err = MINUS_ERRNO;
        close_pipe(inpfd);
        return err;
    }

    inf = outf = NULL;

    pid = fork();
    if (pid == 0) {
        close(inpfd[1]);
        close(outpfd[0]);

        if (dup2(inpfd[0], STDIN_FILENO) != -1
            && dup2(outpfd[1], STDOUT_FILENO) != -1)
            execlp("addr2line", "addr2line", "-e", path, "-f", "-s", NULL);

        close(inpfd[0]);
        close(outpfd[1]);
        _exit(EXIT_FAILURE);
    }
    close(inpfd[0]);
    close(outpfd[1]);
    if (pid == -1)
        goto err3;

    inf = fdopen(inpfd[1], "w");
    if (inf == NULL)
        goto err3;
    if (setvbuf(inf, NULL, _IOLBF, 0) == EOF) {
        err = -ENOMEM;
        goto err2;
    }
    outf = fdopen(outpfd[0], "r");
    if (outf == NULL)
        goto err3;

    if (fprintf(inf, "%x\n", reloff) < 0) {
        err = -EIO;
        goto err2;
    }

    str1 = NULL;
    len = 0;
    if (getline(&str1, &len, outf) == -1) {
        err = errno == 0 ? -EIO : MINUS_ERRNO;
        goto err2;
    }
    len = strlen(str1);
    if (len > 0) {
        --len;
        if (str1[len] == '\n')
            str1[len] = '\0';
    }

    str2 = NULL;
    len = 0;
    if (getline(&str2, &len, outf) == -1) {
        err = errno == 0 ? -EIO : MINUS_ERRNO;
        free(str1);
        goto err2;
    }
    len = strlen(str2);
    if (len > 1) {
        --len;
        if (str2[len] == '\n')
            str2[len] = '\0';
    }

    res = fprintf(f, fmt, str1, str2);
    free(str1);
    free(str2);
    if (res < 0) {
        err = -EIO;
        goto err2;
    }

    fclose(outf);
    if (fclose(inf) == EOF) {
        err = MINUS_ERRNO;
        goto err1;
    }

    return waitpid(pid, &res, 0) == -1
           || !WIFEXITED(res) || WEXITSTATUS(res) != 0
           ? MINUS_ERRNO : 0;

err3:
    err = MINUS_ERRNO;
err2:
    if (outf == NULL)
        close(outpfd[0]);
    else
        fclose(outf);
    if (inf == NULL)
        close(inpfd[1]);
    else
        fclose(inf);
err1:
    if (pid != -1)
        waitpid(pid, &res, 0);
    return err;
}

#endif

int
err_tag(int errcode, void *data)
{
    int errdes;
    struct err_info info;

    if (errcode >= ERRDES_MIN)
        errcode = -EIO;

    if (err_data.err_info == NULL) {
        if (init_err_data(&err_data) != 0)
            goto err;
    } else if (err_data.curr_errdes == 0) /* overflow */
        goto err;

    errdes = err_data.curr_errdes;

    info.errdes = errdes;
    info.errcode = errcode;
    info.data = data;

    if (avl_tree_insert(err_data.err_info, &info) != 0)
        goto err;

    err_data.curr_errdes = errdes == INT_MAX ? 0 : errdes + 1;

    return errdes;

err:
    return errcode;
}

void *
err_get(int errdes, int *errcode)
{
    struct err_info info;

    if (err_data.err_info == NULL)
        goto err;

    info.errdes = errdes;

    if (avl_tree_search(err_data.err_info, &info, &info) != 1)
        goto err;

    *errcode = info.errcode;
    return info.data;

err:
    *errcode = errdes;
    return NULL;
}

int
err_get_code(int errdes)
{
    int ret;

    err_get(errdes, &ret);

    return ret;
}

int
err_clear(int errdes)
{
    int err;
    struct err_info info;

    if (err_data.err_info == NULL)
        return -ENOENT;

    info.errdes = errdes;

    err = avl_tree_delete(err_data.err_info, &info);
    if (!err && errdes == err_data.curr_errdes - 1)
        err_data.curr_errdes = errdes;

    return err;
}

int
err_foreach(int (*cb)(int, void *, void *), void *ctx)
{
    avl_tree_walk_ctx_t wctx = NULL;
    struct err_info_walk_ctx ectx;

    ectx.cb = cb;
    ectx.ctx = ctx;

    return avl_tree_walk(err_data.err_info, NULL, &err_info_walk_cb, &ectx,
                         &wctx);
}

int
_err_tag_bt(int errcode, const char *file, int line)
{
    struct err_info_bt *info;
    int res;
    void *array[32];

    (void)array;

    info = malloc(sizeof(*info));
    if (info == NULL)
        return errcode;

    info->file = file;
    info->line = line;
    info->bt = NULL;
    info->len = 0;

#ifdef HAVE_BACKTRACE
    res = backtrace(array, ARRAY_SIZE(array));
    if (res > 0) {
        info->bt = backtrace_symbols(array, res);
        info->len = res;
    }

#endif
    res = err_tag(errcode, info);
    if (res >= ERRDES_MIN)
        info->errdes = res;
    else
        free(info);

    return res;
}

struct err_info_bt *
err_get_bt(int *err)
{
    return err_get(*err, err);
}

int
err_info_free(struct err_info_bt *info, int freeall)
{
    int err;

    err = err_clear(info->errdes);
    if (!err) {
        if (freeall)
            free(info->bt);
        free(info);
    }

    return err;
}

int
err_print(FILE *f, int *err)
{
    char strerrbuf[256];
    int i;
    int ret;
    struct err_info_bt *info;

    info = err_get_bt(err);
    if (info == NULL)
        return 0;

    ret = -EIO;

    if (fprintf(f, "Error at %s:%d\n", info->file, info->line) < 0)
        goto end;

    for (i = 1; i < info->len; i++) {
#ifdef HAVE_ADDR2LINE
        char buf[PATH_MAX];
        unsigned off, reloff;

        if (sscanf(info->bt[i], "%" STR(PATH_MAX) "[^(](+0x%x) [0x%x]",
                   buf, &reloff, &off)
            == 3
            || sscanf(info->bt[i], "%" STR(PATH_MAX) "[^(]() [0x%x]",
                      buf, &reloff)
               == 2) {
            if (xlat_addr2line_bt(f, "%32s(), %s\n", buf, reloff) != 0)
                goto end;
            continue;
        }

        if (sscanf(info->bt[i], "%*[^(](%64[^+]+0x%x) [0x%x]", buf, &reloff,
                   &off)
            == 3) {
            if (fprintf(f, "%32s(), +0x%04x byte%s\n", buf, PL(reloff)) < 0)
                goto end;
            continue;
        }

#endif
        if (fprintf(f, "%s\n", info->bt[i]) < 0)
            goto end;
    }

    if (fprintf(f, "%s\n", strperror_r(-*err, strerrbuf, sizeof(strerrbuf)))
        >= 0)
        ret = 0;

end:
    err_info_free(info, 1);
    return ret;
}

/* vi: set expandtab sw=4 ts=4: */
