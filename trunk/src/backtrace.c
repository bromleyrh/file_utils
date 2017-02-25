/*
 * backtrace.c
 */

/* TODO: use configure script tests to conditionally include functions requiring
   libunwind */

#define UNW_LOCAL_ONLY

#include <libunwind.h>

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

static int get_proc_name(unw_cursor_t *, char **);

static int
get_proc_name(unw_cursor_t *curs, char **pname)
{
    char *ret;
    int err;
    size_t bufsiz;

    bufsiz = 32;
    ret = malloc(bufsiz);
    if (ret == NULL)
        goto err1;

    for (;;) {
        char *tmp;
        unw_word_t ip;

        err = unw_get_proc_name(curs, ret, bufsiz, &ip);
        if (err != UNW_ENOMEM)
            break;

        bufsiz *= 2;
        tmp = realloc(ret, bufsiz);
        if (tmp == NULL)
            goto err2;
        ret = tmp;
    }

    *pname = err ? NULL : ret;
    return 0;

err2:
    free(ret);
err1:
    return errno;
}

char **
get_backtrace(int *num_symbols)
{
    char **ret;
    int bufsiz, n;
    int i;
    int res;
    unw_context_t ctx;
    unw_cursor_t curs;

    if ((unw_getcontext(&ctx) != 0) || (unw_init_local(&curs, &ctx) != 0))
        return NULL;

    bufsiz = 16;
    ret = malloc((bufsiz+1) * sizeof(*ret));
    if (ret == NULL)
        return NULL;

    for (n = 0;; n++) {
        res = unw_step(&curs);
        if (res < 1) {
            if (res != 0)
                goto err;
            break;
        }

        if (n == bufsiz) {
            char **tmp;

            bufsiz *= 2;
            tmp = realloc(ret, (bufsiz+1) * sizeof(*tmp));
            if (tmp == NULL)
                goto err;
            ret = tmp;
        }

        if (get_proc_name(&curs, &ret[n]) != 0)
            goto err;
        if (ret[n] == NULL)
            goto end;
    }
    ret[n] = NULL;

end:
    if (num_symbols != NULL)
        *num_symbols = n;
    return ret;

err:
    for (i = 0; i < n; i++)
        free(ret[i]);
    free(ret);
    return NULL;
}

void
free_backtrace(char **bt)
{
    int i;

    for (i = 0; bt[i] != NULL; i++)
        free(bt[i]);

    free(bt);
}

/* vi: set expandtab sw=4 ts=4: */
