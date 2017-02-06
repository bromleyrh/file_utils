/*
 * verify_io.c
 */

#include "verify_io.h"

#include <time_ext.h>

#include <adt/queue.h>
#include <adt/set.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <sys/param.h>

#define MIN_TRANSFER_SIZE (512 * 1024)
#define MAX_TRANSFER_SIZE (2 * 1024 * 1024)
#define TRANSFER_GRAN 4096

#define UPDATE_INTERVAL (64 * 1024 * 1024)
#define STATS_WINDOW_SIZE 64

struct ms {
    double      ms;
    unsigned    count;
};

struct io_stats {
    struct queue    *ms_buf;
    struct set      *ms_sorted;
    unsigned        window_size;
    unsigned        num_ms;
    unsigned        num_uniq_ms;
};

struct io_state {
    int             init;
    int             probe_dir;
    size_t          probe_step;
    int             steadiness;
    size_t          transfer_size;
    struct io_stats throughput_stats;
    double          last_throughput;
    size_t          baselen;
    size_t          lastlen;
    size_t          totlen;
    struct timespec t1;
};

static int ms_cmp(const void *, const void *);
static void ms_free(const void *);

static int sorted_stats_add(struct io_stats *, double);
static int sorted_stats_remove(struct io_stats *, double);

static int io_stats_init(struct io_stats *, unsigned);
static void io_stats_destroy(struct io_stats *);
static int io_stats_add(struct io_stats *, double);
static int io_stats_get_median(struct io_stats *, double *, double *, double *);

static int
ms_cmp(const void *k1, const void *k2)
{
    struct ms *ms1 = *(struct ms **)k1;
    struct ms *ms2 = *(struct ms **)k2;

    return (ms1->ms > ms2->ms) - (ms1->ms < ms2->ms);
}

static void
ms_free(const void *k)
{
    struct ms *ms = *(struct ms **)k;

    free(ms);
}

static int
sorted_stats_add(struct io_stats *stats, double ms)
{
    int ret;
    struct ms *m;

    m = malloc(sizeof(*m));
    if (m == NULL)
        return -errno;
    m->ms = ms;
    m->count = 1;

    ret = set_insert(stats->ms_sorted, &m);
    if (ret == 0)
        ++(stats->num_uniq_ms);
    else {
        struct ms *res;

        if (ret != -EADDRINUSE) {
            free(m);
            return ret;
        }
        ret = set_search(stats->ms_sorted, &m, &res);
        free(m);
        if (ret != 1)
            return (ret == 0) ? -EIO : ret;
        ++(res->count);
    }

    return 0;
}

static int
sorted_stats_remove(struct io_stats *stats, double ms)
{
    int ret;
    struct ms m, *mp;

    m.ms = ms;
    mp = &m;
    ret = set_search(stats->ms_sorted, &mp, &mp);
    if (ret != 1)
        return (ret == 0) ? -EIO : ret;

    if (mp->count > 1) {
        --(mp->count);
        return 0;
    }

    ret = set_delete(stats->ms_sorted, &mp);
    if (ret != 0)
        return ret;
    free(mp);
    --(stats->num_uniq_ms);

    return 0;
}

static int
io_stats_init(struct io_stats *stats, unsigned window_size)
{
    int err;

    if ((window_size == 0) || (window_size > 4096 / sizeof(double)))
        return -EINVAL;

    err = queue_new(&stats->ms_buf, QUEUE_FNS_CIRCULAR_BUF, sizeof(double),
                    NULL);
    if (err)
        return err;

    err = set_new(&stats->ms_sorted, SET_FNS_AVL_TREE, sizeof(struct ms *),
                  &ms_cmp, &ms_free);
    if (err) {
        queue_free(stats->ms_buf);
        return err;
    }

    stats->window_size = window_size;
    stats->num_ms = stats->num_uniq_ms = 0;

    return 0;
}

static void
io_stats_destroy(struct io_stats *stats)
{
    queue_free(stats->ms_buf);
    set_free(stats->ms_sorted);
}

static int
io_stats_add(struct io_stats *stats, double ms)
{
    int err;

    if (stats->num_ms >= stats->window_size) {
        double ret;

        if ((err = queue_pop_front(stats->ms_buf, &ret))
            || (err = sorted_stats_remove(stats, ret)))
            return err;
        --(stats->num_ms);
    }
    if ((err = queue_push_back(stats->ms_buf, &ms))
        || (err = sorted_stats_add(stats, ms)))
        return err;
    ++(stats->num_ms);

    return 0;
}

static int
io_stats_get_median(struct io_stats *stats, double *ms, double *min,
                    double *max)
{
    double maximum, median, minimum;
    int mididx;
    int ret;
    struct ms *m;

    /* FIXME: account for duplicate measurements */

    mididx = stats->num_uniq_ms / 2;

    ret = set_select(stats->ms_sorted, mididx, &m);
    if (ret != 1)
        goto err;
    median = m->ms;

    ret = set_select(stats->ms_sorted, 0, &m);
    if (ret != 1)
        goto err;
    minimum = m->ms;

    ret = set_select(stats->ms_sorted, stats->num_uniq_ms - 1, &m);
    if (ret != 1)
        goto err;
    maximum = m->ms;

    *ms = median;
    *min = minimum;
    *max = maximum;
    return 0;

err:
    return (ret == 0) ? -EIO : ret;
}

int
io_state_init(struct io_state **state)
{
    int err;
    struct io_state *ret;

    ret = malloc(sizeof(*ret));
    if (ret == NULL)
        return -errno;

    err = io_stats_init(&ret->throughput_stats, STATS_WINDOW_SIZE);
    if (err) {
        free(ret);
        return err;
    }

    ret->init = 1;
    ret->last_throughput = 0.0;

    *state = ret;
    return 0;
}

void
io_state_free(struct io_state *state)
{
    io_stats_destroy(&state->throughput_stats);

    free(state);
}

size_t
io_state_update(struct io_state *state, size_t len, double tp)
{
    double throughput;
    double min, max;
    struct timespec dt, t2;

    if (state->init) {
        state->probe_dir = 0;
        state->probe_step = TRANSFER_GRAN;
        state->transfer_size = MIN_TRANSFER_SIZE;

        state->baselen = 0;
        state->totlen = state->lastlen = 0;
        clock_gettime(CLOCK_MONOTONIC_RAW, &state->t1);

        state->init = 0;
        goto end;
    }

    len -= state->baselen;
    state->totlen += len - state->lastlen;
    state->lastlen = len;

    if (state->totlen < UPDATE_INTERVAL)
        goto end;

    if (tp < 0.0) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &t2);
        timespec_diff(&t2, &state->t1, &dt);
        throughput = state->totlen
                     / (dt.tv_sec + dt.tv_nsec * 0.000000001)
                     / (1024 * 1024);
    } else
        throughput = tp;

    if ((io_stats_add(&state->throughput_stats, throughput) != 0)
        || (io_stats_get_median(&state->throughput_stats, &throughput, &min,
                                &max) != 0))
        goto end;
    fprintf(stderr, "\rThroughput: %12.6f, %12.6f, %12.6f MiB/s", min,
            throughput, max);

    if ((int)(throughput * 100) == (int)(state->last_throughput * 100))
        ++(state->steadiness);
    else
        state->steadiness = 0;

    if (state->probe_dir == 0)
        state->probe_dir = 1;
    else if (state->steadiness > 128) {
        state->probe_dir *= -1;
        state->steadiness = 0;
    } else {
        int prev_probe_dir;

        prev_probe_dir = state->probe_dir;
        state->probe_dir *= -1 + 2
                            * (((int)(throughput * 100)
                               - (int)(state->last_throughput * 100)) >= 0);
        if (state->probe_dir == prev_probe_dir) {
            state->probe_step = MIN(1024 * 1024,
                                    state->probe_step + TRANSFER_GRAN);
        } else
            state->probe_step = TRANSFER_GRAN;
    }
    if (state->probe_dir > 0) {
        state->transfer_size = MIN(MAX_TRANSFER_SIZE,
                                   state->transfer_size + state->probe_step);
    } else if (state->probe_dir < 0) {
        if (state->probe_step >= state->transfer_size)
            state->transfer_size = MIN_TRANSFER_SIZE;
        else {
            state->transfer_size = MAX(MIN_TRANSFER_SIZE,
                                       state->transfer_size
                                       - state->probe_step);
        }
    }
    fprintf(stderr, " (transfer size %7zd)", state->transfer_size);

    state->last_throughput = throughput;

    state->baselen += state->totlen;
    state->totlen = state->lastlen = 0;
    clock_gettime(CLOCK_MONOTONIC_RAW, &state->t1);

end:
    return state->transfer_size;
}

/* vi: set expandtab sw=4 ts=4: */
