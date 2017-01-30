/*
 * verify_io.h
 */

#ifndef _VERIFY_IO_H
#define _VERIFY_IO_H

#include <stddef.h>

struct io_state;

int io_state_init(struct io_state **state);
void io_state_free(struct io_state *state);

size_t io_state_update(struct io_state *state, size_t len, double tp);

#endif

/* vi: set expandtab sw=4 ts=4: */
