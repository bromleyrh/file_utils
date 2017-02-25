/*
 * backtrace.h
 */

#ifndef _BACKTRACE_H
#define _BACKTRACE_H

char **get_backtrace(int *num_symbols);
void free_backtrace(char **bt);

#endif

/* vi: set expandtab sw=4 ts=4: */
