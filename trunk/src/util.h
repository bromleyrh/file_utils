/*
 * util.h
 */

#ifndef _UTIL_H
#define _UTIL_H

#include <stddef.h>

void *do_malloc(size_t size);
void *do_allocarray(size_t nmemb, size_t size);
void *do_calloc(size_t nmemb, size_t size);
void *do_realloc(void *ptr, size_t size);
void *do_reallocarray(void *ptr, size_t nmemb, size_t size);

#define oemalloc(ptr) (*(ptr) = do_malloc(sizeof(**(ptr))))
#define oeallocarray(ptr, nmemb) \
    (*(ptr) = do_allocarray(nmemb, sizeof(**(ptr))))
#define oecalloc(ptr, nmemb) (*(ptr) = do_calloc(nmemb, sizeof(**(ptr))))
#define oereallocarray(oldptr, ptr, nmemb) \
    (*(ptr) = do_reallocarray(oldptr, nmemb, sizeof(**(ptr))))

#endif

/* vi: set expandtab sw=4 ts=4: */
