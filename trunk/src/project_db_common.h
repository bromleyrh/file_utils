/*
 * project_db_common.h
 */

#ifndef _PROJECT_DB_COMMON_H
#define _PROJECT_DB_COMMON_H

#define ___STATIC_ASSERT(expr, msg) \
    typedef char assertion_##msg[(expr) ? 1 : -1]
#define __STATIC_ASSERT(expr, line) ___STATIC_ASSERT(expr, at_line_##line)
#define _STATIC_ASSERT(expr, line) __STATIC_ASSERT(expr, line)
#define STATIC_ASSERT(expr) _STATIC_ASSERT(expr, __LINE__)

#endif

/* vi: set expandtab sw=4 ts=4: */
