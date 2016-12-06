/*
 * xattrs.xs
 *
 * vi: set expandtab sw=4 ts=4:
 */

#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/xattr.h>

/* export XATTR_* flag constants */
#include "const-c.inc"

static int err_to_retval(int);

static int do_setxattr(const char *, const char *, const void *, size_t, int);
static int do_fsetxattr(int, const char *, const void *, size_t, int);

static int do_getxattr(int, const char *, SV *, int);
static int do_fgetxattr(int, const char *, void *, size_t, int);

static int xattr_buf_to_av(const char *, size_t, AV *);

static int do_listxattr(int, AV *, int);
static int do_flistxattr(int, char *, size_t, int);

static int do_removexattr(const char *, const char *, int);
static int do_fremovexattr(int, const char *, int);

static int
err_to_retval(int err)
{
    return (err == -1) ? errno : err;
}

static int
do_setxattr(const char *path, const char *name, const void *value, size_t size,
            int options)
{
#ifdef __APPLE__
    return setxattr(path, name, value, size, 0, options);
#else
#ifdef __linux__
    return setxattr(path, name, value, size, options);
#else
    (void)path;
    (void)name;
    (void)value;
    (void)size;
    (void)options;

    return -ENOTSUP;
#endif
#endif
}

static int
do_fsetxattr(int fd, const char *name, const void *value, size_t size,
             int options)
{
#ifdef __APPLE__
    return fsetxattr(fd, name, value, size, 0, options);
#else
#ifdef __linux__
    return fsetxattr(fd, name, value, size, options);
#else
    (void)fd;
    (void)name;
    (void)value;
    (void)size;
    (void)options;

    return -ENOTSUP;
#endif
#endif
}

static int
do_fgetxattr(int fd, const char *name, void *value, size_t size, int options)
{
#ifdef __APPLE__
    return fgetxattr(fd, name, value, size, 0, options);
#else
#ifdef __linux__
    (void)options;

    return fgetxattr(fd, name, value, size);
#else
    (void)fd;
    (void)name;
    (void)value;
    (void)size;
    (void)options;

    return -ENOTSUP;
#endif
#endif
}

static int
do_getxattr(int fd, const char *name, SV *value, int options)
{
    char *buf;
    dTHX;
    ssize_t sz;

    sz = do_fgetxattr(fd, name, NULL, 0, options);
    if (sz == -1)
        goto err1;

    buf = malloc(sz);
    if (buf == NULL)
        goto err1;

    for (;;) {
        char *tmp;
        ssize_t tmpsz;

        tmpsz = do_fgetxattr(fd, name, buf, sz, options);
        if (tmpsz >= 0) {
            sz = tmpsz;
            break;
        }
        if (errno != ERANGE)
            goto err2;

        /* enlarge buffer */
        sz *= 2;
        tmp = realloc(buf, sz);
        if (tmp == NULL)
            goto err2;
        buf = tmp;
    }

    sv_setpvn(value, buf, sz);

    free(buf);

    return 0;

err2:
    free(buf);
err1:
    return -errno;
}

static int
xattr_buf_to_av(const char *buf, size_t len, AV *namebuf)
{
    dTHX;
    int n;
    size_t totlen;

    if (len == 0)
        return 0;

    totlen = 0;
    for (n = 1;; n++) {
        size_t slen;
        SV *sv;

        slen = strlen(buf);
        sv = newSVpvn(buf, slen);
        av_push(namebuf, sv);
        ++slen;
        totlen += slen;
        if (totlen >= len)
            break;
        buf += slen;
    }

    return n;
}

static int
do_listxattr(int fd, AV *namebuf, int options)
{
    char *buf;
    int ret;
    ssize_t sz;

    sz = do_flistxattr(fd, NULL, 0, options);
    if (sz == -1)
        goto err1;

    buf = malloc(sz);
    if (buf == NULL)
        goto err1;

    for (;;) {
        char *tmp;
        ssize_t tmpsz;

        tmpsz = do_flistxattr(fd, buf, sz, options);
        if (tmpsz >= 0) {
            sz = tmpsz;
            break;
        }
        if (errno != ERANGE)
            goto err2;

        /* enlarge buffer */
        sz *= 2;
        tmp = realloc(buf, sz);
        if (tmp == NULL)
            goto err2;
        buf = tmp;
    }

    ret = xattr_buf_to_av(buf, sz, namebuf);

    free(buf);

    return ret;

err2:
    free(buf);
err1:
    return -errno;
}

static int
do_flistxattr(int fd, char *namebuf, size_t size, int options)
{
#ifdef __APPLE__
    return flistxattr(fd, namebuf, size, options);
#else
#ifdef __linux__
    (void)options;

    return flistxattr(fd, namebuf, size);
#else
    (void)fd;
    (void)namebuf;
    (void)size;
    (void)options;

    return -ENOTSUP;
#endif
#endif
}

static int
do_removexattr(const char *path, const char *name, int options)
{
#ifdef __APPLE__
    return removexattr(path, name, options);
#else
#ifdef __linux__
    (void)options;

    return removexattr(path, name);
#else
    (void)path;
    (void)name;
    (void)options;

    return -ENOTSUP;
#endif
#endif
}

static int
do_fremovexattr(int fd, const char *name, int options)
{
#ifdef __APPLE__
    return fremovexattr(fd, name, options);
#else
#ifdef __linux__
    (void)options;

    return fremovexattr(fd, name);
#else
    (void)fd;
    (void)name;
    (void)options;

    return -ENOTSUP;
#endif
#endif
}

MODULE = xattrs     PACKAGE = xattrs

PROTOTYPES: ENABLE

INCLUDE: const-xs.inc

int
setxattr(path, name, value, options)
        const char  *path
        const char  *name
        SV          *value
        int         options
    CODE:
        const char *val;
        size_t size;

        val = SvPVbyte(value, size);

        RETVAL = err_to_retval(do_setxattr(path, name, val, size, options));

    OUTPUT:
        RETVAL

int
fsetxattr(fd, name, value, options)
        int         fd
        const char  *name
        SV          *value
        int         options
    CODE:
        const char *val;
        size_t size;

        val = SvPVbyte(value, size);

        RETVAL = err_to_retval(do_fsetxattr(fd, name, val, size, options));

    OUTPUT:
        RETVAL

int
getxattr(path, name, value, options)
        const char  *path
        const char  *name
        SV          *value
        int         options
    CODE:
        int fd;

        fd = open(path, O_RDONLY);
        if (fd == -1)
            XSRETURN_IV(-errno);

        RETVAL = do_getxattr(fd, name, value, options);

        close(fd);

    OUTPUT:
        RETVAL

int
fgetxattr(fd, name, value, options)
        int         fd
        const char  *name
        SV          *value
        int         options
    CODE:
        RETVAL = do_getxattr(fd, name, value, options);

    OUTPUT:
        RETVAL

int
listxattr(path, namebuf, options)
        const char  *path
        AV          *namebuf
        int         options
    CODE:
        int fd;

        fd = open(path, O_RDONLY);
        if (fd == -1)
            XSRETURN_IV(-errno);

        RETVAL = do_listxattr(fd, namebuf, options);

        close(fd);

    OUTPUT:
        RETVAL

int
flistxattr(fd, namebuf, options)
        int fd
        AV  *namebuf
        int options
    CODE:
        RETVAL = do_listxattr(fd, namebuf, options);

    OUTPUT:
        RETVAL

int
removexattr(path, name, options)
        const char  *path
        const char  *name
        int         options
    CODE:
        RETVAL = err_to_retval(do_removexattr(path, name, options));

    OUTPUT:
        RETVAL

int
fremovexattr(fd, name, options)
        int         fd
        const char  *name
        int         options
    CODE:
        RETVAL = err_to_retval(do_fremovexattr(fd, name, options));

    OUTPUT:
        RETVAL

