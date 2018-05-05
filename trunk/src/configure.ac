#
# configure.ac
#

AC_INIT([file_utils], [0.1])
AC_PREREQ([2.69])

AC_CONFIG_SRCDIR([fastcat.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([foreign no-define subdir-objects])
AM_SILENT_RULES([yes])
LT_INIT([disable-static])

case $target_os in
    *linux*)
        platform=linux;;
    *)
        AC_MSG_ERROR([unsupported platform], [1]);;
esac

CFLAGS=""

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB

AM_CONDITIONAL([GCC], [test "x$CC" = "xgcc"])

AX_CODE_COVERAGE

AC_ARG_ENABLE([sanitizers],
              [  --enable-sanitizers     enable GCC sanitizers],
              [case "$enableval" in
                   yes)
                       sanitizers=true;;
                   no)
                       sanitizers=false;;
                   *)
                       AC_MSG_ERROR([invalid "--enable-sanitizers" argument]);;
               esac],
              [sanitizers=false])

AC_ARG_ENABLE([debugging],
              [  --enable-debugging      enable debugging],
              [case "$enableval" in
                   yes)
                       debug=true;;
                   no)
                       debug=false;;
                   *)
                       AC_MSG_ERROR([invalid "--enable-debugging" argument]);;
               esac],
              [debug=false])
if test "x$sanitizers" = xtrue; then
    debug=true
fi
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])

if test "x$sanitizers" = xtrue; then
    AC_CHECK_LIB([asan], [__interceptor_malloc], [asan_libs="-lasan"])
    AC_CHECK_LIB([ubsan], [__ubsan_handle_add_overflow], [ubsan_libs="-lubsan"])

    fsanitizer="-fsanitize=address -fsanitize=undefined"
    fsanitizer="$fsanitizer -fsanitize-undefined-trap-on-error"
    AX_CHECK_COMPILE_FLAG([-fsanitize=address],
        [sanitizer="$fsanitizer"],
        [sanitizer=""]
    )
    if test "x$asan_libs" = x || test "x$ubsan_libs" = x; then
        sanitizer=""
    fi
fi
AM_CONDITIONAL([SANITIZERS], [test x$sanitizers = xtrue])
AC_SUBST([sanitizer])

AX_CHECK_COMPILE_FLAG([-Werror -fstack-protector-all],
    [stack_protector="-fstack-protector-all"],
    [stack_protector=""]
)
AC_SUBST([stack_protector])

libxfs=false
AC_CHECK_HEADERS([xfs/xfs.h], [libxfs=true], [], [
#include <stdint.h>
typedef int64_t off64_t;
])
AM_CONDITIONAL([HAVE_LIBXFS], [test x$libxfs = xtrue])

AC_CHECK_FUNCS([mnt_table_uniq_fs syncfs])

AC_CHECK_TYPES([__fsword_t], [], [], [[#include <sys/vfs.h>]])

pkgcfg=pkg-config

dbus_cflags=`eval $pkgcfg --cflags dbus-1`
libjson_cflags=`eval $pkgcfg --cflags libjson`
libutil_cflags=`eval $pkgcfg --cflags libutil`
openssl_cflags=`eval $pkgcfg --cflags openssl`

dbus_link_dep=`eval $pkgcfg --libs dbus-1`
libjson_link_dep=`eval $pkgcfg --libs libjson`
libutil_link_dep=`eval $pkgcfg --libs libutil`
openssl_link_dep=`eval $pkgcfg --libs openssl`

AC_SUBST([dbus_cflags])
AC_SUBST([libjson_cflags])
AC_SUBST([libutil_cflags])
AC_SUBST([openssl_cflags])

AC_SUBST([dbus_link_dep])
AC_SUBST([libjson_link_dep])
AC_SUBST([libutil_link_dep])
AC_SUBST([openssl_link_dep])

if test x$debug = xtrue; then
    enable_trace=true
else
    enable_trace=false
fi
AM_CONDITIONAL([TRACE], [test $enable_trace = true])

AC_ARG_WITH([pkgconfigdir],
            [  --with-pkgconfigdir=DIR install pkg-config data in DIR],
            [pkgconfigdir="$withval"],
            [pkgconfigdir="$libdir/pkgconfig"])
AC_SUBST([pkgconfigdir])

lbu_cur=0
lbu_age=0
lbu_rev=0
AC_SUBST([lbu_cur])
AC_SUBST([lbu_age])
AC_SUBST([lbu_rev])

ldio_cur=0
ldio_age=0
ldio_rev=0
AC_SUBST([ldio_cur])
AC_SUBST([ldio_age])
AC_SUBST([ldio_rev])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT

dnl vi: set expandtab sw=4 ts=4:
