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
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])

AC_ARG_WITH([pkgconfigdir],
            [  --with-pkgconfigdir=DIR install pkg-config data in DIR],
            [pkgconfigdir="$withval"],
            [pkgconfigdir="$libdir/pkgconfig"])
AC_SUBST([pkgconfigdir])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

dnl vi: set expandtab sw=4 ts=4:
