#
# configure.ac
#

AC_INIT([name], [version])
AC_PREREQ([2.69])

AC_CONFIG_SRCDIR([src.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([foreign no-define subdir-objects])
AM_SILENT_RULES([yes])
LT_INIT([disable-static])

case $target_os in
    *darwin*)
        platform=darwin;;
    *freebsd*)
        platform=freebsd;;
    *linux*)
        platform=linux;;
    *)
        AC_MSG_ERROR([unsupported platform], [1]);;
esac
AM_CONDITIONAL([APPLE], [test "x$platform" = "xdarwin"])
AM_CONDITIONAL([LINUX], [test "x$platform" = "xlinux"])

CFLAGS=""

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB

AM_CONDITIONAL([CLANG], [test "x$CC" = "xclang"])
AM_CONDITIONAL([GCC], [test "x$CC" = "xgcc"])

if test "x$platform" = "xfreebsd"; then
    pkgcfg=pkgconf
else
    pkgcfg=pkg-config
fi

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
