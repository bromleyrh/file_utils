#
# configure.ac
#

AC_INIT([file_utils], [0.1])
AC_PREREQ([2.69])

AC_CONFIG_SRCDIR([fastcat.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([1.11 foreign no-define subdir-objects])
AM_SILENT_RULES([yes])
LT_INIT([disable-static])

AS_CASE(
    [$target_os],
        [*linux*],
            [platform=linux],
        [AC_MSG_ERROR([unsupported platform], [1])]
)

CFLAGS=""

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB

AM_CONDITIONAL([GCC], [test "x$CC" = "xgcc"])

AX_CODE_COVERAGE

AC_ARG_ENABLE([sanitizers],
              [  --enable-sanitizers     enable GCC sanitizers],
              [AS_CASE(
                  ["$enableval"],
                      [yes],
                          [sanitizers=true],
                      [no],
                          [sanitizers=false],
                      [AC_MSG_ERROR([invalid "--enable-sanitizers" argument])]
               )
              ],
              [sanitizers=false])

AC_ARG_ENABLE([debugging],
              [  --enable-debugging      enable debugging],
              [AS_CASE(
                  ["$enableval"],
                      [yes],
                          [debug=true],
                      [no],
                          [debug=false],
                      [AC_MSG_ERROR([invalid "--enable-debugging" argument])]
               )
              ],
              [debug=false])
AS_IF(
    [test "x$sanitizers" = xtrue],
    [debug=true]
)
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])

AS_IF(
    [test "x$sanitizers" = xtrue],
    [AC_CHECK_LIB([asan], [__interceptor_malloc], [asan_libs="-lasan"])
     AC_CHECK_LIB([ubsan], [__ubsan_handle_add_overflow],
                  [ubsan_libs="-lubsan"]
     )

     fsanitizer="-fsanitize=address -fsanitize=undefined"
     fsanitizer="$fsanitizer -fsanitize-undefined-trap-on-error"
     AX_CHECK_COMPILE_FLAG([-fsanitize=address],
         [sanitizer="$fsanitizer"],
         [sanitizer=""]
     )
     AS_IF(
         [test "x$asan_libs" = x || test "x$ubsan_libs" = x],
         [sanitizer=""]
     )
    ]
)
AM_CONDITIONAL([SANITIZERS], [test x$sanitizers = xtrue])
AC_SUBST([sanitizer])

AX_CHECK_COMPILE_FLAG([-Werror -fstack-protector-all],
    [stack_protector="-fstack-protector-all"],
    [stack_protector=""]
)
AC_SUBST([stack_protector])

AC_CHECK_HEADERS([xfs/xfs.h], [libxfs=true], [libxfs=false], [
#include <stdint.h>
typedef int64_t off64_t;
])
AM_CONDITIONAL([HAVE_LIBXFS], [test x$libxfs = xtrue])

AC_CHECK_FUNCS([syncfs])

AC_CHECK_LIB([mount], [mnt_table_uniq_fs],
    [AC_DEFINE(
        [HAVE_MNT_TABLE_UNIQ_FS], [1],
        [Define if you have the 'mnt_table_uniq_fs' function.]
     )
    ]
)

AC_CHECK_TYPES([__fsword_t], [], [], [[#include <sys/vfs.h>]])

PKG_CHECK_MODULES([dbus], [dbus-1],
    [dbus_cflags=$dbus_CFLAGS
     dbus_link_dep=$dbus_LIBS]
)
PKG_CHECK_MODULES([libjson], [libjson],
    [libjson_cflags=$libjson_CFLAGS
     libjson_link_dep=$libjson_LIBS]
)
PKG_CHECK_MODULES([libutil], [libutil],
    [libutil_cflags=$libutil_CFLAGS
     libutil_link_dep=$libutil_LIBS]
)
PKG_CHECK_MODULES([openssl], [openssl],
    [openssl_cflags=$openssl_CFLAGS
     openssl_link_dep=$openssl_LIBS]
)

AC_SUBST([dbus_cflags])
AC_SUBST([libjson_cflags])
AC_SUBST([libutil_cflags])
AC_SUBST([openssl_cflags])

AC_SUBST([dbus_link_dep])
AC_SUBST([libjson_link_dep])
AC_SUBST([libutil_link_dep])
AC_SUBST([openssl_link_dep])

AS_IF(
    [test x$debug = xtrue],
    [enable_trace=true],
    [enable_trace=false]
)
AM_CONDITIONAL([TRACE], [test $enable_trace = true])

AC_ARG_WITH([pkgconfigdir],
            [  --with-pkgconfigdir=DIR install pkg-config data in DIR],
            [pkgconfigdir="$withval"],
            [pkgconfigdir="$libdir/pkgconfig"])
AC_SUBST([pkgconfigdir])

AC_SUBST([lbu_cur], [0])
AC_SUBST([lbu_age], [0])
AC_SUBST([lbu_rev], [0])

AC_SUBST([ldio_cur], [0])
AC_SUBST([ldio_age], [0])
AC_SUBST([ldio_rev], [0])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT

cat <<- EOF

$PACKAGE_NAME configuration

               Compiler: $CC

              Debugging: $debug
         GCC sanitizers: $sanitizers

    Installation prefix: $prefix

EOF

dnl vi: set expandtab sw=4 ts=4:
