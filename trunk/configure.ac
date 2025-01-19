#
# configure.ac
#

AC_INIT([file_utils], m4_esyscmd_s([cat .version]))
AC_PREREQ([2.69])

env_cflags=$CFLAGS

AC_CONFIG_SRCDIR([src/fastcat.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET

dnl ensure installed files are accessible by non-root users when parent
dnl directories are created
dnl FIXME: Honor file mode creation mask for non-installation directories
MKDIR_P="build-aux/mkpath -m 0755"

AM_INIT_AUTOMAKE([1.11 foreign no-define subdir-objects])
AM_SILENT_RULES([yes])
LT_INIT([disable-static])

AS_CASE(
    [$target_os],
        [*freebsd*],
            [platform=freebsd],
        [*linux*],
            [platform=linux],
        [AC_MSG_ERROR([unsupported platform], [1])]
)
AM_CONDITIONAL([LINUX], [test $platform = "linux"])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB

AM_CONDITIONAL([GCC], [test "x$CC" = "xgcc"])

AX_CHECK_COMPILE_FLAG([-std=c11], [std_flags="-std=c11"], [std_flags=])
AC_SUBST([std_flags])

warnings=

AX_CHECK_COMPILE_FLAG(
    [-Werror -Wgnu-include-next -Wnewline-eof -Wnullability-extension],
    [warnings="$warnings -Wpedantic -Wno-gnu-include-next -Wno-newline-eof"
     warnings="$warnings -Wno-nullability-extension"]
)

AC_SUBST([warnings])

AC_ARG_ENABLE([sanitizers],
              [  --enable-sanitizers     enable GCC sanitizers],
              [AS_CASE(
                  [$enableval],
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
                  [$enableval],
                      [yes],
                          [debug=true],
                      [no],
                          [debug=false],
                      [AC_MSG_ERROR([invalid "--enable-debugging" argument])]
               )
              ],
              [debug=false])
AS_IF(
    [test $sanitizers = true],
    [debug=true]
)
AM_CONDITIONAL([DEBUG], [test $debug = true])

AC_ARG_ENABLE([coverage_analysis],
              [  --enable-coverage-analysis
                          enable code coverage analysis],
              [AS_CASE(
                  [$enableval],
                      [yes],
                          [coverage_analysis=true],
                      [no],
                          [coverage_analysis=false],
                      [AC_MSG_ERROR(
                          [invalid "--enable-coverage-analysis" argument]
                       )
                      ]
               )
              ],
              [coverage_analysis=false])
AM_CONDITIONAL([COVERAGE_ANALYSIS], [test $coverage_analysis = true])

AS_IF(
    [test $sanitizers = true],
    [AC_CHECK_LIB([asan], [__interceptor_malloc], [asan_libs="-lasan"])
     AC_CHECK_LIB([ubsan], [__ubsan_handle_add_overflow],
                  [ubsan_libs="-lubsan"]
     )

     fsanitizer="-fsanitize=address -fsanitize=undefined"
     fsanitizer="$fsanitizer -fsanitize-undefined-trap-on-error"
     AX_CHECK_COMPILE_FLAG([-fsanitize=address],
         [sanitizer=$fsanitizer],
         [sanitizer=]
     )
     AS_IF(
         [test "x$asan_libs" = "x" || test "x$ubsan_libs" = "x"],
         [sanitizer=]
     )
    ]
)
AM_CONDITIONAL([SANITIZERS], [test $sanitizers = true])
AC_SUBST([sanitizer])

AX_CHECK_COMPILE_FLAG([-Werror -fstack-protector-all],
    [stack_protector="-fstack-protector-all"],
    [stack_protector=]
)
AC_SUBST([stack_protector])

AC_CHECK_FUNCS_ONCE([strerror_l])

AX_FUNC_ERROR

cat >src/replicate_fs.h <<EOF
#define LIST_LINUX_TMPFILE_FS_TYPES(type)
#define LINUX_FS_TYPE_HASH(type) 0
EOF

AS_IF(
    [test $platform = "linux"],
    [AC_CHECK_HEADERS([xfs/xfs.h], [libxfs=true], [libxfs=false], [
#include <stdint.h>
typedef int64_t off64_t;
])
     AC_CHECK_HEADERS([linux/magic.h])

     AS_IF([test "x$ac_cv_header_linux_magic_h" = "xyes"],
           [m4_define([linux_tmpfile_fs_types], [BTRFS EXT4 F2FS XFS])
            m4_define([linux_tmpfile_fs_type_hash], [(type >> 8) & 0xff])

            m4_foreach_w(i, linux_tmpfile_fs_types, [AX_LINUX_MAGIC(i)])

            printf "" >src/replicate_fs.h
            exec 9>>src/replicate_fs.h
            cat >&9 <<'EOF'
#include <linux/magic.h>

#define LIST_LINUX_TMPFILE_FS_TYPES(type) \
EOF
            for i in linux_tmpfile_fs_types; do
                eval "fs=\$ax_cv_linux_${i}_super_magic"
                AS_IF([test $fs = yes],
                      [printf '    X(type %s) \\\n' ${i}_SUPER_MAGIC >&9]
                     )
            done
            hash_expr="linux_tmpfile_fs_type_hash"
            cat >&9 <<EOF

#define LINUX_FS_TYPE_HASH(type) ($hash_expr)
EOF
            exec 9>&-
           ]
          )

     AC_CHECK_FUNCS([syncfs])

     AC_CHECK_LIB([mount], [mnt_table_uniq_fs],
         [AC_DEFINE(
             [HAVE_MNT_TABLE_UNIQ_FS], [1],
             [Define if you have the 'mnt_table_uniq_fs' function.]
          )
         ]
     )

     AC_CHECK_LIB([crypto], [EVP_MD_CTX_new],
         [AC_DEFINE(
             [HAVE_EVP_MD_CTX_NEW], [1],
             [Define if you have the 'EVP_MD_CTX_new' function.]
          )
         ]
     )

     AC_CHECK_TYPES([__fsword_t], [], [], [[#include <sys/vfs.h>]])

     PKG_CHECK_MODULES([dbus], [dbus-1],
         [dbus_cppflags=$dbus_CFLAGS
          dbus_link_dep=$dbus_LIBS]
     )
     PKG_CHECK_MODULES([libjson], [libjson],
         [libjson_cppflags=$libjson_CFLAGS
          libjson_link_dep=$libjson_LIBS]
     )
     PKG_CHECK_MODULES([libmatroska], [libmatroska],
         [libmatroska_cppflags=$libmatroska_CFLAGS
          libmatroska_link_dep=$libmatroska_LIBS]
     )
     PKG_CHECK_MODULES([openssl], [openssl],
         [openssl_cppflags=$openssl_CFLAGS
          openssl_link_dep=$openssl_LIBS]
     )

     AC_SUBST([dbus_cppflags])
     AC_SUBST([libjson_cppflags])
     AC_SUBST([libmatroska_cppflags])
     AC_SUBST([openssl_cppflags])

     AC_SUBST([dbus_link_dep])
     AC_SUBST([libjson_link_dep])
     AC_SUBST([libmatroska_link_dep])
     AC_SUBST([openssl_link_dep])
    ]
)

AM_CONDITIONAL([HAVE_LIBXFS], [test "x$libxfs" = "xtrue"])

PKG_CHECK_MODULES([libutil], [libutil],
    [libutil_cppflags=$libutil_CFLAGS
     libutil_link_dep=$libutil_LIBS]
)
AC_SUBST([libutil_cppflags])
AC_SUBST([libutil_link_dep])

AS_IF(
    [test $debug = true],
    [enable_trace=true],
    [enable_trace=false]
)
AM_CONDITIONAL([TRACE], [test $enable_trace = true])

AC_ARG_WITH([pkgconfigdir],
            [  --with-pkgconfigdir=DIR install pkg-config data in DIR],
            [pkgconfigdir=$withval],
            [pkgconfigdir="$libdir/pkgconfig"])
AC_SUBST([pkgconfigdir])

AC_SUBST([lbu_cur], [0])
AC_SUBST([lbu_age], [0])
AC_SUBST([lbu_rev], [0])

AC_SUBST([ldio_cur], [0])
AC_SUBST([ldio_age], [0])
AC_SUBST([ldio_rev], [0])

AC_SUBST([lvmp_cur], [0])
AC_SUBST([lvmp_age], [0])
AC_SUBST([lvmp_rev], [0])

dnl FIXME: Later, only prevent Autoconf from adding "-g -O2" to CFLAGS
CFLAGS=$env_cflags

AC_CONFIG_FILES([Makefile man/Makefile])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT

cat <<-EOF

$PACKAGE_NAME configuration

               Compiler: $CC

              Debugging: $debug
         GCC sanitizers: $sanitizers
      Coverage analysis: $coverage_analysis

    Installation prefix: $prefix

EOF

dnl vi: set expandtab sw=4 ts=4:
