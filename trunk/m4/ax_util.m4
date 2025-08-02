#
# ax_util.m4
#

AC_DEFUN([AX_DEFINE_HAVE],
    [AC_DEFINE(
        [HAVE_$1],
        [1],
        [Define to 1 if you have the `$2' $3].
     )
    ]
)

AC_DEFUN([AX_DEFINE_HAVE_FUNC],
    [AX_DEFINE_HAVE([$1], [$2], [function])]
)

AC_DEFUN([AX_DEFINE_HAVE_LIB],
    [AX_DEFINE_HAVE([$1], [$2], [library])]
)

AC_DEFUN([AX_SUBST_BOOL],
    [AS_IF(
        [test '(' '(' "$1" = "yes" ')' -a '(' "$3" = "0" ')' ')' \
            -o '(' '(' "$1" = "no" ')' -a '(' "$3" != "0" ')' ')'],
        [$2=1],
        [$2=0]
     )
     AC_SUBST([$2])
    ]
)

# vi: set expandtab sw=4 ts=4:
