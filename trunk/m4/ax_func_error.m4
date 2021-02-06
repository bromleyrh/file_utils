#
# ax_func_error.m4
#

AC_DEFUN([AX_FUNC_ERROR],
    [AC_CACHE_CHECK(
        [for error],
        [ax_cv_have_error],
        [AC_LINK_IFELSE(
            [AC_LANG_PROGRAM(
                [#include <error.h>],
                [error(0, 1, "%s", "Error");]
             )
            ],
            [ax_cv_have_error=yes],
            [ax_cv_have_error=no]
         )
        ]
     )
     AS_IF(
        [test "x$ax_cv_have_error" = "xno"],
        [AC_CACHE_CHECK(
            [for errc and warnc],
            [ax_cv_have_errc_warnc],
            [AC_LINK_IFELSE(
                [AC_LANG_PROGRAM(
                    [#include <err.h>],
                    [errc(0, 1, "%s", "Error"); warnc(1, "%s", "Warning");]
                 )
                ],
                [ax_cv_have_errc_warnc=yes],
                [ax_cv_have_errc_warnc=no]
             )
            ]
         )
        ]
     )
     AS_IF(
        [test "x$ax_cv_have_error" = "xyes"],
        [AX_DEFINE_HAVE_FUNC([ERROR], [error])],
        [test "x$ax_cv_have_errc_warnc" = "xyes"],
        [AX_DEFINE_HAVE_FUNC([ERRC], [errc])
         AX_DEFINE_HAVE_FUNC([WARNC], [warnc])]
     )
    ]
)

# vi: set expandtab sw=4 ts=4:
