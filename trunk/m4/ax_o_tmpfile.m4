#
# ax_o_tmpfile.m4
#

AC_DEFUN([AX_O_TMPFILE],
    [AC_CACHE_CHECK(
        [for O_TMPFILE],
        [ax_cv_o_tmpfile],
        [AC_COMPILE_IFELSE(
            [AC_LANG_PROGRAM([
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
], [
int test = O_TMPFILE;
return EXIT_SUCCESS;
]            )
            ],
            [ax_cv_o_tmpfile=yes],
            [ax_cv_o_tmpfile=no]
         )
        ]
     )
     AS_IF(
        [test $ax_cv_o_tmpfile = "yes"],
        [AC_DEFINE(
            [HAVE_O_TMPFILE],
            [1],
            [Define to 1 if the O_TMPFILE open() and openat() flag is
             supported.]
         )
        ]
     )
    ]
)

# vi: set expandtab sw=4 ts=4:
