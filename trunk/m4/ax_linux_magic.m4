#
# ax_linux_magic.m4
#

AC_DEFUN([AX_LINUX_MAGIC],
    [AC_CACHE_CHECK(
        [if linux/magic.h defines $1_SUPER_MAGIC],
        [ax_cv_linux_$1_super_magic],
        [AC_COMPILE_IFELSE(
            [AC_LANG_PROGRAM(
                [#include <linux/magic.h>
                 #include <sys/statfs.h>],
                [__fsword_t test = $1_SUPER_MAGIC;]
             )
            ],
            [ax_cv_linux_$1_super_magic=yes],
            [ax_cv_linux_$1_super_magic=no]
         )
        ]
     )
    ]
)

# vi: set expandtab sw=4 ts=4:
