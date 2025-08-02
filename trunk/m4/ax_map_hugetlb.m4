#
# ax_map_hugetlb.m4
#

AC_DEFUN([AX_MAP_HUGETLB],
    [AC_CACHE_CHECK(
        [for MAP_HUGETLB],
        [ax_cv_map_hugetlb],
        [AC_COMPILE_IFELSE(
            [AC_LANG_PROGRAM([
#define _GNU_SOURCE

#include <stdlib.h>

#include <sys/mman.h>
], [
int test = MAP_HUGETLB;
return EXIT_SUCCESS;
]            )
            ],
            [ax_cv_map_hugetlb=yes],
            [ax_cv_map_hugetlb=no]
         )
        ]
     )
     AS_IF(
        [test $ax_cv_map_hugetlb = "yes"],
        [AC_DEFINE(
            [HAVE_MAP_HUGETLB],
            [1],
            [Define to 1 if the MAP_HUGETLB mmap() flag is supported.]
         )
        ]
     )
    ]
)

# vi: set expandtab sw=4 ts=4:
