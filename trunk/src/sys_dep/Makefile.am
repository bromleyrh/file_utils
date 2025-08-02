##
## Makefile.am
##

noinst_HEADERS += src/sys_dep/sys_dep.h

noinst_LIBRARIES += src/sys_dep/libsys.a

generic_sources :=
platform_sources :=

src_sys_dep_libsys_a_CPPFLAGS = $(AM_CPPFLAGS) -Isrc -Isrc/sys_dep
src_sys_dep_libsys_a_CFLAGS = $(AM_CFLAGS)

if LINUX
platform_sources += src/sys_dep/linux/context_new.c
else
generic_sources += src/sys_dep/generic/context_new.c
endif

if LINUX
platform_sources += src/sys_dep/linux/fifo_copy.c
else
generic_sources += src/sys_dep/generic/fifo_copy.c
endif

if LINUX
platform_sources += src/sys_dep/linux/fifo_transfer.c
else
generic_sources += src/sys_dep/generic/fifo_transfer.c
endif

if LINUX
platform_sources += src/sys_dep/linux/file_punch.c
else
generic_sources += src/sys_dep/generic/file_punch.c
endif

if LINUX
platform_sources += src/sys_dep/linux/file_send.c
else
generic_sources += src/sys_dep/generic/file_send.c
endif

if LINUX
if HAVE_SYNCFS
platform_sources += src/sys_dep/linux/fsync_fs.c
sys_dep_cppflags += -DSYS_DEP_FSYNC_FS
else
generic_sources += src/sys_dep/generic/fsync_fs.c
endif
else
generic_sources += src/sys_dep/generic/fsync_fs.c
endif

if LINUX
platform_sources += src/sys_dep/linux/get_bsz.c
else
generic_sources += src/sys_dep/generic/get_bsz.c
endif

if LINUX
platform_sources += src/sys_dep/linux/get_fs_stat.c
else
generic_sources += src/sys_dep/generic/get_fs_stat.c
endif

if LINUX
platform_sources += src/sys_dep/linux/mmap_anonymous.c
if HAVE_MAP_HUGETLB
sys_dep_cppflags += -DSYS_DEP_MAP_HUGETLB
endif
else
generic_sources += src/sys_dep/generic/mmap_anonymous.c
endif

if LINUX
platform_sources += src/sys_dep/linux/openat_direct.c
else
generic_sources += src/sys_dep/generic/openat_direct.c
endif

generic_sources += src/sys_dep/generic/openat_directory.c

if LINUX
if HAVE_O_TMPFILE
platform_sources += src/sys_dep/linux/openat_tmpfile.c
sys_dep_cppflags += -DSYS_DEP_OPENAT_TMPFILE
else
generic_sources += src/sys_dep/generic/openat_tmpfile.c
endif
else
generic_sources += src/sys_dep/generic/openat_tmpfile.c
endif

if LINUX
platform_sources += src/sys_dep/linux/setresuid.c
else
generic_sources += src/sys_dep/generic/setresuid.c
endif

src_sys_dep_libsys_a_SOURCES = $(generic_sources) $(platform_sources)

## vi: set noexpandtab sw=4 ts=4:
