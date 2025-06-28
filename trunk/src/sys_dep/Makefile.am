##
## Makefile.am
##

noinst_HEADERS += src/sys_dep/sys_dep.h

noinst_LIBRARIES += src/sys_dep/libsys.a

src_sys_dep_libsys_a_CPPFLAGS = $(AM_CPPFLAGS) -Isrc -Isrc/sys_dep
src_sys_dep_libsys_a_CFLAGS = $(AM_CFLAGS)

if LINUX
src_sys_dep_libsys_a_SOURCES = src/sys_dep/linux/context_new.c
else
src_sys_dep_libsys_a_SOURCES = src/sys_dep/generic/context_new.c
endif

if LINUX
src_sys_dep_libsys_a_SOURCES += src/sys_dep/linux/fifo_transfer.c
else
src_sys_dep_libsys_a_SOURCES += src/sys_dep/generic/fifo_transfer.c
endif

if LINUX
src_sys_dep_libsys_a_SOURCES += src/sys_dep/linux/file_send.c
else
src_sys_dep_libsys_a_SOURCES += src/sys_dep/generic/file_send.c
endif

if LINUX
if HAVE_SYNCFS
src_sys_dep_libsys_a_SOURCES += src/sys_dep/linux/fsync_fs.c
sys_dep_cppflags += -DSYS_DEP_FSYNC_FS
else
src_sys_dep_libsys_a_SOURCES += src/sys_dep/generic/fsync_fs.c
endif
else
src_sys_dep_libsys_a_SOURCES += src/sys_dep/generic/fsync_fs.c
endif

if LINUX
src_sys_dep_libsys_a_SOURCES += src/sys_dep/linux/get_fs_stat.c
else
src_sys_dep_libsys_a_SOURCES += src/sys_dep/generic/get_fs_stat.c
endif

if LINUX
src_sys_dep_libsys_a_SOURCES += src/sys_dep/linux/get_bsz.c
else
src_sys_dep_libsys_a_SOURCES += src/sys_dep/generic/get_bsz.c
endif

if LINUX
src_sys_dep_libsys_a_SOURCES += src/sys_dep/linux/openat_direct.c
else
src_sys_dep_libsys_a_SOURCES += src/sys_dep/generic/openat_direct.c
endif

src_sys_dep_libsys_a_SOURCES += src/sys_dep/generic/openat_directory.c

if LINUX
if HAVE_O_TMPFILE
src_sys_dep_libsys_a_SOURCES += src/sys_dep/linux/openat_tmpfile.c
sys_dep_cppflags += -DSYS_DEP_OPENAT_TMPFILE
else
src_sys_dep_libsys_a_SOURCES += src/sys_dep/generic/openat_tmpfile.c
endif
else
src_sys_dep_libsys_a_SOURCES += src/sys_dep/generic/openat_tmpfile.c
endif

## vi: set noexpandtab sw=4 ts=4:
