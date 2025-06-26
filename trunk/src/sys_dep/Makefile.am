##
## Makefile.am
##

noinst_HEADERS += src/sys_dep/sys_dep.h

noinst_LIBRARIES += src/sys_dep/libsys.a

src_sys_dep_libsys_a_CPPFLAGS = $(AM_CPPFLAGS) -Isrc -Isrc/sys_dep
src_sys_dep_libsys_a_CFLAGS = $(AM_CFLAGS)

if LINUX
src_sys_dep_libsys_a_SOURCES = src/sys_dep/linux/get_fs_stat.c
else
src_sys_dep_libsys_a_SOURCES = src/sys_dep/generic/get_fs_stat.c
endif

if LINUX
src_sys_dep_libsys_a_SOURCES += src/sys_dep/linux/get_bsz.c
else
src_sys_dep_libsys_a_SOURCES += src/sys_dep/generic/get_bsz.c
endif

## vi: set noexpandtab sw=4 ts=4:
