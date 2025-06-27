##
## Makefile.am
##

include src/libbackup/include/Makefile.am

noinst_HEADERS += src/libbackup/backup_util.h

lib_LTLIBRARIES += src/libbackup/libbackup.la

src_libbackup_libbackup_la_SOURCES = src/libbackup/blkdev.c \
	src/libbackup/mount.c src/libbackup/backup_util.c
src_libbackup_libbackup_la_CPPFLAGS = $(AM_CPPFLAGS) -Isrc -Isrc/libbackup \
	-Isrc/libbackup/include -Isrc/sys_dep
src_libbackup_libbackup_la_CFLAGS = $(AM_CFLAGS)
src_libbackup_libbackup_la_LIBADD = -lmount
src_libbackup_libbackup_la_LDFLAGS = -version-info @lbu_cur@:@lbu_rev@:@lbu_age@

## vi: set noexpandtab sw=4 ts=4:
