##
## Makefile.am
##

include libbackup/include/Makefile.am

lib_LTLIBRARIES += libbackup/libbackup.la

libbackup_libbackup_la_SOURCES = libbackup/blkdev.c libbackup/mount.c \
	libbackup/util.c
libbackup_libbackup_la_CPPFLAGS = $(AM_CPPFLAGS) -Ilibbackup/include
libbackup_libbackup_la_CFLAGS = $(AM_CFLAGS)
libbackup_libbackup_la_LDFLAGS = -lmount \
	-version-info @lbu_cur@:@lbu_rev@:@lbu_age@

## vi: set noexpandtab sw=4 ts=4:
