##
## Makefile.am
##

include %reldir%/include/Makefile.am

lib_LTLIBRARIES += %reldir%/libbackup.la

%canon_reldir%_libbackup_la_SOURCES = %reldir%/blkdev.c %reldir%/mount.c \
	%reldir%/util.c
%canon_reldir%_libbackup_la_CFLAGS = $(AM_CFLAGS) -I%reldir%/include
%canon_reldir%_libbackup_la_LDFLAGS = -lmount

## vi: set noexpandtab sw=4 ts=4:
