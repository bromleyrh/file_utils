##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

if LINUX

EXTRA_DIST += src/replicate.conf.sample src/replicate.spec \
	src/simpledb_obj.idl src/verify.conf.sample src/verify.spec

noinst_HEADERS += src/common.h src/debug.h src/replicate_common.h \
	src/replicate_conf.h src/replicate_gram.h src/replicate_trans.h src/util.h \
	src/verify_common.h src/verify_conf.h src/verify_gram.h src/verify_io.h \
	src/verify_plugin.h src/verify_scan.h

replicate_gram_macro = CONFIG_GRAM
verify_gram_macro = CONFIG_GRAM

gen_files = src/replicate_gram.h src/simpledb_obj.h src/verify_gram.h

BUILT_SOURCES += $(gen_files)

CLEANFILES += $(gen_files)

src/simpledb_obj.h: src/simpledb_obj.idl
	idlc <"$<" >"$@"

src/replicate_gram.h: src/replicate.spec
	scripts/spec_to_h.pl src/replicate.spec $(replicate_gram_macro) >"$@"

src/verify_gram.h: src/verify.spec
	scripts/spec_to_h.pl src/verify.spec $(verify_gram_macro) >"$@"

noinst_LIBRARIES += src/libfileutil.a

src_libfileutil_a_SOURCES = src/util.c
src_libfileutil_a_CFLAGS = $(AM_CFLAGS)

lib_LTLIBRARIES += src/libdirectio.la src/libverify_mkv_plugin.la

src_libdirectio_la_SOURCES = src/libdirectio.c
src_libdirectio_la_CFLAGS = $(AM_CFLAGS)
src_libdirectio_la_LDFLAGS = -lc -ldl \
	-version-info @ldio_cur@:@ldio_rev@:@ldio_age@

src_libverify_mkv_plugin_la_SOURCES = src/verify_mkv_plugin.c
src_libverify_mkv_plugin_la_CFLAGS = $(AM_CFLAGS) @libmatroska_cppflags@
src_libverify_mkv_plugin_la_LDFLAGS = \
	-version-info @lvmp_cur@:@lvmp_rev@:@lvmp_age@
src_libverify_mkv_plugin_la_LIBADD = @libmatroska_link_dep@

sys_dep_cppflags = -Isrc -Isrc/sys_dep

include src/libbackup/Makefile.am
include src/sys_dep/Makefile.am

backup_link = -L$(abs_builddir)/src/libbackup/.libs -lbackup
backup_link_dep = src/sys_dep/libsys.a @libutil_link_dep@

bin_PROGRAMS += src/attr_idx src/cp_mem src/fastcat src/fastcp src/md_verify \
	src/mkmanifest src/open src/open_pipes src/replicate src/simpledb \
	src/sparse_scan src/tmpfile src/verify
if HAVE_LIBXFS
bin_PROGRAMS += src/xfsutil
endif

bin_cppflags = $(sys_dep_cppflags)

src_attr_idx_SOURCES = src/attr_idx.c
src_attr_idx_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
src_attr_idx_CFLAGS = $(AM_CFLAGS)
src_attr_idx_LDADD = @libutil_link_dep@

src_cp_mem_SOURCES = src/cp_mem.c
src_cp_mem_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
src_cp_mem_CFLAGS = $(AM_CFLAGS)
src_cp_mem_LDADD = src/sys_dep/libsys.a @libutil_link_dep@
src_cp_mem_DEPENDENCIES = src/sys_dep/libsys.a

src_fastcat_SOURCES = src/fastcat.c
src_fastcat_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags)
src_fastcat_CFLAGS = $(AM_CFLAGS)
src_fastcat_LDADD = src/sys_dep/libsys.a
src_fastcat_DEPENDENCIES = src/sys_dep/libsys.a

src_fastcp_SOURCES = src/fastcp.c
src_fastcp_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
src_fastcp_CFLAGS = $(AM_CFLAGS)
src_fastcp_LDADD = src/sys_dep/libsys.a @libutil_link_dep@
src_fastcp_DEPENDENCIES = src/sys_dep/libsys.a

src_md_verify_SOURCES = src/md_verify.c src/strptime.c
src_md_verify_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
src_md_verify_CFLAGS = $(AM_CFLAGS)
src_md_verify_LDADD = @libutil_link_dep@

src_mkmanifest_SOURCES = src/mkmanifest.c
src_mkmanifest_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
src_mkmanifest_CFLAGS = $(AM_CFLAGS)
src_mkmanifest_LDADD = @libutil_link_dep@

src_open_SOURCES = src/open.c
src_open_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
src_open_CFLAGS = $(AM_CFLAGS)
src_open_LDADD = src/sys_dep/libsys.a @libutil_link_dep@
src_open_DEPENDENCIES = src/sys_dep/libsys.a

src_open_pipes_SOURCES = src/open_pipes.c
src_open_pipes_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
src_open_pipes_CFLAGS = $(AM_CFLAGS)
src_open_pipes_LDADD = @libutil_link_dep@

src_replicate_SOURCES = src/debug.c src/replicate.c src/replicate_conf.c \
	src/replicate_trans.c src/util.c
src_replicate_CPPFLAGS = $(AM_CPPFLAGS) -D_FILE_OFFSET_BITS=64 \
	-Isrc/libbackup/include $(bin_cppflags) @dbus_cppflags@ @libjson_cppflags@ \
	@libutil_cppflags@ $(trace_cppflags)
src_replicate_CFLAGS = $(AM_CFLAGS)
src_replicate_LDADD = src/libfileutil.a src/sys_dep/libsys.a -lcap -lm -lmount \
	-lpthread $(backup_link) $(backup_link_dep) @dbus_link_dep@ \
	@libjson_link_dep@ @libutil_link_dep@
src_replicate_DEPENDENCIES = src/libfileutil.a src/libbackup/libbackup.la \
	src/sys_dep/libsys.a

src_simpledb_SOURCES = src/simpledb.c
src_simpledb_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
src_simpledb_CFLAGS = $(AM_CFLAGS)
src_simpledb_LDADD = @libutil_link_dep@

src_sparse_scan_SOURCES = src/sparse_scan.c
src_sparse_scan_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
src_sparse_scan_CFLAGS = $(AM_CFLAGS)
src_sparse_scan_LDADD = src/sys_dep/libsys.a @libutil_link_dep@
src_sparse_scan_DEPENDENCIES = src/sys_dep/libsys.a

src_tmpfile_SOURCES = src/tmpfile.c
src_tmpfile_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags)
src_tmpfile_CFLAGS = $(AM_CFLAGS)
src_tmpfile_LDADD = src/sys_dep/libsys.a
src_tmpfile_DEPENDENCIES = src/sys_dep/libsys.a

src_verify_SOURCES = src/debug.c src/util.c src/verify.c src/verify_conf.c \
	src/verify_io.c src/verify_scan.c
src_verify_CPPFLAGS = $(AM_CPPFLAGS) -D_FILE_OFFSET_BITS=64 \
	-Isrc/libbackup/include $(bin_cppflags) @dbus_cppflags@ @libjson_cppflags@ \
	@libutil_cppflags@ @openssl_cppflags@ $(trace_cppflags)
src_verify_CFLAGS = $(AM_CFLAGS)
src_verify_LDADD = src/libfileutil.a src/sys_dep/libsys.a -lcap -lm -lmount \
	-lrt $(backup_link) $(backup_link_dep) @dbus_link_dep@ @libjson_link_dep@ \
	@libutil_link_dep@ @openssl_link_dep@
src_verify_DEPENDENCIES = src/libfileutil.a src/libbackup/libbackup.la \
	src/sys_dep/libsys.a

src_xfsutil_SOURCES = src/xfsutil.c
src_xfsutil_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags)
src_xfsutil_CFLAGS = $(AM_CFLAGS)
src_xfsutil_LDADD = src/sys_dep/libsys.a
src_xfsutil_DEPENDENCIES = src/sys_dep/libsys.a

else

gen_files = src/simpledb_obj.h

BUILT_SOURCES += $(gen_files)

CLEANFILES += $(gen_files)

src/simpledb_obj.h: src/simpledb_obj.idl
	idlc <"$<" >"$@"

bin_PROGRAMS += src/simpledb

src_simpledb_SOURCES = src/simpledb.c
src_simpledb_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
src_simpledb_CFLAGS = $(AM_CFLAGS)
src_simpledb_LDADD = @libutil_link_dep@

endif

## vi: set noexpandtab sw=4 ts=4:
