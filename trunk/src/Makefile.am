##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = man

if COVERAGE_ANALYSIS
debug_cppflags_debug =
debug_cflags_debug = -g -O0

debug_cppflags_ndebug = -DNDEBUG
debug_cflags_ndebug = -g -O0

fortify_source_defines =

coverage_analysis_cflags = -fprofile-arcs -ftest-coverage
else
debug_cppflags_debug =
debug_cflags_debug = -ggdb3 -O0

debug_cppflags_ndebug = -DNDEBUG
debug_cflags_ndebug = -O2

fortify_source_defines = -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2

coverage_analysis_cflags =
endif

if SANITIZERS
AM_CPPFLAGS = $(debug_cppflags_debug)
AM_CFLAGS = $(debug_cflags_debug) $(coverage_analysis_cflags) @sanitizer@ \
	@stack_protector@ -ftrapv -pipe -Wall -Wextra
else
if DEBUG
AM_CPPFLAGS = $(debug_cppflags_debug)
AM_CFLAGS = $(debug_cflags_debug) $(coverage_analysis_cflags) \
	@stack_protector@ -ftrapv -pipe -Wall -Wextra
else
AM_CPPFLAGS = $(debug_cppflags_ndebug) $(fortify_source_defines)
AM_CFLAGS = $(debug_cflags_ndebug) $(coverage_analysis_cflags) -ftrapv \
	-fvisibility=hidden -pipe -Wall -Wextra
endif
endif

if TRACE
trace_cppflags = -DENABLE_TRACE
endif

pkgconfigdir = @pkgconfigdir@

$(pkgconfig_DATA): config.status

EXTRA_DIST = backtrace.c bootstrap replicate.conf.sample replicate.spec \
	verify.conf.sample verify.spec

include scripts/Makefile.am

noinst_HEADERS = common.h replicate_common.h replicate_conf.h replicate_gram.h \
	replicate_trans.h util.h verify_common.h verify_conf.h verify_gram.h \
	verify_io.h verify_scan.h

replicate_gram_macro = CONFIG_GRAM
verify_gram_macro = CONFIG_GRAM

gen_files = replicate_gram.h verify_gram.h

BUILT_SOURCES = $(gen_files)

CLEANFILES = $(gen_files)

replicate_gram.h: replicate.spec
	scripts/spec_to_h.pl replicate.spec $(replicate_gram_macro) > $@

verify_gram.h: verify.spec
	scripts/spec_to_h.pl verify.spec $(verify_gram_macro) > $@

include_HEADERS =

noinst_LIBRARIES = libfileutil.a

libfileutil_a_SOURCES = util.c
libfileutil_a_CFLAGS = $(AM_CFLAGS)

lib_LTLIBRARIES = libdirectio.la

libdirectio_la_SOURCES = libdirectio.c
libdirectio_la_CFLAGS = $(AM_CFLAGS)
libdirectio_la_LDFLAGS = -lc -ldl -version-info @ldio_cur@:@ldio_rev@:@ldio_age@

include libbackup/Makefile.am

backup_link = -L$(abs_builddir)/libbackup/.libs -lbackup
backup_link_dep = @libutil_link_dep@

bin_PROGRAMS = attr_idx cp_mem fastcat fastcp md_verify mkmanifest open \
	open_pipes replicate sparse_scan tmpfile verify
if HAVE_LIBXFS
bin_PROGRAMS += xfsutil
endif

bin_cppflags =
bin_libs =

attr_idx_SOURCES = attr_idx.c
attr_idx_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
attr_idx_CFLAGS = $(AM_CFLAGS)
attr_idx_LIBS = $(bin_libs)
attr_idx_LDFLAGS = @libutil_link_dep@

cp_mem_SOURCES = cp_mem.c
cp_mem_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
cp_mem_CFLAGS = $(AM_CFLAGS)
cp_mem_LIBS = $(bin_libs)
cp_mem_LDFLAGS = @libutil_link_dep@

fastcat_SOURCES = fastcat.c
fastcat_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags)
fastcat_CFLAGS = $(AM_CFLAGS)
fastcat_LIBS = $(bin_libs)

fastcp_SOURCES = fastcp.c
fastcp_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
fastcp_CFLAGS = $(AM_CFLAGS)
fastcp_LIBS = $(bin_libs)
fastcp_LDFLAGS = @libutil_link_dep@

md_verify_SOURCES = md_verify.c
md_verify_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
md_verify_CFLAGS = $(AM_CFLAGS)
md_verify_LIBS = $(bin_libs)
md_verify_LDFLAGS = @libutil_link_dep@

mkmanifest_SOURCES = mkmanifest.c
mkmanifest_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
mkmanifest_CFLAGS = $(AM_CFLAGS)
mkmanifest_LIBS = $(bin_libs)
mkmanifest_LDFLAGS = @libutil_link_dep@

open_SOURCES = open.c
open_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags)
open_CFLAGS = $(AM_CFLAGS)
open_LIBS = $(bin_libs)

open_pipes_SOURCES = open_pipes.c
open_pipes_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags)
open_pipes_CFLAGS = $(AM_CFLAGS)
open_pipes_LIBS = $(bin_libs)

replicate_SOURCES = replicate.c replicate_conf.c replicate_trans.c
replicate_CPPFLAGS = $(AM_CPPFLAGS) -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE \
	-Ilibbackup/include $(bin_cppflags) @dbus_cppflags@ @libjson_cppflags@ \
	@libutil_cppflags@ $(trace_cppflags)
replicate_CFLAGS = $(AM_CFLAGS)
replicate_LIBS = $(bin_libs)
replicate_LDADD = libfileutil.a
replicate_LDFLAGS = -lcap -lm -lmount $(backup_link) $(backup_link_dep) \
	@dbus_link_dep@ @libjson_link_dep@ @libutil_link_dep@
replicate_DEPENDENCIES = libfileutil.a libbackup/libbackup.la

sparse_scan_SOURCES = sparse_scan.c
sparse_scan_CPPFLAGS = $(AM_CPPFLAGS) $(bin_cppflags) @libutil_cppflags@
sparse_scan_CFLAGS = $(AM_CFLAGS)
sparse_scan_LIBS = $(bin_libs)
sparse_scan_LDFLAGS = @libutil_link_dep@

verify_SOURCES = verify.c verify_conf.c verify_io.c verify_scan.c
verify_CPPFLAGS = $(AM_CPPFLAGS) -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE \
	-Ilibbackup/include $(bin_cppflags) @dbus_cppflags@ @libjson_cppflags@ \
	@libutil_cppflags@ @openssl_cppflags@ $(trace_cppflags)
verify_CFLAGS = $(AM_CFLAGS)
verify_LIBS = $(bin_libs)
verify_LDADD = libfileutil.a
verify_LDFLAGS = -lcap -lm -lmount -lrt $(backup_link) $(backup_link_dep) \
	@dbus_link_dep@ @libjson_link_dep@ @libutil_link_dep@ @openssl_link_dep@
verify_DEPENDENCIES = libfileutil.a libbackup/libbackup.la

install-exec-hook:
	ln -fs open $(bindir)/delete_input
	chmod u+s $(bindir)/replicate $(bindir)/verify
	@if ldc=`which ldconfig 2>/dev/null` && test -x ${ldc}; then \
		echo "Regenerating runtime linker cache"; \
		ldconfig || true; \
	fi; \
	echo; \
	echo "Note: The path \"$(pkgconfigdir)\" must be added to"; \
	echo "PKG_CONFIG_PATH in order to build dependent modules"; \
	echo

## vi: set noexpandtab sw=4 ts=4:
