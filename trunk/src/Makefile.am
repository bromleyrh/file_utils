##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

if SANITIZERS
AM_CFLAGS = @sanitizer@ @stack_protector@ -ftrapv -ggdb3 -O0 -pipe -Wall -Wextra
else
if DEBUG
AM_CFLAGS = @stack_protector@ -ftrapv -ggdb3 -O0 -pipe -Wall -Wextra
else
AM_CFLAGS = -DNDEBUG -ftrapv -fvisibility=hidden -O2 -pipe -Wall -Wextra
endif
endif

if TRACE
trace_cflags = -DENABLE_TRACE
endif

pkgconfigdir = @pkgconfigdir@

$(pkgconfig_DATA): config.status

EXTRA_DIST = backtrace.c bootstrap replicate.conf.sample replicate.spec \
	verify.conf.sample verify.spec

include scripts/Makefile.am

noinst_HEADERS = common.h replicate_common.h replicate_conf.h replicate_gram.h \
	replicate_trans.h verify_common.h verify_conf.h verify_gram.h verify_io.h \
	verify_scan.h

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

lib_LTLIBRARIES = libdirectio.la

libdirectio_la_SOURCES = libdirectio.c
libdirectio_la_CFLAGS = $(AM_CFLAGS)
libdirectio_la_LDFLAGS = -lc -ldl -version-info @ldio_cur@:@ldio_rev@:@ldio_age@

include libbackup/Makefile.am

backup_link = -L$(abs_builddir)/libbackup/.libs -lbackup
backup_link_dep = @libutil_link_dep@

bin_PROGRAMS = attr_idx cp_mem fastcat fastcp md_verify mkmanifest open \
	open_pipes replicate sparse_scan tmpfile verify xfsutil

bin_cflags = $(CODE_COVERAGE_CFLAGS)
bin_libs = $(CODE_COVERAGE_LIBS)

attr_idx_SOURCES = attr_idx.c
attr_idx_CFLAGS = $(AM_CFLAGS) $(bin_cflags) @libutil_cflags@
attr_idx_LIBS = $(bin_libs)
attr_idx_LDFLAGS = @libutil_link_dep@

cp_mem_SOURCES = cp_mem.c
cp_mem_CFLAGS = $(AM_CFLAGS) $(bin_cflags) @libutil_cflags@
cp_mem_LIBS = $(bin_libs)
cp_mem_LDFLAGS = @libutil_link_dep@

fastcat_SOURCES = fastcat.c
fastcat_CFLAGS = $(AM_CFLAGS) $(bin_cflags)
fastcat_LIBS = $(bin_libs)

fastcp_SOURCES = fastcp.c
fastcp_CFLAGS = $(AM_CFLAGS) $(bin_cflags) @libutil_cflags@
fastcp_LIBS = $(bin_libs)
fastcp_LDFLAGS = @libutil_link_dep@

md_verify_SOURCES = md_verify.c
md_verify_CFLAGS = $(AM_CFLAGS) $(bin_cflags) @libutil_cflags@
md_verify_LIBS = $(bin_libs)
md_verify_LDFLAGS = @libutil_link_dep@

mkmanifest_SOURCES = mkmanifest.c
mkmanifest_CFLAGS = $(AM_CFLAGS) $(bin_cflags) @libutil_cflags@
mkmanifest_LIBS = $(bin_libs)
mkmanifest_LDFLAGS = @libutil_link_dep@

open_SOURCES = open.c
open_CFLAGS = $(AM_CFLAGS) $(bin_cflags)
open_LIBS = $(bin_libs)

open_pipes_SOURCES = open_pipes.c
open_pipes_CFLAGS = $(AM_CFLAGS) $(bin_cflags)
open_pipes_LIBS = $(bin_libs)

replicate_SOURCES = replicate.c replicate_conf.c replicate_trans.c
replicate_CFLAGS = $(AM_CFLAGS) -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE \
	-Ilibbackup/include $(bin_cflags) @dbus_cflags@ @libjson_cflags@ \
	@libutil_cflags@ $(trace_cflags)
replicate_LIBS = $(bin_libs)
replicate_LDFLAGS = -lcap -lm -lmount $(backup_link) $(backup_link_dep) \
	@dbus_link_dep@ @libjson_link_dep@ @libutil_link_dep@
replicate_DEPENDENCIES = libbackup/libbackup.la

sparse_scan_SOURCES = sparse_scan.c
sparse_scan_CFLAGS = $(AM_CFLAGS) $(bin_cflags) @libutil_cflags@
sparse_scan_LIBS = $(bin_libs)
sparse_scan_LDFLAGS = @libutil_link_dep@

verify_SOURCES = verify.c verify_conf.c verify_io.c verify_scan.c
verify_CFLAGS = $(AM_CFLAGS) -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE \
	-Ilibbackup/include $(bin_cflags) @dbus_cflags@ @libjson_cflags@ \
	@libutil_cflags@ @openssl_cflags@ $(trace_cflags)
verify_LIBS = $(bin_libs)
verify_LDFLAGS = -lcap -lm -lmount -lrt $(backup_link) $(backup_link_dep) \
	@dbus_link_dep@ @libjson_link_dep@ @libutil_link_dep@ @openssl_link_dep@
verify_DEPENDENCIES = libbackup/libbackup.la

@CODE_COVERAGE_RULES@

install-exec-hook:
	ln -fs open $(bindir)/delete_input
	chmod u+s $(bindir)/replicate $(bindir)/verify
	@if ldc=`which ldconfig 2>/dev/null` && test -x ${ldc}; then \
		echo "Regenerating runtime linker cache"; \
		ldconfig || true; \
	fi

## vi: set noexpandtab sw=4 ts=4:
