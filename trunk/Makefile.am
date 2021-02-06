##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = man

EXTRA_DIST = bin bootstrap build-aux git java perl vm_mgmt

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

BUILT_SOURCES =
include_HEADERS =
noinst_HEADERS =
lib_LTLIBRARIES =
noinst_LIBRARIES =
bin_PROGRAMS =

CLEANFILES =

include scripts/Makefile.am
include src/Makefile.am

if LINUX
install-exec-hook:
	ln -fs open $(bindir)/delete_input
	chmod u+s $(bindir)/replicate $(bindir)/verify
	@if ldc=`which ldconfig 2>/dev/null` && test -x ${ldc}; then \
		echo "Regenerating runtime linker cache"; \
		ldconfig || true; \
	fi
	@echo
	@echo "Note: The path \"$(pkgconfigdir)\" must be added to"
	@echo "PKG_CONFIG_PATH in order to build dependent modules"
	@echo
endif

## vi: set noexpandtab sw=4 ts=4:
