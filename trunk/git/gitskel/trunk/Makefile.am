##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

if DEBUG
AM_CFLAGS = -ggdb3 -O0 -pipe -Wall -Wextra
else
AM_CFLAGS = -DNDEBUG -fvisibility=hidden -O2 -pipe -Wall -Wextra
endif

pkgconfigdir = @pkgconfigdir@

$(pkgconfig_DATA): config.status

## vi: set noexpandtab sw=4 ts=4:
