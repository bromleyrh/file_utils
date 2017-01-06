#
# Makefile
#

debug = 0

lbup_vmaj = 0
lbup_vmin = 1
lbup_so = libbackup.so.$(lbup_vmaj).$(lbup_vmin)

ifeq ($(debug), 1)
CFLAGS = -ggdb3 -Iinclude -O0 -Wall -Wextra
else
CFLAGS = -Iinclude -O2 -s -Wall -Wextra
endif

prefix = /usr/local
libdir = $(prefix)/lib

libs = $(lbup_so)

all: libbackup

%.o: %.c
	gcc -c -fPIC $(CFLAGS) $^

.PHONY: libbackup clean

libbackup: blkdev.o mount.o util.o
	gcc -o $(lbup_so) -shared -Wl,-soname,libbackup.so.$(lbup_vmaj) $^

install-libs: libbackup
	make -C include install
	install -D -g root -o root $(lbup_so) $(libdir)/$(lbup_so)
	ln -fs $(libdir)/$(lbup_so) $(libdir)/libbackup.so
	ln -fs $(libdir)/$(lbup_so) $(libdir)/libbackup.so.0

clean:
	rm -f *.o $(libs)

# vi: set noexpandtab sw=4 ts=4:
