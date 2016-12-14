#
# Makefile
#

debug=0

ldio_vmaj = 0
ldio_vmin = 1
ldio_so = libdirectio.so.$(ldio_vmaj).$(ldio_vmin)

ifeq ($(debug), 1)
CFLAGS=-ggdb3 -O0 -Wall -Wextra
else
CFLAGS=-O2 -s -Wall -Wextra
endif

prefix=/usr/local
bindir=$(prefix)/bin
libdir=$(prefix)/lib

progs = attr_idx cp_mem open open_pipes replicate tmpfile
libs = $(ldio_so)

all: $(progs) libdirectio

%: %.c
	gcc $(CFLAGS) -o $@ $^

attr_idx: attr_idx.o
	gcc -o $@ `pkg-config --libs libutil` $^

attr_idx.o: attr_idx.c
	gcc -c -Wall -Wextra `pkg-config --cflags libutil` $^

replicate: replicate.o
	gcc -o $@ -lmount `pkg-config --libs libjson` `pkg-config --libs libutil` $^

replicate.o: replicate.c
	gcc -c $(CFLAGS) `pkg-config --cflags libjson` \
	`pkg-config --cflags libutil` $^

replicate.c: replicate.h

replicate.h: replicate.spec
	scripts/spec_to_h.pl $^ CONFIG_GRAM > $@

libdirectio.o: libdirectio.c
	gcc -c -fPIC -O2 -Wall -Wextra $^

.PHONY: libdirectio install-progs install-libs clean

libdirectio: libdirectio.o
	gcc -o $(ldio_so) -shared \
	-Wl,-soname,libdirectio.so.$(ldio_vmaj) $^ -lc -ldl

install-git-helpers:
	make -C git install

install-progs: $(progs)
	install -D -g root -o root -s $(progs) $(bindir)
	ln -fs open $(bindir)/delete_input

install-libs: libdirectio
	install -D -g root -o root $(ldio_so) $(libdir)/$(ldio_so)
	ln -fs $(libdir)/$(ldio_so) $(libdir)/libdirectio.so
	ln -fs $(libdir)/$(ldio_so) $(libdir)/libdirectio.so.0

clean:
	rm -f replicate.h *.o $(progs) $(libs)
