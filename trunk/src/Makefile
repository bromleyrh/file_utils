#
# Makefile
#

ldio_vmaj = 0
ldio_vmin = 1
ldio_so = libdirectio.so.$(ldio_vmaj).$(ldio_vmin)

progs = cp_mem open open_pipes
libs = $(ldio_so)

all: $(progs) libdirectio

%: %.c
	gcc -O2 -o $@ -s -Wall -Wextra $^

libdirectio.o: libdirectio.c
	gcc -c -fPIC -O2 -Wall -Wextra $^

.PHONY:
libdirectio: libdirectio.o
	gcc -o $(ldio_so) -shared \
	-Wl,-soname,libdirectio.so.$(ldio_vmaj) $^ -lc -ldl

.PHONY:
clean:
	rm -f *.o $(progs) $(libs)
