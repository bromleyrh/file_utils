#
# Makefile
#

all: cp_mem open open_pipes libdirectio

cp_mem: cp_mem.c
	gcc -O2 -o $@ -s -Wall -Wextra $^

open: open.c
	gcc -O2 -o $@ -s -Wall -Wextra $^

open_pipes: open_pipes.c
	gcc -O2 -o $@ -s -Wall -Wextra $^

libdirectio.o: libdirectio.c
	gcc -c -fPIC -O2 -Wall -Wextra $^

LDIO_VMAJ = 0
LDIO_VMIN = 1
libdirectio: libdirectio.o
	gcc -o libdirectio.so.$(LDIO_VMAJ).$(LDIO_VMIN) -shared \
	-Wl,-soname,libdirectio.so.$(LDIO_VMAJ) $^ -lc -ldl
