#
# Makefile
#

prefix = /usr/local
includedir = $(prefix)/include

headers = backup.h

install:
	make -C backup install
	install -D -g root -m 0644 -o root -t $(includedir) $(headers)

# vi: set noexpandtab sw=4 ts=4:
