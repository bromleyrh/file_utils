#
# Makefile
#

prefix=/usr/local
bindir=$(prefix)/bin

helpers=git-commit-archive git-make-bundle git-prepare git-set-version \
git-verify

.PHONY: install clean

all:

install:
	if [ `uname` = "FreeBSD" ]; then \
		for i in $(helpers); \
			do install -g wheel -o root -m 0755 $$i $(bindir); \
		done; \
	else \
		for i in $(helpers); \
			do install -D -g root -o root -m 0755 $$i $(bindir)/$$i; \
		done; \
	fi

clean:

# vi: set noexpandtab sw=4 ts=4:
