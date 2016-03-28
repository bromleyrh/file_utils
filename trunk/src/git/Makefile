#
# Makefile
#

prefix=/usr/local
bindir=$(prefix)/bin

.PHONY: install clean

all:

install:
	for i in git-commit-archive git-set-version git-verify; \
		do install -D -g root -o root -m 0755 $$i $(bindir)/$$i; \
	done

clean:

# vi: set noexpandtab sw=4 ts=4:
