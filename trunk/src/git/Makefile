#
# Makefile
#

prefix=/usr/local
bindir=$(prefix)/bin

.PHONY: install clean

all:

install:
	if [ `uname` = "FreeBSD" ]; then \
		for i in git-commit-archive git-prepare git-set-version git-verify; \
			do install -g wheel -o root -m 0755 $$i $(bindir); \
		done; \
	else \
		for i in git-commit-archive git-prepare git-set-version git-verify; \
			do install -D -g root -o root -m 0755 $$i $(bindir)/$$i; \
		done; \
	fi

clean:

# vi: set noexpandtab sw=4 ts=4:
