#
# Makefile
#

prefix=/usr/local
bindir=$(prefix)/bin

helpers=git-ck git-commit-archive git-cscope git-get-bundles git-install-dist \
git-make-bundle git-prepare git-set-version git-submodule-commit git-verify

.PHONY: install clean

all:

install:
	if [ `uname` = "FreeBSD" ]; then \
		for i in $(helpers); \
			do install -g wheel -o root -m 0755 $$i $(bindir); \
		done; \
		ln -fs git-make-bundle $(bindir)/git-make-bundles; \
	else \
		for i in $(helpers); \
			do install -D -g root -o root -m 0755 $$i $(bindir)/$$i; \
		done; \
		ln -fs git-make-bundle $(bindir)/git-make-bundles; \
	fi

clean:

# vi: set noexpandtab sw=4 ts=4:
