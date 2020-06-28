#
# Makefile
#

prefix=/usr/local
bindir=$(prefix)/bin

helpers=git-branches git-ck git-clean-bundles git-commit-archive git-cscope \
git-get-bundles git-install-dist git-make-bundle git-prepare git-prepare-init \
git-rebase-all git-remotes git-set-version git-skel git-submodule-commit \
git-submodule-repeat git-update git-verify

.PHONY: install clean

all:

install:
	if [ `uname` = "FreeBSD" ]; then \
		for i in $(helpers); \
			do install -g wheel -o root -m 0755 $$i $(bindir); \
		done; \
	elif [ `uname` = "Darwin" ]; then \
		for i in $(helpers); \
			do install -g 0 -o 0 -m 0755 $$i $(bindir)/$$i; \
		done; \
	else \
		for i in $(helpers); \
			do install -D -g root -o root -m 0755 $$i $(bindir)/$$i; \
		done; \
	fi; \
	ln -fs git-branches $(bindir)/git-sync; \
	ln -fs git-install-dist $(bindir)/git-install-dist-cmdpost; \
	ln -fs git-install-dist $(bindir)/git-install-dist-cmdpre; \
	ln -fs git-make-bundle $(bindir)/git-make-bundles; \
	ln -fs git-submodule-repeat $(bindir)/git-submodule-clean; \
	ln -fs git-submodule-repeat $(bindir)/git-submodule-fetch; \
	if [ `uname` = "Darwin" ]; then \
		chmod -h 0755 $(bindir)/git-sync $(bindir)/git-install-dist-cmdpost \
			$(bindir)/git-install-dist-cmdpre $(bindir)/git-make-bundles \
			$(bindir)/git-submodule-clean $(bindir)/git-submodule-fetch; \
	fi

clean:

# vi: set noexpandtab sw=4 ts=4:
