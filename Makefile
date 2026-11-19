# yindle — build, test, coverage-gate, and FHS install targets.
#
# Standard root install:
#   make && sudo make install
# Unprivileged / packager staging (no cargo rebuild, no chown):
#   cargo build --workspace --release --locked
#   make install-files DESTDIR=/path/to/stage PROFILE=release CHOWN=0

PREFIX        ?= /usr
DESTDIR       ?=
BINDIR        ?= $(PREFIX)/bin
SBINDIR       ?= $(PREFIX)/sbin
SERVERBIN     ?= $(PREFIX)/lib/cups
DATADIR       ?= $(PREFIX)/share/cups
DOCDIR        ?= $(PREFIX)/share/doc/yindle
MANDIR        ?= $(PREFIX)/share/man
UNITDIR       ?= $(PREFIX)/lib/systemd/system
TMPFILESDIR   ?= $(PREFIX)/lib/tmpfiles.d
SYSUSERSDIR   ?= $(PREFIX)/lib/sysusers.d
SYSCONFDIR    ?= /etc/cups
PAMDIR        ?= /etc/pam.d
LOGROTATEDIR  ?= /etc/logrotate.d
SPOOLDIR      ?= /var/spool/cups
LOGDIR        ?= /var/log/cups
CACHEDIR      ?= /var/cache/cups
RUNDIR        ?= /run/cups
USER          ?= lp
GROUP         ?= lp
CHOWN         ?= 1
INSTALL_SYSTEMD ?= 1
INSTALL_DOCS  ?= 1
THRESHOLD     ?= 95

CARGO         ?= cargo
STRIP         ?= strip
PROFILE       ?= release
TARGETDIR     ?= target/$(PROFILE)

ifeq ($(CHOWN),1)
  INSTALL_OWNER_LP := -o $(USER) -g $(GROUP)
  INSTALL_GROUP_LP := -g $(GROUP)
else
  INSTALL_OWNER_LP :=
  INSTALL_GROUP_LP :=
endif

# Shipped binaries -> their FHS install locations (ServerBin layout).
DAEMONS       := cups-deviced cups-driverd
HELPERS       := cups-exec cups-lpd
BACKENDS      := socket file ipp lpd snmp usb dnssd serial parallel
BIN_PROGS     := cupsfilter
SYSTEMD_UNITS := cups.service cups.socket cups.path cups-lpd@.service cups-lpd.socket
MIME_FILES    := mime.types mime.convs

.PHONY: all build install install-files install-strip uninstall \
        test check-fmt clippy conformance coverage test-gate

all: build

build:
	$(CARGO) build --workspace --profile $(PROFILE)

# ---- install -------------------------------------------------------------
# Perm map (upstream CUPS FHS install):
#   sbin/cupsd           0755 root:root
#   daemon/*             0755 root:root   (cups-deviced/cups-driverd/cups-exec/cups-lpd)
#   backend/*            0755 root:root   (usb/parallel are 0700 for device access)
#   filter/ notifier/    0755 root:root   (dirs for external/site filters)
#   bin/cupsfilter       0755 root:root
#   etc/cups             0755 root:lp     (cupsd.conf 0640, ssl 0700 root:root)
#   spool/log/cache/run  lp:lp            (explicit modes below)
install: build install-files

install-files:
	install -d -m 0755 "$(DESTDIR)$(SBINDIR)" "$(DESTDIR)$(BINDIR)"
	install -m 0755 "$(TARGETDIR)/cupsd" "$(DESTDIR)$(SBINDIR)/cupsd"
	# ServerBin helpers and backends.
	install -d -m 0755 \
		"$(DESTDIR)$(SERVERBIN)/daemon" \
		"$(DESTDIR)$(SERVERBIN)/backend" \
		"$(DESTDIR)$(SERVERBIN)/filter" \
		"$(DESTDIR)$(SERVERBIN)/notifier" \
		"$(DESTDIR)$(SERVERBIN)/driver" \
		"$(DESTDIR)$(SERVERBIN)/cgi-bin"
	for d in $(DAEMONS) $(HELPERS); do \
		install -m 0755 "$(TARGETDIR)/$$d" "$(DESTDIR)$(SERVERBIN)/daemon/$$d"; \
	done
	for b in $(BACKENDS); do \
		install -m 0755 "$(TARGETDIR)/$$b" "$(DESTDIR)$(SERVERBIN)/backend/$$b"; \
	done
	# usb + parallel backends are mode 0700 upstream (direct device access).
	chmod 0700 "$(DESTDIR)$(SERVERBIN)/backend/usb"
	chmod 0700 "$(DESTDIR)$(SERVERBIN)/backend/parallel"
	for p in $(BIN_PROGS); do \
		install -m 0755 "$(TARGETDIR)/$$p" "$(DESTDIR)$(BINDIR)/$$p"; \
	done
	# Data files (MIME DB, banners, drv, ppd, doc-root).
	install -d -m 0755 \
		"$(DESTDIR)$(DATADIR)/mime" \
		"$(DESTDIR)$(DATADIR)/banners" \
		"$(DESTDIR)$(DATADIR)/drv" \
		"$(DESTDIR)$(DATADIR)/ppd" \
		"$(DESTDIR)$(DATADIR)/data" \
		"$(DESTDIR)$(DATADIR)/templates" \
		"$(DESTDIR)$(DATADIR)/doc-root"
	for f in $(MIME_FILES); do \
		install -m 0644 "data/mime/$$f" "$(DESTDIR)$(DATADIR)/mime/$$f"; \
	done
	if [ -d data/banners ]; then \
		for f in data/banners/*; do \
			[ -f "$$f" ] && install -m 0644 "$$f" "$(DESTDIR)$(DATADIR)/banners/"; \
		done; \
	fi
	# Configuration tree — never overwrite existing cupsd.conf or cups-files.conf.
	install -d -m 0755 $(INSTALL_GROUP_LP) "$(DESTDIR)$(SYSCONFDIR)"
	install -d -m 0755 "$(DESTDIR)$(SYSCONFDIR)/ppd" "$(DESTDIR)$(SYSCONFDIR)/interfaces"
	install -d -m 0700 "$(DESTDIR)$(SYSCONFDIR)/ssl"
	install -m 0640 $(INSTALL_GROUP_LP) data/cupsd.conf.default \
		"$(DESTDIR)$(SYSCONFDIR)/cupsd.conf.default"
	install -m 0640 $(INSTALL_GROUP_LP) data/cups-files.conf.default \
		"$(DESTDIR)$(SYSCONFDIR)/cups-files.conf.default"
	if [ ! -e "$(DESTDIR)$(SYSCONFDIR)/cupsd.conf" ]; then \
		install -m 0640 $(INSTALL_GROUP_LP) data/cupsd.conf.default \
			"$(DESTDIR)$(SYSCONFDIR)/cupsd.conf"; \
	else \
		echo "Preserving existing $(DESTDIR)$(SYSCONFDIR)/cupsd.conf (see cupsd.conf.default)"; \
	fi
	if [ ! -e "$(DESTDIR)$(SYSCONFDIR)/cups-files.conf" ]; then \
		install -m 0640 $(INSTALL_GROUP_LP) data/cups-files.conf.default \
			"$(DESTDIR)$(SYSCONFDIR)/cups-files.conf"; \
	else \
		echo "Preserving existing $(DESTDIR)$(SYSCONFDIR)/cups-files.conf (see cups-files.conf.default)"; \
	fi
	# Mutable spool/log/cache/run trees.
	install -d -m 0710 $(INSTALL_OWNER_LP) "$(DESTDIR)$(SPOOLDIR)" "$(DESTDIR)$(SPOOLDIR)/tmp"
	install -d -m 0755 $(INSTALL_OWNER_LP) "$(DESTDIR)$(LOGDIR)"
	install -d -m 0770 $(INSTALL_OWNER_LP) "$(DESTDIR)$(CACHEDIR)" "$(DESTDIR)$(CACHEDIR)/rss"
	install -d -m 0755 $(INSTALL_OWNER_LP) "$(DESTDIR)$(RUNDIR)" "$(DESTDIR)$(RUNDIR)/certs"
	# systemd units, tmpfiles.d, sysusers.d.
	if [ "$(INSTALL_SYSTEMD)" = "1" ]; then \
		install -d -m 0755 "$(DESTDIR)$(UNITDIR)" "$(DESTDIR)$(TMPFILESDIR)" "$(DESTDIR)$(SYSUSERSDIR)"; \
		for u in $(SYSTEMD_UNITS); do \
			install -m 0644 "data/systemd/$$u" "$(DESTDIR)$(UNITDIR)/$$u"; \
		done; \
		install -m 0644 data/tmpfiles.d/yindle.conf "$(DESTDIR)$(TMPFILESDIR)/yindle.conf"; \
		install -m 0644 data/sysusers.d/yindle.conf "$(DESTDIR)$(SYSUSERSDIR)/yindle.conf"; \
	fi
	# PAM and logrotate configuration (preserve existing live configs).
	install -d -m 0755 "$(DESTDIR)$(PAMDIR)" "$(DESTDIR)$(LOGROTATEDIR)"
	if [ ! -e "$(DESTDIR)$(PAMDIR)/cups" ]; then \
		install -m 0644 packaging/pam/cups "$(DESTDIR)$(PAMDIR)/cups"; \
	else \
		echo "Preserving existing $(DESTDIR)$(PAMDIR)/cups"; \
	fi
	if [ ! -e "$(DESTDIR)$(LOGROTATEDIR)/yindle" ]; then \
		install -m 0644 data/logrotate.d/yindle "$(DESTDIR)$(LOGROTATEDIR)/yindle"; \
	else \
		echo "Preserving existing $(DESTDIR)$(LOGROTATEDIR)/yindle"; \
	fi
	# Man pages (installed automatically when man/ is present).
	if [ -d man ]; then \
		for f in man/*.[1-8] man/man[1-8]/*.[1-8]; do \
			[ -f "$$f" ] || continue; \
			sec=$${f##*.}; \
			install -d -m 0755 "$(DESTDIR)$(MANDIR)/man$$sec"; \
			install -m 0644 "$$f" "$(DESTDIR)$(MANDIR)/man$$sec/"; \
		done; \
	fi
	# Documentation.
	if [ "$(INSTALL_DOCS)" = "1" ]; then \
		install -d -m 0755 "$(DESTDIR)$(DOCDIR)"; \
		for doc in README.md SECURITY.md CHANGELOG.md NOTICE LICENSE-APACHE LICENSE-MIT \
		           docs/conformance.md docs/deviations.md; do \
			[ -f "$$doc" ] && install -m 0644 "$$doc" "$(DESTDIR)$(DOCDIR)/"; \
		done; \
	fi

install-strip: install-files
	$(STRIP) "$(DESTDIR)$(SBINDIR)/cupsd"
	for d in $(DAEMONS) $(HELPERS); do \
		$(STRIP) "$(DESTDIR)$(SERVERBIN)/daemon/$$d"; \
	done
	for b in $(BACKENDS); do \
		$(STRIP) "$(DESTDIR)$(SERVERBIN)/backend/$$b"; \
	done
	for p in $(BIN_PROGS); do \
		$(STRIP) "$(DESTDIR)$(BINDIR)/$$p"; \
	done

# Remove installed binaries, data, units, docs, and default templates.
# User configuration (/etc/cups/*.conf) and spool/log state are preserved.
uninstall:
	rm -f "$(DESTDIR)$(SBINDIR)/cupsd"
	for d in $(DAEMONS) $(HELPERS); do \
		rm -f "$(DESTDIR)$(SERVERBIN)/daemon/$$d"; \
	done
	for b in $(BACKENDS); do \
		rm -f "$(DESTDIR)$(SERVERBIN)/backend/$$b"; \
	done
	for p in $(BIN_PROGS); do \
		rm -f "$(DESTDIR)$(BINDIR)/$$p"; \
	done
	for f in $(MIME_FILES); do \
		rm -f "$(DESTDIR)$(DATADIR)/mime/$$f"; \
	done
	rm -f "$(DESTDIR)$(SYSCONFDIR)/cupsd.conf.default" \
		"$(DESTDIR)$(SYSCONFDIR)/cups-files.conf.default"
	for u in $(SYSTEMD_UNITS); do \
		rm -f "$(DESTDIR)$(UNITDIR)/$$u"; \
	done
	rm -f "$(DESTDIR)$(TMPFILESDIR)/yindle.conf" \
		"$(DESTDIR)$(SYSUSERSDIR)/yindle.conf"
	if [ -d man ]; then \
		for f in man/*.[1-8] man/man[1-8]/*.[1-8]; do \
			[ -f "$$f" ] || continue; \
			sec=$${f##*.}; \
			rm -f "$(DESTDIR)$(MANDIR)/man$$sec/$$(basename "$$f")"; \
		done; \
	fi
	rm -rf "$(DESTDIR)$(DOCDIR)"

check-fmt:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

test:
	$(CARGO) test --workspace

conformance:
	./scripts/conformance.sh

coverage:
	THRESHOLD=$(THRESHOLD) ./scripts/coverage-gate.sh --summary

test-gate: check-fmt clippy test coverage
