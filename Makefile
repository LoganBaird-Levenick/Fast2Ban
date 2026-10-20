PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1
SYSCONFDIR ?= /etc
SYSTEMD_DIR ?= $(SYSCONFDIR)/systemd/system
LOGROTATE_DIR ?= $(SYSCONFDIR)/logrotate.d
BASH_COMPLETION_DIR ?= $(PREFIX)/share/bash-completion/completions
ZSH_COMPLETION_DIR ?= $(PREFIX)/share/zsh/site-functions

BINARIES = fast2ban-server fast2ban-client fast2ban-regex
MANPAGES = fast2ban-server.1 fast2ban-client.1 fast2ban-regex.1

.PHONY: all build clean test install install-symlinks uninstall

all: build

build:
	cargo build --release

test:
	cargo test --workspace

clean:
	cargo clean

install:
	install -d "$(DESTDIR)$(BINDIR)"
	for bin in $(BINARIES); do \
		install -m 755 "target/release/$$bin" "$(DESTDIR)$(BINDIR)/$$bin"; \
	done
	install -d "$(DESTDIR)$(MANDIR)"
	for man in $(MANPAGES); do \
		install -m 644 "man/$$man" "$(DESTDIR)$(MANDIR)/$$man"; \
	done
	install -d "$(DESTDIR)$(SYSTEMD_DIR)"
	install -m 644 files/fast2ban.service "$(DESTDIR)$(SYSTEMD_DIR)/fast2ban.service"
	install -d "$(DESTDIR)$(LOGROTATE_DIR)"
	install -m 644 files/fast2ban.logrotate "$(DESTDIR)$(LOGROTATE_DIR)/fast2ban"
	install -d "$(DESTDIR)$(BASH_COMPLETION_DIR)"
	install -m 644 files/bash-completion/fast2ban "$(DESTDIR)$(BASH_COMPLETION_DIR)/fast2ban"
	install -d "$(DESTDIR)$(ZSH_COMPLETION_DIR)"
	install -m 644 files/zsh-completion/_fast2ban "$(DESTDIR)$(ZSH_COMPLETION_DIR)/_fast2ban"

install-symlinks:
	ln -sf fast2ban-server "$(DESTDIR)$(BINDIR)/fail2ban-server"
	ln -sf fast2ban-client "$(DESTDIR)$(BINDIR)/fail2ban-client"
	ln -sf fast2ban-regex  "$(DESTDIR)$(BINDIR)/fail2ban-regex"

uninstall:
	for bin in $(BINARIES) fail2ban-server fail2ban-client fail2ban-regex; do \
		rm -f "$(DESTDIR)$(BINDIR)/$$bin"; \
	done
	for man in $(MANPAGES); do \
		rm -f "$(DESTDIR)$(MANDIR)/$$man"; \
	done
	rm -f "$(DESTDIR)$(SYSTEMD_DIR)/fast2ban.service"
	rm -f "$(DESTDIR)$(LOGROTATE_DIR)/fast2ban"
	rm -f "$(DESTDIR)$(BASH_COMPLETION_DIR)/fast2ban"
	rm -f "$(DESTDIR)$(ZSH_COMPLETION_DIR)/_fast2ban"
