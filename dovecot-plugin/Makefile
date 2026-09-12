# Build the kyriakon-encrypt Dovecot plugin.
#
# Requires Dovecot's headers, seeded on OpenBSD by the dovecot package:
#   pkg_add dovecot        # ships include/dovecot/*.h and lib/dovecot/*.so
#
#   make                  # produces lib<abi>_kyriakon_encrypt_plugin.so
#   doas make install     # installs into $(MODULEDIR)
#
# Enable in dovecot.conf:
#   mail_plugins = $mail_plugins kyriakon_encrypt
#
# and run the kyriakon-encrypt daemon on /var/run/kyriakon/encrypt.sock
# (see ../kyriakon-encrypt). Compile-verify this on a real OpenBSD host - it
# is not buildable in CI without Dovecot headers, per docs/planning/specs.

# On OpenBSD this file is a shell variable file: 0644, not on PATH, and it has
# no --flags interface, so it is sourced rather than executed. It defines
# dovecot_pkgincludedir and dovecot_moduledir, which is all this build needs.
DOVECOT_CONFIG ?= /usr/local/lib/dovecot/dovecot-config

dovecot_includedir := $(shell [ -r "$(DOVECOT_CONFIG)" ] && . "$(DOVECOT_CONFIG)" && printf '%s' "$${dovecot_pkgincludedir}")
dovecot_moduledir := $(shell [ -r "$(DOVECOT_CONFIG)" ] && . "$(DOVECOT_CONFIG)" && printf '%s' "$${dovecot_moduledir}")

# Fall back to the packaged layout when dovecot-config is absent, so the build
# still works if upstream moves it.
INCLUDEDIR ?= $(if $(dovecot_includedir),$(dovecot_includedir),/usr/local/include/dovecot)
MODULEDIR ?= $(if $(dovecot_moduledir),$(dovecot_moduledir),/usr/local/lib/dovecot)

# The packaged file carries no ABI version, so take it from the binary: Dovecot
# 2.3.x reports 2.3. The prefix is the third-party naming convention, and the
# loader globs lib*_<name>_plugin.so, so this only has to be consistent.
ABI ?= $(shell dovecot --version 2>/dev/null | cut -d. -f1,2)

CC ?= cc
CFLAGS += -fPIC -Wall -Wextra -O2
CFLAGS += -I$(INCLUDEDIR)
LDFLAGS += -shared

PLUGIN = lib$(ABI)_kyriakon_encrypt_plugin.so

all: check $(PLUGIN)

check:
	@if [ -z "$(ABI)" ]; then \
		echo "cannot determine the Dovecot ABI version: install dovecot, or run make ABI=2.3"; \
		exit 1; \
	fi
	@if [ ! -d "$(INCLUDEDIR)" ]; then \
		echo "Dovecot headers not found in $(INCLUDEDIR): install the dovecot package"; \
		exit 1; \
	fi

$(PLUGIN): kyriakon-encrypt-plugin.c check
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

install: check $(PLUGIN)
	install -m 0644 $(PLUGIN) $(MODULEDIR)/$(PLUGIN)

clean:
	rm -f $(PLUGIN)

.PHONY: all check install clean
