# Build the kyriakon-encrypt Dovecot plugin.
#
# Requires Dovecot's headers, seeded by the dovecot package on OpenBSD:
#   pkg_add dovecot        # ships /usr/local/lib/dovecot/dovecot-config,
#                          # NOT on PATH, and include/dovecot/*.h
#
#   make                  # produces lib<abi>_kyriakon_encrypt_plugin.so
#   doas make install     # installs into $(dovecot-config --moduledir)
#
# Enable in dovecot.conf:
#   mail_plugins = $mail_plugins kyriakon_encrypt
#
# and run the kyriakon-encrypt daemon on /var/run/kyriakon/encrypt.sock
# (see ../kyriakon-encrypt). Compile-verify this on a real OpenBSD host - it
# is not buildable in CI without Dovecot headers, per docs/planning/specs.

# Upstream installs dovecot-config into the library directory, so it is not
# found by name on OpenBSD. Prefer that path when it exists, and fall back to a
# PATH lookup for systems that put it elsewhere.
DOVECOT_CONFIG ?= $(firstword $(wildcard /usr/local/lib/dovecot/dovecot-config) dovecot-config)
CC ?= cc
CFLAGS += -fPIC -Wall -Wextra -O2
CFLAGS += $(shell $(DOVECOT_CONFIG) --cflags)
LDFLAGS += -shared

MODULEDIR ?= $(shell $(DOVECOT_CONFIG) --moduledir)
ABI ?= $(shell $(DOVECOT_CONFIG) --abiversion)

PLUGIN = lib$(ABI)_kyriakon_encrypt_plugin.so

all: $(PLUGIN)

$(PLUGIN): kyriakon-encrypt-plugin.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

install: $(PLUGIN)
	install -m 0644 $(PLUGIN) $(MODULEDIR)/$(PLUGIN)

clean:
	rm -f $(PLUGIN)

.PHONY: all install clean
