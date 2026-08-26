# Build the kyriakon-encrypt Dovecot plugin.
#
# Requires Dovecot development headers (dovecot-config on PATH). On OpenBSD:
#   pkg_add dovecot        # ships /usr/local/bin/dovecot-config
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

DOVECOT_CONFIG ?= dovecot-config
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
