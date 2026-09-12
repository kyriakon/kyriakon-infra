# Build the kyriakon-encrypt Dovecot plugin.
#
# Requires Dovecot's headers, seeded on OpenBSD by the dovecot package:
#   pkg_add dovecot        # ships include/dovecot/*.h and lib/dovecot/*.so
#
#   make                  # produces libkyriakon_encrypt_plugin.so
#   doas make install     # installs into $(MODULEDIR)
#
# Paths default to the packaged OpenBSD layout and can be overridden:
#   make INCLUDEDIR=/usr/include/dovecot MODULEDIR=/usr/lib/dovecot
# deploy-mail.sh sources lib/dovecot/dovecot-config on the box and passes both,
# so the defaults here only matter for a hand run.
#
# The filename deliberately carries no ABI prefix. src/lib/module-dir.c derives
# the plugin name from the filename as [lib][nn_]name(.so), so
# lib2.3_kyriakon_encrypt_plugin.so registers as "2.3_kyriakon_encrypt" and the
# `mail_plugins = kyriakon_encrypt` lookup never matches it. A run of digits
# followed by "_" is stripped, so a numeric priority prefix would work, but
# nothing here needs a load order.
#
# Plain make syntax only, on purpose: OpenBSD's make is bmake, which has no
# $(shell) or $(wildcard), and macOS ships GNU make 3.81, which has no !=.

INCLUDEDIR ?= /usr/local/include/dovecot
MODULEDIR ?= /usr/local/lib/dovecot

CC ?= cc
CFLAGS += -fPIC -Wall -Wextra -O2
CFLAGS += -I${INCLUDEDIR}
LDFLAGS += -shared

PLUGIN = libkyriakon_encrypt_plugin.so

all: check ${PLUGIN}

check:
	@if [ ! -d "${INCLUDEDIR}" ]; then \
		echo "Dovecot headers not found in ${INCLUDEDIR}: install the dovecot package, or pass INCLUDEDIR="; \
		exit 1; \
	fi

${PLUGIN}: kyriakon-encrypt-plugin.c check
	${CC} ${CFLAGS} ${LDFLAGS} -o ${PLUGIN} kyriakon-encrypt-plugin.c

install: check ${PLUGIN}
	install -m 0644 ${PLUGIN} ${MODULEDIR}/${PLUGIN}

clean:
	rm -f ${PLUGIN}

.PHONY: all check install clean
