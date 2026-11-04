#ifndef KYRIAKON_ENCRYPT_RUN_H
#define KYRIAKON_ENCRYPT_RUN_H

/* Running the kyriakon-encrypt CLI from the Dovecot save path, shared by the
 * plugin and its test.
 *
 * The plugin hands the plaintext message to `kyriakon-encrypt encrypt` and
 * takes the ciphertext from its stdout. The child's exit status is the save's
 * verdict: exit 0 and a non-empty ciphertext mean the bytes are the whole
 * armour, anything else fails the save before the Maildir is touched. No
 * crypto, keyring, or protocol lives here.
 *
 * Only libc and no Dovecot headers on purpose: the plugin needs Dovecot to
 * build, this does not, so CI compiles and tests the process glue.
 */

#include <stdbool.h>
#include <stddef.h>

/* Installed by deploy-mail.sh; overridable at build time for a relocated box. */
#ifndef KYRIAKON_ENCRYPT_BIN
#define KYRIAKON_ENCRYPT_BIN "/usr/local/sbin/kyriakon-encrypt"
#endif
#ifndef KYRIAKON_KEYRING
#define KYRIAKON_KEYRING "/etc/kyriakon/keys"
#endif

struct kyriakon_encrypt_result {
	/* malloc'd ciphertext; NULL on failure, and the caller owns it on
	 * success. */
	unsigned char *ciphertext;
	size_t ciphertext_len;
	/* Exit status of the child, or -1 when it died on a signal. */
	int exit_code;
	/* Why the save failed, empty when it did not. */
	char error[256];
};

/* Encrypt `input` to `user`'s key by running `bin`. `keyring` is the directory
 * of `<localpart>.asc` certs; `gpg_home` is a writable scratch directory the
 * caller creates and removes. Returns true only when the child exited 0 and
 * wrote a non-empty ciphertext. */
bool kyriakon_encrypt_message(const char *bin, const char *user,
			      const char *keyring, const char *gpg_home,
			      const unsigned char *input, size_t input_len,
			      struct kyriakon_encrypt_result *result);

#endif
