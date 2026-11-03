/* Test for the save path's process glue: spawn, move the message, read the
 * ciphertext, and read the exit status. The plugin needs Dovecot's headers to
 * build, this does not, so it is compiled and run on its own:
 *
 *   cc -std=c99 -Wall -Wextra -Werror -o test-encrypt-run \
 *      test-encrypt-run.c encrypt-run.c
 *   ./test-encrypt-run ./test-fake-encryptor
 */

/* POSIX pipe/fork/sigaction/setenv under -std=c99. */
#define _POSIX_C_SOURCE 200809L

#include "encrypt-run.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void
expect(bool ok, const char *what)
{
	if (!ok) {
		fprintf(stderr, "FAIL: %s\n", what);
		failures++;
	}
}

static void
mode(const char *name)
{
	if (name == NULL)
		unsetenv("KYRIAKON_FAKE_MODE");
	else
		setenv("KYRIAKON_FAKE_MODE", name, 1);
}

int
main(int argc, char **argv)
{
	const char *fake;
	struct kyriakon_encrypt_result result;
	unsigned char *input;
	size_t input_len = 1024 * 1024;
	size_t i;
	bool ok;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <fake-encryptor>\n", argv[0]);
		return 2;
	}
	fake = argv[1];

	/* A message larger than a pipe buffer both ways: the glue has to move all
	 * of it, and the child has to have read every byte. */
	input = malloc(input_len);
	for (i = 0; i < input_len; i++)
		input[i] = (unsigned char)(i * 31 + 7);

	mode(NULL);
	ok = kyriakon_encrypt_message(fake, "alice", "/keyring", "/gpg",
				      input, input_len, &result);
	expect(ok, "a successful encryption is accepted");
	if (ok) {
		expect(result.ciphertext_len == input_len + 3,
		       "the whole ciphertext arrives");
		expect(memcmp(result.ciphertext, "CT:", 3) == 0,
		       "the ciphertext is the child's stdout");
		expect(result.ciphertext_len > 3 &&
			       memcmp(result.ciphertext + 3, input, input_len) == 0,
		       "the whole message reaches the child");
		expect(result.exit_code == 0, "a successful run exits 0");
		expect(result.error[0] == '\0', "success carries no error");
		free(result.ciphertext);
	}

	/* gpg failed: no key, bad cert. The save must fail and keep nothing. */
	mode("fail");
	ok = kyriakon_encrypt_message(fake, "alice", "/keyring", "/gpg",
				      input, input_len, &result);
	expect(!ok, "a failed encryption is rejected");
	expect(result.ciphertext == NULL, "a failed encryption returns no bytes");
	expect(result.exit_code == 1, "the child's exit status is reported");
	expect(result.error[0] != '\0', "a failure says why");

	/* The child died after writing part of its output: the partial armour is
	 * exactly what must never reach save_begin. */
	mode("truncated");
	ok = kyriakon_encrypt_message(fake, "alice", "/keyring", "/gpg",
				      input, input_len, &result);
	expect(!ok, "a truncated encryption is rejected");
	expect(result.ciphertext == NULL,
	       "the partial ciphertext is discarded");

	mode("empty");
	ok = kyriakon_encrypt_message(fake, "alice", "/keyring", "/gpg",
				      input, input_len, &result);
	expect(!ok, "an empty ciphertext is rejected");

	/* A CLI killed after writing part of its ciphertext has no exit status at
	 * all: the parent has to notice the signal, not read 0 as success. */
	mode("killed");
	ok = kyriakon_encrypt_message(fake, "alice", "/keyring", "/gpg",
				      input, input_len, &result);
	expect(!ok, "a killed encryptor is rejected");
	expect(result.ciphertext == NULL,
	       "a killed encryptor returns no bytes");
	expect(result.exit_code == -1, "a signal is reported as -1");
	expect(strstr(result.error, "signal") != NULL, "the signal is named");

	/* A host that has SIGCHLD ignored reaps its children without a status, and
	 * every save would fail on waitpid unless the glue resets it. */
	mode(NULL);
	{
		struct sigaction ignore, previous;

		memset(&ignore, 0, sizeof(ignore));
		ignore.sa_handler = SIG_IGN;
		sigemptyset(&ignore.sa_mask);
		sigaction(SIGCHLD, &ignore, &previous);
		ok = kyriakon_encrypt_message(fake, "alice", "/keyring", "/gpg",
					      input, input_len, &result);
		sigaction(SIGCHLD, &previous, NULL);
	}
	expect(ok, "an ignored SIGCHLD does not break the save");
	if (ok)
		free(result.ciphertext);

	mode(NULL);
	ok = kyriakon_encrypt_message("/nonexistent/kyriakon-encrypt", "alice",
				      "/keyring", "/gpg", input, input_len,
				      &result);
	expect(!ok, "a missing encryptor is rejected");
	expect(strstr(result.error, "cannot run") != NULL,
	       "a missing encryptor says which one");

	free(input);
	if (failures != 0)
		return 1;
	printf("encrypt-run: all checks passed\n");
	return 0;
}
