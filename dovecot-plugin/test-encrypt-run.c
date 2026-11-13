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
#include "encrypt-save.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

/* One save driven through encrypt-save.h: a non-blocking pipe stands in for
 * the IMAP client socket (or the LMTP temp file, once its write end closes),
 * and the backend's save methods just record what they were handed. */
struct save_fixture {
	struct kyriakon_save_ops ops;
	int begin_calls, continue_calls, finish_calls, cancel_calls;
	unsigned char cipher[4096];
	size_t cipher_len;

	int fd;
	unsigned char read_buffer[4096];
	unsigned int pull_calls;

	const char *fake;
	unsigned int encrypt_calls;
	unsigned char plain[4096];
	size_t plain_len;
};

static int
fixture_save_begin(void *context, const unsigned char *cipher, size_t size)
{
	struct save_fixture *f = context;

	f->begin_calls++;
	if (size <= sizeof(f->cipher)) {
		memcpy(f->cipher, cipher, size);
		f->cipher_len = size;
	}
	return 0;
}

static int
fixture_save_continue(void *context)
{
	struct save_fixture *f = context;

	f->continue_calls++;
	return 0;
}

static int
fixture_save_finish(void *context)
{
	struct save_fixture *f = context;

	f->finish_calls++;
	return 0;
}

static void
fixture_save_cancel(void *context)
{
	struct save_fixture *f = context;

	f->cancel_calls++;
}

static int
fixture_pull(void *context, const unsigned char **data_r, size_t *size_r,
	     char *error, size_t error_size)
{
	struct save_fixture *f = context;
	ssize_t ret;

	f->pull_calls++;
	ret = read(f->fd, f->read_buffer, sizeof(f->read_buffer));
	if (ret > 0) {
		*data_r = f->read_buffer;
		*size_r = (size_t)ret;
		return KYRIAKON_SAVE_PULL_DATA;
	}
	if (ret == 0)
		return KYRIAKON_SAVE_PULL_EOF;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return KYRIAKON_SAVE_PULL_WAIT;
	snprintf(error, error_size, "%s", strerror(errno));
	return KYRIAKON_SAVE_PULL_ERROR;
}

static bool
fixture_encrypt(void *context, const unsigned char *plain, size_t plain_len,
		struct kyriakon_encrypt_result *result)
{
	struct save_fixture *f = context;

	f->encrypt_calls++;
	if (plain_len <= sizeof(f->plain)) {
		memcpy(f->plain, plain, plain_len);
		f->plain_len = plain_len;
	}
	return kyriakon_encrypt_message(f->fake, "alice", "/keyring", "/gpg",
					plain, plain_len, result);
}

static void
save_arm(struct kyriakon_save *save, struct save_fixture *f, int fd,
	 const char *fake)
{
	memset(f, 0, sizeof(*f));
	f->fd = fd;
	f->fake = fake;
	f->ops.save_begin = fixture_save_begin;
	f->ops.save_continue = fixture_save_continue;
	f->ops.save_finish = fixture_save_finish;
	f->ops.save_cancel = fixture_save_cancel;
	kyriakon_save_begin(save, &f->ops, f, fixture_pull, fixture_encrypt, f);
}

/* The ordering that makes a synchronizing IMAP APPEND work: save_begin reads
 * nothing, a save with no literal available returns to the ioloop instead of
 * spinning, and the ciphertext appears only once the input reaches EOF. */
static void
test_save_ordering(const char *fake)
{
	struct kyriakon_save save;
	struct save_fixture f;
	int fds[2];

	/* (a) Arming the save must not touch the input, the encryptor, or the
	 * backend: Dovecot answers `+ OK` only after save_begin returns. */
	pipe(fds);
	fcntl(fds[0], F_SETFL, O_NONBLOCK);
	memset(&save, 0, sizeof(save));
	save_arm(&save, &f, fds[0], fake);
	expect(f.pull_calls == 0, "save_begin does not read the input");
	expect(f.encrypt_calls == 0, "save_begin does not run the encryptor");
	expect(f.begin_calls == 0, "save_begin does not start the backend");

	/* The client is still waiting for `+ OK`: one non-blocking read, then
	 * back to the ioloop. The old drain loop spun here. */
	expect(kyriakon_save_continue(&save) == 0, "an empty input waits");
	expect(f.pull_calls == 1, "an empty input is read once, not spun on");
	expect(f.encrypt_calls == 0, "nothing is encrypted before EOF");
	expect(f.begin_calls == 0, "the backend is not started before EOF");

	/* Half the literal has arrived: still nothing to encrypt. */
	expect(write(fds[1], "hello ", 6) == 6, "write the first half");
	expect(kyriakon_save_continue(&save) == 0, "a partial literal waits");
	expect(f.encrypt_calls == 0, "a partial literal is not encrypted");
	expect(f.begin_calls == 0, "the backend waits for the whole literal");

	/* (b) The literal completes: encrypt once, then start the backend on the
	 * ciphertext and continue it. */
	expect(write(fds[1], "world", 5) == 5, "write the second half");
	close(fds[1]);
	expect(kyriakon_save_continue(&save) == 0, "EOF starts the save");
	expect(save.begun, "the save is begun at EOF");
	expect(f.encrypt_calls == 1, "the message is encrypted exactly once");
	expect(f.plain_len == 11 && memcmp(f.plain, "hello world", 11) == 0,
	       "the encryptor gets the whole message");
	expect(f.begin_calls == 1, "the backend starts at EOF");
	expect(f.cipher_len == 14 &&
		       memcmp(f.cipher, "CT:hello world", 14) == 0,
	       "the backend is handed the ciphertext");
	expect(f.continue_calls == 1, "the backend is continued once");

	expect(kyriakon_save_continue(&save) == 0, "later continues forward");
	expect(f.continue_calls == 2, "later continues reach the backend");
	expect(kyriakon_save_finish(&save) == 0, "finish forwards");
	expect(f.finish_calls == 1, "the backend finishes");
	kyriakon_save_deinit(&save);
	close(fds[0]);

	/* A failed encryptor refuses the save before anything reaches the
	 * backend, exactly as the exit status decides today. */
	pipe(fds);
	fcntl(fds[0], F_SETFL, O_NONBLOCK);
	memset(&save, 0, sizeof(save));
	mode("fail");
	save_arm(&save, &f, fds[0], fake);
	expect(write(fds[1], "x", 1) == 1, "write a message that will fail");
	close(fds[1]);
	expect(kyriakon_save_continue(&save) == -1,
	       "a failed encryption is refused");
	expect(f.encrypt_calls == 1, "the encryptor ran once");
	expect(f.begin_calls == 0, "a refused save never starts the backend");
	expect(save.error[0] != '\0', "a refusal says why");
	kyriakon_save_cancel(&save);
	expect(f.cancel_calls == 0,
	       "cancelling before the backend starts touches nothing");
	kyriakon_save_deinit(&save);
	close(fds[0]);

	/* Finishing before the input reaches EOF refuses rather than starting a
	 * backend that has no ciphertext. */
	pipe(fds);
	fcntl(fds[0], F_SETFL, O_NONBLOCK);
	memset(&save, 0, sizeof(save));
	mode(NULL);
	save_arm(&save, &f, fds[0], fake);
	expect(write(fds[1], "x", 1) == 1, "write a partial message");
	expect(kyriakon_save_continue(&save) == 0, "the partial message waits");
	expect(kyriakon_save_finish(&save) == -1, "finish before EOF is refused");
	expect(f.finish_calls == 0, "the backend is not finished");
	expect(f.cancel_calls == 1, "the backend's context is cancelled");
	expect(save.error[0] != '\0', "the refusal says why");
	kyriakon_save_cancel(&save);
	expect(f.cancel_calls == 1, "cancelling after the refusal is local");
	kyriakon_save_deinit(&save);
	close(fds[1]);
	close(fds[0]);
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

	test_save_ordering(fake);

	free(input);
	if (failures != 0)
		return 1;
	printf("encrypt-run: all checks passed\n");
	return 0;
}
