#ifndef KYRIAKON_ENCRYPT_SAVE_H
#define KYRIAKON_ENCRYPT_SAVE_H

/* The Save path's ordering, kept free of Dovecot types so the test can drive
 * it with a pipe.
 *
 * Dovecot's APPEND state machine begins the save before it answers a
 * synchronizing literal: cmd_append_parse_new_msg() (2.3 and 2.4
 * cmd-append.c) calls mailbox_save_begin(), and only then does
 * cmd_append_send_literal_continue() write the `+ OK`; the literal is fed
 * afterwards through mailbox_save_continue() by cmd_append_continue_message().
 * So save_begin must not read the input: the client only sends the literal
 * after the `+ OK`, and the mail process's idle ioloop is what runs meanwhile.
 * Reading there returns 0 on EAGAIN for the whole literal, and a retry loop
 * spins a core.
 *
 * So save_begin only arms the save. The caller drives the literal into
 * save_continue; each call pulls whatever the input has without blocking, and
 * returns to the ioloop when there is nothing yet. Once the input reaches EOF
 * the encryptor runs and the ciphertext is handed to the wrapped backend's
 * save_begin. LMTP needs no such round trip: its DATA is a blocking temp file
 * whose reads never return 0, so the first save_continue drains it to EOF and
 * encrypts inside that call.
 *
 * The child's exit status is still the save's verdict: a failed or truncated
 * encryption never starts the backend, so no plaintext reaches the Maildir.
 */

#include "encrypt-run.h"

enum kyriakon_save_pull {
	KYRIAKON_SAVE_PULL_ERROR = -2,
	KYRIAKON_SAVE_PULL_EOF = -1,
	KYRIAKON_SAVE_PULL_WAIT = 0,
	KYRIAKON_SAVE_PULL_DATA = 1
};

/* The whole plaintext is held in memory, so an authenticated member could
 * APPEND a multi-GB literal and exhaust the mail process. A message over this
 * size fails the save before the encryptor runs. 128 MiB is far above a real
 * message; the test compiles a smaller cap. */
#ifndef KYRIAKON_SAVE_PLAIN_MAX
#define KYRIAKON_SAVE_PLAIN_MAX (128 * 1024 * 1024)
#endif

/* Map one i_stream_read() result onto a pull status: > 0 data, 0 nothing yet,
 * -1 EOF, anything lower a stream error named by read_error. Lives here, not
 * in the plugin, so the status mapping is the one the test exercises. */
int kyriakon_save_pull(int ret, const char *read_error,
		       char *error, size_t error_size);

/* One chunk of plaintext, or a pull status. *data_r is valid only with
 * KYRIAKON_SAVE_PULL_DATA; the pump copies it before pulling again. WAIT means
 * nothing is available yet and must return to the caller. */
typedef int (*kyriakon_save_pull_fn)(void *context,
				     const unsigned char **data_r, size_t *size_r,
				     char *error, size_t error_size);

/* Run the encryptor over the complete plaintext. */
typedef bool (*kyriakon_save_encrypt_fn)(void *context,
					 const unsigned char *plain,
					 size_t plain_len,
					 struct kyriakon_encrypt_result *result);

/* The wrapped backend's save methods. save_begin is given the ciphertext. */
struct kyriakon_save_ops {
	int (*save_begin)(void *context, const unsigned char *cipher, size_t size);
	int (*save_continue)(void *context);
	int (*save_finish)(void *context);
	void (*save_cancel)(void *context);
};

struct kyriakon_save {
	const struct kyriakon_save_ops *ops;
	void *ops_context;
	kyriakon_save_pull_fn pull;
	kyriakon_save_encrypt_fn encrypt;

	/* shortcut: the whole message is held in memory (plain, then cipher);
	   spool to a temp file if mailbox volume makes that measurable. */
	unsigned char *plain;
	size_t plain_len;
	size_t plain_capacity;
	struct kyriakon_encrypt_result result;
	char error[256];

	bool encrypted;
	bool begun;
	bool failed;
};

/* Arm a save. Touches neither the input nor the encryptor; the caller drives
 * the literal afterwards through kyriakon_save_continue(). */
void kyriakon_save_begin(struct kyriakon_save *save,
			 const struct kyriakon_save_ops *ops, void *ops_context,
			 kyriakon_save_pull_fn pull,
			 kyriakon_save_encrypt_fn encrypt);

/* Pull whatever the input has now, without blocking. Returns 0 while the input
 * is incomplete; at EOF it runs the encryptor, starts the wrapped backend on
 * the ciphertext and returns the backend's continue verdict. A failure before
 * the backend starts returns -1 with save->error set. Once failed, every
 * later call returns -1 without touching the backend or the input. */
int kyriakon_save_continue(struct kyriakon_save *save);

/* Forward to the wrapped backend, which is started only after EOF. Returns -1
 * without touching the backend if the input never reached EOF. */
int kyriakon_save_finish(struct kyriakon_save *save);

/* Cancel; forwards only if the backend was started. */
void kyriakon_save_cancel(struct kyriakon_save *save);

/* Wipe the plaintext and release it, along with the ciphertext. */
void kyriakon_save_deinit(struct kyriakon_save *save);

#endif
