#ifndef KYRIAKON_ENCRYPT_SAVE_H
#define KYRIAKON_ENCRYPT_SAVE_H

/* The Save path's ordering, kept free of Dovecot types so the test can drive
 * it with a pipe.
 *
 * Dovecot calls save_begin before it answers a synchronizing APPEND literal
 * (2.3 and 2.4 cmd-append.c), so save_begin must not read the input: the
 * client only sends the literal after the `+ OK`, and the mail process's idle
 * ioloop is what runs meanwhile. Reading there returns 0 on EAGAIN for the
 * whole literal, and a retry loop spins a core.
 *
 * So save_begin only arms the save. The caller drives the literal into
 * save_continue; each call pulls whatever the input has without blocking, and
 * returns to the ioloop when there is nothing yet. Once the input reaches EOF
 * the encryptor runs and the ciphertext is handed to the wrapped backend's
 * save_begin. LMTP is unchanged: its DATA is a temp file that is already at
 * EOF when the first save_continue runs.
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
	void *io_context;

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
			 kyriakon_save_encrypt_fn encrypt, void *io_context);

/* Pull whatever the input has now, without blocking. Returns 0 while the input
 * is incomplete; at EOF it runs the encryptor, starts the wrapped backend on
 * the ciphertext and returns the backend's continue verdict. A failure before
 * the backend starts returns -1 with save->error set. */
int kyriakon_save_continue(struct kyriakon_save *save);

/* Forward to the wrapped backend, which is started only after EOF. Returns -1
 * without touching the backend if the input never reached EOF. */
int kyriakon_save_finish(struct kyriakon_save *save);

/* Cancel; forwards only if the backend was started. */
void kyriakon_save_cancel(struct kyriakon_save *save);

/* Release the plaintext and ciphertext buffers. */
void kyriakon_save_deinit(struct kyriakon_save *save);

#endif
