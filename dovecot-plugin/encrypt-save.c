/* Deferred encryption on the save path. See encrypt-save.h for the ordering
 * and why save_begin must not read the input. */

#include "encrypt-save.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
kyriakon_save_pull(int ret, const char *read_error,
		   char *error, size_t error_size)
{
	if (ret > 0)
		return KYRIAKON_SAVE_PULL_DATA;
	if (ret == 0)
		return KYRIAKON_SAVE_PULL_WAIT;
	/* i_stream_read() returns -1 for both EOF and a stream error: only the
	   error text says which. A prefix followed by an error must fail the
	   save, never be encrypted as a complete message. */
	if (read_error != NULL && read_error[0] != '\0') {
		snprintf(error, error_size, "read input: %s", read_error);
		return KYRIAKON_SAVE_PULL_ERROR;
	}
	/* -2 is "buffer full", not a failure: data is buffered and the caller
	   consumes it before reading again. */
	return ret == -1 ? KYRIAKON_SAVE_PULL_EOF : KYRIAKON_SAVE_PULL_WAIT;
}

static bool
plain_append(struct kyriakon_save *save, const unsigned char *data, size_t size)
{
	size_t needed, capacity;
	unsigned char *grown;

	if (size == 0)
		return true;
	if (size > KYRIAKON_SAVE_PLAIN_MAX - save->plain_len) {
		snprintf(save->error, sizeof(save->error),
			 "message exceeds the %u MiB plaintext limit",
			 (unsigned int)(KYRIAKON_SAVE_PLAIN_MAX / (1024 * 1024)));
		return false;
	}
	needed = save->plain_len + size;
	if (needed > save->plain_capacity) {
		capacity = save->plain_capacity == 0 ? 8192 :
			save->plain_capacity;
		while (capacity < needed)
			capacity *= 2;
		if (capacity > KYRIAKON_SAVE_PLAIN_MAX)
			capacity = KYRIAKON_SAVE_PLAIN_MAX;
		grown = realloc(save->plain, capacity);
		if (grown == NULL) {
			snprintf(save->error, sizeof(save->error),
				 "out of memory");
			return false;
		}
		save->plain = grown;
		save->plain_capacity = capacity;
	}
	memcpy(save->plain + save->plain_len, data, size);
	save->plain_len = needed;
	return true;
}

void
kyriakon_save_begin(struct kyriakon_save *save,
		    const struct kyriakon_save_ops *ops, void *ops_context,
		    kyriakon_save_pull_fn pull,
		    kyriakon_save_encrypt_fn encrypt)
{
	kyriakon_save_deinit(save);
	save->ops = ops;
	save->ops_context = ops_context;
	save->pull = pull;
	save->encrypt = encrypt;
}

int
kyriakon_save_continue(struct kyriakon_save *save)
{
	const unsigned char *data;
	size_t size;
	int ret;

	/* Failed is checked first and stays set: a backend save_begin that
	   half-started must not have its save_continue called on it. */
	if (save->failed)
		return -1;
	if (save->begun)
		return save->ops->save_continue(save->ops_context);

	if (!save->encrypted) {
		for (;;) {
			ret = save->pull(save->ops_context, &data, &size,
					 save->error, sizeof(save->error));
			if (ret != KYRIAKON_SAVE_PULL_DATA)
				break;
			if (!plain_append(save, data, size)) {
				save->failed = true;
				return -1;
			}
		}
		if (ret == KYRIAKON_SAVE_PULL_WAIT)
			return 0;
		if (ret == KYRIAKON_SAVE_PULL_ERROR) {
			if (save->error[0] == '\0')
				snprintf(save->error, sizeof(save->error),
					 "read input failed");
			save->failed = true;
			return -1;
		}
		/* EOF: the whole message is buffered now. */
		if (!save->encrypt(save->ops_context, save->plain, save->plain_len,
				   &save->result)) {
			snprintf(save->error, sizeof(save->error), "%s",
				 save->result.error[0] != '\0' ?
				 save->result.error : "encryption failed");
			save->failed = true;
			return -1;
		}
		save->encrypted = true;
	}

	ret = save->ops->save_begin(save->ops_context,
				    (const unsigned char *)save->result.ciphertext,
				    save->result.ciphertext_len);
	/* If the backend half-started, core's cancel path is still ours to
	   drive, so mark it begun either way. */
	save->begun = true;
	if (ret < 0) {
		save->failed = true;
		return -1;
	}
	return save->ops->save_continue(save->ops_context);
}

int
kyriakon_save_finish(struct kyriakon_save *save)
{
	if (!save->begun) {
		if (save->error[0] == '\0')
			snprintf(save->error, sizeof(save->error),
				 "message input did not reach EOF");
		/* The backend's context exists even though its save_begin never
		   ran; cancel it so the context stays reusable. */
		save->ops->save_cancel(save->ops_context);
		return -1;
	}
	return save->ops->save_finish(save->ops_context);
}

void
kyriakon_save_cancel(struct kyriakon_save *save)
{
	if (save->begun)
		save->ops->save_cancel(save->ops_context);
}

void
kyriakon_save_deinit(struct kyriakon_save *save)
{
	if (save->plain != NULL) {
		volatile unsigned char *p = save->plain;
		size_t i;

		/* Mail plaintext: a memset the optimiser may drop is not a
		   wipe, so write through a volatile pointer. */
		for (i = 0; i < save->plain_len; i++)
			p[i] = 0;
		free(save->plain);
	}
	free(save->result.ciphertext);
	memset(save, 0, sizeof(*save));
}
