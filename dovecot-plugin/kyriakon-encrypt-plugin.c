/* kyriakon-encrypt Dovecot plugin: encrypt every message on the lib-storage
 * save path, covering both LMTP delivery and IMAP APPEND.
 *
 * This is a thin shim. It overrides mailbox_vfuncs.save_begin so the raw
 * RFC 5322 message is run through `kyriakon-encrypt encrypt`, and the
 * ciphertext that command writes to stdout is handed to the wrapped
 * save_begin in place of the plaintext. No crypto, keyring, parsing, or
 * private key lives here - the encryptor owns all of that.
 * See docs/planning/research/zero-access-mail-imap-append.md.
 *
 * Fail-closed: a non-zero exit status (missing key, gpg error, the process
 * killed mid-write) aborts the save before anything is written, so plaintext
 * never reaches the Maildir. The encryptor logs the specific reason to stderr,
 * which the mail process's log picks up.
 *
 * The encryptor is installed at /usr/local/sbin/kyriakon-encrypt by
 * deploy-mail.sh and runs as the mailbox user, because that is who saves mail.
 * It reads the world-readable keyring and is given a scratch gpg homedir of
 * its own for the life of one save.
 */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "buffer.h"
#include "mail-error.h"
#include "mail-user.h"
#include "mail-storage.h"
#include "mail-storage-private.h"
#include "mail-storage-hooks.h"
#include "module-context.h"
#include "unlink-directory.h"
#include "encrypt-run.h"

#include <stdlib.h>

const char *kyriakon_encrypt_plugin_version = DOVECOT_ABI_VERSION;

struct kyriakon_mailbox {
	union mailbox_module_context module_ctx;
};

static MODULE_CONTEXT_DEFINE_INIT(kyriakon_mailbox_module,
				  &mail_storage_module_register);

/* Encrypt the plaintext message and return the ciphertext as an istream over a
 * box-pool buffer, or NULL with *error_r set. */
static struct istream *
kyriakon_encrypt(struct mailbox *box, struct istream *input,
		 const char **error_r)
{
	const char *user = t_strcut(box->storage->user->username, '@');
	struct kyriakon_encrypt_result result;
	buffer_t *plain, *cipher;
	const unsigned char *data;
	/* gpg needs a writable, private homedir; mkdtemp creates it 0700 and it
	   dies with the save. */
	char scratch[] = "/tmp/kyriakon-encrypt.XXXXXX";
	size_t size;
	ssize_t ret;

	*error_r = NULL;

	/* The child gets the message as one buffer. Save inputs are already
	   materialised by the backend. */
	plain = buffer_create_dynamic(box->pool, 8192);
	while ((ret = i_stream_read(input)) != -1) {
		if (ret == -2) {
			*error_r = t_strdup_printf("read input: %s",
						   i_stream_get_error(input));
			return NULL;
		}
		if (ret == 0)
			continue;
		data = i_stream_get_data(input, &size);
		buffer_append(plain, data, size);
		i_stream_skip(input, size);
	}

	if (mkdtemp(scratch) == NULL) {
		*error_r = t_strdup_printf("mkdtemp(/tmp): %m");
		return NULL;
	}
	if (!kyriakon_encrypt_message(KYRIAKON_ENCRYPT_BIN, user,
				      KYRIAKON_KEYRING, scratch, plain->data,
				      plain->used, &result)) {
		unlink_directory(scratch, UNLINK_DIRECTORY_FLAG_RMDIR);
		*error_r = t_strdup_printf("encryptor: %s", result.error);
		return NULL;
	}
	unlink_directory(scratch, UNLINK_DIRECTORY_FLAG_RMDIR);

	/* ponytail: buffers the whole ciphertext per save; spool to a temp file
	   only if mailbox lifetime/volume makes this measurable. */
	cipher = buffer_create_dynamic(box->pool, result.ciphertext_len);
	buffer_append(cipher, result.ciphertext, result.ciphertext_len);
	free(result.ciphertext);
	return i_stream_create_from_data(cipher->data, cipher->used);
}

static int
kyriakon_save_begin(struct mail_save_context *ctx, struct istream *input)
{
	struct mailbox *box = ctx->transaction->box;
	struct kyriakon_mailbox *mbox =
		MODULE_CONTEXT_REQUIRE(box, kyriakon_mailbox_module);
	struct istream *cipher;
	const char *error;
	int ret;

	cipher = kyriakon_encrypt(box, input, &error);
	if (cipher == NULL) {
		mail_storage_set_error(box->storage, MAIL_ERROR_TEMP,
				       t_strdup_printf("kyriakon-encrypt: %s",
						       error));
		return -1;
	}

	/* super.save_begin takes its own ref on cipher (via the backend's
	   i_stream_create_lf/crlf wrapper); drop ours. */
	ret = mbox->module_ctx.super.save_begin(ctx, cipher);
	i_stream_unref(&cipher);
	return ret;
}

static void
kyriakon_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	struct kyriakon_mailbox *mbox;

	mbox = p_new(box->pool, struct kyriakon_mailbox, 1);
	mbox->module_ctx.super = *v;
	box->vlast = &mbox->module_ctx.super;

	v->save_begin = kyriakon_save_begin;
	/* copy is intentionally not overridden: phase 1 is single-user, so an
	   IMAP COPY hardlinks the same user's ciphertext, which is already
	   correct. Cross-user copy into a shared mailbox would need
	   re-encryption to the destination key and is a phase 3 concern. */

	MODULE_CONTEXT_SET(box, kyriakon_mailbox_module, mbox);
}

static struct mail_storage_hooks kyriakon_hooks = {
	.mailbox_allocated = kyriakon_mailbox_allocated,
};

void kyriakon_encrypt_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &kyriakon_hooks);
}

void kyriakon_encrypt_plugin_deinit(void)
{
	mail_storage_hooks_remove(&kyriakon_hooks);
}
