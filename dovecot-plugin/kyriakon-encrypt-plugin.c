/* kyriakon-encrypt Dovecot plugin: encrypt every message on the lib-storage
 * save path, covering both LMTP delivery and IMAP APPEND.
 *
 * This is a thin shim. It overrides the mailbox save vfuncs so the raw
 * RFC 5322 message is run through `kyriakon-encrypt encrypt`, and the
 * ciphertext that command writes to stdout is handed to the wrapped save
 * methods in place of the plaintext. No crypto, keyring, parsing, or private
 * key lives here - the encryptor owns all of that.
 * See docs/planning/research/zero-access-mail-imap-append.md.
 *
 * Ordering: Dovecot calls save_begin before it answers a synchronizing APPEND
 * literal, so save_begin only arms the save and never reads the input. The
 * caller drives the literal through save_continue; the input is pulled there
 * without blocking, and at EOF the message is encrypted and the wrapped
 * save_begin starts on the ciphertext (encrypt-save.h). LMTP's DATA is a temp
 * file, so its first save_continue still encrypts before anything is written.
 *
 * Fail-closed: a non-zero exit status (missing key, gpg error, the process
 * killed mid-write) aborts the save before the wrapped save_begin runs, so
 * plaintext never reaches the Maildir. The encryptor logs the specific reason
 * to stderr, which the mail process's log picks up.
 *
 * The encryptor is installed at /usr/local/sbin/kyriakon-encrypt by
 * deploy-mail.sh and runs as the mailbox user, because that is who saves mail.
 * It reads the world-readable keyring and is given a scratch gpg homedir of
 * its own for the life of one save.
 */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "mail-error.h"
#include "mail-user.h"
#include "mail-storage.h"
#include "mail-storage-private.h"
#include "mail-storage-hooks.h"
#include "module-context.h"
#include "unlink-directory.h"
#include "encrypt-run.h"
#include "encrypt-save.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *kyriakon_encrypt_plugin_version = DOVECOT_ABI_VERSION;

/* One in-flight save: the plugin's share of a mail_save_context. Backends
 * reuse their save context, so these nodes are recycled through free_saves
 * rather than allocated per message. */
struct kyriakon_save_ctx {
	struct kyriakon_save_ctx *next;
	struct mail_save_context *ctx;
	struct mailbox *box;
	struct istream *input;
	struct kyriakon_save save;
};

struct kyriakon_mailbox {
	union mailbox_module_context module_ctx;
	struct kyriakon_save_ctx *saves;
	struct kyriakon_save_ctx *free_saves;
};

static MODULE_CONTEXT_DEFINE_INIT(kyriakon_mailbox_module,
				  &mail_storage_module_register);

/* The input can be a non-blocking client socket (IMAP APPEND): a 0 read means
 * "nothing yet", and the ioloop has to run before there can be more. */
static int
kyriakon_pull_input(void *context, const unsigned char **data_r, size_t *size_r,
		    char *error, size_t error_size)
{
	struct kyriakon_save_ctx *sctx = context;
	int ret;

	ret = i_stream_read(sctx->input);
	if (ret > 0) {
		*data_r = i_stream_get_data(sctx->input, size_r);
		i_stream_skip(sctx->input, *size_r);
		return KYRIAKON_SAVE_PULL_DATA;
	}
	if (ret == 0)
		return KYRIAKON_SAVE_PULL_WAIT;
	if (ret == -1)
		return KYRIAKON_SAVE_PULL_EOF;
	snprintf(error, error_size, "read input: %s",
		 i_stream_get_error(sctx->input));
	return KYRIAKON_SAVE_PULL_ERROR;
}

static bool
kyriakon_encrypt_input(void *context, const unsigned char *plain,
		       size_t plain_len, struct kyriakon_encrypt_result *result)
{
	struct kyriakon_save_ctx *sctx = context;
	struct mailbox *box = sctx->box;
	const char *user = t_strcut(box->storage->user->username, '@');
	/* gpg needs a writable, private homedir; mkdtemp creates it 0700 and it
	   dies with the save. Created only once the message is complete. */
	char scratch[] = "/tmp/kyriakon-encrypt.XXXXXX";
	const char *unlink_error;
	bool ok;

	if (mkdtemp(scratch) == NULL) {
		memset(result, 0, sizeof(*result));
		result->exit_code = -1;
		snprintf(result->error, sizeof(result->error),
			 "mkdtemp(/tmp): %s", strerror(errno));
		return false;
	}
	ok = kyriakon_encrypt_message(KYRIAKON_ENCRYPT_BIN, user,
				      KYRIAKON_KEYRING, scratch, plain, plain_len,
				      result);
	(void)unlink_directory(scratch, UNLINK_DIRECTORY_FLAG_RMDIR,
			       &unlink_error);
	return ok;
}

/* The wrapped backend's save methods. The ciphertext stays alive in the pump
 * until finish/cancel, because the backend's input stream only references
 * it. */
static int
kyriakon_backend_save_begin(void *context, const unsigned char *cipher,
			    size_t size)
{
	struct kyriakon_save_ctx *sctx = context;
	struct kyriakon_mailbox *mbox =
		MODULE_CONTEXT_REQUIRE(sctx->box, kyriakon_mailbox_module);
	struct istream *input;
	int ret;

	input = i_stream_create_from_data(cipher, size);
	ret = mbox->module_ctx.super.save_begin(sctx->ctx, input);
	i_stream_unref(&input);
	return ret;
}

static int
kyriakon_backend_save_continue(void *context)
{
	struct kyriakon_save_ctx *sctx = context;
	struct kyriakon_mailbox *mbox =
		MODULE_CONTEXT_REQUIRE(sctx->box, kyriakon_mailbox_module);

	return mbox->module_ctx.super.save_continue(sctx->ctx);
}

static int
kyriakon_backend_save_finish(void *context)
{
	struct kyriakon_save_ctx *sctx = context;
	struct kyriakon_mailbox *mbox =
		MODULE_CONTEXT_REQUIRE(sctx->box, kyriakon_mailbox_module);

	return mbox->module_ctx.super.save_finish(sctx->ctx);
}

static void
kyriakon_backend_save_cancel(void *context)
{
	struct kyriakon_save_ctx *sctx = context;
	struct kyriakon_mailbox *mbox =
		MODULE_CONTEXT_REQUIRE(sctx->box, kyriakon_mailbox_module);

	mbox->module_ctx.super.save_cancel(sctx->ctx);
}

static const struct kyriakon_save_ops kyriakon_save_ops = {
	.save_begin = kyriakon_backend_save_begin,
	.save_continue = kyriakon_backend_save_continue,
	.save_finish = kyriakon_backend_save_finish,
	.save_cancel = kyriakon_backend_save_cancel,
};

static struct kyriakon_save_ctx *
kyriakon_save_ctx_get(struct mailbox *box, struct kyriakon_mailbox *mbox,
		      struct mail_save_context *ctx)
{
	struct kyriakon_save_ctx *sctx;

	for (sctx = mbox->saves; sctx != NULL; sctx = sctx->next) {
		if (sctx->ctx == ctx)
			break;
	}
	if (sctx == NULL) {
		if (mbox->free_saves != NULL) {
			sctx = mbox->free_saves;
			mbox->free_saves = sctx->next;
		} else {
			sctx = p_new(box->pool, struct kyriakon_save_ctx, 1);
		}
		sctx->next = mbox->saves;
		mbox->saves = sctx;
	}
	sctx->ctx = ctx;
	sctx->box = box;
	return sctx;
}

static struct kyriakon_save_ctx *
kyriakon_save_ctx_find(struct kyriakon_mailbox *mbox,
		       struct mail_save_context *ctx)
{
	struct kyriakon_save_ctx *sctx;

	for (sctx = mbox->saves; sctx != NULL; sctx = sctx->next) {
		if (sctx->ctx == ctx)
			return sctx;
	}
	return NULL;
}

static void
kyriakon_save_ctx_free(struct kyriakon_mailbox *mbox,
		       struct kyriakon_save_ctx *sctx)
{
	struct kyriakon_save_ctx **p;

	for (p = &mbox->saves; *p != NULL; p = &(*p)->next) {
		if (*p == sctx) {
			*p = sctx->next;
			break;
		}
	}
	kyriakon_save_deinit(&sctx->save);
	i_stream_unref(&sctx->input);
	sctx->ctx = NULL;
	sctx->box = NULL;
	sctx->next = mbox->free_saves;
	mbox->free_saves = sctx;
}

static void
kyriakon_save_set_error(struct kyriakon_save_ctx *sctx)
{
	mail_storage_set_error(sctx->box->storage, MAIL_ERROR_TEMP,
			       t_strdup_printf("kyriakon-encrypt: %s",
					       sctx->save.error));
}

static int
kyriakon_mail_save_begin(struct mail_save_context *ctx, struct istream *input)
{
	struct mailbox *box = ctx->transaction->box;
	struct kyriakon_mailbox *mbox =
		MODULE_CONTEXT_REQUIRE(box, kyriakon_mailbox_module);
	struct kyriakon_save_ctx *sctx =
		kyriakon_save_ctx_get(box, mbox, ctx);

	/* Dovecot answers a synchronizing APPEND only after this returns, so
	   nothing may read the input yet. */
	i_assert(sctx->input == NULL);
	sctx->input = input;
	i_stream_ref(input);
	kyriakon_save_begin(&sctx->save, &kyriakon_save_ops, sctx,
			    kyriakon_pull_input, kyriakon_encrypt_input, sctx);
	return 0;
}

static int
kyriakon_mail_save_continue(struct mail_save_context *ctx)
{
	struct mailbox *box = ctx->transaction->box;
	struct kyriakon_mailbox *mbox =
		MODULE_CONTEXT_REQUIRE(box, kyriakon_mailbox_module);
	struct kyriakon_save_ctx *sctx = kyriakon_save_ctx_find(mbox, ctx);
	int ret;

	/* Core only continues a save it began. */
	if (sctx == NULL)
		return -1;
	ret = kyriakon_save_continue(&sctx->save);
	if (ret < 0 && !sctx->save.begun)
		kyriakon_save_set_error(sctx);
	return ret;
}

static int
kyriakon_mail_save_finish(struct mail_save_context *ctx)
{
	struct mailbox *box = ctx->transaction->box;
	struct kyriakon_mailbox *mbox =
		MODULE_CONTEXT_REQUIRE(box, kyriakon_mailbox_module);
	struct kyriakon_save_ctx *sctx = kyriakon_save_ctx_find(mbox, ctx);
	int ret;

	if (sctx == NULL)
		return -1;
	ret = kyriakon_save_finish(&sctx->save);
	if (ret < 0 && !sctx->save.begun)
		kyriakon_save_set_error(sctx);
	kyriakon_save_ctx_free(mbox, sctx);
	return ret;
}

static void
kyriakon_mail_save_cancel(struct mail_save_context *ctx)
{
	struct mailbox *box = ctx->transaction->box;
	struct kyriakon_mailbox *mbox =
		MODULE_CONTEXT_REQUIRE(box, kyriakon_mailbox_module);
	struct kyriakon_save_ctx *sctx = kyriakon_save_ctx_find(mbox, ctx);

	if (sctx == NULL) {
		/* No save was begun through us; core still cancels the
		   backend's context. */
		mbox->module_ctx.super.save_cancel(ctx);
	} else {
		kyriakon_save_cancel(&sctx->save);
		kyriakon_save_ctx_free(mbox, sctx);
	}
}

static void
kyriakon_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	struct kyriakon_mailbox *mbox;

	mbox = p_new(box->pool, struct kyriakon_mailbox, 1);
	mbox->module_ctx.super = *v;
	box->vlast = &mbox->module_ctx.super;

	v->save_begin = kyriakon_mail_save_begin;
	v->save_continue = kyriakon_mail_save_continue;
	v->save_finish = kyriakon_mail_save_finish;
	v->save_cancel = kyriakon_mail_save_cancel;
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
