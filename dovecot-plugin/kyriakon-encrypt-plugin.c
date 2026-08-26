/* kyriakon-encrypt Dovecot plugin: encrypt every message on the lib-storage
 * save path, covering both LMTP delivery and IMAP APPEND.
 *
 * This is a thin shim. It overrides mailbox_vfuncs.save_begin so the raw RFC
 * 5322 message is piped to the kyriakon-encrypt daemon over its unix socket,
 * and the returned whole-message RFC 3156 PGP/MIME ciphertext is handed to the
 * wrapped save_begin in place of the plaintext. No crypto, keyring, parsing,
 * or private key lives here - the daemon owns all of that. See
 * docs/planning/research/zero-access-mail-imap-append.md.
 *
 * Fail-closed: any error (socket, gpg, missing key) aborts the save before
 * anything is written, so plaintext never reaches the Maildir.
 *
 * Socket protocol (must match kyriakon-encrypt's handle_conn): connect, write
 * "<localpart>\n" then the raw message, half-close (shutdown SHUT_WR), read
 * the ciphertext until EOF. An empty response means the daemon failed closed.
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

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Must match kyriakon-encrypt's DEFAULT_SOCKET. */
#define KYRIAKON_SOCKET "/var/run/kyriakon/encrypt.sock"

const char *kyriakon_encrypt_plugin_version = DOVECOT_ABI_VERSION;

struct kyriakon_mailbox {
	union mailbox_module_context module_ctx;
};

static MODULE_CONTEXT_DEFINE_INIT(kyriakon_mailbox_module,
				  &mail_storage_module_register);

/* Write all of data to fd, handling partial writes and EINTR. */
static bool
kyriakon_write_all(int fd, const void *data, size_t size)
{
	const unsigned char *p = data;

	while (size > 0) {
		ssize_t ret = write(fd, p, size);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return FALSE;
		}
		p += ret;
		size -= ret;
	}
	return TRUE;
}

/* Pipe the plaintext message to the daemon and return the ciphertext as an
 * istream over a box-pool buffer, or NULL with *error_r set. */
static struct istream *
kyriakon_encrypt(struct mailbox *box, struct istream *input,
		 const char **error_r)
{
	const char *localpart = t_strcut(box->storage->user->username, '@');
	struct sockaddr_un sa;
	buffer_t *resp;
	int fd;
	char tmp[8192];
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	*error_r = NULL;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		*error_r = t_strdup_printf("socket(): %m");
		return NULL;
	}
	i_zero(&sa);
	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, KYRIAKON_SOCKET, sizeof(sa.sun_path));
	if (connect(fd, (const struct sockaddr *)&sa, sizeof(sa)) < 0) {
		*error_r = t_strdup_printf("connect(%s): %m", KYRIAKON_SOCKET);
		i_close_fd(&fd);
		return NULL;
	}

	/* request = "<localpart>\n" + raw message; the daemon splits on the
	   first newline and reads the message until our EOF. */
	if (!kyriakon_write_all(fd, localpart, strlen(localpart)) ||
	    !kyriakon_write_all(fd, "\n", 1)) {
		*error_r = t_strdup_printf("write(%s): %m", KYRIAKON_SOCKET);
		i_close_fd(&fd);
		return NULL;
	}
	while ((ret = i_stream_read(input)) != -1) {
		if (ret == -2) {
			*error_r = t_strdup_printf("read input: %s",
						   i_stream_get_error(input));
			i_close_fd(&fd);
			return NULL;
		}
		if (ret == 0)
			continue; /* save inputs are already materialized */
		data = i_stream_get_data(input, &size);
		if (!kyriakon_write_all(fd, data, size)) {
			*error_r = t_strdup_printf("write(%s): %m",
						   KYRIAKON_SOCKET);
			i_close_fd(&fd);
			return NULL;
		}
		i_stream_skip(input, size);
	}
	if (shutdown(fd, SHUT_WR) < 0) {
		*error_r = t_strdup_printf("shutdown(%s): %m", KYRIAKON_SOCKET);
		i_close_fd(&fd);
		return NULL;
	}

	/* Read the ciphertext. Empty response = the daemon failed closed
	   (missing key, gpg error, ...); the daemon logs the specific reason. */
	resp = buffer_create_dynamic(box->pool, 8192);
	while ((ret = read(fd, tmp, sizeof(tmp))) > 0)
		buffer_append(resp, tmp, ret);
	if (ret < 0) {
		*error_r = t_strdup_printf("read(%s): %m", KYRIAKON_SOCKET);
		buffer_free(&resp);
		i_close_fd(&fd);
		return NULL;
	}
	i_close_fd(&fd);
	if (resp->used == 0) {
		*error_r = "no ciphertext returned";
		buffer_free(&resp);
		return NULL;
	}

	/* The buffer lives on box->pool, so it outlives the save. ponytail:
	   buffers the whole ciphertext per save; spool to a temp file only if
	   mailbox lifetime/volume makes this measurable. */
	return i_stream_create_from_data(resp->data, resp->used);
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
				       "kyriakon-encrypt: %s", error);
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
