/* kyriakon-encrypt Dovecot plugin: encrypt every message on the lib-storage
 * save path, covering both LMTP delivery and IMAP APPEND.
 *
 * This is a thin shim. It overrides mailbox_vfuncs.save_begin/save_finish so
 * the raw RFC 5322 message is piped to the kyriakon-encrypt daemon over its
 * unix socket, and the returned whole-message RFC 3156 PGP/MIME ciphertext is
 * handed to the wrapped save_begin in place of the plaintext. No crypto,
 * keyring, parsing, or private key lives here - the daemon owns all of that.
 * See docs/planning/research/zero-access-mail-imap-append.md.
 *
 * Fail-closed: any error (socket, gpg, missing key) aborts the save before
 * anything is written, so plaintext never reaches the Maildir.
 *
 * Socket protocol (must match kyriakon-encrypt's handle_conn): connect, write
 * "<localpart>\n" then the raw message, half-close (shutdown SHUT_WR), read
 * the response until EOF. A successful response is framed: a
 * "KYRIAKON-ENCRYPT 1 OK <len>\n" line and then exactly <len> bytes of
 * ciphertext. A body shorter than that is a daemon that died mid-write, and
 * the save fails rather than store half an armour. An empty response means the
 * daemon failed closed.
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
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Must match kyriakon-encrypt's DEFAULT_SOCKET. */
#define KYRIAKON_SOCKET "/var/run/kyriakon/encrypt.sock"
/* First line of the RFC 3156 envelope the daemon emits; the save_finish
   backstop checks the saved mail starts with this. */
#define KYRIAKON_MARKER \
	"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";"
/* Success-response header, followed by the decimal ciphertext length in
   bytes. Must match kyriakon-encrypt's RESPONSE_FRAME. */
#define KYRIAKON_FRAME "KYRIAKON-ENCRYPT 1 OK "

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

/* True when data holds one complete framed response: the header line names a
 * body length, and exactly that many bytes follow. A daemon restarted
 * mid-write leaves a shorter body, which the save must refuse. */
static bool
kyriakon_parse_frame(const unsigned char *data, size_t size,
		     size_t *body_offset_r, size_t *body_size_r)
{
	const size_t prefix_len = sizeof(KYRIAKON_FRAME) - 1;
	const unsigned char *nl;
	unsigned long long len = 0;
	size_t header_len, body_size, i;

	nl = memchr(data, '\n', size);
	if (nl == NULL)
		return FALSE;
	header_len = (size_t)(nl - data);
	if (header_len <= prefix_len ||
	    memcmp(data, KYRIAKON_FRAME, prefix_len) != 0)
		return FALSE;
	for (i = prefix_len; i < header_len; i++) {
		unsigned long long digit;

		if (data[i] < '0' || data[i] > '9')
			return FALSE;
		digit = (unsigned long long)(data[i] - '0');
		if (len > (ULLONG_MAX - digit) / 10)
			return FALSE;
		len = len * 10 + digit;
	}
	body_size = size - header_len - 1;
	if (len != (unsigned long long)body_size)
		return FALSE;
	*body_offset_r = header_len + 1;
	*body_size_r = body_size;
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
	size_t offset;
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
	/* A non-empty body is not enough: a daemon restarted mid-write leaves
	   half an armour that starts with the marker like any other. Only the
	   frame's own length can tell the two apart. */
	if (!kyriakon_parse_frame(resp->data, resp->used, &offset, &size)) {
		*error_r = "truncated or malformed encryptor response";
		buffer_free(&resp);
		return NULL;
	}
	if (size < sizeof(KYRIAKON_MARKER) - 1 ||
	    memcmp((const unsigned char *)resp->data + offset,
		   KYRIAKON_MARKER, sizeof(KYRIAKON_MARKER) - 1) != 0) {
		*error_r = "encryptor response is not kyriakon ciphertext";
		buffer_free(&resp);
		return NULL;
	}

	/* The buffer lives on box->pool, so it outlives the save. ponytail:
	   buffers the whole ciphertext per save; spool to a temp file only if
	   mailbox lifetime/volume makes this measurable. */
	return i_stream_create_from_data(
		(const char *)resp->data + offset, size);
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

static int
kyriakon_save_finish(struct mail_save_context *ctx)
{
	struct mailbox *box = ctx->transaction->box;
	struct kyriakon_mailbox *mbox =
		MODULE_CONTEXT_REQUIRE(box, kyriakon_mailbox_module);
	struct istream *input;
	const unsigned char *data;
	size_t size;
	bool ok = FALSE;

	if (mbox->module_ctx.super.save_finish(ctx) < 0)
		return -1;

	/* Fail-closed backstop: what landed in storage must be our RFC 3156
	   envelope, never plaintext. */
	if (mail_get_stream(ctx->dest_mail, NULL, NULL, &input) < 0)
		return -1;
	if (i_stream_read(input) > 0) {
		data = i_stream_get_data(input, &size);
		ok = size >= sizeof(KYRIAKON_MARKER) - 1 &&
		     memcmp(data, KYRIAKON_MARKER,
			    sizeof(KYRIAKON_MARKER) - 1) == 0;
	}
	if (!ok) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			"saved mail is not kyriakon ciphertext");
		return -1;
	}
	return 0;
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
	v->save_finish = kyriakon_save_finish;
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
