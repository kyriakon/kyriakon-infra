#ifndef KYRIAKON_FRAME_H
#define KYRIAKON_FRAME_H

/* Response framing for the kyriakon-encrypt daemon, shared by the Dovecot
 * plugin and its test. A successful response is
 * "KYRIAKON-ENCRYPT 1 OK <len>\n" followed by exactly <len> bytes of
 * ciphertext; a daemon restarted mid-write leaves a shorter body, which must
 * fail the save rather than store half an armour.
 *
 * Header-only and libc-only on purpose: the plugin needs Dovecot's headers to
 * build, this parser does not, so CI can compile and test it without them.
 */

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Must match kyriakon-encrypt's RESPONSE_FRAME. */
#define KYRIAKON_FRAME "KYRIAKON-ENCRYPT 1 OK "

/* True when data holds one complete framed response: the header line names a
 * body length, and exactly that many bytes follow. */
static inline bool
kyriakon_parse_frame(const unsigned char *data, size_t size,
		     size_t *body_offset_r, size_t *body_size_r)
{
	const size_t prefix_len = sizeof(KYRIAKON_FRAME) - 1;
	const unsigned char *nl;
	unsigned long long len = 0;
	size_t header_len, body_size, i;

	nl = memchr(data, '\n', size);
	if (nl == NULL)
		return false;
	header_len = (size_t)(nl - data);
	if (header_len <= prefix_len ||
	    memcmp(data, KYRIAKON_FRAME, prefix_len) != 0)
		return false;
	for (i = prefix_len; i < header_len; i++) {
		unsigned long long digit;

		if (data[i] < '0' || data[i] > '9')
			return false;
		digit = (unsigned long long)(data[i] - '0');
		if (len > (ULLONG_MAX - digit) / 10)
			return false;
		len = len * 10 + digit;
	}
	body_size = size - header_len - 1;
	if (len != (unsigned long long)body_size)
		return false;
	*body_offset_r = header_len + 1;
	*body_size_r = body_size;
	return true;
}

#endif
