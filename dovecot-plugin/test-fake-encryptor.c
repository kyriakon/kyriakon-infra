/* Stand-in for the kyriakon-encrypt CLI, driven by KYRIAKON_FAKE_MODE.
 *
 * It exists so the save path's process glue can be tested without gpg, a
 * keyring, or Dovecot: each mode is one outcome the real CLI can produce.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Drain stdin, so the parent's write completes the way it does against the
 * real CLI, and return the bytes read in a malloc'd buffer. */
static unsigned char *
drain(size_t *size_r)
{
	size_t capacity = 65536, size = 0;
	unsigned char *data = malloc(capacity);

	if (data == NULL)
		return NULL;
	for (;;) {
		ssize_t ret;

		if (size == capacity) {
			unsigned char *grown = realloc(data, capacity * 2);

			if (grown == NULL) {
				free(data);
				return NULL;
			}
			data = grown;
			capacity *= 2;
		}
		ret = read(STDIN_FILENO, data + size, capacity - size);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			free(data);
			return NULL;
		}
		if (ret == 0)
			break;
		size += (size_t)ret;
	}
	*size_r = size;
	return data;
}

static int
write_all(const unsigned char *data, size_t size)
{
	size_t offset = 0;

	while (offset < size) {
		ssize_t ret = write(STDOUT_FILENO, data + offset, size - offset);

		if (ret <= 0)
			return -1;
		offset += (size_t)ret;
	}
	return 0;
}

int
main(void)
{
	const char *mode = getenv("KYRIAKON_FAKE_MODE");
	unsigned char *input;
	size_t size;

	input = drain(&size);
	if (input == NULL)
		return 1;

	if (mode != NULL && strcmp(mode, "fail") == 0) {
		free(input);
		return 1;
	}
	if (mode != NULL && strcmp(mode, "truncated") == 0) {
		free(input);
		write_all((const unsigned char *)"CT:partial", 10);
		return 1;
	}
	if (mode != NULL && strcmp(mode, "empty") == 0) {
		free(input);
		return 0;
	}

	/* Default: a ciphertext that carries the input, so the test can prove the
	 * whole message crossed both pipes. */
	write_all((const unsigned char *)"CT:", 3);
	if (write_all(input, size) < 0) {
		free(input);
		return 1;
	}
	free(input);
	return 0;
}
