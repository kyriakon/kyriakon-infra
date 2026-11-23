/* Stand-in for the kyriakon-encrypt CLI, driven by KYRIAKON_FAKE_MODE.
 *
 * It exists so the save path's process glue can be tested without gpg, a
 * keyring, or Dovecot: each mode is one outcome the real CLI can produce.
 */

/* POSIX nanosleep under -std=c99. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
	/* Reads the whole message, then never writes or exits: the parent has to
	 * kill it at its deadline. */
	if (mode != NULL && strcmp(mode, "stall") == 0) {
		free(input);
		for (;;)
			pause();
	}
	/* Runs long enough for a sibling child to exit during the encryption. */
	if (mode != NULL && strcmp(mode, "slow") == 0) {
		struct timespec nap = { 0, 300 * 1000 * 1000 };

		nanosleep(&nap, NULL);
	}
	/* Writes the descriptors it holds to KYRIAKON_FAKE_FD_LOG, then returns the
	 * usual ciphertext. A descriptor the mail process opened must not be
	 * listed. */
	if (mode != NULL && strcmp(mode, "fds") == 0) {
		const char *path = getenv("KYRIAKON_FAKE_FD_LOG");
		char list[2048];
		size_t offset = 0;
		int fd;

		for (fd = 0; fd < 256 && offset < sizeof(list) - 8; fd++) {
			if (fcntl(fd, F_GETFD) != -1)
				offset += (size_t)snprintf(list + offset,
							   sizeof(list) - offset,
							   "%d,", fd);
		}
		list[offset] = '\0';
		if (path != NULL) {
			int log = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

			if (log >= 0) {
				(void)write(log, list, offset);
				close(log);
			}
		}
	}
	/* The process dies mid-write, as a killed CLI does: the parent has bytes
	 * but no exit status, and the save must fail. */
	if (mode != NULL && strcmp(mode, "killed") == 0) {
		free(input);
		write_all((const unsigned char *)"CT:partial", 10);
		raise(SIGKILL);
		return 1;
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
