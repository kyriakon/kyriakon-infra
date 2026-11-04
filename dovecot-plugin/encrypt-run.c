/* Fork/exec the kyriakon-encrypt CLI and move one message through it.
 * See encrypt-run.h for the contract. */

/* POSIX pipe/fork/sigaction/setenv under -std=c99. */
#define _POSIX_C_SOURCE 200809L

#include "encrypt-run.h"

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void
set_error(struct kyriakon_encrypt_result *result, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(result->error, sizeof(result->error), fmt, args);
	va_end(args);
}

/* write(2) the whole buffer. SIGPIPE is ignored for the duration, because a
 * child that exited early must come back as an errno the save path reports,
 * not as a signal that kills the mail process. *error_r is 0 on success. */
static bool
write_all(int fd, const unsigned char *data, size_t size, int *error_r)
{
	struct sigaction ignore, previous;
	size_t offset = 0;

	*error_r = 0;
	memset(&ignore, 0, sizeof(ignore));
	ignore.sa_handler = SIG_IGN;
	sigemptyset(&ignore.sa_mask);
	if (sigaction(SIGPIPE, &ignore, &previous) < 0) {
		*error_r = errno;
		return false;
	}
	for (;;) {
		ssize_t ret;

		if (offset == size)
			break;
		ret = write(fd, data + offset, size - offset);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0) {
			*error_r = ret < 0 ? errno : EPIPE;
			break;
		}
		offset += (size_t)ret;
	}
	sigaction(SIGPIPE, &previous, NULL);
	return *error_r == 0;
}

/* Read stdout to EOF into a growing buffer. *error_r is 0 on success. */
static bool
read_all(int fd, unsigned char **data_r, size_t *size_r, int *error_r)
{
	size_t capacity = 65536, size = 0;
	unsigned char *data = malloc(capacity);

	*error_r = 0;
	if (data == NULL) {
		*error_r = ENOMEM;
		return false;
	}
	for (;;) {
		ssize_t ret;

		if (size == capacity) {
			unsigned char *grown = realloc(data, capacity * 2);

			if (grown == NULL) {
				free(data);
				*error_r = ENOMEM;
				return false;
			}
			data = grown;
			capacity *= 2;
		}
		ret = read(fd, data + size, capacity - size);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0) {
			*error_r = errno;
			free(data);
			return false;
		}
		if (ret == 0)
			break;
		size += (size_t)ret;
	}
	*data_r = data;
	*size_r = size;
	return true;
}

bool
kyriakon_encrypt_message(const char *bin, const char *user,
			 const char *keyring, const char *gpg_home,
			 const unsigned char *input, size_t input_len,
			 struct kyriakon_encrypt_result *result)
{
	int to_child[2], from_child[2];
	struct sigaction reaper_default, reaper_previous;
	bool reaper_saved = false;
	pid_t pid;
	int status = 0, write_error = 0, read_error = 0;
	bool wrote, read_ok;
	unsigned char *ciphertext = NULL;
	size_t ciphertext_len = 0;

	memset(result, 0, sizeof(*result));
	result->exit_code = -1;

	if (pipe(to_child) < 0) {
		set_error(result, "pipe(): %s", strerror(errno));
		return false;
	}
	if (pipe(from_child) < 0) {
		set_error(result, "pipe(): %s", strerror(errno));
		close(to_child[0]);
		close(to_child[1]);
		return false;
	}

	/* A host process that ignores SIGCHLD has its children reaped without a
	 * status, and waitpid would report ECHILD for every save. Default the
	 * disposition around our own wait, and put it back after. */
	memset(&reaper_default, 0, sizeof(reaper_default));
	reaper_default.sa_handler = SIG_DFL;
	if (sigaction(SIGCHLD, &reaper_default, &reaper_previous) == 0)
		reaper_saved = true;

	pid = fork();
	if (pid < 0) {
		set_error(result, "fork(): %s", strerror(errno));
		if (reaper_saved)
			sigaction(SIGCHLD, &reaper_previous, NULL);
		close(to_child[0]);
		close(to_child[1]);
		close(from_child[0]);
		close(from_child[1]);
		return false;
	}
	if (pid == 0) {
		dup2(to_child[0], STDIN_FILENO);
		dup2(from_child[1], STDOUT_FILENO);
		close(to_child[0]);
		close(to_child[1]);
		close(from_child[0]);
		close(from_child[1]);
		/* The save path's environment is Dovecot's; the encryptor's own
		 * gpg call needs a PATH it can find. */
		setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
		execl(bin, bin, "encrypt", "--user", user, "--keyring", keyring,
		      "--gpg-home", gpg_home, (char *)NULL);
		/* exec failed: the parent reports this as an exit status. */
		_exit(127);
	}

	close(to_child[0]);
	close(from_child[1]);

	/* Write the message, then read: the CLI drains stdin to EOF before it
	 * writes stdout, so neither pipe can fill against the other.
	 * shortcut: holds only while the CLI keeps that order; poll both ends if
	 * it ever starts streaming a ciphertext back. */
	wrote = write_all(to_child[1], input, input_len, &write_error);
	close(to_child[1]);
	read_ok = read_all(from_child[0], &ciphertext, &ciphertext_len,
			   &read_error);
	close(from_child[0]);

	while (waitpid(pid, &status, 0) < 0) {
		if (errno == EINTR)
			continue;
		set_error(result, "waitpid(): %s", strerror(errno));
		free(ciphertext);
		if (reaper_saved)
			sigaction(SIGCHLD, &reaper_previous, NULL);
		return false;
	}
	if (reaper_saved)
		sigaction(SIGCHLD, &reaper_previous, NULL);

	if (WIFEXITED(status))
		result->exit_code = WEXITSTATUS(status);
	if (!WIFEXITED(status)) {
		set_error(result, "encryptor killed by signal %d",
			  WTERMSIG(status));
		free(ciphertext);
		return false;
	}
	if (result->exit_code != 0) {
		if (result->exit_code == 127)
			set_error(result, "cannot run %s", bin);
		else
			set_error(result, "encryptor failed (exit %d)",
				  result->exit_code);
		free(ciphertext);
		return false;
	}
	if (!wrote) {
		set_error(result, "encryptor closed its input: %s",
			  strerror(write_error));
		free(ciphertext);
		return false;
	}
	if (!read_ok) {
		set_error(result, "cannot read ciphertext: %s",
			  strerror(read_error));
		free(ciphertext);
		return false;
	}
	if (ciphertext_len == 0) {
		set_error(result, "encryptor wrote no ciphertext");
		free(ciphertext);
		return false;
	}

	result->ciphertext = ciphertext;
	result->ciphertext_len = ciphertext_len;
	return true;
}
