/* Fork/exec the kyriakon-encrypt CLI and move one message through it.
 * See encrypt-run.h for the contract. */

/* POSIX pipe/fork/sigaction/setenv under -std=c99. */
#define _POSIX_C_SOURCE 200809L

#include "encrypt-run.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void
set_error(struct kyriakon_encrypt_result *result, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(result->error, sizeof(result->error), fmt, args);
	va_end(args);
}

static long long
now_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		return 0;
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Milliseconds left before the deadline, 0 once it has passed. */
static int
remaining_ms(long long deadline)
{
	long long left = deadline - now_ms();

	if (left <= 0)
		return 0;
	if (left > INT_MAX)
		return INT_MAX;
	return (int)left;
}

/* Wait until fd is ready for `events`. 1 is ready, 0 is the deadline, -1 is
 * an error with errno set. */
static int
wait_ready(int fd, short events, long long deadline)
{
	for (;;) {
		struct pollfd pollfd;
		int left = remaining_ms(deadline);
		int ret;

		if (left == 0)
			return 0;
		pollfd.fd = fd;
		pollfd.events = events;
		pollfd.revents = 0;
		ret = poll(&pollfd, 1, left);
		if (ret < 0 && errno == EINTR)
			continue;
		return ret;
	}
}

static void
set_cloexec(int fd)
{
	int flags = fcntl(fd, F_GETFD);

	if (flags >= 0)
		(void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static bool
set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags < 0)
		return false;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

/* The child must not hold the mail process's client socket, Maildir fds or
 * master pipe. The two pipes are O_CLOEXEC; this closes everything else after
 * dup2. The loop covers OpenBSD (where closefrom exists) and the test hosts
 * alike. */
static void
close_extra_fds(void)
{
	long max = sysconf(_SC_OPEN_MAX);
	long fd;

	if (max < 0 || max > 65536)
		max = 65536;
	for (fd = STDERR_FILENO + 1; fd < max; fd++)
		(void)close((int)fd);
}

/* write(2) the whole buffer without blocking past the deadline. SIGPIPE is
 * ignored for the duration, because a child that exited early must come back
 * as an errno the save reports, not as a signal that kills the mail process.
 * The previous disposition is restored and the restore failure is checked, so
 * a failure to put it back is not silent (#938). */
static bool
write_all(int fd, const unsigned char *data, size_t size, int *error_r,
	  long long deadline, bool *timed_out)
{
	struct sigaction ignore, previous;
	bool restored;
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
		if (ret > 0) {
			offset += (size_t)ret;
			continue;
		}
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			int ready = wait_ready(fd, POLLOUT, deadline);

			if (ready == 0) {
				*timed_out = true;
				*error_r = ETIMEDOUT;
				break;
			}
			if (ready < 0) {
				*error_r = errno;
				break;
			}
			continue;
		}
		*error_r = ret < 0 ? errno : EPIPE;
		break;
	}

	restored = sigaction(SIGPIPE, &previous, NULL) == 0;
	if (!restored && *error_r == 0)
		*error_r = errno;
	return *error_r == 0;
}

/* Read stdout to EOF into a growing buffer, bounded by the same deadline. */
static bool
read_all(int fd, unsigned char **data_r, size_t *size_r, int *error_r,
	 long long deadline, bool *timed_out)
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
		if (ret > 0) {
			size += (size_t)ret;
			continue;
		}
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			int ready = wait_ready(fd, POLLIN, deadline);

			if (ready == 0) {
				*timed_out = true;
				*error_r = ETIMEDOUT;
				free(data);
				return false;
			}
			if (ready < 0) {
				*error_r = errno;
				free(data);
				return false;
			}
			continue;
		}
		if (ret < 0) {
			*error_r = errno;
			free(data);
			return false;
		}
		break;
	}
	*data_r = data;
	*size_r = size;
	return true;
}

/* Wait for the child, killing it if it outlives the deadline. */
static bool
wait_child(pid_t pid, int *status, long long deadline, bool *timed_out,
	   int *error_r)
{
	for (;;) {
		pid_t ret = waitpid(pid, status, WNOHANG);

		if (ret == pid)
			return true;
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			*error_r = errno;
			return false;
		}
		if (remaining_ms(deadline) == 0) {
			if (kill(pid, SIGKILL) < 0 && errno != ESRCH) {
				*error_r = errno;
				return false;
			}
			while (waitpid(pid, status, 0) < 0 && errno == EINTR)
				;
			*timed_out = true;
			return true;
		}
		(void)poll(NULL, 0, 10);
	}
}

/* The child's side of the handoff. exec resets a caught handler to default but
 * preserves SIG_IGN, and an ignored SIGCHLD makes the encryptor's own children
 * auto-reaped: gpg's wait then fails with ECHILD. Force the default here,
 * whatever the mail process had, so the CLI can wait for its own child. */
static void
child_setup(int to_child_read, int from_child_write, bool restore_mask,
	    const sigset_t *mask)
{
	struct sigaction chld_default;

	if (dup2(to_child_read, STDIN_FILENO) < 0 ||
	    dup2(from_child_write, STDOUT_FILENO) < 0)
		_exit(127);
	close_extra_fds();
	memset(&chld_default, 0, sizeof(chld_default));
	chld_default.sa_handler = SIG_DFL;
	sigemptyset(&chld_default.sa_mask);
	(void)sigaction(SIGCHLD, &chld_default, NULL);
	if (restore_mask)
		(void)sigprocmask(SIG_SETMASK, mask, NULL);
}

bool
kyriakon_encrypt_message_timeout(const char *bin, const char *user,
				 const char *keyring, const char *gpg_home,
				 const unsigned char *input, size_t input_len,
				 int timeout_ms,
				 struct kyriakon_encrypt_result *result)
{
	int to_child[2] = { -1, -1 }, from_child[2] = { -1, -1 };
	struct sigaction reaper_default, reaper_previous;
	bool disposition_saved = false, defaulted = false;
	sigset_t chld_set, previous_mask;
	bool mask_saved = false;
	pid_t pid = -1;
	int status = 0, write_error = 0, read_error = 0, wait_error = 0;
	bool wrote = false, read_ok = false, timed_out = false, success = false;
	unsigned char *ciphertext = NULL;
	size_t ciphertext_len = 0;
	long long deadline;

	memset(result, 0, sizeof(*result));
	result->exit_code = -1;
	if (timeout_ms <= 0)
		timeout_ms = KYRIAKON_ENCRYPT_TIMEOUT_MS;
	deadline = now_ms() + timeout_ms;

	if (pipe(to_child) < 0) {
		set_error(result, "pipe(): %s", strerror(errno));
		return false;
	}
	set_cloexec(to_child[0]);
	set_cloexec(to_child[1]);
	if (pipe(from_child) < 0) {
		set_error(result, "pipe(): %s", strerror(errno));
		close(to_child[0]);
		close(to_child[1]);
		return false;
	}
	set_cloexec(from_child[0]);
	set_cloexec(from_child[1]);
	if (!set_nonblocking(to_child[1]) || !set_nonblocking(from_child[0])) {
		set_error(result, "fcntl(O_NONBLOCK): %s", strerror(errno));
		goto cleanup;
	}

	/* Dovecot reaps its own children from a SIGCHLD handler. Blocking the
	 * signal for our own fork and wait leaves any sibling's delivery pending
	 * for that handler instead of replacing it process-wide (#938). Only a
	 * disposition that would reap our child without a status is changed, and
	 * it is changed for the child's lifetime alone. */
	sigemptyset(&chld_set);
	sigaddset(&chld_set, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &chld_set, &previous_mask) < 0) {
		set_error(result, "sigprocmask(): %s", strerror(errno));
		goto cleanup;
	}
	mask_saved = true;
	if (sigaction(SIGCHLD, NULL, &reaper_previous) == 0) {
		disposition_saved = true;
		if (reaper_previous.sa_handler == SIG_IGN ||
		    (reaper_previous.sa_flags & SA_NOCLDWAIT) != 0) {
			memset(&reaper_default, 0, sizeof(reaper_default));
			reaper_default.sa_handler = SIG_DFL;
			sigemptyset(&reaper_default.sa_mask);
			if (sigaction(SIGCHLD, &reaper_default, NULL) == 0)
				defaulted = true;
		}
	}

	pid = fork();
	if (pid < 0) {
		set_error(result, "fork(): %s", strerror(errno));
		goto cleanup;
	}
	if (pid == 0) {
		child_setup(to_child[0], from_child[1], mask_saved,
			    &previous_mask);
		/* The save path's environment is Dovecot's; the encryptor's own
		 * gpg call needs a PATH it can find. */
		setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
		execl(bin, bin, "encrypt", "--user", user, "--keyring", keyring,
		      "--gpg-home", gpg_home, (char *)NULL);
		/* exec failed: the parent reports this as an exit status. */
		_exit(127);
	}

	close(to_child[0]);
	to_child[0] = -1;
	close(from_child[1]);
	from_child[1] = -1;

	/* Write then read: the CLI drains stdin to EOF before it writes stdout, so
	 * neither pipe can fill against the other. Both ends are polled against the
	 * one deadline, so a child that stops reading or writing is killed rather
	 * than wedging the mail process (#881).
	 * shortcut: holds only while the CLI keeps that order; poll both ends if
	 * it ever starts streaming a ciphertext back. */
	wrote = write_all(to_child[1], input, input_len, &write_error, deadline,
			  &timed_out);
	close(to_child[1]);
	to_child[1] = -1;
	if (wrote)
		read_ok = read_all(from_child[0], &ciphertext, &ciphertext_len,
				   &read_error, deadline, &timed_out);
	close(from_child[0]);
	from_child[0] = -1;

	if (!wrote || !read_ok)
		(void)kill(pid, SIGKILL);
	if (!wait_child(pid, &status, deadline, &timed_out, &wait_error)) {
		set_error(result, "waitpid(): %s", strerror(wait_error));
		goto cleanup;
	}
	pid = -1;

	if (timed_out) {
		set_error(result, "encryptor timed out after %d ms", timeout_ms);
		goto cleanup;
	}
	if (!WIFEXITED(status)) {
		set_error(result, "encryptor killed by signal %d",
			  WTERMSIG(status));
		goto cleanup;
	}
	result->exit_code = WEXITSTATUS(status);
	if (result->exit_code != 0) {
		if (result->exit_code == 127)
			set_error(result, "cannot run %s", bin);
		else
			set_error(result, "encryptor failed (exit %d)",
				  result->exit_code);
		goto cleanup;
	}
	if (!wrote) {
		set_error(result, "encryptor closed its input: %s",
			  strerror(write_error));
		goto cleanup;
	}
	if (!read_ok) {
		set_error(result, "cannot read ciphertext: %s",
			  strerror(read_error));
		goto cleanup;
	}
	if (ciphertext_len == 0) {
		set_error(result, "encryptor wrote no ciphertext");
		goto cleanup;
	}

	result->ciphertext = ciphertext;
	result->ciphertext_len = ciphertext_len;
	ciphertext = NULL;
	success = true;

cleanup:
	if (pid > 0) {
		(void)kill(pid, SIGKILL);
		while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
			;
	}
	if (to_child[0] >= 0)
		close(to_child[0]);
	if (to_child[1] >= 0)
		close(to_child[1]);
	if (from_child[0] >= 0)
		close(from_child[0]);
	if (from_child[1] >= 0)
		close(from_child[1]);
	if (defaulted && disposition_saved)
		(void)sigaction(SIGCHLD, &reaper_previous, NULL);
	if (mask_saved)
		(void)sigprocmask(SIG_SETMASK, &previous_mask, NULL);
	free(ciphertext);
	return success;
}

bool
kyriakon_encrypt_message(const char *bin, const char *user,
			 const char *keyring, const char *gpg_home,
			 const unsigned char *input, size_t input_len,
			 struct kyriakon_encrypt_result *result)
{
	return kyriakon_encrypt_message_timeout(bin, user, keyring, gpg_home,
						input, input_len,
						KYRIAKON_ENCRYPT_TIMEOUT_MS,
						result);
}
