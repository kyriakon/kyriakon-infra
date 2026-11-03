/* Test for the response-frame parser the Dovecot plugin uses. The plugin needs
 * Dovecot's headers to build; the parser needs none, so this is compiled and
 * run on its own:
 *
 *   cc -std=c99 -Wall -Wextra -Werror -o test-frame test-frame.c
 *   ./test-frame
 */

#include "frame.h"

#include <stdio.h>

static int failures;

static void
expect(bool ok, const char *what)
{
	if (!ok) {
		fprintf(stderr, "FAIL: %s\n", what);
		failures++;
	}
}

static void
expect_frame(const char *data, bool accepted, size_t offset, size_t size,
	     const char *what)
{
	size_t offset_got = 0, size_got = 0;
	bool got = kyriakon_parse_frame((const unsigned char *)data, strlen(data),
					&offset_got, &size_got);

	expect(got == accepted, what);
	if (got && accepted) {
		expect(offset_got == offset, "body offset");
		expect(size_got == size, "body length");
	}
}

int main(void)
{
	static const char complete[] = "KYRIAKON-ENCRYPT 1 OK 5\nhello";
	static const char empty_body[] = "KYRIAKON-ENCRYPT 1 OK 0\n";
	static const char short_body[] = "KYRIAKON-ENCRYPT 1 OK 5\nhell";
	static const char long_body[] = "KYRIAKON-ENCRYPT 1 OK 5\nhelloo";
	static const char bad_magic[] = "KYRIAKON-ENCRYPT 1 NO 5\nhello";
	static const char bad_length[] = "KYRIAKON-ENCRYPT 1 OK five\nhello";

	/* A whole frame is accepted, and the body starts after the header. */
	expect_frame(complete, true, strlen("KYRIAKON-ENCRYPT 1 OK 5\n"), 5,
		     "a complete frame is accepted");
	expect_frame(empty_body, true, strlen("KYRIAKON-ENCRYPT 1 OK 0\n"), 0,
		     "an empty body of the announced length is complete");

	/* What a daemon killed mid-write looks like, and what must never reach
	 * save_begin. */
	expect_frame(short_body, false, 0, 0, "a short body is rejected");
	expect_frame(long_body, false, 0, 0, "extra bytes are rejected");
	expect_frame(bad_magic, false, 0, 0, "a foreign header is rejected");
	expect_frame(bad_length, false, 0, 0, "a non-numeric length is rejected");
	expect_frame("KYRIAKON-ENCRYPT 1 OK 5", false, 0, 0,
		     "a header with no terminator is rejected");
	expect_frame("", false, 0, 0, "an empty response is rejected");

	if (failures != 0)
		return 1;
	printf("frame parser: all checks passed\n");
	return 0;
}
