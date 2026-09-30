# Serving a dynamic Gemini capsule on the existing gmid (public release, onboarding)

**Question:** how can a dynamic Gemini front end be served when `gmid` already owns port
1965 on the box? The onboarding service gets three front ends at release, a web form behind
`relayd`, a Gemini capsule and an SSH TUI, all writing intents for the same drain, and the
capsule answers on `onboard.kyriakon.net`. Today that name is served by `gmid` from a static
checkout, so an interactive application form needs something dynamic behind it. The ticket
asks whether the deployed `gmid` can do dynamic content at all, and if it cannot, what the
alternatives cost.

**Answer, in eleven lines.** The deployed `gmid` 2.1.1p0 does have dynamic content, and the
deployed binary parses it: `fastcgi socket ...` and `fastcgi { ... }` both return `config OK`
from `gmid -n`, `strings` on `/usr/local/bin/gmid` carries the FastCGI runtime messages, and
the OpenBSD port builds it in unconditionally. There is no CGI, no SCGI and no hook: `cgi`
was removed in `gmid` 2.0 and the parser now answers `` `cgi' was removed in gmid 2.0.  Please
use fastcgi or proxy instead. ``, which is the same message the deployed binary prints. The
FastCGI handler is not run by `gmid` at all. `gmid` never execs a program: its server process
is chrooted to `/var/www`, dropped to `_gmid`, and pledged `stdio rpath inet unix dns recvfd`,
so it can only connect to a socket, and the program behind that socket runs as whatever user
its own `rc.d` script gave it. The handler receives the request as CGI variables,
`GEMINI_URL_PATH` for the path, `QUERY_STRING` for the raw query, `REMOTE_ADDR` for the client
address and the client certificate fields, and it writes back a Gemini status line, so it can
issue status 10 prompts itself. That means the capsule needs no second server, no proxy and no
port change: one `fastcgi` line inside a `server "onboard.kyriakon.net"` block, with the app
behind it. `relayd` cannot substitute for that, because its SNI support selects a certificate
only and both its `listen on` and `forward to` grammar resolve to IP addresses. Two processes
cannot share 1965 by hostname either: `gmid` picks the vhost from the SNI at the handshake and
then refuses any request whose host differs from it with status 53. The decisions left to the
design are the ones the protocol does not solve: multi-step state has no place to live in
Gemini, a CA certificate renews about a month before it expires and that lands in the branch
where all three clients examined treat the change as suspicious, and the endpoint is public and
unauthenticated with nothing in front of it that rate limits.

**Tested against versus read from sources.** An OpenBSD 7.9 host is reachable and was used:
`mail.kyriakon.net` (7.9 GENERIC.MP#11 amd64, `gmid-2.1.1p0`, port 1965 listening, `deploy-mail.sh`
having installed it). The account is unprivileged and `doas` needs a password, so every command
run on the box was read-only or wrote under `/tmp`: `gmid -h`, `gmid -n` against throwaway
configs under `/tmp/wf-gd` with a self-signed certificate generated in `/tmp` by `openssl req`,
`strings` over the installed binary, `man` pages read on the box, `pkg_info`, `ls -la` of
`/var/www` and `/etc/ssl`, `openssl x509 -text` over the installed certificates, `rcctl ls on`,
`rcctl check`, `ps auxww`, `netstat -anf inet`, `dig`, and reads of `/etc/gmid.conf`,
`/etc/httpd.conf`, `/etc/acme-client.conf`, `/etc/inetd.conf`, `/etc/login.conf`, `/etc/passwd`
and `/var/db`. `gmid -n` cannot check a config that names a `chroot` without root, and cannot
read `/etc/ssl/private/*` as this account, so the throwsaway configs carry no `chroot` and use
a `/tmp` keypair. `pfctl -sr` needs `/dev/pf` and was refused, so the firewall rules come from
`scripts/pf-apply.sh` in this repository rather than from the running kernel. Upstream source
was read from `github.com/omar-polo/gmid`, `github.com/openbsd/src` and the OpenBSD ports tree;
sections 8 and 9 say which claim rests on which. Nothing was written outside `/tmp`, no daemon
was signalled, no configuration was edited, and no port was bound.

---

## 1. The deployed gmid has dynamic content, and it is FastCGI

`gmid(8)` on the box opens with the capability, not a list of options:

> gmid is a simple and minimal gemini server that can serve static files, talk to FastCGI
> applications and act as a gemini reverse proxy.

The installed version is confirmed twice, once by the binary that is running and once by the
package: `gmid -h` prints `Version: gmid 2.1.1`, and `pkg_info` lists `gmid-2.1.1p0    simple
gemini server`.

That the deployed binary was compiled with FastCGI is tested, not assumed. `strings` over
`/usr/local/bin/gmid` returns the runtime messages that only exist in `fcgi.c` and its parser
rules:

```
CGI/1.1
FastCGI application is trying to send a header that's too long.
FastCGI application is trying to send an invalid reply code: %d
opening fastcgi connection for (%s,%s)
got invalid fcgi record (type=%d)
can't find fcgi #%d
fastcgi path is too long: %s
`cgi' was removed in gmid 2.0.  Please use fastcgi or proxy instead.
`fastcgi path' is deprecated.  Please use `fastcgi socket path' instead.
```

and `gmid -n` accepts the directive. Each of these was run against a throwaway config under
`/tmp/wf-gd` with a self-signed certificate in the same directory:

| config | result | exit |
|---|---|---|
| `fastcgi socket "/run/onboard.sock"` | `config OK` | 0 |
| `fastcgi socket tcp 127.0.0.1 port 9000` | `config OK` | 0 |
| `fastcgi { socket "/run/onboard.sock"; param SCRIPT_NAME = "/onboard"; strip 1 }` | `config OK` | 0 |
| `proxy { relay-to 127.0.0.1 port 1966 }` | `config OK` | 0 |
| `fastcgi socket "/run/does-not-exist.sock"` | `config OK` | 0 |
| `cgi "/cgi-bin/onboard"` | ``/tmp/wf-gd/cgi.conf:8 error: `cgi' was removed in gmid 2.0.  Please use fastcgi or proxy instead.`` | 1 |
| `bubblegum on` | `/tmp/wf-gd/bad.conf:6 error: syntax error` | 1 |

Two of those rows matter beyond their success. An unknown keyword is a distinguishable parse
failure, so the `config OK` results are not a parser that swallows everything. And a
non-existent FastCGI socket is accepted at config time: `gmid -n` does not connect to it, which
matches `apply_fastcgi()`, where the connect happens per request. A typo in the socket path
therefore ships clean and fails only when a member asks for the page.

`gmid -n` needs root or a readable keypair for reasons that are all in the config loader: with
`chroot` and `user` present it exits `fatal in gmid: need root privileges`; with a root
directory that does not exist it exits `fatal in gmid: open /tmp/whatever for domain
onboard.kyriakon.net: No such file or directory`; against the real `/etc/ssl/private` key as
this account it exits `can't open /etc/ssl/private/kyriakon.net.key: Permission denied`. The
`rc.d` script on the box runs `${daemon} -n ${daemon_flags}` as root, so `rcctl check gmid`
does exercise the real config.

The OpenBSD port does not disable any of it. `net/gmid/Makefile` from the ports tree is:

```
COMMENT =	simple gemini server
DISTNAME =	gmid-2.1.1
REVISION =	0

CATEGORIES =	net

HOMEPAGE =	https://gmid.omarpolo.com/

MAINTAINER =	Omar Polo <op@openbsd.org>

# ISC
PERMIT_PACKAGE = Yes

# uses pledge()
WANTLIB += c crypto event ssl tls util

SITES = 	https://ftp.omarpolo.com/

CONFIGURE_STYLE = simple
```

There is no `--disable-fastcgi` and no FastCGI library in `WANTLIB`, because `gmid` speaks the
FastCGI wire protocol itself in `fcgi.c`; the upstream `Makefile` lists `fcgi.c` among
`GMID_SRCS` and `GEMEXP_SRCS` with no conditional. `pkg/PLIST` installs `bin/gmid`, `gg`,
`gemexp`, `titan` and the man pages, and nothing FastCGI named, because there is no separate
binary to install.

### 1.1 What there is not, and when it went

CGI existed once and was removed. Upstream `ChangeLog` records the addition of FastCGI and,
two years later, the deletion of the older mechanism:

> 2021-05-09  Omar Polo  <op@omarpolo.com>
>
> 	* server.c (apply_fastcgi): added fastcgi support!

> 2022-09-06  Omar Polo  <op@omarpolo.com>
>
> 	* server.c: drop CGI support.

The 2021 commit sits after the 1.6.1 tag (2021-04-12) and before the 1.7 tag (2021-07-10), so
FastCGI first shipped in 1.7. The removal shipped in 2.0 (released 2024-01-11 per the same
file). What is left of CGI in 2.1.1 is a grammar rule that exists only to produce an error,
`parse.y`:

```
		| CGI string		{
			free($2);
			yyerror("`cgi' was removed in gmid 2.0."
			    "  Please use fastcgi or proxy instead.");
		}
```

There is no SCGI anywhere in the tree, and no hook mechanism: `configure` has no
`fastcgi`/`fcgi` option to toggle, and the man page's only dynamic directives are `fastcgi`,
`fastcgi off` and `proxy`. Anyone arriving with a CGI script has two routes, which are the
subject of section 3: rewrite it as a FastCGI app, or put the base system's `slowcgi` between
`gmid` and the script.

## 2. What the handler is handed, and what it must send back

The request reaches the program as FastCGI parameters, documented in `gmid.conf(5)` on the box
and built in `fcgi.c`. The man page's list, abbreviated to the lines that matter for a form:

> GEMINI_URL_PATH    Full path of the request.
>
> GEMINI_SEARCH_STRING    The decoded QUERY_STRING if defined in the request and if it doesn't
> contain any unencoded `=' characters, otherwise unset.
>
> GATEWAY_INTERFACE    "CGI/1.1"
>
> AUTH_TYPE    The string "Certificate" if the client used a certificate, otherwise unset.
>
> QUERY_STRING    The URL-encoded search or parameter string.
>
> REMOTE_ADDR, REMOTE_HOST    Textual representation of the client IP.
>
> REQUEST_METHOD    This is present only for RFC3875 (CGI) compliance.  It's always set to
> "GET".
>
> SCRIPT_NAME    The virtual URI path to the script.  Since it's impossible to determine in all
> cases the correct SCRIPT_NAME programmatically gmid assumes it's the empty string.  It is
> recommended to manually specify this parameter when serving a sub-tree of a virtual host via
> FastCGI.
>
> SERVER_NAME    The name of the server
>
> SERVER_PORT    The port the server is listening on.
>
> SERVER_PROTOCOL    "GEMINI"
>
> SERVER_SOFTWARE    The name and version of the server, i.e. "gmid/2.1.1"
>
> REMOTE_USER    The subject of the client certificate if provided, otherwise unset.
>
> TLS_CLIENT_ISSUER, TLS_CLIENT_HASH, TLS_VERSION, TLS_CIPHER, TLS_CIPHER_STRENGTH,
> TLS_CLIENT_NOT_BEFORE, TLS_CLIENT_NOT_AFTER

The code that sets them, `fcgi.c` in `fcgi_req()`, is where the status 10 input arrives:

```c
	fcgi_send_param(c->cgibev, "QUERY_STRING", c->iri.query);
	fcgi_send_param(c->cgibev, "REMOTE_ADDR", c->rhost);
	fcgi_send_param(c->cgibev, "REMOTE_HOST", c->rhost);
	fcgi_send_param(c->cgibev, "REQUEST_METHOD", "GET");
	fcgi_send_param(c->cgibev, "SERVER_NAME", c->iri.host);
	fcgi_send_param(c->cgibev, "SERVER_PORT", port);
	fcgi_send_param(c->cgibev, "SERVER_PROTOCOL", "GEMINI");
	fcgi_send_param(c->cgibev, "SERVER_SOFTWARE", GMID_VERSION);

	fcgi_send_param(c->cgibev, "GEMINI_URL_PATH", c->iri.path);

	if (*c->iri.query != '\0' &&
	    strchr(c->iri.query, '=') == NULL &&
	    (qs = strdup(c->iri.query)) != NULL) {
		pct_decode_str(qs);
		fcgi_send_param(c->cgibev, "GEMINI_SEARCH_STRING", qs);
		free(qs);
	}
```

Three consequences for the form design. The query string arrives percent-encoded in
`QUERY_STRING`, and the decoded copy is only sent when the query is non-empty and contains no
`=`. A form that submits `field=value` pairs gets `QUERY_STRING` and must decode it itself; a
form that submits one bare token gets `GEMINI_SEARCH_STRING` decoded for free. The client
address arrives as `REMOTE_ADDR`, which is the only per-applicant key `gmid` supplies on its
own, and section 4.1 of this note on the alternatives explains why that fact is load bearing
here.

There is one discrepancy between the man page and the binary worth recording, because a design
that tests for the documented string will not match: the man page says `AUTH_TYPE` is the
string `"Certificate"`, and `fcgi.c` sends `"CERTIFICATE"`:

```c
	if (tls_peer_cert_provided(c->ctx)) {
		fcgi_send_param(c->cgibev, "AUTH_TYPE", "CERTIFICATE");
```

The reply travels the other way as a Gemini response. `fcgi.c` parses the first line it gets
from the app, requires two digits, a space and a status in the documented range, and refuses
anything else:

```c
		if (!isdigit((unsigned char)c->sbuf[0]) ||
		    !isdigit((unsigned char)c->sbuf[1]) ||
		    c->sbuf[2] != ' ') {
			fcgi_error(bev, EVBUFFER_ERROR, c);
			return;
		}

		code = (c->sbuf[0] - '0') * 10 + (c->sbuf[1] - '0');
		if (code < 10 || code >= 70) {
			log_warnx("FastCGI application is trying to send an"
			    " invalid reply code: %d", code);
			fcgi_error(bev, EVBUFFER_ERROR, c);
			return;
		}

		if (start_reply(c, code, c->sbuf + 3) == -1 ||
		    c->code < 20 || c->code > 29) {
			fcgi_error(bev, EVBUFFER_EOF, c);
			return;
		}
```

So a handler can return a 10 with a prompt, and that prompt is what the member sees. Only 2x
carries a body through. When the handler dies, `fcgi_error()` and `apply_fastcgi()` both answer
`start_reply(c, CGI_ERROR, "CGI error")`, and `gmid.h` defines that as 42:

```c
#define CGI_ERROR	42
#define PROXY_ERROR	43
...
#define BAD_REQUEST	59
```

The Gemini specification gives 42 and 43 their meanings, and both are named for exactly this
plumbing:

> Status 42---CGI error
> A CGI process, or similar system for generating dynamic content, died unexpectedly or timed
> out.

> Status 43---proxy error
> A proxy request failed because the server was unable to successfully complete a transaction
> with the remote host. (cf HTTP 502, 504)

What the handler cannot do is as fixed as what it can. It cannot see the TLS key, because the
key is root-only and `gmid` reads it before dropping privileges. It cannot reach another
vhost's document root through `gmid`, because it is not inside `gmid` at all. It cannot
influence `gmid`'s answer for a name it does not own, because the vhost was already chosen at
the handshake. It cannot ask `gmid` to keep anything, because the FastCGI connection is opened
per request by the server process that accepted the connection, and `gmid` passes no session
state of any kind. Everything a multi-step form needs to remember is therefore the app's own
problem, which is what makes section 5 the hard part of this ticket.

## 3. The exact configuration for a dynamic capsule

The deployed `/etc/gmid.conf` has two server blocks, both `listen on * port 1965`, one for
`kyriakon.net` and one for `oliver.kyriakon.net`, each with `cert`, `key`, `root` and a
`location "/.git/*" { block }`. A dynamic capsule adds a third block with the same shape plus
the FastCGI directive. Unix socket:

```
server "onboard.kyriakon.net" {
	listen on * port 1965

	cert "/etc/ssl/onboard.kyriakon.net.fullchain.pem"
	key "/etc/ssl/private/onboard.kyriakon.net.key"

	# the app's socket, as seen from inside gmid's chroot "/var/www"
	fastcgi socket "/run/onboard.sock"
}
```

Or a loopback TCP socket, which avoids the chroot coupling entirely:

```
	fastcgi socket tcp 127.0.0.1 port 9000
```

`fastcgi` is a location rule as well as a server rule, and `fastcgi off` disables it inside a
location, so a capsule that serves static pages most of the time and dynamic ones under one
path is configured as a static vhost with one location carrying the directive. Both forms above
parse on the deployed binary (section 1).

### 3.1 Which user the handler runs as

Not any user `gmid` chooses, because `gmid` never runs it. The chain is:

`gmid`'s parent process starts as root, binds the listening socket, reads the certificates, and
hands them to children as file descriptors. `proc.c` then chroots and drops each child:

```c
	/* Change root directory */
	if (p->p_chroot != NULL)
		root = p->p_chroot;
	else
		root = pw->pw_dir;

	if (chroot(root) == -1)
		fatal("%s: chroot", __func__);
	if (chdir("/") == -1)
		fatal("%s: chdir(\"/\")", __func__);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("%s: cannot drop privileges", __func__);
```

and then `sandbox.c` pledges it:

```c
void
sandbox_server_process(void)
{
	if (pledge("stdio rpath inet unix dns recvfd", NULL) == -1)
		fatal("pledge");
}
```

That pledge has `inet` and `unix` for the FastCGI connect and no `proc` and no `exec`, so the
process that talks to the handler cannot itself run anything. The running processes on the box
agree with the source:

```
root     27406  ...  /usr/local/bin/gmid
_gmid    94817  ...  gmid: server (gmid)
_gmid    29635  ...  gmid: server (gmid)
_gmid    19077  ...  gmid: server (gmid)
_gmid    91918  ...  gmid: crypto (gmid)
_gmid    28507  ...  gmid: logger (gmid)
```

Three server processes, which is the documented default (`prefork number`, "gmid(8) runs 3
server processes by default"), plus the crypto and logger children, all as `_gmid`.

So the handler runs as whatever user its own `rc.d` script starts it as, and the `gmid` side of
the socket is `_gmid` inside the chroot. For a unix socket that has two consequences. The path
is resolved after the chroot, so `/run/onboard.sock` must exist inside `/var/www`, matching the
man page's "a local path name within the chroot(2) root directory of gmid(8)". And the socket
has to be openable by `_gmid`, so either the socket file is group-owned by `_gmid` with group
write, or (worse) mode 0666. `/var/www/run` on the box is `drwxr-xr-x root daemon`, which means
a handler running as a dedicated user cannot create the socket there without a subdirectory or
an ownership change; that directory exists empty today, because the stock `httpd` example that
uses it is not enabled. The TCP form sidesteps all of this: a loopback listener has no chroot
path and no socket permissions, at the cost of a local port and a pf consideration if the
ruleset stops being permissive.

### 3.2 The base system already ships a FastCGI-to-CGI bridge

`slowcgi(8)` is installed on the box (`/usr/sbin/slowcgi`, `/etc/rc.d/slowcgi`) and is not
running or enabled (`rcctl check slowcgi` returns `slowcgi(failed)` and it is absent from
`rcctl ls on`). It exists to let CGI scripts be reached over FastCGI, and its defaults line up
with this deployment's chroot:

> slowcgi opens a socket at /var/www/run/slowcgi.sock, owned by www:www, with permissions 0660.
> It will then chroot(8) to /var/www and drop privileges to user "www".

The socket location is the alignment that matters. `gmid` is chrooted to `/var/www`, so the same
socket is `/run/slowcgi.sock` from `gmid`'s point of view and `/var/www/run/slowcgi.sock` from
the host's. The stock OpenBSD `httpd` example expects exactly that path, which is why the
directory already exists.

The bridge works because `slowcgi` does not interpret what it is given. The parameters arrive,
are passed to the script as the CGI environment, and the path to execute is taken from
`SCRIPT_NAME` or `SCRIPT_FILENAME`:

```c
		if (val_len < PATH_MAX && strcmp(env_entry->val,
		    "SCRIPT_NAME") == 0 && c->script_name[0] == '\0') {
			bcopy(buf, c->script_name, val_len);
			c->script_name[val_len] = '\0';
		} else if (val_len < PATH_MAX && strcmp(env_entry->val,
		    "SCRIPT_FILENAME") == 0) {
			bcopy(buf, c->script_name, val_len);
			c->script_name[val_len] = '\0';
		}
```

```c
		argv[0] = c->script_name;
		argv[1] = NULL;
		if ((env = calloc(c->env_count + 1, sizeof(char*))) == NULL)
			_exit(1);
		SLIST_FOREACH(env_entry, &c->env, entry)
			env[i++] = env_entry->val;
		env[i++] = NULL;
		execve(c->script_name, argv, env);
```

and the script's stdout is wrapped into FastCGI records unchanged, with no `Status:` or
header parsing anywhere in the file: `script_in()` reads the child's stdout and writes it into
an `FCGI_STDOUT` record. That is what makes the combination work, because what `gmid` wants on
that socket is a Gemini response header, not an HTTP one. A shell or Perl script that prints
`20 text/gemini\r\n` and a body, or `10 Full name\r\n`, is a complete handler.

Three caveats come with it. `gmid`'s default `SCRIPT_NAME` is the empty string, so the config
must set it (`param SCRIPT_NAME = "/cgi-bin/onboard"`) or `slowcgi` has no path to execute; the
man page says as much: "It is recommended to manually specify this parameter when serving a
sub-tree of a virtual host via FastCGI." The socket is owned by `www` by default and `-U user`
changes that, so `_gmid`'s ability to connect is a deliberate choice either way. And the bridge
costs a process per request, which `slowcgi` accepts by design: "While CGI scripts need to be
forked for every request, FastCGI scripts can be kept running and handle many HTTP requests."
Its own `-t timeout`, default 120 seconds, closes the script's standard streams without killing
it: "The CGI script is left to run but its standard input, output and error will be closed."

For a form that spans several prompts, the process-per-request shape is the point to weigh
rather than the speed. State cannot live in a CGI process that exits after one response, so it
moves to disk either way, which is where section 5.4 and section 7 pick it up.

## 4. The alternatives, and what each costs

`gmid` can serve the capsule, so these are not required. They are here because the ticket asks
for their costs, and because two of them are the answers to questions the FastCGI route does
not settle: whether the URL has to change, and whether anything can sit in front.

### 4.1 A second Gemini server on another port

A second process, for instance `agate` or `gemexp` (which the `gmid` package installs), listens
on its own port and serves `onboard.kyriakon.net` there. The costs are the ones the ticket
names.

The URL changes. Gemini has no way to carry a port other than the authority component of the
URI, so the member types `gemini://onboard.kyriakon.net:1966/` rather than
`gemini://onboard.kyriakon.net/`. Nothing in DNS can hide it, because DNS maps names to
addresses, not to ports. The name already resolves today (`dig +short onboard.kyriakon.net`
returns `95.216.152.17` and `2a01:4f9:c013:7888::1` from the zone's wildcard), so it is the port the
member has to be told, and a signup link in a browser or on paper has to spell it out.

Trust on first use is pinned per hostname and port, per the specification quoted in section 6,
so a port is not cosmetic. Amfora's store is keyed on the domain with the port appended for
every port except 1965 (`client/tofu.go`, quoted in section 6.2), so `onboard.kyriakon.net:1966`
is a separate entry from `onboard.kyriakon.net:1965`, and a later move back to 1965 is a new
pin, meaning a fresh warning for every member who had already accepted the other one. The second
server also needs its own certificate and private key, and its own line in the firewall, since
the deployed rule is port specific.

What it buys is isolation: the onboarding front end no longer shares a process family, a chroot
or a config file with the public capsules, and a bug in it cannot reach the static sites' config
at all.

### 4.2 Routing by SNI through relayd

`relayd` is in the base system (`/usr/sbin/relayd`) and is not running (`rcctl check relayd`
returns `relayd(failed)`). The question in the ticket is whether it can route a non-HTTP
protocol by SNI, and the answer is no, for two independent reasons.

SNI in `relayd` selects a certificate and nothing else. `relayd.conf(5)` on the box, under the
`tls` protocol options:

> keypair name
>     The relay will attempt to look up a private key in /etc/ssl/private/name:port.key and a
>     public certificate in /etc/ssl/name:port.crt, where port is the specified port that the
>     relay listens on.  If these files are not present, the relay will continue to look in
>     /etc/ssl/private/name.key and /etc/ssl/name.crt.  This option can be specified multiple
>     times for TLS Server Name Indication.  If not specified, a keypair will be loaded using
>     the specified IP address of the relay as name.

The relay's own source contains no SNI handling at all: a case-insensitive search for `sni` and
`servername` across `usr.sbin/relayd/relay.c`, `relay_http.c`, `relayd.h` and `parse.y` returns
only `#define RELAYD_SERVERNAME "OpenBSD relayd"`, which is the string relayd puts in HTTP
responses. Backend selection is the protocol rule engine's job, and its keys are HTTP ones
(cookie, header, path, query, url). The man page says what the engine is for:

> The main purpose of a relay is to provide advanced load balancing functionality based on
> specified protocol characteristics, such as HTTP headers, to provide TLS acceleration and to
> allow basic handling of the underlying application protocol.

The second reason is the socket. `relayd`'s grammar resolves addresses through `host()`, which
keeps only `AF_INET` and `AF_INET6` results (`parse.y`, `host()`: `if (res->ai_family != AF_INET
&& res->ai_family != AF_INET6) continue;`), and both the listener and the target are `STRING`
addresses:

```
relayoptsl	: LISTEN ON STRING port opttls {
...
forwardspec	: STRING port retry {
```

so there is no Unix domain socket on either side. That closes the "listen on 1965 in relayd,
forward to `gmid`'s socket" shape as well as the "SNI picks the backend" shape.

What relayd can do is terminate TLS for a plain TCP relay, and the man page lists the two modes:

> TLS client
>     When configuring the relay forward statements with the with tls directive, relayd(8) will
>     enable client-side TLS to connect to the remote host.  This is commonly used for TLS
>     tunneling and transparent encapsulation of plain TCP connections.

> TLS server
>     When specifying the tls keyword in the relay listen statements, relayd(8) will accept
>     connections from clients as a TLS server.  This mode is also known as "TLS acceleration".

So a relay could sit on 1965, present the right certificate per SNI, and hand the stream to a
fixed backend. The backend would be one process for every hostname on that listener, which
defeats the purpose, and the certificate files would have to be in relayd's own naming scheme
rather than the acme-client paths this repo uses. It also moves TLS termination away from
`gmid`, which is a larger change than the ticket needs.

### 4.3 Socket activation

OpenBSD has no systemd-style inherited-descriptor activation, and `gmid` has no option to
accept a pre-bound socket: `gmid -h` offers `[-fnv] [-c config] [-D macro=value] [-P pidfile]`,
and `config_send_socks()` is where listeners are created, with its own `socket()`, `bind()` and
`listen()` per address. So there is no way to have a wrapper own port 1965 and hand it to
`gmid`; a second daemon on that port is a second `bind()` on that port, which is section 4.4.

The nearest primitive on the box is `inetd(8)`, which is enabled and already in use for
`fingerd`. It spawns a process per connection and gives it the connected socket on stdin and
stdout, and it has a per-service rate limit:

> -R rate
>     Specify the maximum number of times a service can be invoked in one minute; the default is
>     256.  If a service exceeds this limit, inetd will log the problem and stop servicing
>     requests for the specific service for ten minutes.

> The optional "max" suffix (separated from "wait" or "nowait" by a dot) specifies the maximum
> number of times a service can be invoked in one minute; the default is 256.

Applied to this ticket, `inetd` can put a handler on its own port (1966, say) without a
long-running daemon, but the handler then does its own TLS with the selected certificate, and
the port-in-the-URL cost of section 4.1 applies unchanged. It cannot help share 1965, and it
does not reduce the work of writing the Gemini responses, since `inetd` hands over a raw socket
rather than a parsed request.

### 4.4 Two processes serving 1965 by hostname

This does not work, and the interesting part is why, because `gmid` will not stop it at the
`bind()`. `gmid` sets both `SO_REUSEADDR` and `SO_REUSEPORT` on every listener, `config.c`:

```c
		v = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v))
		    == -1)
			fatal("setsockopt(SO_REUSEADDR)");

		v = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v))
		    == -1)
			fatal("setsockopt(SO_REUSEPORT)");

		mark_nonblock(sock);

		if (bind(sock, (struct sockaddr *)&addr->ss, addr->slen)
		    == -1)
			fatal("bind");
```

and `setsockopt(2)` on the box describes the option as being for a different problem:

> SO_REUSEPORT allows completely duplicate bindings by multiple processes if they all set
> SO_REUSEPORT before binding the port.  This option permits multiple instances of a program to
> each receive UDP/IP multicast or broadcast datagrams destined for the bound port.

Two `gmid` instances on 1965 would therefore both bind, and which one accepts a given TCP
connection is not defined by that man page. Even if the kernel alternated between them
perfectly, the split would be per connection rather than per hostname, so a request for
`kyriakon.net` could land in the process whose config only knows `onboard.kyriakon.net`.

That is fatal here because hostname selection inside `gmid` happens once per connection, at the
handshake, on the SNI, and the answer is then enforced against the request. `server.c`, in
`handle_handshake()`:

```c
	if ((servname = tls_conn_servername(c->ctx)) == NULL)
		log_debug("handshake: missing SNI");
	if (!puny_decode(servname, c->domain, sizeof(c->domain), &parse_err)) {
		log_info("puny_decode: %s", parse_err);
		start_reply(c, BAD_REQUEST, "Wrong/malformed host");
		return;
	}
...
	TAILQ_FOREACH(h, &conf->hosts, vhosts)
		if (match_host(h, c))
			break;
```

and in the request path:

```c
	if (strcmp(c->iri.schema, "gemini") ||
	    strcasecmp(c->domain, decoded)) {
		start_reply(c, PROXY_REFUSED, "won't proxy request");
		return;
	}

	if (apply_require_ca(c) ||
	    apply_block_return(c)||
	    apply_fastcgi(c))
		return;
```

So the vhost, and with it the certificate and the document root, is fixed before a single byte
of the request is read, and a request whose host does not match the SNI is refused with 53. The
specification gives 53 the same meaning: "The request was for a resource at a domain not served
by the server and the server does not accept proxy requests." A name that arrives in a process
that does not have a matching `server` block gets 59 `Wrong/malformed host` instead, which is
what the repo's `scripts/pf-apply.sh` is describing when it says "gmid itself only serves
hostnames named in its config, and answers anything else with a 59".

The upshot is that per hostname routing is a property of one TLS terminator, not something two
processes can split, and `gmid` is already that terminator. No SIGHUP, no firewall rule and no
second daemon changes that, which is why the FastCGI route in section 3 is the one that keeps
`gemini://onboard.kyriakon.net/` as the URL.

### 4.5 gmid's own reverse proxy

`gmid` also has a `proxy` block, which relays a whole request to another Gemini server, and it
is worth naming separately because it is a middle path: the public URL stays
`gemini://onboard.kyriakon.net/`, `gmid` terminates the client's TLS, and a second process
speaks Gemini somewhere else. `gmid.conf(5)`:

> relay-to host [port port]
>     Relay the request to the given host at the given port, 1965 by default.  This is the only
>     mandatory option in a proxy block.

> use-tls bool
>     Specify whether to use TLS when connecting to the proxied host.  Enabled by default.

> proxy-v1
>     Use the proxy protocol v1.  If supported by the remote server, this is useful to
>     propagate the information about the originating IP address and port.

against the man page's own note on what is lost:

> This example shows how to set up a reverse proxy: all request for `example.com' will be
> forwarded to 10.0.0.6 transparently.  Proxying establish a new TLS connection, so any
> client-certificates used to connect to gmid(8) cannot be provided to the proxied server.

The costs are the client certificate, which stops at `gmid`, and one extra network hop. The
gains are a normal request and response interface for the app, and `use-tls off` means the
backend can speak plain Gemini on loopback, with no FastCGI library and no certificate of its
own. `proxy-v1` restores the client address for rate limiting. It is the closest thing to a
conventional reverse proxy on this stack, and unlike relayd it is configured per vhost by host
name, which is the thing relayd could not do.

## 5. The input flow: a form on status 10

Gemini has exactly one input mechanism, and the specification (version 0.24.1, the current
`protocol-specification.gmi`) defines it in a way that constrains the form before any server
code exists:

> ## Input expected
>
> The server is expecting user input from the client. The additional information sent after
> the status code is the text that a client MUST use to prompt the user for the information. If
> the requested information is provided, the client should make a subsequent request for the
> same URI with the user input included as the query portion. Spaces in the user input MUST be
> encoded as '%20'. Clients MAY allow for the entry of input composed of multiple lines and in
> such cases the linebreaks in the user input SHOULD be encoded as '%0A', while servers SHOULD
> recognise both '%0A' and '%0D%0A' as linebreaks.

> ### Status 10
>
> The basic input status code. A client MUST prompt a user for input, it should be URI-encoded
> per [STD66] and sent as a query to the same URI that generated this response.

> If a client receives a 1x response to a URI that already contains a query string, the client
> MUST replace the query string with the user input.

There is no form element, no field name, no ordering and no way to submit several values at
once. The client's whole vocabulary is one URI and one line.

### 5.1 One prompt at a time, or one line with separators

Both shapes are available and the protocol treats them as the same thing, an inseparable
string appended to the URL. One prompt at a time means the server returns 10 with the next
question as META, and the member answers one field per round trip. One line with separators
means the server returns a single 10 whose META describes a template, and the member types
`Alice Smith|1970-01-01|GB`, which the app splits.

The trade is legibility against round trips, and the failure modes differ. Per field, one wrong
value can be re-asked with a better prompt, and the applicant never has to remember a
separator. One line, a wrong field means the whole line is wrong, and the app has to return
either another 10 (asking again, with the error in the META, which is the only place a client
displays text) or a 4x error that ends the flow. The specification does not define a length
limit on user input, but the request line does: the URI is capped at 1024 bytes ("When making a
request, the URI MUST NOT exceed 1024 bytes, and a server MUST reject requests where the URI
exceeds this limit"), and `gmid` enforces it at the same number, `server.c`:

```c
	if (c->reqlen > 1024+2) {
		log_debug("URL too long");
		start_reply(c, BAD_REQUEST, "bad request");
		return;
	}
```

so the single line's total, plus the path, plus whatever token carries the state, has to fit in
just over a kilobyte. A date, a name and a country fit. A free text box, an address and a
payment reference do not, comfortably.

Both shapes are also single-field from the client's point of view, which section 5.2 shows is
not just a figure of speech: no client has a multi-field widget.

### 5.2 What the client shows the applicant

In all three clients examined, META is the prompt text, verbatim, and the client reads exactly
one value before starting a fresh connection.

Amfora (`display/handlers.go`):

```go
	switch status {
	case 10, 11:
		var userInput string
		var ok bool

		if status == 10 {
			// Regular input
			userInput, ok = Input(res.Meta, false)
		} else {
			// Sensitive input
			userInput, ok = Input(res.Meta, true)
		}
		if ok {
			// Make another request with the query string added
			parsed.RawQuery = gemini.QueryEscape(userInput)
			if len(parsed.String()) > gemini.URLMaxLength {
				Error("Input Error", "URL for that input would be too long.")
				return ret("", false)
			}
			return ret(handleURL(t, parsed.String(), 0))
		}
		return ret("", false)
```

and its prompt widget is a single cview line, masked with `*` for status 11.

Lagrange shows META as a label above one input widget, and falls back to a generated prompt
when META is empty (`src/ui/documentwidget.c`, `makeInputPrompt_DocumentWidget`):

```c
    iWidget *dlg = makeValueInput_Widget(
        as_Widget(d),
        NULL,
        format_CStr(uiHeading_ColorEscape "%s", cstr_Rangecc(parts.host)),
        promptLabel ? promptLabel
                    : format_CStr(cstr_Lang("dlg.input.prompt"), cstr_Rangecc(parts.path)),
```

with `dlg.input.prompt` set to `Enter input for %s:` in the translation catalogue. Lagrange's
input widget for status 10 has line breaks enabled (`src/ui/inputwidget.c`: `lineBreaksEnabled_
InputWidgetFlag` is in the default flags, and `isAllowedToInsertNewline_InputWidget_` returns
true for it), so a member can paste a multi-line value there, and the client sends the newline
as part of the query. For status 11 the flag is off, the dialog says so in a comment ("There is
no line breaks in sensitive input") and the characters are masked with U+25CF.

Kristall uses `QPlainTextEdit` for status 10 and a masked `QLineEdit` for status 11
(`src/widgets/querydialog.cpp`), labels the dialog with META
(`dialog.setLabelText(query)`), and sets the query on the current URL
(`new_location.setQuery(dialog.textValue())`) before navigating.

The consequence for the one-line-with-separators design is that a client which permits
multi-line input will happily send a literal newline in the middle of the value, which is why
the specification's advice to encode `%0A` and to recognise `%0D%0A` matters to a server that
splits on a separator such as `|`: the app has to normalise line breaks before splitting, or
reject the request. `gmid` hands the query over percent-encoded, so the app sees the `%0A` and
decides.

### 5.3 Where the state lives between prompts

This is the part the protocol does not solve. Each status 10 response ends with the server
closing the connection, and the client's next request opens a new one. There is no cookie, no
session identifier and no header. `gmid` helps with none of it: it has no session storage, and
the FastCGI connection it opens is per request.

Two mechanisms keep a flow together, and the specification's own worked example uses the first.

The client certificate. Section 6 of the specification describes status 60 and then gives an
example whose comment is the design note:

> This example provides a minimal example of combining client certificates and user input to
> implement an application which maintains per-user server-side state and adds together two
> numbers.

In that example the server answers 60, the client presents a certificate, and the server then
"recognises client certificate, stores value '42' in memory or on disk in association with
certificate". `gmid` supports this shape directly, since it accepts client certificates without
verification and passes `AUTH_TYPE`, `REMOTE_USER`, `TLS_CLIENT_HASH`, `TLS_CLIENT_ISSUER` and
the validity dates to the handler; `TLS_CLIENT_HASH` is the stable key. Two things to be honest
about. Any client can generate a certificate on demand, so the hash identifies a browser
profile rather than a person, which makes it a state key and a rate limit key rather than an
authenticator. And the specification constrains client behaviour: "Clients MUST NOT
automatically generate a client certificate and use it to repeat the request without the active
involvement of the user", so the applicant sees a prompt before the certificate exists.

A token in the path. Because the client re-requests the same URI with the input as the query,
the path is free to carry state, and the server can hand out a fresh path per step:
`/apply/step2/<token>?<answer>`. The token is either a random identifier that indexes server
side state or a signed blob. The identifier is smaller and needs a store with an expiry; the
blob needs no store but consumes the 1024-byte budget quickly, and if it is signed and the
signing key is not exclusive to the app, a leak of it lets a stranger mint tokens. Either way,
the query `=` rule from section 2 bites: a token plus `key=value` fields means the app reads
`QUERY_STRING` and percent-decodes it itself rather than using `GEMINI_SEARCH_STRING`.

### 5.4 Wrong field, abandoned flow, and timeouts

A wrong field has one place to appear: META. The specification fixes META's role ("the text
that a client MUST use to prompt the user for the information"), so the server re-answers 10
with the error in the prompt, or answers a 4x and ends the flow. The status codes give both
options a name: 40 for an unspecified recoverable condition, 41 for overload, 44 for "The
server is requesting the client to slow down requests, and SHOULD use an exponential back off",
50 and 59 for the permanent cases.

An abandoned flow sends nothing. That is a client property, not a server one, and it is the same
in all three clients examined: Amfora returns without issuing a request when the input is empty
or cancelled, Lagrange posts `navigate.back` or destroys the inline prompt and writes nothing
to the socket, and Kristall has already closed the connection before the dialog appears, because
it closes the socket for any non-2x code (`src/protocols/geminiclient.cpp`:
`if(primary_code != 2) socket.close();`). So the server never learns that the applicant stopped.
State keyed on a client certificate or a token therefore needs an expiry that the app enforces
itself; there is no disconnect event to hang it on. An onboarding form that leaves abandoned
applications for days is a data retention problem, not just a memory one, and the project's own
log discipline applies to it (section 7.4).

Timeouts are the app's business too. `gmid` has no FastCGI-specific timeout: there is no
`bufferevent_settimeout` call on the FastCGI bufferevent, and the only timeout in the request
path is the proxy path's five-second handshake (`proxy.c`: `static const struct timeval
handshake_timeout = { 5, 0 };`). What exists is the generic client-side timeout branch in
`server.c`, which answers 59 for a client that has sent nothing yet and closes otherwise. With
`slowcgi` in between there is one more clock, its `-t` default of 120 seconds, which closes the
script's standard streams without killing it. A handler that hangs therefore holds a `gmid`
server process slot; with three prefork servers, a few hung handlers are a denial of service for
the other capsules on the same listener.

## 6. TLS

### 6.1 Which certificate a dynamic capsule presents

The certificate is chosen by SNI, before the request is read, from the keypairs of the vhosts
that share the listening address. `gmid` loads them into one libtls configuration per address
(`server.c`, `add_matching_kps()`, calling `tls_config_set_keypair_ocsp_mem()` for the first
match and `tls_config_add_keypair_ocsp_mem()` for the rest), and libtls picks among them. The
man page for the add function on the box says exactly what they are for:

> tls_config_add_keypair_mem() adds an additional public certificate and private key from
> memory, used as an alternative certificate for Server Name Indication (server only).

So a dynamic capsule needs its own `server "onboard.kyriakon.net"` block with its own `cert` and
`key`, and nothing else on that host changes: `hostname` matching is shell globbing against the
SNI, and the certificate is presentation only, since `gmid` neither verifies clients nor
requires them unless the config says so. `server.c`:

```c
		/* optionally accept client certs but don't verify */
		tls_config_verify_client_optional(tlsconf);
		tls_config_insecure_noverifycert(tlsconf);
```

A name with no matching server block is not served at all: the handshake proceeds to the first
configured keypair, and the request is then refused with 59 `Wrong/malformed host`, which is
the behaviour the repo's firewall commentary already records.

### 6.2 Trust on first use, and what a renewal does to it

The specification is explicit that certificate validation is client policy, and recommends the
scheme this platform relies on:

> Clients are strongly RECOMMENDED to use a Trust on First Use or "TOFU" certificate-pinning
> system, which does not reject self-signed certificates as invalid, as the basis of their
> validation system. Under such an system, the first time a Gemini client connects to a server,
> it accepts whichever certificate it is presented. That certificate's fingerprint and expiry
> date are saved in a persistent database, associated with the server's hostname and port. On
> all subsequent connections to the same hostname on the same port, the received certificate's
> fingerprint is computed and compared against the one stored in the database. If the
> fingerprints do not match but the previous certificate's expiry date has not passed, this is
> considered potential evidence of a Man-In-The-Middle attack.

The pinned entry includes the expiry date, and the comparison is per hostname and port, so a
renewal that happens while the old pin is still inside its validity window is the case the
specification points at. Three clients were read to see what that costs a member.

Amfora stores a SHA-256 of the subject public key info plus `NotAfter`, and appends the port to
the key only when it is not 1965 (`client/tofu.go`):

```go
func idKey(domain string, port string) string {
	if port == "1965" || port == "" {
		return strings.ReplaceAll(domain, ".", "/")
	}
	return strings.ReplaceAll(domain, ".", "/") + ":" + port
}
```

```go
func certID(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.RawSubjectPublicKeyInfo) // Better than cert.Raw, see #7
	return fmt.Sprintf("%X", h.Sum(nil))
}
```

A mismatch with a live pin fails the fetch, and the applicant sees a blocking modal:
"<host>'s certificate has changed, possibly indicating a security issue. The certificate would
have expired <when>. Are you sure you want to continue?" Answering Yes re-pins the new
certificate and continues. The expiry gate is explicit in `handleTofu()`:

```go
	if time.Now().After(expiry) {
		// Old cert expired, so anything is valid
		saveTofuEntry(domain, port, cert)
		return true
	}
	return false
```

Lagrange stores the public key fingerprint with a `validUntil` that starts as the certificate's
own expiry, and its check has an exception for CA-verified certificates (`src/gmcerts.c`):

```c
        if (elapsedSeconds_Time(&trust->validUntil) < 0) {
            /* Trusted cert is still valid. */
            const iBool isTrusted = cmp_Block(fingerprint, &trust->fingerprint) == 0;
            /* Even if we don't trust it, we will go ahead and update the trusted certificate
               if a CA vouched for it. */
            if (isTrusted || !isCATrusted) {
                unlock_Mutex(d->mtx);
                delete_Block(fingerprint);
                deinit_String(&key);
                return isTrusted;
            }
        }
```

so a mismatch that is not CA-verified cancels the connection and the applicant gets the
"Untrusted Server" page ("Connection to the server was cancelled because its TLS certificate
does not match the one we trust. Please check if the server has announced a certificate
change."), plus a Security Issue banner whose wording is aimed at exactly this situation: "The
server certificate may have been recently renewed — it is for the correct domain and has not
expired. The currently trusted certificate will expire on %s, in %d days." Acceptance is
possible through Page Information, Trust.

Kristall stores the whole public key and no expiry, and a changed key is a dead end inside the
client. The error page says:

> The host you tried to visit does not look trustworty anymore. The certificate changed since
> your last visit.
>
> If you still trust this host, please revoke trust in the settings menu, then reload the page.

There is no accept button on that page; only the first-use page has one. So a Kristall user who
has visited `onboard.kyriakon.net` once cannot reach it again after a renewal until they clear
the entry in settings.

An ACME certificate renews about a month before it expires, because `acme-client(1)` on the box
says "For certificates with a lifetime of more than 10 days, this is done when less than a third
of the lifetime remains", and the current Let's Encrypt lifetime is 90 days. That lands squarely
in the "pin still valid" branch of all three clients: an Amfora modal, a Lagrange refusal with a
Trust action, and a Kristall dead end, at every renewal, for a service whose whole purpose is to
be reached by a stranger once.

A long-lived self-signed certificate has none of that. The protocol accepts it ("which does not
reject self-signed certificates as invalid"), it never changes, and the pin is written once and
never revisited. Nothing in the protocol requires a CA. The one asymmetry in the other direction
is Lagrange's CA exception, which silently re-pins a CA-verified certificate, so an ACME renewal
disturbs Lagrange users less than a self-signed rotation would. The choice is a deliberate one
either way; the repo's comment in `openbsd/etc/gmid.conf` already takes the position that this
certificate "encrypts rather than proving identity to a stranger".

One mechanical detail supports either choice: a renewed certificate is picked up by a reload
rather than a restart. `gmid(8)` says "gmid rereads the configuration file when it receives
SIGHUP and reopens log files when it receives SIGUSR1", and the reload path re-reads the
keypairs (`config_send()` calls `config_send_kp()` per vhost), so `rcctl reload gmid` is enough
after `acme-client` writes new files. A reload also re-runs the whole config parse, so a config
error at that moment leaves the running configuration in place rather than taking the capsules
down.

### 6.3 Whether the existing acme-client configuration covers a new capsule

It does not, and four separate files have to know about a new name. Verified on the box:

- `/etc/ssl/onboard.kyriakon.net.fullchain.pem` does not exist. The installed certificates are
  `kyriakon.net` (with `www.kyriakon.net` as a subject alternative name, expiring Dec 14 2026),
  `mail.kyriakon.net`, `kyriakon.com` and `oliver.kyriakon.net`.
- `/etc/acme-client.conf` has four `domain` blocks plus the `authority letsencrypt` block, and
  none of them is `onboard.kyriakon.net`. acme-client is HTTP-01 only, as the file's own comment
  says, so a new name needs a block there:
  ```
  domain onboard.kyriakon.net {
  	domain key "/etc/ssl/private/onboard.kyriakon.net.key"
  	domain full chain certificate "/etc/ssl/onboard.kyriakon.net.fullchain.pem"
  	sign with letsencrypt
  }
  ```
- `/etc/httpd.conf` needs a matching port 80 vhost, because HTTP-01 validation arrives over
  plain HTTP on the same name. The file already states the rule for itself: "Every name the
  certificate covers needs its own port 80 vhost, since acme-client only does HTTP-01. Port 443
  needs no challenge location." The challenge location has to be the first `location` in that
  vhost or the catch-all shadows it, which the file also says.
- `scripts/renew-acme.sh` renews three domains explicitly (`mail.kyriakon.net dovecot smtpd`,
  `kyriakon.net httpd`, `kyriakon.com httpd`), so a new name needs its own line, and a `gmid`
  reload after it.

DNS needs nothing: `dig +short onboard.kyriakon.net` already answers with this box's address
from the zone's wildcard record, verified from outside the box. What the name does not have is a
listener that serves it, which is what the 443 and 1965 vhosts would add.

There is a cheaper path for a capsule that does not want a CA certificate at all, and the
sister note `cert-issuance-ceiling.md` establishes its context: a new certificate is a new
issuance against the registered-domain rate limit, and Gemini clients do not check the CA
chain. A self-signed certificate generated once with the recipe in `gmid(8)` ("A self-signed
certificate, which are commonly used in the Geminispace, can be generated using for e.g.
openssl(1)") costs nothing, does not renew, and does not touch the Let's Encrypt budget. Choose
per the TOFU reasoning above rather than per habit.

## 7. The trust boundary

The endpoint is public and unauthenticated, and the FastCGI route puts the handler outside every
sandbox `gmid` has. `gmid`'s server processes are chrooted, dropped to `_gmid` and pledged to
`stdio rpath inet unix dns recvfd`; the handler is a separate daemon with its own config, its own
user and its own pledge or none. Nothing in this section is a `gmid` property: it is what the
handler's own service definition has to get right.

### 7.1 Which user

The pattern already on the box is the one to copy. `_gmid` is created by the port with
`@newuser _gmid:878:878::Gmid User:/var/empty:/sbin/nologin`, and the same shape is stored in
`/etc/passwd` on the box. An onboarding handler wants its own account in that form: a numeric
uid and gid reserved for it, home `/var/empty`, shell `/sbin/nologin`, no group memberships
beyond its own, and no `doas` rule. It must not be `_gmid`, because then a bug in the form can
touch anything `_gmid` can reach, and it must not be `www`, because `slowcgi`'s default user is
`www` and that account is the CGI user for whatever else the box runs later.

Resource limits come from the login class and are worth setting deliberately, because the two
classes on the box differ by a factor of four on file descriptors (`/etc/login.conf`):

```
default:\
	:datasize-max=1536M:\
	:datasize-cur=1536M:\
	:maxproc-max=256:\
	:maxproc-cur=128:\
	:openfiles-max=1024:\
	:openfiles-cur=512:\

daemon:\
	:datasize=4096M:\
	:maxproc=infinity:\
	:openfiles-max=1024:\
	:openfiles-cur=128:\
```

`openfiles-cur=128` in the `daemon` class is a connection limit, not a file limit, for anything
that serves many applicants at once. The `rc.d` framework sets the class for a service that
asks for it; assigning the wrong one is the kind of default that only shows up under load.

### 7.2 Where its state lives

Not in `/var/www`. The document root is public content, and it is a git checkout of a published
site, so an application's database there would be served by `httpd` or `gmid` on any path the
config does not block. The convention on this box is `/var/db/<service>`, and it has a
precedent: `/var/db/kyriakon-monitor` exists as `drwxr-xr-x root wheel`, with the service's own
write area beneath it. The same shape works here: a root-owned directory created by the deploy
script, with a subdirectory owned by the handler's user for the intent queue and the session
state.

If the handler uses the unix FastCGI socket rather than TCP, that socket is the one thing it
must place inside `/var/www`. A dedicated subdirectory under `/var/www/run`, owned by the
handler's user with group `_gmid`, keeps the socket out of reach of the document roots and still
lets `_gmid` connect.

### 7.3 What it may read

The handler needs its own state, a socket directory inside `/var/www`, and the log its `rc.d`
script wires up. It should not read mail, and it cannot read the certificates. Verified on the
box: `/etc/ssl/private` is not listable by an unprivileged account, and `/etc/ssl/*.pem`
contains only public certificates. The private keys are read by root at startup and passed to
`gmid`'s children as file descriptors, so a handler has no reason to be able to open them, and
if it runs as its own user it cannot. `/home` holds member mail, and no part of an onboarding
form needs it. If the handler is written in a language with `unveil(2)` and `pledge(2)`
available, the natural configuration is what `gmid`'s own server process has, minus `inet` and
minus `rpath` beyond its own tree.

### 7.4 Rate limiting and logging a public endpoint

Nothing currently limits this port. The deployed firewall fragment for Gemini, from
`scripts/pf-apply.sh`, is a plain pass:

```
pass in log on egress proto tcp to any port 1965
```

That is the same file that rate limits the other public, unauthenticated, single-line service on
the box, so the pattern to copy is already written down:

```
pass in log on egress proto tcp to any port 79 keep state (max-src-conn 5)
```

`pf.conf(5)` describes the two limit options and what happens when they are hit:

> max-src-conn number
>     Limits the maximum number of simultaneous TCP connections which have completed the 3-way
>     handshake that a single host can make.

> max-src-conn-rate number/seconds
>     Limit the rate of new connections over a time interval.  The connection rate is an
>     approximation calculated as a moving average.

> With the overload <table> state option, source IP addresses which hit either of the limits on
> established connections will be added to the named table.  This table can be used in the
> ruleset to block further activity from the offending host, redirect it to a tarpit process, or
> restrict its bandwidth.

A limit on port 1965 would apply to every capsule on that port, since pf cannot see the SNI, and
that is worth accepting deliberately rather than by omission: the landing site and a member's
own capsule share the listener, so a rule tuned for a signup form is a rule for the whole
Gemini service. The alternative is per-source limits inside the handler, which sees
`REMOTE_ADDR` on every request (and sees the original client address through `proxy-v1` if the
proxy route of section 4.5 is chosen). The two compose: pf for the crude bound, the app for the
per-application fair share.

A client certificate can also serve as a key, within the limits already stated: it is cheap to
generate, so it partitions abuse rather than preventing it, and it is only available after the
applicant has accepted a certificate prompt. It is useful for counting applications per browser
profile and for continuing a flow, not for keeping anyone out.

Logging is the other half, and the project has already written the rule down. The threat model
says "The Phase 3 onboarding service will emit its own log, and it is to be born bounded by a
`newsyslog.conf` entry on the day it lands rather than grandfathered in afterwards", and
`openbsd/etc/newsyslog.conf` repeats it at the point of use. An application form logs the
applicant's address and the fields of their application, so it is a per-user record and needs
the same bounded treatment the mail logs get.

### 7.5 What a design must satisfy

Collected from the evidence above, as constraints rather than as choices:

1. The handler runs outside `gmid`'s chroot, privilege drop and pledge, so its isolation is its
   own service definition: its own user, its own directory, its own limits.
2. A unix FastCGI socket path is resolved inside `gmid`'s chroot, so it must exist under
   `/var/www` and be connectable by `_gmid`.
3. The handler must emit a Gemini status line and nothing else as its first bytes, and only 2x
   responses may carry a body.
4. Every piece of state that spans prompts has to live outside the protocol, keyed either on the
   client certificate hash `gmid` supplies or on a token the handler puts in the path, and it
   needs its own expiry because an abandoned flow sends nothing.
5. The whole request URI, including any token and the member's input, must fit in 1024 bytes.
6. A query containing `=` suppresses `GEMINI_SEARCH_STRING`, so the handler must decode
   `QUERY_STRING` itself if it uses field names.
7. The capsule URL stays `gemini://onboard.kyriakon.net/` only if `gmid` keeps port 1965 and the
   new name gets its own server block; a second port changes the URL, and TOFU pins per host
   and port.
8. If the capsule uses an ACME certificate, it needs a domain block, a port 80 vhost, a line in
   `renew-acme.sh` and a `gmid` reload, and every renewal will look like a possible interception
   to any client that has already pinned the previous certificate.
9. The endpoint is unauthenticated and public, so rate limiting has to come from pf, from the
   handler, or both, and its log needs a bounded `newsyslog.conf` entry.

## 8. Tested on the box versus read from sources

Verified by running something on `mail.kyriakon.net`, or by reading a file on it:

- `gmid -h` prints `Version: gmid 2.1.1`; `pkg_info` lists `gmid-2.1.1p0 simple gemini server`;
  `/usr/local/bin/gmid` exists and port 1965 is in `netstat -anf inet` as `*.1965`.
- The six `gmid -n` results in section 1, with exit codes, including that `fastcgi socket`,
  `fastcgi socket tcp`, `fastcgi { param ... }` and `proxy { relay-to ... }` parse while `cgi`
  and an unknown keyword do not.
- That `gmid -n` does not check the FastCGI socket's existence.
- That `gmid -n` requires root when the config has `chroot`, and a readable keypair and an
  existing `root` directory when it does not, with the exact messages quoted in section 1.
- `strings /usr/local/bin/gmid`, including the FastCGI messages and the `cgi` removal text.
- The deployed `/etc/gmid.conf`: `user "_gmid"`, `chroot "/var/www"`, two server blocks on port
  1965, no `fastcgi` and no `proxy`.
- `ps auxww` showing the root parent process and the `_gmid` server, crypto and logger children,
  three servers, which matches the documented default prefork of 3.
- `man` pages read on the box: `gmid(8)`, `gmid.conf(5)`, `slowcgi(8)`, `relayd.conf(5)`,
  `relayd(8)`, `inetd(8)`, `acme-client.conf(5)`, `pf.conf(5)`, `setsockopt(2)`,
  `tls_load_file(3)`, `login.conf` values from `/etc/login.conf`. Every man page quote in this
  note comes from the box's own pages, not from the web.
- `/var/www` and `/var/www/run` permissions, the empty `run` directory, and `/var/www/cgi-bin`
  holding only the stock `bgplg` example.
- `/etc/ssl/*.fullchain.pem` subjects, validity dates and subject alternative names, and that
  `/etc/ssl/private` is not readable by this account and that no `onboard.kyriakon.net`
  certificate exists.
- `/etc/acme-client.conf`, `/etc/httpd.conf`, `/etc/inetd.conf` (the two `finger` lines and
  `inetd` enabled), `/etc/passwd` for `_gmid`, `/etc/login.conf` classes, `/var/db` contents,
  `/etc/rc.d/gmid` and `/etc/rc.d/kyriakon_encrypt`.
- `rcctl ls on`, `rcctl check slowcgi` and `rcctl check relayd`: `slowcgi` and `relayd` are both
  installed and both not running.
- `dig +short onboard.kyriakon.net` outside the box, returning the box's address.

Read from source or specifications, and not run on this box:

- The behaviour of `gmid`'s FastCGI path at request time: the parameter list and the reply
  parser in `fcgi.c`, the connect in `server.c`, and the per-request timing. The deployed binary
  contains the code, but no FastCGI application exists on the box to talk to, and writing one
  and pointing `gmid` at it would mean binding a port or creating a socket, which this ticket
  forbids.
- The chroot and privilege drop in `proc.c` and the pledge strings in `sandbox.c`, which are
  consistent with the running process list but were not exercised for a new child.
- The SNI-based vhost selection and the host-equals-SNI rule in `server.c`. The running server
  behaves this way for the names it serves, but the failure cases (59 and 53) were not triggered,
  because doing so would need a request against the live service.
- What happens when two `gmid` processes bind 1965: `config.c` sets `SO_REUSEPORT` and
  `setsockopt(2)` documents duplicate bindings, but the man page describes the option for UDP
  multicast, and which process accepts a TCP connection when both have bound is not stated
  anywhere quoted here. It was not tested, because the test is binding a port.
- `relayd`'s SNI behaviour: read from `relayd.conf(5)` and the relayd source, where no SNI key
  exists outside libtls. `relayd` is installed but not running and was not started.
- `slowcgi`'s execution path: read from `slowcgi.c` and `slowcgi(8)` on the box. `slowcgi` is
  installed and not running, so no CGI script was executed through it.
- The client behaviour in sections 5.2, 5.4 and 6.2, which comes from the Amfora, Lagrange and
  Kristall sources, the two error pages Kristall ships as Gemtext, and Lagrange's translation
  catalogue. No Gemini client was run against this box, so no member has seen any of these
  dialogs here.
- Upstream history: the FastCGI addition, the CGI removal and the 1.7 and 2.0 release dates,
  from the upstream `ChangeLog`.
- The OpenBSD port's build flags, from `net/gmid/Makefile` and `pkg/PLIST` in the ports tree.

## 9. Not verified, or not reachable

- The running firewall ruleset. `pfctl -sr` returns `pfctl: /dev/pf: Permission denied` for this
  account, so the port 1965 rule quoted in section 7.4 comes from the fragment
  `scripts/pf-apply.sh` appends, not from the kernel. Whether the box's live ruleset carries
  state limits on 1965 beyond what that fragment shows was not checked.
- Whether two `gmid` processes can usefully share port 1965. The code path and the `setsockopt`
  documentation are quoted, and the conclusion in section 4.4 rests on hostname selection
  happening at the handshake inside one process, which does not depend on the duplicate-bind
  question. The duplicate-bind behaviour itself is unverified, because testing it means binding
  the port.
- Any request-time FastCGI behaviour of the deployed binary. No FastCGI application was written
  or run, and no socket was created, so the parameter values, the reply parsing and the 42 error
  path are read from source rather than observed. `gmid -n` proves the parser, not the runtime.
- `slowcgi` end to end. It is not enabled on the box, and enabling it was out of scope, so the
  claim that a CGI script printing a Gemini status line reaches the member intact rests on the
  source reading of `script_in()` and on `gmid`'s parser, not on a run.
- `relayd` end to end. Not enabled, not started, not configured; the SNI conclusion comes from
  the source and the man page.
- Which client a given member actually uses. The certificate-change paths in Amfora, Lagrange
  and Kristall are quoted from their sources, so the mechanism is grounded, but nothing here
  measures which clients members run, and a client not examined could pin the whole certificate
  rather than the key, or offer no acceptance path at all. Lagrange's sources were read from its
  `dev` branch, which is the repository's default; `main` does not exist there.
- Anything requiring root: no `doas`, no service restarts, no firewall change, no certificate
  issuance, no `slowcgi` or `relayd` start, no config edits. The throwaway configs and keys all
  live under `/tmp/wf-gd` and were never installed.
- The rate limit figures in Let's Encrypt's published policy, which are the sister note's
  subject (`cert-issuance-ceiling.md`), not this one's; this note only relies on the renewal
  interval that follows from acme-client's one-third rule.

## 10. Primary sources

- `gmid(8)` and `gmid.conf(5)`, gmid 2.1.1p0 as installed on the box
  (`/usr/local/man/man8/gmid.8`, `/usr/local/man/man5/gmid.conf.5`). Also at
  https://man.openbsd.org/gmid.8 and https://man.openbsd.org/gmid.conf.5
- gmid source, master branch, read from https://raw.githubusercontent.com/omar-polo/gmid/master/:
  `fcgi.c` (`fcgi_req()` at line 399, the parameter list at lines 447 to 502, the reply parser at
  lines 214 to 256, `fcgi_error()` at line 348), `server.c` (`apply_fastcgi()` at line 726,
  `handle_handshake()` at line 351, the request path at lines 1015 to 1045, `add_matching_kps()`
  at line 1489, `setup_tls()` at line 1521), `config.c` (`config_send_kp()` at line 209,
  `config_send_socks()` at line 240), `proc.c` (`proc_run()` at line 551, chroot and `setresuid`
  at lines 578 to 591), `sandbox.c` (`sandbox_server_process()`), `parse.y` (the `CGI` rule, the
  `fastcgi` grammar), `gmid.h` (`CGI_ERROR 42`, `PROXY_ERROR 43`, `NOT_FOUND 51`,
  `PROXY_REFUSED 53`, `BAD_REQUEST 59`), `ChangeLog`. Repository:
  https://github.com/omar-polo/gmid
- OpenBSD ports: `net/gmid/Makefile`, `net/gmid/pkg/PLIST`, `net/gmid/files/gmid.conf`, from
  https://raw.githubusercontent.com/openbsd/ports/master/net/gmid/Makefile and
  https://raw.githubusercontent.com/openbsd/ports/master/net/gmid/pkg/PLIST
- `slowcgi(8)` and `slowcgi.c` (`parse_params()` reading `SCRIPT_NAME` and `SCRIPT_FILENAME`,
  `exec_cgi()` at line 879, `script_in()` forwarding the child's stdout), from
  https://raw.githubusercontent.com/openbsd/src/master/usr.sbin/slowcgi/slowcgi.c
- `relayd.conf(5)`, `relayd(8)`, and `usr.sbin/relayd/parse.y` (`relayoptsl`, `forwardspec`,
  `host()`), `relay.c`, `relay_http.c`, `relayd.h` (`RELAYD_SERVERNAME`), from
  https://raw.githubusercontent.com/openbsd/src/master/usr.sbin/relayd/parse.y
- `inetd(8)`, OpenBSD 7.9, on the box (`/usr/share/man/man8/inetd.8`); there is no
  `inetd.conf(5)` on this system, so the configuration file format is documented inside
  `inetd(8)`. https://man.openbsd.org/inetd.8
- `setsockopt(2)`, OpenBSD 7.9, on the box, for `SO_REUSEPORT`.
  https://man.openbsd.org/setsockopt.2
- `tls_load_file(3)`, OpenBSD 7.9, on the box, for `tls_config_add_keypair_mem()` and
  `tls_config_verify_client_optional()`. https://man.openbsd.org/tls_load_file.3
- `pf.conf(5)`, OpenBSD 7.9, on the box, for `max-src-conn`, `max-src-conn-rate` and
  `overload`. https://man.openbsd.org/pf.conf.5
- `acme-client.conf(5)`, OpenBSD 7.9, on the box. https://man.openbsd.org/acme-client.conf.5
- Project Gemini network protocol specification, version 0.24.1, fetched from
  https://geminiprotocol.net/docs/protocol-specification.gmi (the older combined document at
  `/docs/specification.gmi` now redirects to the split versions). Quoted for status 10 and 11,
  the replacement rule, the URI limit, status 42, 43, 53 and 60, SNI, and TOFU.
- Client sources: Amfora `display/handlers.go`, `display/modals.go`, `client/tofu.go`,
  `client/client.go` and `config/config.go` from https://github.com/makew0rld/amfora (canonical
  owner; `makeworld-the-better-one` redirects); Lagrange `src/ui/documentwidget.c`,
  `src/ui/inputwidget.c`, `src/ui/util.c`, `src/gmcerts.c`, `src/gmrequest.c` and `po/en.po`
  from https://github.com/skyjake/lagrange, default branch `dev`; Kristall
  `src/protocols/geminiclient.cpp`, `src/browsertab.cpp`, `src/widgets/querydialog.cpp`,
  `querydialog.ui`, `src/ssltrust.cpp`, `src/mainwindow.cpp` and the bundled
  `src/error_page/MistrustedHost.gemini` and `UntrustedHost.gemini` from
  https://github.com/MasterQ32/kristall
- `acme-client(1)`, OpenBSD 7.9, on the box, for the one-third renewal rule.
  https://man.openbsd.org/acme-client.1
- Repo files read for the current shape and conventions: `openbsd/etc/gmid.conf`,
  `openbsd/etc/httpd.conf`, `openbsd/etc/acme-client.conf`, `openbsd/etc/newsyslog.conf`,
  `openbsd/etc/rc.d/kyriakon_encrypt`, `openbsd/etc/nsd/kyriakon.net.zone`,
  `scripts/pf-apply.sh`, `scripts/renew-acme.sh`, `docs/threat-model.md`, and the sister notes
  `docs/planning/research/openbsd-per-member-hosting.md` and
  `docs/planning/research/cert-issuance-ceiling.md`.
