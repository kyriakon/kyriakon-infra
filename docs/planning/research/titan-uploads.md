# Serving Titan uploads on the box (public release, signup capsule)

**Question:** the capsule's key page has to get a PGP public key from an applicant into the service.
A key pasted into a status 10 answer runs into gmid's 1024-byte request-line limit, which is why the
capsule spec's fallback is to mail the key to `apply@kyriakon.net`. Titan is the upload companion
protocol built for exactly this, and gmid ships only its client. This note settles what a Titan
request is, what gmid does with one, which servers implement the server side and which of those run
on OpenBSD 7.9, whether a client can reach a non-default port, and what `token` does in practice.

**Answer, in eight lines.** Titan is gemini's write companion on the same port, and it carries the
payload in the request body rather than the request line, so the 1024-byte ceiling that caps a
status 10 answer does not apply to the key. The request line is the target URL plus a mandatory
`;size=`, and optionally `;mime=`, which defaults to `text/gemini`, and `;token=`. gmid cannot serve
it: its server parses the first line as an IRI and answers any scheme other than `gemini` with
status 53 before the FastCGI dispatch, so no handler behind gmid ever sees a Titan request, and no
gmid release has added server-side Titan. `titan(1)` in the same package is a client. A Titan
endpoint beside gmid is therefore a second process on a second port, because two listeners cannot
split 1965 by protocol: the kernel chooses which socket accepts a connection, and the scheme only
appears in the first line after the handshake. The ready-made server is GmCapsule, which serves
gemini and Titan on one port, is packaged nowhere on OpenBSD and installs from pip; a handler of our
own is the other option. Lagrange reaches any port, by putting it in the `titan://` URL or by setting
it in the upload dialog, and that dialog also carries the token and MIME fields; gmid's `titan(1)`
honours a URL port too. `token` is an optional bearer capability whose format the specification
leaves undefined, and the server owns the check.

**Tested against versus read from sources.** An OpenBSD 7.9 host is reachable and was used:
`mail.kyriakon.net` (7.9 GENERIC.MP#11 amd64, `gmid-2.1.1p0`, gmid 2.1.1). The account is
unprivileged and needs a password for `doas`, so every command run on the box was read-only:
`uname -a`, `gmid -V`, `pkg_info`, `pkg_info -L gmid-2.1.1p0`, `command -v titan`, `netstat -anf
inet` for the listeners, `grep _gmid /etc/passwd`, `python3 -V`, `python3 -m pip --version`,
`python3 -m ensurepip --version`, `python3 -m venv --help`, `go version` and `cargo -V`. Nothing was
written, no daemon was signalled and no port was bound. Everything else comes from the specification
texts, from upstream source at the tag or commit named in each citation, and from first-party
documentation. Section "Not verified" lists what stayed documentary.

---

## 1. What a Titan request is

The canonical Titan specification is a gemini capsule, `gemini://transjovian.org/titan/`, and there
is no https copy of the text: `https://communitywiki.org/wiki/Titan` answers 402 and
`https://transjovian.org/titan/` answers 404 to a plain fetch. I read the specification page and its
two companions, every fetch on 2026-10-13, through the mozz.us gemini portal, which fetches the
capsule and renders it over https. The portal echoed the original gemini URL and the response
header `20 (Success), text/gemini` with each page, so what I read was a live fetch of the capsule
rather than a copy of it. gmid's own `titan(1)` man page points at the same URL under STANDARDS,
which is a second reason to trust the target.

### The request line

The specification opens the protocol with an example:

> Client and server do the usual TLS handshake and then the client sends the Titan URL:
>
>     titan://transjovian.org/test/raw/testing;size=123;mime=plain/text;token=hello\r\n

and continues, "After the Titan URL and the carriage return and linefeed the client sends the data
and the server replies with a regular Gemini status response." The parameters are not a query
string: "Parameters are not query parameters! There is no question mark after the URL. Parameters
are separated from the rest of the URL and each other using a semicolon and they come as key/value
pairs," which the specification grounds in RFC 3986 section 3.3. The same page says, "No other
parameters are used," so `size`, `mime` and `token` are the whole set the specification defines.

Of the three, `size` is mandatory ("a mandatory filesize in bytes so that the server knows when
you're done"), `mime` is optional and defaults to `text/gemini` ("If no MIME type is provided, the
server should assume text/gemini"), and `token` is optional. The `gemini-protocol` Rust crate
documents the same line, `<titan-url>;size=<n>[;mime=<type>][;token=<token>]\r\n`, in its `titan`
module. One extension exists in the wild and not in the specification: GmCapsule understands a
fourth parameter, `edit`, which turns the request into a gemini read of the same resource
(`gmcapsule/gemini.py`, `handle_gemini_or_titan_request()`, the `elif p == 'edit'` branch).

### Responses

The specification says the server "replies with a regular Gemini status response" and that "Any
Gemini response is possible". Its examples are `20 text/gemini; charset=UTF-8` followed by
`Upload succeeded.\n`, `30 titan://transjovian.org/test/testing` as a redirect to the updated
resource, and `50 Error writing file: some exception`. The validation section gives the refusal
example `50 A token is required to upload a file`. The gemini protocol specification groups the
codes: 10 to 19 are input, 20 to 29 success, 30 to 39 redirection, 40 to 49 temporary failure, 50 to
59 permanent failure and 60 to 69 client certificate required, and a client acts on the first digit
when it does not know the second. The Titan specification's history page records that its reference
implementation uses "59 error codes for them all" for its own validation failures, and GmCapsule
follows that: a Titan line with no `size=` is answered `59 Unspecified content length`, an
unrecognised parameter is `59 Invalid parameter`, content over the configured limit is `59 Maximum
content length exceeded`, a URL port that does not match the listening port is `59 Invalid port
number`, and an upload with no client certificate is `60` when the configuration requires one.

### A bare `titan://` navigation

The specification does not define a zero-byte upload on navigation. What it defines is a prompt:
"An interactive client following a Titan link or ending up at a Titan link following a redirect must
ignore all existing parameters, query the user and make the Titan request using the one, two or
three parameters provided by the user." The zero-byte form appears as deletion, not navigation:
"When the client wants to delete a resource, it uses the Titan protocol to send zero bytes of
content (size=0)."

The zero-byte upload on navigation is the convention of one client library, not the specification.
The `gemini-protocol` crate's `fetch` "sends a zero-byte upload" for a `titan://` URL and notes that
"the server typically replies with a redirect (`30`/`31`) to the read location or a failure". The
two clients I read behave differently again. Lagrange opens its upload dialog and sends nothing
until the user acts (`src/app.c`, the `titan` scheme branch at line 5218). GmCapsule rejects a Titan
request that carries no `size` with status 59, unless the client sent the `edit` parameter. So the
redirect on bare navigation is a server's choice and not a defined behaviour, and the ticket's
framing of "a zero-byte upload and a redirect" holds only for the Rust crate's convention.

### Ports

The specification text names one port, in its walkthrough ("Opens connection eg.
transjovian.org:1965"), and forbids none. The URL is an ordinary URI authority, so the port is
optional and the gemini specification supplies the default: "the port defaults to 1965 if not
specified". Every implementation I read honours a port in the URL. gmid's `titan(1)` dials
`dial(iri.host, iri.port)` (`titan.c` line 344) and defaults an empty port string to `"1965"`
(`titan.c` line 66). The `gemini-protocol` crate uses `url.port().unwrap_or(DEFAULT_PORT)`
(`titan.rs` line 76). GmCapsule requires the URL port to match the port it listens on, and answers
`59 Invalid port number` when a URL names a different one, which means a server on any port works as
long as the client names it (`gmcapsule/gemini.py`, the `url.port != None and url.port !=
worker.port` check). So a Titan URL may carry a port other than 1965 and the client connects to it;
the only requirement is that a server is listening there.

### `token`

The specification defines `token` and does not define its format. It lists the parameter as "token
for the answer to the security question (optional, but probably a good idea)", gives `hello` and
`hunter2` as examples, and files it under the question "Why a token?": "Use the token when anonymous
users can make changes on the server. If only known users can make changes, no token is required:
use the features Gemini already provides, client certificates." Its companion page states the
model plainly: "The Titan protocol only does authorization: you bear a token (the password) of
authorization. People can pass it on and invite other people to join," and "It's up to the server to
check the token. If the server doesn't check the token, then users don't have to send it. It's
optional." A token is therefore a bearer capability by design, with no defined length, encoding or
single-use rule.

## 2. What gmid does with a Titan request

The server never interprets one. In `server.c`, `client_read()` parses the first line as an IRI and
then checks the scheme:

```
	/* ignore the port number */
	if (strcmp(c->iri.schema, "gemini") ||
	    strcasecmp(c->domain, decoded)) {
		start_reply(c, PROXY_REFUSED, "won't proxy request");
		return;
	}
```

`server.c` line 1022, with `PROXY_REFUSED` defined as 53 at `gmid.h` line 70. A Titan request line
begins `titan://`, so the scheme comparison fails and gmid answers 53 and closes. It never reads the
body that follows the request line, and it does not treat `;size=` as a parameter. The FastCGI
handler is not reached either: `apply_fastcgi(c)` runs lower in the same function, at `server.c`
line 1030, and the scheme check returns before it. So a `fastcgi` block in a server block does not
give the handler a Titan request, because there is no way for one to get that far.

The 1024-byte line limit is separate and applies to every request: `if (EVBUFFER_LENGTH(src) > 1024 +
2)` answers `59` (`BAD_REQUEST`, `gmid.h` line 71) at `server.c` line 985. That is the limit behind
the capsule spec's warning on the key page.

`titan(1)`, listed in the package as `/usr/local/bin/titan` with `titan.1`, is a client. Its `main()`
requires the IRI scheme to be `titan` (`titan.c` line 308), builds the `;size=`, `;token=` and
`;mime=` suffix (`titan.c` lines 312 to 321), and dials the host and port from the URL (`titan.c`
line 344). The man page calls it "Titan client", documents `-m` for the MIME type and `-t` for the
token, and reads a file or standard input as the payload. It does not verify the server certificate
(`tls_config_insecure_noverifycert` in `titan.c`), and its CAVEATS section says it "doesn't perform
TOFU".

The changelog has no server-side Titan work. The only two entries that mention titan are
`2023-07-22 * titan.c (main): add titan(1), a simple titan client` and `2024-06-17 * titan.c
(open_input_file): improve error checking`. 2.1.1 is the newest tag on both mirrors (codeberg lists
2.1.1 dated 2024-08-25 as the top tag), so nothing landed after.

One detail matters for the port question below: gmid does set `SO_REUSEPORT` on its listening
sockets, in `config.c` `config_send_socks()` (function at line 239, the `setsockopt(sock,
SOL_SOCKET, SO_REUSEPORT, ...)` call at line 260). The port is therefore not held exclusively at the
bind level, which is not the same as being shareable in the way a Titan endpoint would need.

## 3. Which servers implement the server side, and which run on OpenBSD 7.9

The implementations I could verify from their own source or documentation:

- **GmCapsule** (Python, by Jaakko Keränen) is the fullest. Its page says, "The supported protocols
  are Gemini and Titan. Both are accepted via the same TCP port." `handle_gemini_or_titan_request()`
  in `gmcapsule/gemini.py` (line 345) branches on `request.startswith('titan:')`, splits the path on
  `;`, requires `size`, rejects an unknown parameter, enforces `[titan] upload_limit` (default 10
  MiB) and `[titan] require_identity` (default true, so a client certificate is required for an
  upload), and passes `token` straight to the handler. Its server binds `[server] port`, default
  1965, and reads certificates from `[server] certs`, one `cert.pem` and `key.pem` per host
  subdirectory (`gmcapsule/__init__.py`, `port()` at line 684 and `certs_dir()` at line 691). It
  needs Python 3.10 or later and installs from pip.
- **spacecat** (Node, by Geoff Kimball) advertises "Titan support, with middleware for token and
  certificate authentication". A route registered with `.put()` receives a Titan request whose
  fields are `url`, `cert`, `mime`, `token` and a `data` stream, which the README shows being piped
  to a file.
- **Phoebe** (Perl, by Alex Schroeder) is the implementation the specification grew out of; the Titan
  history page names it as the second of the author's server-side implementations. Perl is in
  OpenBSD base.

The servers that do not implement it:

- **Molly Brown** (Go) has no occurrence of "titan" in its source tree or its documentation.
- **gemserv** (Rust) does not mention Titan in its README.
- **jetforce** (Python) does not mention Titan in its README.

On OpenBSD 7.9, from the ports tree: `net/gmid` is the only gemini server. `net/lagrange`,
`net/amfora` and `net/kristall` are clients. None of GmCapsule, spacecat, Phoebe, Molly Brown,
gemserv or jetforce has a port, so any of them is a source or package-manager install. On the box,
`python3` is 3.13.14 with `venv` present and `ensurepip` reporting pip 26.1.2, `cargo` is 1.94.1,
and `go` is absent.

Two processes cannot usefully share port 1965. `bind(2)` on an address already in use fails with
`EADDRINUSE`, and the one way around that is `SO_REUSEPORT`, which OpenBSD's `setsockopt(2)`
describes as allowing "completely duplicate bindings by multiple processes if they all set
SO_REUSEPORT before binding the port". gmid sets it, so a second process could bind 1965; but the
two sockets would then share the incoming connection stream, and the kernel, not the protocol,
decides which listener accepts each connection. A gemini request and a Titan request look
identical at that point, because both are TLS on the same port and the scheme only appears in the
first line after the handshake. So sharing gives an arbitrary split of connections between the two
servers, not a way to send gemini to gmid and Titan to the handler. [INFERENCE] The intended split
needs a port of its own.

## 4. Pointing a client at a non-default port

Lagrange is the client that matters, and it reaches any port. Two paths exist in the interface:

- Navigating to a `titan://` URL opens the upload dialog (`src/app.c`, the `titan` scheme branch at
  line 5218), and the Page menu carries "Upload with Titan…" and "Edit Page with Titan…", which
  issue `document.upload` (`src/ui/root.c` lines 1776 and 1777, bound to Command-U and Command-E in
  `src/ui/keys.c` lines 259 and 260). A `spartan://` or `gemini://` page also offers the same
  command (`src/ui/documentwidget.c` line 3922).
- The dialog has a Port action. Its description is "Set the Titan server port to use for this URL.
  The port is saved in the site-specific configuration," under the heading "Titan Upload Port"
  (`po/en.po`, `upload.port`, `heading.uploadport` and `dlg.uploadport.msg`). The port resolution is
  `titanPortForUrl_` in `src/ui/uploadwidget.c` (line 827): the URL's port if it has one, otherwise
  the site-specific `titanPort`, otherwise 1965. `setUrlPort_UploadWidget_` (line 1081) writes the
  resolved port into the `titan://` URL that the request uses.

The dialog also carries the token field, whose hint is "see server's instructions"
(`hint.upload.token`), a MIME field, and a choice of pasted text or a chosen file. So an applicant
whose client refuses a long status 10 answer can be told to paste the key into the Titan dialog, or
to give the `titan://` URL with the port in it.

As a cross-check, gmid's own `titan(1)` is already on the box. It reads the payload from a file or
standard input, takes `-t` for the token and `-m` for the MIME type, dials the host and port from
the URL, and exits 2 when the response is not in the 2x or 3x range (`titan.1`). That is a second
client, on the same OpenBSD host, that reaches a non-default port, and it needs no interface
question because it is a command.

Of the other clients in OpenBSD ports, neither supports Titan: Amfora's README has no occurrence of
it, and Kristall's source has none at all. So the member who wants to upload rather than mail a key
needs Lagrange, or the `titan` command on the box.

## 5. What `token` does in practice

The specification leaves the token's format open and puts the check on the server. In practice the
servers I read treat it as an opaque string passed to the application:

- GmCapsule parses `token=` into the request's `content_token` and hands it to the route, or to a
  CGI program as `TITAN_TOKEN` (`gmcapsule/gemini.py`, the `content_token=req_token` call;
  `gmcapsule/__init__.py` line 496 lists `TITAN_TOKEN` among the CGI variables). GmCapsule itself
  never compares it. Its own gate for an upload is the client certificate, which it requires by
  default (`require_identity`).
- spacecat exposes the token on the Titan request object and offers middleware for token or
  certificate authentication, so the route decides.

So a server that ignores `token` must have some other gate, or it accepts anonymous writes, which is
the case the specification's author warns against: "On the Internet, it is probably a bad idea to
let anonymous users upload any file they want."

For a missing or unknown token the specification fixes no code. It gives one refusal example, `50 A
token is required to upload a file`, and lists "the token is invalid" among the errors a server may
detect, so the code is the server's choice within the gemini groups. GmCapsule, which does not check
tokens, answers nothing for a missing or unknown one and leaves the decision to the handler behind
it. Nothing in the specification or in the servers I read requires a particular length, a constant
time comparison, or single use.

## What an endpoint of our own would cost

This section is my reading of the sources above, not a decision.

gmid cannot be the endpoint, so a Titan endpoint is one more process beside it, and the cheapest
shape is a second server that speaks only the Titan side. The concrete parts:

- **Listener and port.** One new listening socket, on a port of its own, because 1965 cannot be
  split. A Titan URL then names the port, and every client that reaches it must either take the
  port from the URL or have it set per site, which Lagrange does in its upload dialog.
- **User.** A second unprivileged account, in the shape of `_gmid` (`_gmid` is uid 878 with home
  `/var/empty` and shell `/sbin/nologin` on the box), so a fault in the upload path cannot reach
  what gmid can reach.
- **Config and startup.** A second config file and a second `rc.d` script, since the endpoint is a
  separate process. If the endpoint is GmCapsule, that config is an ini file with `[server] port`,
  `[server] certs` and `[titan] upload_limit` and `require_identity`; if it is a handler of our own,
  the config is the size cap and the token check.
- **What it accepts.** A `titan://` line with `;size=`, an optional `;mime=`, and a `;token=`, then
  a body of exactly `size` bytes, capped by a configured limit (GmCapsule's default is 10 MiB). The
  accepted MIME types can be narrowed to `application/pgp-keys` or `text/plain` for this use, and
  everything else refused. The payload is in the body, so the 1024-byte ceiling never applies to the
  key; only the URL and its parameters must stay short, which they are.
- **Certificate.** The endpoint presents a certificate for `signup.kyriakon.net`, the same name the
  capsule uses, so the trust-on-first-use decision the applicant already made covers it. GmCapsule
  reads one certificate per host from its certs directory, so it needs the capsule key and
  certificate placed there.
- **The token check.** The endpoint mints, or the handler accepts, a token that is the draft's own
  random secret, and compares it in constant time. A missing or wrong token is refused with a 5x
  code in the gemini groups, and the endpoint never echoes the token. Because the specification
  treats the token as a bearer capability, the secret wants the same properties the draft token
  already has under the capsule spec: 128 random bits, carried only over TLS, and scoped to one
  draft.

The alternative shape is to replace gmid with GmCapsule, which serves gemini and Titan on one port
and so keeps 1965 and the existing URLs unchanged. That trades the config work of four server blocks
and a Python runtime in the place of a pledged C daemon for the second port, and it is the larger
change by far.

## Not verified

- No Titan client or server was run, on the box or elsewhere. Nothing was installed, no port was
  bound and no upload was sent, because the box is a live mail host and the account is unprivileged.
- `gmid -n` was not run against a Titan config, since gmid has no Titan directive to configure.
- The claim that two listeners on 1965 divide connections rather than routing them by protocol rests
  on the `setsockopt(2)` text and gmid's `SO_REUSEPORT` call, not on a test. A test would need two
  servers and a free port, and the box was left untouched.
- GmCapsule, spacecat and Phoebe were read from their source and documentation, not built or run.
  The OpenBSD availability claim is from the ports tree's `net/` and `www/` categories; a port under
  another category was not searched.
- Amfora and Kristall were checked for the absence of Titan by searching their source and
  documentation, not by running them.
- The mirror caveat stands: the specification text was read through a third-party https portal,
  because the canonical copy is a gemini capsule. The portal fetched it live and echoed the gemini
  status header, but the primary text itself was not read by a gemini client from the box.

## Sources

- The Titan specification, `gemini://transjovian.org/titan/The Titan Specification`, and its
  companions `Authentication & Authorisation` and `Titan history`, read 2026-10-13 through
  `https://portal.mozz.us/gemini/transjovian.org/titan/...`. The request-line form and example, the
  three parameters and their defaults, the `;` separator and the RFC 3986 grounding, the response
  examples, the validation example, the redirect rules, the creation and deletion sections, and the
  `size=0` deletion rule are quoted from these pages.
- gemini protocol specification 0.24.1, `protocol-specification.gmi`,
  `https://geminiprotocol.net/docs/protocol-specification.gmi`, read 2026-10-13. The port 1965
  default, the 1024-byte request limit and the status code groups are quoted from it.
- `gemini-protocol` crate 0.1.7, `titan.rs`, `https://docs.rs/gemini-protocol/0.1.7/src/gemini_protocol/titan.rs.html`,
  read 2026-10-13. The `fetch` zero-byte upload convention, the request-line builder, and
  `url.port().unwrap_or(DEFAULT_PORT)`.
- gmid 2.1.1 source, `https://raw.githubusercontent.com/omar-polo/gmid/2.1.1/`: `server.c`
  (`client_read()` at line 964, the `1024 + 2` check at line 985, the scheme check at line 1022),
  `gmid.h` (`PROXY_REFUSED 53`, `BAD_REQUEST 59`), `config.c` (`config_send_socks()` at line 239,
  `SO_REUSEPORT` at line 260), `titan.c` (default port at line 66, scheme check at line 308, the
  parameter builder at lines 312 to 321, the dial at line 344), `titan.1`, and `ChangeLog` (the two
  titan entries). The codeberg mirror (`https://codeberg.org/op/gmid`) confirms 2.1.1 as the newest
  tag, dated 2024-08-25.
- gmid 2.1.1p0 as installed on the box, and `openbsd/etc/gmid.conf` in this repository for `user
  "_gmid"`, `chroot "/home/www"` and the four existing server blocks on port 1965.
- GmCapsule, main branch at commit `b5dd5169` dated 2026-06-05,
  `https://codeberg.org/skyjake/gmcapsule`. `gmcapsule/gemini.py`
  (`handle_gemini_or_titan_request()` at line 345, the parameter parsing, the port check, the size
  check), `gmcapsule/__init__.py` (`port()` at line 684, `certs_dir()` at line 691,
  `max_upload_size()` at line 722, `require_upload_identity()` at line 725, and the `TITAN_TOKEN`
  CGI variable at line 496), `example.ini`, and the project page
  `https://gmi.skyjake.fi/gmcapsule/` for "Both are accepted via the same TCP port."
- spacecat, `https://github.com/gakimball/spacecat`, README read 2026-10-13, for the Titan route, the
  token and certificate middleware, and the `TitanRequest` fields.
- Jetforce, Molly Brown and gemserv READMEs and source, read 2026-10-13
  (`https://github.com/michael-lazar/jetforce`, `https://github.com/RobinBoers/molly-brown`,
  `https://github.com/calacuda/gemserv`), for the absence of Titan.
- Lagrange release branch at tag v1.21.2, commit `ffab25b2` dated 2026-09-30,
  `https://git.skyjake.fi/gemini/lagrange`. `src/app.c` line 5218, `src/ui/documentwidget.c` line
  3922, `src/ui/root.c` lines 1776 and 1777, `src/ui/keys.c` lines 259 and 260, `src/ui/uploadwidget.c`
  lines 827, 1081 and 1347, and `po/en.po` for `menu.page.upload`, `upload.port`, `heading.uploadport`
  and `dlg.uploadport.msg`.
- Amfora README (`https://github.com/makeworld-the-better-one/amfora`) and Kristall source
  (`https://github.com/masterQ32/kristall`), read 2026-10-13, both without Titan.
- OpenBSD ports tree, `net/` and `www/` category listings read 2026-10-13 through
  `https://cvsweb.openbsd.org/ports/net/` and `.../www/`, for `gmid`, `lagrange`, `amfora` and
  `kristall`.
- OpenBSD 7.9 man pages read through `https://man.openbsd.org/`: `bind(2)` for `EADDRINUSE` and
  `setsockopt(2)` for the `SO_REUSEPORT` text.
- OpenBSD 7.9 facts from the box, read 2026-10-13: `uname -a`, `gmid -V`, `pkg_info`, `pkg_info -L
  gmid-2.1.1p0`, `/etc/passwd` for `_gmid`, `netstat -anf inet` for the listeners, and `python3 -V`,
  `python3 -m ensurepip --version`, `go version` and `cargo -V` for what a second server could run
  on.
