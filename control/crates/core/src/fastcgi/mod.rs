//! The FastCGI responder: the wire both front-ends speak to reach the service.
//!
//! The service was an HTTP daemon on a loopback port with relayd in front. It is
//! a responder now, because httpd and gmid both speak FastCGI and neither needs a
//! second HTTP parser in the path: httpd reaches this responder over a unix socket
//! for the routes its vhost already served, and gmid over one of its own for the
//! capsule. The request arrives as a CGI environment rather than as an HTTP
//! request, and the reply is a CGI header block, so the pages above this module
//! are the same pages they were.
//!
//! The responder side of the wire, and the server that drives it: bind the unix
//! socket, take a bounded number of connections, read the parameters and the
//! body under a deadline, write the reply under the same deadline. That is what
//! the two front-ends on this box send and accept, and nothing more is
//! implemented, because a protocol implemented further than its peers need is a
//! protocol with untested paths.
//!
//! Three details of the wire are worth stating where the code can be read against
//! them.
//!
//! The manager and responder roles negotiate through `FCGI_BEGIN_REQUEST`, whose
//! flag byte carries "keep this connection" in bit 0. gmid sets it and httpd does
//! not, so the connection is closed when the flag is absent and read again when it
//! is present.
//!
//! Every record carries a request id, and gmid fails the connection on a record
//! whose id is not 1 (`fcgi_read()`, "got invalid client id"). Both front-ends
//! send 1, and the reply echoes the id it was sent rather than assuming that, so a
//! peer that numbers its requests differently still gets a reply it recognises.
//!
//! The parameters arrive as name and value pairs across one or more `FCGI_PARAMS`
//! records, each length written in one byte below 128 and in four bytes with the
//! high bit set above it. gmid always uses the four-byte form and httpd the short
//! one where it fits, so both are read.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

/// The descriptors the daemons may hold: the `daemon` login class gives them
/// `openfiles-cur=128`, and each listener's permit count is a slice of it.
pub const OPEN_FILES: usize = 128;

/// What the process keeps outside its listeners: the store's files, the config,
/// the log and the standard streams. The listener budgets must fit in what is
/// left.
pub const RESERVED_FILES: usize = 32;

/// How long the accept loop waits after an error it cannot attribute to a dead
/// connection. A full descriptor table (`EMFILE`, `ENFILE`) leaves the backlog
/// as ready as it was, so an unpaused retry would spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The version byte of the FastCGI specification this speaks. A record that does
/// not carry it is not a record this responder can read, so the connection fails
/// rather than being parsed on a guess.
const VERSION: u8 = 1;

const BEGIN_REQUEST: u8 = 1;
const ABORT_REQUEST: u8 = 2;
const END_REQUEST: u8 = 3;
const PARAMS: u8 = 4;
const STDIN: u8 = 5;
const STDOUT: u8 = 6;

/// The record header: version, type, request id, content length, padding length,
/// one reserved byte. Fixed, so the reader is a loop over fixed steps.
const HEADER: usize = 8;

/// The most one record's content can carry, which is what the two-byte length
/// field allows. A reply larger than this goes out as several records, and the
/// applicant page with a body's community block open is larger than this.
const MAX_CONTENT: usize = u16::MAX as usize;

/// The most the parameters of one request may occupy together. gmid bounds a
/// request line at 1024 bytes and httpd its headers, so this is far above anything
/// either sends and exists only to stop a peer that does not.
const MAX_PARAMS: usize = 64 * 1024;

/// One request, as the front-end built it.
pub struct Request {
    env: BTreeMap<String, String>,
    /// The request body, from the `FCGI_STDIN` records. Empty for every gemini
    /// request, which has no body at all, and the form post for the web's.
    pub body: Vec<u8>,
    /// Whether the body ran past the cap the caller set. The body stops at the
    /// first record that would cross it, so the connection must be closed after
    /// the refusal rather than read again.
    pub body_too_large: bool,
    /// Whether the front-end asked for the connection to stay open.
    pub keep_conn: bool,
    id: u16,
}

impl Request {
    /// A parameter as the front-end sent it, or `None` when it sent none.
    ///
    /// Presence is not meaning here. gmid sends `AUTH_TYPE` only with a client
    /// certificate and httpd sends `REMOTE_USER` only under HTTP authentication,
    /// so a caller that tests for a variable rather than for its value reads the
    /// same request two ways depending on which front-end answered it.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.env.get(name).map(String::as_str)
    }

    /// A parameter as a value, with the empty string for one that was not sent.
    /// This is the CGI reading: a variable that is absent and a variable sent
    /// empty mean the same thing to every reader above this module.
    pub fn value(&self, name: &str) -> &str {
        self.get(name).unwrap_or("")
    }

    /// The request id the reply is sent under.
    pub fn id(&self) -> u16 {
        self.id
    }
}

/// A FastCGI record that does not parse, or a socket read that failed.
#[derive(Debug)]
pub enum Error {
    /// The front end sent a record the protocol does not allow.
    Malformed(String),
    /// Reading a record from the socket failed.
    Io {
        what: &'static str,
        source: std::io::Error,
    },
    /// A failure whose context is the value the caller needs, with its source.
    Context {
        context: String,
        source: Box<crate::Source>,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Malformed(message) => f.write_str(message),
            Error::Io { what, source } => write!(f, "cannot {what}: {source}"),
            Error::Context { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Malformed(_) => None,
            Error::Io { source, .. } => Some(source),
            Error::Context { source, .. } => Some(source.as_ref()),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Error::Io {
            what: "read a record",
            source,
        }
    }
}

impl Error {
    pub fn context(context: impl Into<String>, source: impl Into<crate::Source>) -> Self {
        Error::Context {
            context: context.into(),
            source: Box::new(source.into()),
        }
    }
}

/// Read one request, or `None` when the peer closed between requests, which is how
/// both front-ends finish a connection.
///
/// `body_cap` is the most of a body the caller will accept. A record that would
/// cross it is not read to its end: the request comes back with `body_too_large`
/// and the connection must be closed after the refusal. Draining an unbounded
/// slow POST to find its terminator is what lets a stranger pin a task and a
/// descriptor, and a front-end that is refused the body has nothing left to say
/// on the connection.
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    body_cap: usize,
) -> Result<Option<Request>, Error> {
    let mut env_buf = Vec::new();
    let mut body = Vec::new();
    let mut keep_conn = false;
    let mut id = 0u16;
    let mut begun = false;

    loop {
        let mut header = [0u8; HEADER];
        match reader.read_exact(&mut header).await {
            Ok(_) => {}
            // The peer closed between requests, which is how both front-ends
            // finish a connection. Closing inside one is a truncated request
            // rather than a tidy end, and it is reported as that.
            Err(e) if e.kind() == ErrorKind::UnexpectedEof && !begun => return Ok(None),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                return Err(Error::Malformed(
                    "the connection ended inside a request".to_string(),
                ))
            }
            Err(e) => return Err(Error::context("cannot read a record header", e)),
        }
        if header[0] != VERSION {
            return Err(Error::Malformed(format!("record version {}", header[0])));
        }
        let kind = header[1];
        let record_id = u16::from_be_bytes([header[2], header[3]]);
        let len = u16::from_be_bytes([header[4], header[5]]) as usize;
        let padding = header[6] as usize;

        let mut content = vec![0u8; len + padding];
        reader
            .read_exact(&mut content)
            .await
            .map_err(|e| Error::context("cannot read a record body", e))?;
        content.truncate(len);

        if !begun && kind != BEGIN_REQUEST {
            return Err(Error::Malformed(
                "a record arrived before the request began".to_string(),
            ));
        }

        // One request per connection at a time, numbered by its begin record.
        // A record that carries another number belongs to a request this reader
        // is not in, and accepting it would merge two requests: the reply would
        // carry one request's id and the other's date.
        if begun && kind != BEGIN_REQUEST && record_id != id {
            return Err(Error::Malformed(format!(
                "record id {record_id} inside request {id}"
            )));
        }

        match kind {
            BEGIN_REQUEST => {
                if begun {
                    return Err(Error::Malformed(
                        "a second begin record inside one request".to_string(),
                    ));
                }
                if content.len() != 8 {
                    return Err(Error::Malformed(format!(
                        "a begin record of {} bytes",
                        content.len()
                    )));
                }
                // Role is big-endian in the first two bytes and is 1 for a
                // responder. Another role is another conversation, and this one
                // answers the responder's only.
                let role = u16::from_be_bytes([content[0], content[1]]);
                if role != 1 {
                    return Err(Error::Malformed(format!("role {role}")));
                }
                id = record_id;
                keep_conn = content[2] & 1 == 1;
                begun = true;
            }
            PARAMS => {
                if env_buf.len() + content.len() > MAX_PARAMS {
                    return Err(Error::Malformed(
                        "the parameters of one request are too long".to_string(),
                    ));
                }
                env_buf.extend_from_slice(&content);
            }
            STDIN => {
                if content.is_empty() {
                    break;
                }
                if body.len() + content.len() > body_cap {
                    // Stop reading here rather than draining the body: the rest
                    // of it may never arrive, and the connection is closed after
                    // the refusal below.
                    return Ok(Some(Request {
                        env: params(&env_buf)?,
                        body,
                        body_too_large: true,
                        keep_conn,
                        id,
                    }));
                }
                body.extend_from_slice(&content);
            }
            ABORT_REQUEST => {
                return Err(Error::Malformed(
                    "the front-end aborted the request".to_string(),
                ))
            }
            other => return Err(Error::Malformed(format!("record type {other}"))),
        }
    }

    Ok(Some(Request {
        env: params(&env_buf)?,
        body,
        body_too_large: false,
        keep_conn,
        id,
    }))
}

/// The parameters of one request, as name and value pairs.
///
/// A value that is not valid UTF-8 is replaced rather than refused. gmid decodes
/// the request path before it sends it, so a client can put a byte there that is
/// no UTF-8 at all, and a path that decodes to nonsense should miss the route
/// table rather than fail the request: the alternative is a way to make the
/// service log an error by asking for a file that does not exist.
type Params = BTreeMap<String, String>;

fn params(buf: &[u8]) -> Result<Params, Error> {
    let mut out = BTreeMap::new();
    let mut i = 0usize;
    while i < buf.len() {
        let name_len = length(buf, &mut i)?;
        let value_len = length(buf, &mut i)?;
        if name_len + value_len > buf.len() - i {
            return Err(Error::Malformed(
                "a parameter runs past the end of its record".to_string(),
            ));
        }
        let name = String::from_utf8_lossy(&buf[i..i + name_len]).into_owned();
        let value =
            String::from_utf8_lossy(&buf[i + name_len..i + name_len + value_len]).into_owned();
        i += name_len + value_len;
        out.insert(name, value);
    }
    Ok(out)
}

/// One length field: a byte below 128, four bytes with the high bit of the first
/// set above it.
fn length(buf: &[u8], i: &mut usize) -> Result<usize, Error> {
    let first = *buf
        .get(*i)
        .ok_or_else(|| Error::Malformed("a parameter record ends inside a length".to_string()))?;
    if first & 0x80 == 0 {
        *i += 1;
        return Ok(first as usize);
    }
    let four = buf
        .get(*i..*i + 4)
        .ok_or_else(|| Error::Malformed("a parameter record ends inside a length".to_string()))?;
    *i += 4;
    Ok(u32::from_be_bytes([four[0] & 0x7f, four[1], four[2], four[3]]) as usize)
}

/// What a front-end reads back: the header block, a blank line, the body.
pub enum Reply {
    /// httpd's reply, which is a CGI header block: a status line, then the headers
    /// the page carries. httpd validates the code against its own table and
    /// silently serves 200 for one that table does not carry, so only codes it
    /// carries are ever sent, and `reason` is that table's own spelling.
    Http(Http),
    /// gmid's reply, which is gemini's: two digits, a space, the META, CRLF, then
    /// the body. gmid passes a 2x status through and fails the connection on a
    /// malformed header, so the status is the status and never a line in the body.
    Gemini {
        status: u8,
        meta: String,
        body: Vec<u8>,
    },
}

/// A reply the web front-end reads. It is its own type so a header can only be
/// added to the reply that carries headers: a gemini reply has no method for one,
/// rather than a header silently dropped.
pub struct Http {
    status: u16,
    headers: Vec<(String, String)>,
    /// Bytes rather than a `String`: the web form's pages are text, and a
    /// member's file is whatever the member uploaded.
    body: Vec<u8>,
}

impl Http {
    /// A 303 to `location`, which is what a login and a logout answer with. It
    /// is a capability in a cookie, so it carries the capability page's headers
    /// too; the caller adds the cookie header its answer needs.
    pub fn redirect(location: &str) -> Http {
        Http {
            status: 303,
            headers: vec![
                (
                    "Content-Type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                ),
                ("Cache-Control".to_string(), "no-store".to_string()),
                ("Referrer-Policy".to_string(), "no-referrer".to_string()),
                (
                    "Content-Security-Policy".to_string(),
                    CONTENT_SECURITY_POLICY.to_string(),
                ),
                ("Location".to_string(), location.to_string()),
            ],
            body: Vec::new(),
        }
    }

    /// A file's bytes and the type its name announces. A header can be added
    /// with `with_header`, which is how a change time reaches the reply.
    pub fn file(status: u16, media: &str, body: Vec<u8>) -> Http {
        Http {
            status,
            headers: vec![("Content-Type".to_string(), media.to_string())],
            body,
        }
    }

    /// A 301 to `location`, for a directory asked for without its trailing
    /// separator: a browser resolves a relative link against the URL, so serving
    /// `sub/index.html` at `/sub` sends every request for a sibling of that page
    /// to the wrong place.
    pub fn moved(location: &str) -> Http {
        Http {
            status: 301,
            headers: vec![
                (
                    "Content-Type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                ),
                ("Location".to_string(), location.to_string()),
            ],
            body: Vec::new(),
        }
    }

    /// The same reply with one header added, for a `Set-Cookie` or a
    /// `Location`.
    pub fn with_header(mut self, name: &str, value: String) -> Http {
        self.headers.push((name.to_string(), value));
        self
    }
}

/// Every HTML reply's policy. The pages carry one inline stylesheet and no
/// script, so the inline style allowance is the whole of what they need; the
/// frame refusal is what stops a hostile page overlaying a one-click control on
/// one of them, and the handler is the only place it can be added because
/// OpenBSD's httpd has no header-rewrite directive.
const CONTENT_SECURITY_POLICY: &str = concat!(
    "default-src 'none'; style-src 'unsafe-inline'; ",
    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
);

impl Reply {
    /// An HTML page, which is every page the web form renders.
    pub fn html(status: u16, body: String) -> Reply {
        Reply::Http(Http {
            status,
            headers: vec![
                (
                    "Content-Type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                ),
                (
                    "Content-Security-Policy".to_string(),
                    CONTENT_SECURITY_POLICY.to_string(),
                ),
            ],
            body: body.into_bytes(),
        })
    }

    /// A page that carries a capability in its URL, or is a capability itself:
    /// never stored, and its URL never sent as a referrer.
    pub fn capability(status: u16, body: String) -> Reply {
        Reply::Http(Http {
            status,
            headers: vec![
                (
                    "Content-Type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                ),
                ("Cache-Control".to_string(), "no-store".to_string()),
                ("Referrer-Policy".to_string(), "no-referrer".to_string()),
                (
                    "Content-Security-Policy".to_string(),
                    CONTENT_SECURITY_POLICY.to_string(),
                ),
            ],
            body: body.into_bytes(),
        })
    }

    /// A gemini page. The body is anything that converts to bytes, so a capsule
    /// page passes the `String` it built and a member's file passes the bytes it
    /// read.
    pub fn gemini(status: u8, meta: &str, body: impl Into<Vec<u8>>) -> Reply {
        Reply::Gemini {
            status,
            meta: meta.to_string(),
            body: body.into(),
        }
    }

    /// A file the member published: its bytes and the type its name announces,
    /// under the status the resolver's answer calls for.
    ///
    /// No policy headers: the bytes are the member's page, not one of ours, and
    /// the only header this server has an opinion about is the one that decides
    /// whether it renders or downloads.
    pub fn file(status: u16, media: &str, body: Vec<u8>) -> Reply {
        Reply::Http(Http::file(status, media, body))
    }

    /// The code this reply answers with, for the log line.
    pub fn code(&self) -> u16 {
        match self {
            Reply::Http(http) => http.status,
            Reply::Gemini { status, .. } => u16::from(*status),
        }
    }

    /// The header block and the body, with the blank line between them. The blank
    /// line is not optional for either front-end: httpd reads headers until it,
    /// and gmid reads its reply header as the first CRLF-terminated line, so
    /// without it a gemini client would be shown the rest of the headers.
    ///
    /// The Titan listener writes this straight to its socket: there is no front-end
    /// between the handler and the client there, so gemini's framing is the wire
    /// format.
    pub fn head(&self) -> Vec<u8> {
        let mut out = self.head_block();
        out.extend_from_slice(self.body());
        out
    }

    /// The header block alone: the status line, the headers, the blank line.
    /// A file reply writes this and then streams the bytes, and a `HEAD` answer
    /// is this and nothing else.
    pub fn head_block(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Reply::Http(http) => {
                out.extend_from_slice(
                    format!("Status: {} {}\r\n", http.status, reason(http.status)).as_bytes(),
                );
                for (name, value) in &http.headers {
                    out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
                }
                out.extend_from_slice(b"\r\n");
            }
            Reply::Gemini { status, meta, .. } => {
                out.extend_from_slice(format!("{status} {meta}\r\n").as_bytes());
            }
        }
        out
    }

    /// The body bytes. Empty only for the replies a file is written after,
    /// whose bytes are streamed rather than held.
    pub fn body(&self) -> &[u8] {
        match self {
            Reply::Http(http) => &http.body,
            Reply::Gemini { body, .. } => body,
        }
    }
}

/// Where a reply's body comes from when it is written.
pub enum Body<'a> {
    /// Bytes already in memory.
    Bytes(&'a [u8]),
    /// A file read as it is written. A member's upload costs one buffer here
    /// rather than one whole file per in-flight request, and both front-ends
    /// take the body into their own buffer anyway, so a copy here would double
    /// what one download costs. A file shorter than the announced length is an
    /// error, not a short reply: the end marker is never sent for a body the
    /// front-end would take as complete ([#913]).
    ///
    /// [#913]: https://github.com/kyriakon/kyriakon-infra/issues/913
    File(&'a mut tokio::fs::File, u64),
}

/// Write a reply to the front-end: the header block as stdout records, the body,
/// then the end marker. The header block is never empty, which matters: httpd
/// aborts a request whose first stdout record is empty ("empty stdout",
/// server_fcgi.c), and gmid waits for a header it would then never see.
pub async fn write_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    head: &[u8],
    body: Body<'_>,
    id: u16,
) -> std::io::Result<()> {
    for chunk in head.chunks(MAX_CONTENT) {
        put_record(writer, STDOUT, id, chunk).await?;
    }
    match body {
        Body::Bytes(bytes) => {
            for chunk in bytes.chunks(MAX_CONTENT) {
                put_record(writer, STDOUT, id, chunk).await?;
            }
        }
        Body::File(file, len) => {
            // One record's content, not a round number: the length field is two
            // bytes, so 64 KiB would wrap to zero.
            let mut buf = vec![0u8; MAX_CONTENT];
            let mut left = len;
            while left > 0 {
                let want = (buf.len() as u64).min(left) as usize;
                let read = file.read(&mut buf[..want]).await?;
                if read == 0 {
                    // The file shrank after its length was taken. Ending here
                    // would send a shorter body under a length the front-end
                    // already accepted, which is a truncation presented as a
                    // complete answer.
                    return Err(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "the file ended before the length it was announced with",
                    ));
                }
                left -= read as u64;
                put_record(writer, STDOUT, id, &buf[..read]).await?;
            }
        }
    }
    put_record(writer, END_REQUEST, id, &[0; 8]).await?;
    writer.flush().await
}

/// One record, written header then content: the bytes go straight to the socket
/// rather than through a buffer the size of the chunk, so streaming a file costs
/// the read buffer and nothing else.
async fn put_record<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: u8,
    id: u16,
    content: &[u8],
) -> std::io::Result<()> {
    let mut header = [0u8; HEADER];
    header[0] = VERSION;
    header[1] = kind;
    header[2..4].copy_from_slice(&id.to_be_bytes());
    header[4..6].copy_from_slice(&(content.len() as u16).to_be_bytes());
    writer.write_all(&header).await?;
    if !content.is_empty() {
        writer.write_all(content).await?;
    }
    Ok(())
}

/// What one listener may serve, and for how long.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Requests served at once on this listener. Each one holds a descriptor,
    /// so the four listeners' counts must fit in the login class's file table.
    pub connections: usize,
    /// The longest one connection may take, from accept to its last byte. It
    /// bounds both the request read and the reply write, so a peer that stalls
    /// either half is gone by it.
    pub deadline: Duration,
    /// The most of a request body this listener accepts.
    pub body_cap: usize,
}

/// One request's answer: a reply already in memory, or a member's file streamed
/// behind its header block.
pub enum Answer {
    Reply(Reply),
    /// A file whose bytes are written as they are read.
    File {
        head: Vec<u8>,
        file: tokio::fs::File,
        len: u64,
        code: u16,
    },
}

impl Answer {
    /// The status this answer carries, for a log line.
    pub fn code(&self) -> u16 {
        match self {
            Answer::Reply(reply) => reply.code(),
            Answer::File { code, .. } => *code,
        }
    }

    /// Write the answer, end marker included, to one front-end.
    pub async fn write_to<W: AsyncWrite + Unpin>(
        self,
        writer: &mut W,
        id: u16,
    ) -> std::io::Result<()> {
        match self {
            Answer::Reply(reply) => {
                let head = reply.head_block();
                write_reply(writer, &head, Body::Bytes(reply.body()), id).await
            }
            Answer::File {
                head,
                mut file,
                len,
                ..
            } => write_reply(writer, &head, Body::File(&mut file, len), id).await,
        }
    }
}

/// Bind `path`, replacing whatever a previous run left there, with mode 0660 so
/// the socket directory's group decides who may connect. A socket file outlives
/// the process that made it, so a restart after a crash would otherwise fail to
/// bind until somebody removed it by hand. `symlink_metadata` makes a dangling
/// symlink a file to clear rather than the `ENOENT` a following `metadata`
/// reports, and `remove_file` unlinks the symlink itself, never its target.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => std::fs::remove_file(path)?,
        Err(source) if source.kind() == ErrorKind::NotFound => {}
        Err(source) => return Err(source),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// Accept connections until the listener fails, bounding how many are served at
/// once and how long each may take. A refusal is answered by `answer`, which
/// receives the parsed request.
///
/// The permit is taken before the task is spawned, so a flood costs the
/// listening backlog and one accepted socket rather than a task and a descriptor
/// per waiting connection.
pub async fn serve<F, Fut>(path: &Path, limits: Limits, answer: F) -> std::io::Result<()>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Answer> + Send + 'static,
{
    let listener = bind(path)?;
    let answer = Arc::new(answer);
    let body_cap = limits.body_cap;
    accept(
        listener,
        limits.connections,
        limits.deadline,
        "front-end",
        move |stream| {
            let answer = answer.clone();
            async move {
                if let Err(error) = connection(stream, body_cap, &*answer).await {
                    crate::util::log(&format!(
                        "kyriakon-control: the fastcgi connection failed: {error}"
                    ));
                }
            }
        },
    )
    .await
}

/// Serve a Unix listener at `connections` at a time, each for at most
/// `deadline`, until the listener cannot accept. `name` is the word the timeout
/// line carries.
///
/// An accept error is a connection a flood provoked, not the listener:
/// returning it would cancel the process's other listeners, so the loop reports,
/// waits and continues. Errors inside one connection are the closure's to log.
pub async fn accept<F, Fut>(
    listener: UnixListener,
    connections: usize,
    deadline: Duration,
    name: &'static str,
    served: F,
) -> std::io::Result<()>
where
    F: Fn(UnixStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let slots = Arc::new(Semaphore::new(connections));
    let served = Arc::new(served);
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                let wait = match error.kind() {
                    ErrorKind::ConnectionAborted | ErrorKind::Interrupted => Duration::ZERO,
                    _ => ACCEPT_BACKOFF,
                };
                crate::util::log(&format!(
                    "kyriakon-control: cannot accept a {name} connection: {error}"
                ));
                tokio::time::sleep(wait).await;
                continue;
            }
        };
        let permit = match slots.clone().acquire_owned().await {
            Ok(permit) => permit,
            // The semaphore is never closed while the process lives.
            Err(_) => return Ok(()),
        };
        let served = served.clone();
        tokio::spawn(async move {
            // Held for as long as this connection is served.
            let _permit = permit;
            if tokio::time::timeout(deadline, served(stream))
                .await
                .is_err()
            {
                crate::util::log(&format!(
                    "kyriakon-control: the {name} connection timed out"
                ));
            }
        });
    }
}

/// Answer the requests on one connection. Both front-ends connect for one
/// request and close, and gmid asks for the connection to be kept in case it has
/// another, so the loop runs until the peer closes, the request is refused for
/// its body, or a record cannot be read.
async fn connection<F, Fut>(stream: UnixStream, body_cap: usize, answer: &F) -> Result<(), Error>
where
    F: Fn(Request) -> Fut,
    Fut: Future<Output = Answer>,
{
    let (mut reader, mut writer) = stream.into_split();
    loop {
        let request = match read_request(&mut reader, body_cap).await? {
            Some(request) => request,
            None => return Ok(()),
        };
        let id = request.id();
        let keep_conn = request.keep_conn;
        // The body was not read to its end, so the bytes still on the socket
        // belong to a request that is already refused: answer once and close.
        let refused = request.body_too_large;
        answer(request)
            .await
            .write_to(&mut writer, id)
            .await
            .map_err(|source| Error::Io {
                what: "write the reply",
                source,
            })?;
        if refused || !keep_conn {
            return Ok(());
        }
    }
}

/// The reason phrase for a status, in httpd's own table's spelling so the two
/// agree if anyone compares them. httpd drops it and writes its own, and gmid
/// never reads one, so this exists for the reader of the bytes.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        303 => "See Other",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "",
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixture {
    //! Requests as the two front-ends write them, for the tests of what reads
    //! them. The responder's check sends a request the way httpd and gmid send
    //! one, so the bytes are built once, here, rather than in each test that
    //! needs a request.

    use super::{BEGIN_REQUEST, END_REQUEST, PARAMS, STDIN, STDOUT, VERSION};

    /// One record, with the request id and type given, which is what a test that
    /// is deliberately sending something malformed needs.
    pub fn raw(id: u16, kind: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![VERSION, kind];
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.push(0);
        out.push(0);
        out.extend_from_slice(content);
        out
    }

    /// One record of a well-formed request.
    fn record(kind: u8, id: u16, content: &[u8]) -> Vec<u8> {
        raw(id, kind, content)
    }

    /// One parameter in the four-byte length form, which is the form gmid always
    /// writes: the two lengths first, then the name and the value.
    fn param_long(out: &mut Vec<u8>, name: &str, value: &str) {
        for n in [name.len() as u32, value.len() as u32] {
            out.extend_from_slice(&[
                ((n >> 24) as u8) | 0x80,
                (n >> 16) as u8,
                (n >> 8) as u8,
                n as u8,
            ]);
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(value.as_bytes());
    }

    /// One parameter in the one-byte form, which is what httpd writes where it
    /// fits.
    fn param_short(out: &mut Vec<u8>, name: &str, value: &str) {
        out.push(name.len() as u8);
        out.push(value.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(value.as_bytes());
    }

    /// A request as httpd sends one: the responder role, no keep-connection flag,
    /// the short length form, and the body in stdin records.
    pub fn httpd(env: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut out = record(BEGIN_REQUEST, 1, &[0, 1, 0, 0, 0, 0, 0, 0]);
        let mut params = Vec::new();
        // httpd always sends the method (server_fcgi.c); the tests that care
        // about another one pass it themselves.
        if !env.iter().any(|(name, _)| *name == "REQUEST_METHOD") {
            param_short(&mut params, "REQUEST_METHOD", "GET");
        }
        for (name, value) in env {
            param_short(&mut params, name, value);
        }
        out.extend(record(PARAMS, 1, &params));
        out.extend(record(PARAMS, 1, &[]));
        // A record's content length is two bytes, so a body larger than that
        // goes out as several, as a front-end's own writer does.
        for chunk in body.chunks(u16::MAX as usize) {
            out.extend(record(STDIN, 1, chunk));
        }
        out.extend(record(STDIN, 1, &[]));
        out
    }

    /// A request as gmid sends one: the responder role, the keep-connection flag,
    /// the four-byte length form, and no body, because a gemini request has none.
    pub fn gmid(env: &[(&str, &str)]) -> Vec<u8> {
        let mut out = record(BEGIN_REQUEST, 1, &[0, 1, 1, 0, 0, 0, 0, 0]);
        let mut params = Vec::new();
        // gmid hardcodes GET (fcgi.c).
        if !env.iter().any(|(name, _)| *name == "REQUEST_METHOD") {
            param_long(&mut params, "REQUEST_METHOD", "GET");
        }
        for (name, value) in env {
            param_long(&mut params, name, value);
        }
        out.extend(record(PARAMS, 1, &params));
        out.extend(record(PARAMS, 1, &[]));
        out.extend(record(STDIN, 1, &[]));
        out
    }

    /// The bytes a front-end reads out of a reply: the stdout records'
    /// contents, concatenated, which is the header block and the body, and the
    /// end marker's type as the last thing in the stream.
    pub fn reply(bytes: &[u8]) -> (Vec<u8>, u8) {
        let mut body = Vec::new();
        let mut at = 0;
        let mut last = 0;
        while at < bytes.len() {
            assert_eq!(bytes[at], VERSION, "every record carries the version");
            let kind = bytes[at + 1];
            let len = u16::from_be_bytes([bytes[at + 4], bytes[at + 5]]) as usize;
            if kind == STDOUT {
                body.extend_from_slice(&bytes[at + 8..at + 8 + len]);
            }
            last = kind;
            at += 8 + len;
        }
        (body, last)
    }

    /// The end marker's type, so a test can say a reply was finished rather than
    /// truncated.
    pub const END: u8 = END_REQUEST;
}

#[cfg(test)]
mod tests {
    use super::fixture::{self, END};
    use super::*;

    /// One record, for the tests that build a stream by hand.
    fn record(kind: u8, id: u16, content: &[u8]) -> Vec<u8> {
        fixture::raw(id, kind, content)
    }

    /// A reply as the front-end reads it.
    async fn wire(reply: Reply, id: u16) -> Vec<u8> {
        let mut out = Vec::new();
        Answer::Reply(reply).write_to(&mut out, id).await.unwrap();
        out
    }

    /// One request at a time: a second begin record would merge two requests,
    /// and a record carrying another number belongs to one this reader is not
    /// in.
    #[tokio::test]
    async fn a_second_begin_or_a_foreign_id_is_refused() {
        let begin = |id: u16| record(BEGIN_REQUEST, id, &[0, 1, 0, 0, 0, 0, 0, 0]);

        let mut merged = begin(1);
        merged.extend(begin(2));
        assert!(read_request(&mut &merged[..], 1024).await.is_err());

        let mut foreign = begin(1);
        foreign.extend(record(PARAMS, 9, b""));
        assert!(read_request(&mut &foreign[..], 1024).await.is_err());

        // The same stream with the right id is a request.
        let mut fine = begin(1);
        fine.extend(record(PARAMS, 1, b""));
        fine.extend(record(STDIN, 1, b""));
        fine.extend(record(STDIN, 1, b""));
        assert!(read_request(&mut &fine[..], 1024).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn a_request_reads_its_parameters_in_either_length_form() {
        // gmid's four-byte form and the keep-connection flag.
        let request = read_request(
            &mut &fixture::gmid(&[("GEMINI_URL_PATH", "status/x")])[..],
            1024,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(request.value("GEMINI_URL_PATH"), "status/x");
        assert_eq!(
            request.value("SERVER_NAME"),
            "",
            "an absent parameter is empty"
        );
        assert!(request.get("SERVER_NAME").is_none());
        assert!(request.keep_conn);
        assert_eq!(request.id(), 1);
        assert!(request.body.is_empty());

        // httpd's short form, no keep-connection flag, and a body.
        let request = read_request(
            &mut &fixture::httpd(&[("REQUEST_URI", "/")], b"username=theophilus")[..],
            1024,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(request.value("REQUEST_URI"), "/");
        assert_eq!(request.body, b"username=theophilus");
        assert!(!request.keep_conn, "httpd does not ask for the connection");
    }

    #[tokio::test]
    async fn a_body_over_the_cap_is_reported_rather_than_dropped() {
        let bytes = fixture::httpd(&[], b"username=theophilus");
        let request = read_request(&mut &bytes[..], 4).await.unwrap().unwrap();
        assert!(request.body_too_large);
    }

    #[tokio::test]
    async fn a_closed_connection_between_requests_is_not_an_error() {
        let mut empty: &[u8] = &[];
        assert!(read_request(&mut empty, 1024).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_malformed_request_fails_rather_than_being_guessed_at() {
        // A record before the request began.
        assert!(read_request(&mut &fixture::raw(0, PARAMS, &[])[..], 1024)
            .await
            .is_err());

        // A truncated length.
        let mut buf = fixture::raw(0, BEGIN_REQUEST, &[0, 1, 0, 0, 0, 0, 0, 0]);
        buf.extend(fixture::raw(0, PARAMS, &[0x80]));
        assert!(read_request(&mut &buf[..], 1024).await.is_err());

        // A parameter that runs past its record.
        let mut buf = fixture::raw(0, BEGIN_REQUEST, &[0, 1, 0, 0, 0, 0, 0, 0]);
        buf.extend(fixture::raw(0, PARAMS, &[9, 1, b'a']));
        assert!(read_request(&mut &buf[..], 1024).await.is_err());

        // The wrong version byte.
        let mut buf = fixture::raw(0, BEGIN_REQUEST, &[0, 1, 0, 0, 0, 0, 0, 0]);
        buf[0] = 2;
        assert!(read_request(&mut &buf[..], 1024).await.is_err());

        // The authorizer role rather than the responder's.
        let buf = fixture::raw(0, BEGIN_REQUEST, &[0, 2, 0, 0, 0, 0, 0, 0]);
        assert!(read_request(&mut &buf[..], 1024).await.is_err());

        // An abort.
        let mut buf = fixture::raw(0, BEGIN_REQUEST, &[0, 1, 0, 0, 0, 0, 0, 0]);
        buf.extend(fixture::raw(0, ABORT_REQUEST, &[]));
        assert!(read_request(&mut &buf[..], 1024).await.is_err());
    }

    #[tokio::test]
    async fn a_gemini_reply_is_the_header_the_body_and_the_end_marker() {
        let bytes = wire(Reply::gemini(20, "text/gemini", "# hello\n"), 1).await;
        let (body, last) = fixture::reply(&bytes);
        assert_eq!(last, END, "the reply is finished, not truncated");
        assert_eq!(body, b"20 text/gemini\r\n# hello\n");
    }

    #[tokio::test]
    async fn an_http_reply_carries_the_status_the_headers_and_the_body() {
        let bytes = wire(Reply::capability(422, "<p>no</p>".into()), 1).await;
        let (body, last) = fixture::reply(&bytes);
        assert_eq!(last, END);
        let text = String::from_utf8(body).unwrap();
        assert!(
            text.starts_with("Status: 422 Unprocessable Content\r\n"),
            "{text}"
        );
        assert!(text.contains("Cache-Control: no-store\r\n"), "{text}");
        assert!(text.ends_with("\r\n\r\n<p>no</p>"), "{text}");
    }

    /// Every HTML reply carries the policy, including the bare error and refusal
    /// pages a caller answers with no body.
    #[tokio::test]
    async fn every_html_reply_carries_the_content_security_policy() {
        for reply in [
            Reply::html(200, "<p>page</p>".into()),
            Reply::html(404, String::new()),
            Reply::capability(200, "<p>page</p>".into()),
            Reply::Http(Http::redirect("/account")),
        ] {
            let bytes = wire(reply, 1).await;
            let (body, _) = fixture::reply(&bytes);
            let text = String::from_utf8(body).unwrap();
            assert!(
                text.contains(
                    "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'\r\n"
                ),
                "{text}"
            );
        }
    }

    #[tokio::test]
    async fn a_page_larger_than_one_record_goes_out_as_several() {
        let body = "x".repeat(MAX_CONTENT + 10);
        let bytes = wire(Reply::html(200, body), 1).await;
        let mut at = 0;
        let mut stdout = 0;
        while at < bytes.len() {
            let kind = bytes[at + 1];
            let len = u16::from_be_bytes([bytes[at + 4], bytes[at + 5]]) as usize;
            if kind == STDOUT {
                stdout += 1;
                assert!(
                    len <= MAX_CONTENT,
                    "no record is longer than the field allows"
                );
            } else {
                assert_eq!(kind, END_REQUEST);
                assert_eq!(len, 8);
            }
            at += HEADER + len;
        }
        assert_eq!(
            stdout, 3,
            "the header block and the body over two more records"
        );
    }

    /// A directory with a socket path of its own, so each test's listener cannot
    /// collide with another's.
    fn temp_socket(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "kyriakon-fastcgi-{}-{name}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.sock");
        (dir, path)
    }

    fn spawn_server<F, Fut>(
        path: std::path::PathBuf,
        limits: Limits,
        answer: F,
    ) -> tokio::task::JoinHandle<std::io::Result<()>>
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Answer> + Send + 'static,
    {
        tokio::spawn(async move { serve(&path, limits, answer).await })
    }
    /// Wait until the listener's path exists. `serve` binds before its first
    /// await, and the wait yields so its task runs.
    async fn wait_for(path: &Path) {
        for _ in 0..400 {
            if path.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the server did not bind {}", path.display());
    }

    /// One request over a socket, read to the reply's end.
    async fn round_trip(path: &Path, bytes: &[u8]) -> Vec<u8> {
        let mut stream = UnixStream::connect(path).await.unwrap();
        stream.write_all(bytes).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        out
    }

    /// A slow POST against a listener with no body budget is refused on its
    /// first body record, not after a terminator the client may never send, and
    /// its permit is free again by the time the reply is read.
    #[tokio::test]
    async fn a_body_over_the_cap_is_refused_without_waiting_or_holding_a_permit() {
        let (_dir, path) = temp_socket("body-cap");
        let server = spawn_server(
            path.clone(),
            Limits {
                connections: 1,
                deadline: Duration::from_secs(5),
                body_cap: 0,
            },
            |_request| async { Answer::Reply(Reply::html(413, String::new())) },
        );
        wait_for(&path).await;

        let mut first = UnixStream::connect(&path).await.unwrap();
        let mut partial = fixture::raw(1, BEGIN_REQUEST, &[0, 1, 0, 0, 0, 0, 0, 0]);
        partial.extend(fixture::raw(1, PARAMS, &[]));
        partial.extend(fixture::raw(1, STDIN, b"x"));
        first.write_all(&partial).await.unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), first.read_to_end(&mut reply))
            .await
            .expect("the refusal arrives without the body's terminator")
            .unwrap();
        assert_eq!(fixture::reply(&reply).1, END, "the refusal is complete");

        // The single permit was released: the next request is answered.
        let second = round_trip(&path, &fixture::httpd(&[], b"")).await;
        assert_eq!(fixture::reply(&second).1, END);
        server.abort();
    }

    /// A file truncated after its length was taken never gets the end marker,
    /// so the front-end cannot read a short body as a complete reply.
    #[tokio::test]
    async fn a_file_truncated_mid_stream_does_not_emit_the_end_marker() {
        let (_dir, path) = temp_socket("truncated");
        let file_path = path.with_extension("body");
        std::fs::write(&file_path, b"0123456789").unwrap();

        let server = spawn_server(
            path.clone(),
            Limits {
                connections: 1,
                deadline: Duration::from_secs(5),
                body_cap: 0,
            },
            move |_request| {
                let file_path = file_path.clone();
                async move {
                    let file = tokio::fs::File::open(&file_path).await.unwrap();
                    let head =
                        Reply::file(200, "application/octet-stream", Vec::new()).head_block();
                    Answer::File {
                        head,
                        file,
                        len: 1000,
                        code: 200,
                    }
                }
            },
        );
        wait_for(&path).await;

        let bytes = round_trip(&path, &fixture::httpd(&[("REQUEST_URI", "/file.bin")], b"")).await;
        let (_, last) = fixture::reply(&bytes);
        assert_ne!(
            last, END,
            "a body shorter than its length is not a complete reply"
        );
        server.abort();
    }

    /// A GET whose reply the client does not read hits the write deadline and
    /// frees the only permit for the next request.
    #[tokio::test]
    async fn a_slow_reading_get_hits_the_write_deadline_and_frees_the_permit() {
        let (_dir, path) = temp_socket("slow-get");
        let file_path = path.with_extension("body");
        // A sparse file: long enough that the socket buffer cannot hold it, and
        // no blocks are written for it.
        std::fs::File::create(&file_path)
            .unwrap()
            .set_len(4 * 1024 * 1024)
            .unwrap();

        let server = spawn_server(
            path.clone(),
            Limits {
                connections: 1,
                deadline: Duration::from_millis(150),
                body_cap: 0,
            },
            move |request| {
                let file_path = file_path.clone();
                async move {
                    if request.value("REQUEST_URI") == "/small" {
                        return Answer::Reply(Reply::html(200, "small".into()));
                    }
                    let file = tokio::fs::File::open(&file_path).await.unwrap();
                    let head =
                        Reply::file(200, "application/octet-stream", Vec::new()).head_block();
                    Answer::File {
                        head,
                        file,
                        len: 4 * 1024 * 1024,
                        code: 200,
                    }
                }
            },
        );
        wait_for(&path).await;

        let mut stalled = UnixStream::connect(&path).await.unwrap();
        stalled
            .write_all(&fixture::httpd(&[("REQUEST_URI", "/big")], b""))
            .await
            .unwrap();
        // No read: the server's write fills the socket buffer and waits.
        tokio::time::sleep(Duration::from_millis(400)).await;

        let served = tokio::time::timeout(
            Duration::from_secs(2),
            round_trip(&path, &fixture::httpd(&[("REQUEST_URI", "/small")], b"")),
        )
        .await
        .expect("the stalled connection's permit was released");
        assert_eq!(fixture::reply(&served).1, END);
        drop(stalled);
        server.abort();
    }

    /// Each listener has its own permit pool, so a stalled request on one cannot
    /// stop the other from serving.
    #[tokio::test]
    async fn each_listener_spends_its_own_permits() {
        let (_dir_a, first_path) = temp_socket("permits-a");
        let (_dir_b, second_path) = temp_socket("permits-b");
        let limits = Limits {
            connections: 1,
            deadline: Duration::from_secs(30),
            body_cap: 0,
        };
        let answer = |_request: Request| async { Answer::Reply(Reply::html(200, "ok".into())) };
        let first = spawn_server(first_path.clone(), limits, answer);
        let second = spawn_server(second_path.clone(), limits, answer);
        wait_for(&first_path).await;
        wait_for(&second_path).await;

        // A connection that never finishes its request holds the only permit on
        // the first listener.
        let mut held = UnixStream::connect(&first_path).await.unwrap();
        held.write_all(&fixture::raw(1, BEGIN_REQUEST, &[0, 1, 0, 0, 0, 0, 0, 0]))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let served = tokio::time::timeout(
            Duration::from_secs(2),
            round_trip(&second_path, &fixture::httpd(&[], b"")),
        )
        .await
        .expect("the second listener is not blocked by the first");
        assert_eq!(fixture::reply(&served).1, END);
        drop(held);
        first.abort();
        second.abort();
    }

    /// A file or a dangling symlink left at the path is cleared, and the link's
    /// target is untouched.
    #[tokio::test]
    async fn bind_clears_a_file_or_a_dangling_link_at_the_path() {
        use std::os::unix::fs::{symlink, FileTypeExt};

        let (dir, path) = temp_socket("bind");
        std::fs::write(&path, b"planted").unwrap();
        let listener = bind(&path).expect("bind over a planted file");
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_socket());
        drop(listener);

        let target = dir.join("gone");
        std::fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        let listener = bind(&path).expect("bind over a dangling symlink");
        assert!(
            target.symlink_metadata().is_err(),
            "the link's target is untouched"
        );
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_socket());
        drop(listener);
    }
}
