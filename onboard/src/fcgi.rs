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
//! Only the responder side is here: read the parameters and the body, write the
//! reply. That is what the two front-ends on this box send and accept, and nothing
//! more is implemented, because a protocol implemented further than its peers need
//! is a protocol with untested paths.
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
use std::io::ErrorKind;

use tokio::io::{AsyncRead, AsyncReadExt};

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
    /// Whether the body ran past the cap the caller set. The body is still read to
    /// its end, so the request can be answered rather than the connection dropped,
    /// and the answer is a refusal.
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

/// Read one request, or `None` when the peer closed between requests, which is how
/// both front-ends finish a connection.
///
/// `body_cap` is the most of a body the caller will accept. A body over it is
/// still read to its end and reported through `body_too_large`, because the
/// front-end is mid-request: dropping the connection there would leave the client
/// with a reset rather than with the refusal the caller can still send.
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    body_cap: usize,
) -> Result<Option<Request>, String> {
    let mut env_buf = Vec::new();
    let mut body = Vec::new();
    let mut body_too_large = false;
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
                return Err("the connection ended inside a request".to_string())
            }
            Err(e) => return Err(format!("cannot read a record header: {e}")),
        }
        if header[0] != VERSION {
            return Err(format!("record version {}", header[0]));
        }
        let kind = header[1];
        let record_id = u16::from_be_bytes([header[2], header[3]]);
        let len = u16::from_be_bytes([header[4], header[5]]) as usize;
        let padding = header[6] as usize;

        let mut content = vec![0u8; len + padding];
        reader
            .read_exact(&mut content)
            .await
            .map_err(|e| format!("cannot read a record body: {e}"))?;
        content.truncate(len);

        if !begun && kind != BEGIN_REQUEST {
            return Err("a record arrived before the request began".to_string());
        }

        match kind {
            BEGIN_REQUEST => {
                if content.len() != 8 {
                    return Err(format!("a begin record of {} bytes", content.len()));
                }
                // Role is big-endian in the first two bytes and is 1 for a
                // responder. Another role is another conversation, and this one
                // answers the responder's only.
                let role = u16::from_be_bytes([content[0], content[1]]);
                if role != 1 {
                    return Err(format!("role {role}"));
                }
                id = record_id;
                keep_conn = content[2] & 1 == 1;
                begun = true;
            }
            PARAMS => {
                if env_buf.len() + content.len() > MAX_PARAMS {
                    return Err("the parameters of one request are too long".to_string());
                }
                env_buf.extend_from_slice(&content);
            }
            STDIN => {
                if content.is_empty() {
                    break;
                }
                if body.len() + content.len() > body_cap {
                    body_too_large = true;
                } else {
                    body.extend_from_slice(&content);
                }
            }
            ABORT_REQUEST => return Err("the front-end aborted the request".to_string()),
            other => return Err(format!("record type {other}")),
        }
    }

    Ok(Some(Request {
        env: params(&env_buf)?,
        body,
        body_too_large,
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
fn params(buf: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let mut i = 0usize;
    while i < buf.len() {
        let name_len = length(buf, &mut i)?;
        let value_len = length(buf, &mut i)?;
        if name_len + value_len > buf.len() - i {
            return Err("a parameter runs past the end of its record".to_string());
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
fn length(buf: &[u8], i: &mut usize) -> Result<usize, String> {
    let first = *buf
        .get(*i)
        .ok_or_else(|| "a parameter record ends inside a length".to_string())?;
    if first & 0x80 == 0 {
        *i += 1;
        return Ok(first as usize);
    }
    let four = buf
        .get(*i..*i + 4)
        .ok_or_else(|| "a parameter record ends inside a length".to_string())?;
    *i += 4;
    Ok(u32::from_be_bytes([four[0] & 0x7f, four[1], four[2], four[3]]) as usize)
}

/// What a front-end reads back: the header block, a blank line, the body.
pub enum Reply {
    /// httpd's reply, which is a CGI header block: a status line, then the headers
    /// the page carries. httpd validates the code against its own table and
    /// silently serves 200 for one that table does not carry, so only codes it
    /// carries are ever sent, and `reason` is that table's own spelling.
    Http {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: String,
    },
    /// gmid's reply, which is gemini's: two digits, a space, the META, CRLF, then
    /// the body. gmid passes a 2x status through and fails the connection on a
    /// malformed header, so the status is the status and never a line in the body.
    Gemini {
        status: u8,
        meta: String,
        body: String,
    },
}

impl Reply {
    /// An HTML page, which is every page the web form renders.
    pub fn html(status: u16, body: String) -> Reply {
        Reply::Http {
            status,
            headers: vec![("Content-Type", "text/html; charset=utf-8".to_string())],
            body,
        }
    }

    /// A page that carries a capability in its URL, or is a capability itself:
    /// never stored, and its URL never sent as a referrer.
    pub fn capability(status: u16, body: String) -> Reply {
        Reply::Http {
            status,
            headers: vec![
                ("Content-Type", "text/html; charset=utf-8".to_string()),
                ("Cache-Control", "no-store".to_string()),
                ("Referrer-Policy", "no-referrer".to_string()),
            ],
            body,
        }
    }

    /// A gemini page.
    pub fn gemini(status: u8, meta: &str, body: String) -> Reply {
        Reply::Gemini {
            status,
            meta: meta.to_string(),
            body,
        }
    }

    /// The code this reply answers with, for the log line.
    pub fn code(&self) -> u16 {
        match self {
            Reply::Http { status, .. } => *status,
            Reply::Gemini { status, .. } => u16::from(*status),
        }
    }

    /// The header block and the body, with the blank line between them. The blank
    /// line is not optional for either front-end: httpd reads headers until it,
    /// and gmid reads its reply header as the first CRLF-terminated line, so
    /// without it a gemini client would be shown the rest of the headers.
    fn head(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Reply::Http {
                status,
                headers,
                body,
            } => {
                out.extend_from_slice(
                    format!("Status: {status} {}\r\n", reason(*status)).as_bytes(),
                );
                for (name, value) in headers {
                    out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
                }
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(body.as_bytes());
            }
            Reply::Gemini { status, meta, body } => {
                out.extend_from_slice(format!("{status} {meta}\r\n").as_bytes());
                out.extend_from_slice(body.as_bytes());
            }
        }
        out
    }
}

/// The reply as the front-end reads it: the header block and the body across as
/// many `FCGI_STDOUT` records as they need, then the end marker.
///
/// The end marker is what tells both front-ends the response is complete, and gmid
/// refuses one whose body is not exactly eight bytes, so it is written in full.
pub fn reply_bytes(reply: &Reply, id: u16) -> Vec<u8> {
    let content = reply.head();
    let mut out = Vec::with_capacity(content.len() + 2 * HEADER + 8);
    if content.is_empty() {
        push_record(&mut out, STDOUT, id, &[]);
    } else {
        for chunk in content.chunks(MAX_CONTENT) {
            push_record(&mut out, STDOUT, id, chunk);
        }
    }
    // appStatus and protocolStatus, both zero: the application finished and the
    // protocol had no trouble. A protocol status is not an HTTP or gemini status
    // and cannot carry one, which is why a refusal is the reply header above.
    push_record(&mut out, END_REQUEST, id, &[0; 8]);
    out
}

fn push_record(out: &mut Vec<u8>, kind: u8, id: u16, content: &[u8]) {
    let len = content.len() as u16;
    out.extend_from_slice(&[VERSION, kind]);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.push(0); // no padding: the response is written whole, so none is needed
    out.push(0); // reserved
    out.extend_from_slice(content);
}

/// The reason phrase for a status, in httpd's own table's spelling so the two
/// agree if anyone compares them. httpd drops it and writes its own, and gmid
/// never reads one, so this exists for the reader of the bytes.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "",
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    //! Requests as the two front-ends write them, for the tests of what reads
    //! them. The responder's check sends a request the way httpd and gmid send
    //! one, so the bytes are built once, here, rather than in each test that
    //! needs a request.

    use super::{BEGIN_REQUEST, END_REQUEST, PARAMS, STDIN, STDOUT, VERSION};

    /// One record, with the request id and type given, which is what a test that
    /// is deliberately sending something malformed needs.
    pub(crate) fn raw(id: u16, kind: u8, content: &[u8]) -> Vec<u8> {
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
    pub(crate) fn httpd(env: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut out = record(BEGIN_REQUEST, 1, &[0, 1, 0, 0, 0, 0, 0, 0]);
        let mut params = Vec::new();
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
    pub(crate) fn gmid(env: &[(&str, &str)]) -> Vec<u8> {
        let mut out = record(BEGIN_REQUEST, 1, &[0, 1, 1, 0, 0, 0, 0, 0]);
        let mut params = Vec::new();
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
    pub(crate) fn reply(bytes: &[u8]) -> (Vec<u8>, u8) {
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
    pub(crate) const END: u8 = END_REQUEST;
}

#[cfg(test)]
mod tests {
    use super::fixture::{self, END};
    use super::*;

    #[tokio::test]
    async fn a_request_reads_its_parameters_in_either_length_form() {
        // gmid's four-byte form and the keep-connection flag.
        let request = read_request(&mut &fixture::gmid(&[("GEMINI_URL_PATH", "status/x")])[..], 1024)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.value("GEMINI_URL_PATH"), "status/x");
        assert_eq!(request.value("SERVER_NAME"), "", "an absent parameter is empty");
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

    #[test]
    fn a_gemini_reply_is_the_header_the_body_and_the_end_marker() {
        let bytes = reply_bytes(&Reply::gemini(20, "text/gemini", "# hello\n".into()), 1);
        let (body, last) = fixture::reply(&bytes);
        assert_eq!(last, END, "the reply is finished, not truncated");
        assert_eq!(body, b"20 text/gemini\r\n# hello\n");
    }

    #[test]
    fn an_http_reply_carries_the_status_the_headers_and_the_body() {
        let bytes = reply_bytes(&Reply::capability(422, "<p>no</p>".into()), 1);
        let (body, last) = fixture::reply(&bytes);
        assert_eq!(last, END);
        let text = String::from_utf8(body).unwrap();
        assert!(text.starts_with("Status: 422 Unprocessable Content\r\n"), "{text}");
        assert!(text.contains("Cache-Control: no-store\r\n"), "{text}");
        assert!(text.ends_with("\r\n\r\n<p>no</p>"), "{text}");
    }

    #[test]
    fn a_page_larger_than_one_record_goes_out_as_several() {
        let body = "x".repeat(MAX_CONTENT + 10);
        let bytes = reply_bytes(&Reply::html(200, body), 1);
        let mut at = 0;
        let mut stdout = 0;
        while at < bytes.len() {
            let kind = bytes[at + 1];
            let len = u16::from_be_bytes([bytes[at + 4], bytes[at + 5]]) as usize;
            if kind == STDOUT {
                stdout += 1;
                assert!(len <= MAX_CONTENT, "no record is longer than the field allows");
            } else {
                assert_eq!(kind, END_REQUEST);
                assert_eq!(len, 8);
            }
            at += HEADER + len;
        }
        assert_eq!(stdout, 2, "the header block and the body over two records");
    }
}
