//! The requests the portal makes of the handler.
//!
//! The portal runs as `hello`, outside the store, and cannot read an
//! application's record itself: the store is `_onboard`'s and the handler is the
//! only process that reads it. A status read and a filed application are
//! therefore lines over its own socket, because the portal has no network reach
//! but this one and the socket's group is what lets the account connect at all.
//!
//! The protocol is a request line and a reply line, both bounded. A status read
//! carries no answer. A filed application adds one line of JSON between them,
//! because a key does not fit a line the way a token and a stage do, and that
//! line is the answers. Either request carries no address but the one the portal
//! took from `SSH_CONNECTION`, which the handler uses as the counter key and logs
//! as the front-ends' own log line already does.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The portal's side of the handler protocol: the reply it could not read, the
/// refusal the handler sent, and the socket operation that failed.
#[derive(Debug)]
pub enum Error {
    /// A status reply line carries no answer.
    NoAnswer { line: String },
    /// A file reply line is neither `OK` nor `ERR`.
    NoFileAnswer { line: String },
    /// The handler refused the application in its own words.
    HandlerRefusal { message: String },
    /// The socket could not be reached.
    Connect {
        what: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    /// The socket's read or write timeout could not be set.
    SetTimeout {
        what: &'static str,
        source: io::Error,
    },
    /// The reply line could not be read.
    ReadAnswer {
        what: &'static str,
        source: io::Error,
    },
    /// The handler closed before finishing its reply line.
    ClosedBeforeAnswer { what: &'static str },
    /// The status request could not be written.
    Ask { source: io::Error },
    /// The application could not be encoded.
    EncodeApplication { source: serde_json::Error },
    /// The application body is over the protocol's bound.
    ApplicationTooLarge { length: usize, max: usize },
    /// The file request could not be written.
    FileApplication { source: io::Error },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoAnswer { line } => {
                write!(f, "the status service sent no answer: {line:?}")
            }
            Error::NoFileAnswer { line } => {
                write!(f, "the file service sent no answer: {line:?}")
            }
            Error::HandlerRefusal { message } => f.write_str(message),
            Error::Connect { what, path, source } => {
                write!(f, "cannot reach the {what} at {}: {source}", path.display())
            }
            Error::SetTimeout { what, source } => {
                write!(f, "cannot set the {what}'s timeout: {source}")
            }
            Error::ReadAnswer { what, source } => {
                write!(f, "cannot read the {what}'s answer: {source}")
            }
            Error::ClosedBeforeAnswer { what } => {
                write!(f, "the {what} closed the connection before answering")
            }
            Error::Ask { source } => {
                write!(f, "cannot ask the status service: {source}")
            }
            Error::EncodeApplication { source } => {
                write!(f, "cannot encode the application: {source}")
            }
            Error::ApplicationTooLarge { length, max } => write!(
                f,
                "the application is too large to send ({length} bytes, the limit is {max}); shorten an answer"
            ),
            Error::FileApplication { source } => {
                write!(f, "cannot file the application: {source}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Connect { source, .. }
            | Error::SetTimeout { source, .. }
            | Error::ReadAnswer { source, .. }
            | Error::Ask { source }
            | Error::FileApplication { source } => Some(source),
            Error::EncodeApplication { source } => Some(source),
            _ => None,
        }
    }
}

/// The longest request or reply line. The token is 26 characters, an address is
/// at most 45, and the stage is a sentence the handler writes; anything past this
/// is not one of these messages.
pub const MAX_LINE: usize = 512;

/// The longest JSON body a filed application may carry, the same bound the web
/// form's post has: ten mail keys and the free text beside them.
pub const MAX_BODY: usize = 256 * 1024;

/// A read or write that takes longer than this is a handler that has stopped
/// answering, not a slow answer. A session should say so rather than hold a pty
/// open forever.
const TIMEOUT: Duration = Duration::from_secs(5);

/// What the handler answers a status read with: the stage a filed application
/// has reached, or the one notice that covers an unknown, expired or spent token
/// alike.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    Stage(String),
    Notice(String),
}

impl Answer {
    /// The reply line, with line breaks in its text flattened: the protocol is
    /// one line, and a stage a record somehow carries a newline in must not become
    /// a second line.
    pub fn line(&self) -> String {
        let (word, text) = match self {
            Answer::Stage(text) => ("stage", text),
            Answer::Notice(text) => ("notice", text),
        };
        format!("{word} {}\n", single_line(text))
    }

    pub fn parse(line: &str) -> Result<Answer, Error> {
        let line = line.trim_end_matches(['\r', '\n']);
        let (word, text) = line.split_once(' ').ok_or_else(|| Error::NoAnswer {
            line: line.to_string(),
        })?;
        match word {
            "stage" => Ok(Answer::Stage(text.to_string())),
            "notice" => Ok(Answer::Notice(text.to_string())),
            _ => Err(Error::NoAnswer {
                line: line.to_string(),
            }),
        }
    }
}

fn single_line(text: &str) -> String {
    text.chars()
        .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
        .collect()
}

pub fn request_line(address: Option<&str>, token: &str) -> String {
    format!("STATUS {} {token}\n", address.unwrap_or("-"))
}

/// The address and token of a request line, or `None` when it is not one.
pub fn parse_request(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_end_matches('\n');
    let mut fields = line.splitn(3, ' ');
    if fields.next()? != "STATUS" {
        return None;
    }
    Some((fields.next()?, fields.next()?))
}

/// The request line a filed application opens with. The answers follow as one
/// JSON line: a key does not fit a line, and JSON escapes its newlines.
pub fn file_request(address: Option<&str>) -> String {
    format!("FILE {}\n", address.unwrap_or("-"))
}

/// The address of a file request, or `None` when the line is not one.
pub fn parse_file_request(line: &str) -> Option<&str> {
    line.trim_end_matches('\n').strip_prefix("FILE ")
}

/// The reply to a filed application: the token, or the reason it was not filed.
pub fn file_answer(token: Option<&str>, why: &str) -> String {
    match token {
        Some(token) => format!("OK {token}\n"),
        None => format!("ERR {}\n", single_line(why)),
    }
}

/// The token in a file reply, or the refusal the handler sent.
pub fn parse_file_answer(line: &str) -> Result<String, Error> {
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some(token) = line.strip_prefix("OK ") {
        Ok(token.to_string())
    } else if let Some(message) = line.strip_prefix("ERR ") {
        Err(Error::HandlerRefusal {
            message: message.to_string(),
        })
    } else {
        Err(Error::NoFileAnswer {
            line: line.to_string(),
        })
    }
}

/// Connect to the handler, with the timeouts every request here uses.
fn connect(socket: &Path, what: &'static str) -> Result<UnixStream, Error> {
    connect_with(socket, what, TIMEOUT)
}

/// Connect with an explicit timeout, for a test that cannot wait the service's
/// five seconds.
fn connect_with(socket: &Path, what: &'static str, timeout: Duration) -> Result<UnixStream, Error> {
    let stream = connect_timeout(socket, timeout).map_err(|source| Error::Connect {
        what,
        path: socket.to_path_buf(),
        source,
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|source| Error::SetTimeout { what, source })?;
    Ok(stream)
}

/// The socket address and its length for `socket`. The BSD address carries its
/// own length; Linux's does not.
fn socket_address(socket: &Path) -> std::io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = socket.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the socket path is too long",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    // The BSD socket address carries its own length; Linux's does not.
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        address.sun_len = std::mem::size_of::<libc::sockaddr_un>() as u8;
    }
    Ok((
        address,
        std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
    ))
}

fn timed_out() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "the connection was not accepted in time",
    )
}

/// Wait until `fd` is writable, or the deadline passes. `false` is the deadline.
fn wait_writable(fd: i32, deadline: std::time::Instant) -> std::io::Result<bool> {
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        let wait = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let polled = unsafe { libc::poll(&mut ready, 1, wait) };
        if polled > 0 {
            return Ok(true);
        }
        if polled == 0 {
            return Ok(false);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

/// The pending error on a socket, or zero when the connect succeeded.
fn socket_error(fd: i32) -> std::io::Result<libc::c_int> {
    let mut pending: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut pending as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(pending)
}

/// Connect to a unix socket, giving up after `timeout`.
///
/// A plain blocking connect waits in the listener's backlog, so a handler that
/// has stopped accepting would hang the portal before its read timeout could
/// apply (#878). The socket is non-blocking for the connect. `EINPROGRESS` waits
/// for writability; `EAGAIN` is a full backlog, which is a retry rather than a
/// completed connect, so the loop tries again until the deadline.
///
/// [#878]: https://github.com/kyriakon/kyriakon-infra/issues/878
fn connect_timeout(socket: &Path, timeout: Duration) -> std::io::Result<UnixStream> {
    use std::time::Instant;

    let (address, length) = socket_address(socket)?;
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Own the descriptor from here, so every error path closes it.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let deadline = Instant::now() + timeout;
    loop {
        let connected = unsafe {
            libc::connect(
                fd,
                &address as *const libc::sockaddr_un as *const libc::sockaddr,
                length,
            )
        };
        if connected == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINPROGRESS) => {
                if !wait_writable(fd, deadline)? {
                    return Err(timed_out());
                }
                let pending = socket_error(fd)?;
                if pending != 0 {
                    return Err(std::io::Error::from_raw_os_error(pending));
                }
                break;
            }
            Some(libc::EAGAIN) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(timed_out());
                }
                // The backlog is full. Waiting a little and trying again is what
                // a blocking connect does in the kernel, and it keeps the poll
                // branch above for a connect that is genuinely in progress.
                std::thread::sleep((deadline - now).min(Duration::from_millis(5)));
            }
            Some(libc::EINTR) => continue,
            _ => return Err(error),
        }
    }
    // Back to blocking for the read and write timeouts.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stream)
}

/// Read one bounded reply line, or say the handler closed first.
fn reply(stream: UnixStream, what: &'static str) -> Result<String, Error> {
    let mut line = String::new();
    // The cap is on the wire, before the buffer grows: a reply past it is a
    // handler that is not speaking this protocol.
    BufReader::new(stream.take(MAX_LINE as u64))
        .read_line(&mut line)
        .map_err(|source| Error::ReadAnswer { what, source })?;
    if !line.ends_with('\n') {
        return Err(Error::ClosedBeforeAnswer { what });
    }
    Ok(line)
}

/// Ask the handler for one token's stage.
pub fn ask(socket: &Path, address: Option<&str>, token: &str) -> Result<Answer, Error> {
    ask_with(socket, address, token, TIMEOUT)
}

fn ask_with(
    socket: &Path,
    address: Option<&str>,
    token: &str,
    timeout: Duration,
) -> Result<Answer, Error> {
    let stream = connect_with(socket, "status service", timeout)?;
    (&stream)
        .write_all(request_line(address, token).as_bytes())
        .and_then(|()| (&stream).flush())
        .map_err(|source| Error::Ask { source })?;
    Answer::parse(&reply(stream, "status service")?)
}

/// File one completed application and return the token the handler drew.
pub fn file(
    socket: &Path,
    address: Option<&str>,
    form: &BTreeMap<String, String>,
) -> Result<String, Error> {
    let body = serde_json::to_string(form).map_err(|source| Error::EncodeApplication { source })?;
    // The handler reads one line and rejects it past this bound, so refuse here
    // where the reader can be told, rather than after a whole session's answers.
    if body.len() >= MAX_BODY {
        return Err(Error::ApplicationTooLarge {
            length: body.len(),
            max: MAX_BODY,
        });
    }
    let stream = connect(socket, "file service")?;
    let mut request = file_request(address);
    request.push_str(&body);
    request.push('\n');
    (&stream)
        .write_all(request.as_bytes())
        .and_then(|()| (&stream).flush())
        .map_err(|source| Error::FileApplication { source })?;
    parse_file_answer(&reply(stream, "file service")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_line_round_trips_with_and_without_an_address() {
        assert_eq!(
            request_line(Some("203.0.113.10"), "abcdefghjkmnpqrstvwxyz0123"),
            "STATUS 203.0.113.10 abcdefghjkmnpqrstvwxyz0123\n"
        );
        assert_eq!(
            parse_request("STATUS - abcdefghjkmnpqrstvwxyz0123\n"),
            Some(("-", "abcdefghjkmnpqrstvwxyz0123"))
        );
        assert_eq!(parse_request("GET / HTTP/1.1\n"), None);
    }

    #[test]
    fn a_file_request_and_answer_are_bounded_lines() {
        assert_eq!(
            parse_file_request(&file_request(Some("203.0.113.9"))),
            Some("203.0.113.9")
        );
        assert_eq!(parse_file_request("STATUS - token\n"), None);
        assert_eq!(
            parse_file_answer("OK abcdefghjkmnpqrstvwxyz0123\n").unwrap(),
            "abcdefghjkmnpqrstvwxyz0123"
        );
        assert_eq!(
            parse_file_answer("ERR this is needed\n")
                .unwrap_err()
                .to_string(),
            "this is needed"
        );
        assert_eq!(
            file_answer(None, "one\ntwo"),
            "ERR one two\n",
            "a reply is one line"
        );
    }

    #[test]
    fn an_application_over_the_body_bound_is_refused_before_it_is_sent() {
        let form = BTreeMap::from([("anything_else".to_string(), "x".repeat(MAX_BODY))]);
        let why = file(Path::new("/nonexistent/portal.sock"), None, &form).unwrap_err();
        assert!(
            matches!(&why, Error::ApplicationTooLarge { length, max } if *length >= MAX_BODY && *max == MAX_BODY),
            "{why}"
        );
    }

    #[test]
    fn file_sends_the_form_and_reads_the_token_over_a_socket() {
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("onboard-portal-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("portal.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let handler = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, "FILE 203.0.113.9\n");
            let mut body = String::new();
            reader.read_line(&mut body).unwrap();
            let form: BTreeMap<String, String> = serde_json::from_str(&body).unwrap();
            assert_eq!(form.get("username").unwrap(), "theophilus");
            stream
                .write_all(b"OK abcdefghjkmnpqrstvwxyz0123\n")
                .unwrap();
        });

        let form = BTreeMap::from([("username".to_string(), "theophilus".to_string())]);
        assert_eq!(
            file(&path, Some("203.0.113.9"), &form).unwrap(),
            "abcdefghjkmnpqrstvwxyz0123"
        );
        handler.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_answer_is_one_line_even_when_its_text_is_not() {
        assert_eq!(
            Answer::Stage("received\nwith the reviewer".into()).line(),
            "stage received with the reviewer\n"
        );
        assert_eq!(
            Answer::parse("notice This link is not in use.\n").unwrap(),
            Answer::Notice("This link is not in use.".into())
        );
        assert!(Answer::parse("nothing here").is_err());
    }

    /// The client and the wire together: what `ask` writes is what the handler's
    /// parser reads, and what the handler writes is what `ask` returns.
    #[test]
    fn ask_reads_the_reply_over_a_socket() {
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("onboard-portal-ipc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("portal.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let handler = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            assert_eq!(line, "STATUS 203.0.113.9 abcdefghjkmnpqrstvwxyz0123\n");
            stream.write_all(b"stage with the reviewer\n").unwrap();
        });

        assert_eq!(
            ask(&path, Some("203.0.113.9"), "abcdefghjkmnpqrstvwxyz0123").unwrap(),
            Answer::Stage("with the reviewer".into())
        );
        handler.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A handler that accepts and never answers must not hold the portal on a
    /// blocking read forever: the reply timeout ends it ([#878]).
    ///
    /// [#878]: https://github.com/kyriakon/kyriakon-infra/issues/878
    #[test]
    fn a_stalled_portal_socket_times_out() {
        use std::os::unix::net::UnixListener;
        use std::time::Instant;

        let dir = std::env::temp_dir().join(format!("onboard-portal-stall-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("portal.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let handler = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            // Hold the connection open without writing a reply.
            std::thread::sleep(Duration::from_millis(500));
        });

        let started = Instant::now();
        let why = ask_with(
            &path,
            Some("203.0.113.9"),
            "abcdefghjkmnpqrstvwxyz0123",
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the read ended at the timeout rather than at the handler: {why}"
        );
        assert!(
            why.to_string().contains("status service"),
            "the failure names the boundary: {why}"
        );
        handler.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A listener whose queue is full never accepts, so the connect itself must
    /// end at the bound rather than waiting for a reply. This is the case the
    /// read timeout cannot see ([#878]).
    ///
    /// Linux only: macOS's AF_UNIX accepts connections past the listen backlog,
    /// so a full queue cannot be built there and the read timeout is the only
    /// bound that can fire.
    ///
    /// [#878]: https://github.com/kyriakon/kyriakon-infra/issues/878
    #[cfg(target_os = "linux")]
    #[test]
    fn a_full_connect_queue_times_out() {
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::time::Instant;

        let dir = std::env::temp_dir().join(format!("onboard-portal-full-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("portal.sock");

        let (address, length) = socket_address(&path).unwrap();
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0, "a socket");
        let _listener = unsafe { OwnedFd::from_raw_fd(fd) };
        assert_eq!(
            unsafe {
                libc::bind(
                    fd,
                    &address as *const libc::sockaddr_un as *const libc::sockaddr,
                    length,
                )
            },
            0,
            "bind {}",
            path.display()
        );
        // A queue of zero holds one pending connection and no more, so one
        // client fills it.
        assert_eq!(unsafe { libc::listen(fd, 0) }, 0, "listen");

        let _held = UnixStream::connect(&path).unwrap();
        let started = Instant::now();
        let why = ask(&path, None, "abcdefghjkmnpqrstvwxyz0123").unwrap_err();
        let waited = started.elapsed();
        assert!(
            waited < TIMEOUT + Duration::from_secs(3),
            "the connect did not end near its bound: {waited:?}"
        );
        assert!(
            why.to_string().contains("not accepted in time"),
            "the failure is the connect, not the read: {why}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
