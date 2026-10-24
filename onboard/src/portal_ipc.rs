//! The requests the portal makes of the handler.
//!
//! The portal runs as `hello`, outside the store, and cannot read an
//! application's record itself: the store is `_onboard`'s and the handler is the
//! only process that reads it. A status read and a filed application are
//! therefore lines over its own socket, because the portal has no network reach
//! but this one and the socket's group is what lets the account connect at all.
//!
//! The protocol is a request line and a reply line, both bounded, and a filed
//! application adds one line of JSON between them because a key does not fit a
//! line the token and a stage fit. It carries no answer and no address but the
//! one the portal took from `SSH_CONNECTION`, which the handler uses as the
//! counter key and logs as the front-ends' own log line already does.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

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

    pub fn parse(line: &str) -> Result<Answer, String> {
        let line = line.trim_end_matches(['\r', '\n']);
        let (word, text) = line
            .split_once(' ')
            .ok_or_else(|| format!("the status service sent no answer: {line:?}"))?;
        match word {
            "stage" => Ok(Answer::Stage(text.to_string())),
            "notice" => Ok(Answer::Notice(text.to_string())),
            _ => Err(format!("the status service sent no answer: {line:?}")),
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
pub fn parse_file_answer(line: &str) -> Result<String, String> {
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some(token) = line.strip_prefix("OK ") {
        Ok(token.to_string())
    } else if let Some(why) = line.strip_prefix("ERR ") {
        Err(why.to_string())
    } else {
        Err(format!("the file service sent no answer: {line:?}"))
    }
}

/// Connect to the handler, with the timeouts every request here uses.
fn connect(socket: &Path, what: &str) -> Result<UnixStream, String> {
    let stream = UnixStream::connect(socket)
        .map_err(|e| format!("cannot reach the {what} at {}: {e}", socket.display()))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
        .map_err(|e| format!("cannot set the {what}'s timeout: {e}"))?;
    Ok(stream)
}

/// Read one bounded reply line, or say the handler closed first.
fn reply(stream: UnixStream, what: &str) -> Result<String, String> {
    let mut line = String::new();
    // The cap is on the wire, before the buffer grows: a reply past it is a
    // handler that is not speaking this protocol.
    BufReader::new(stream.take(MAX_LINE as u64))
        .read_line(&mut line)
        .map_err(|e| format!("cannot read the {what}'s answer: {e}"))?;
    if !line.ends_with('\n') {
        return Err(format!("the {what} closed the connection before answering"));
    }
    Ok(line)
}

/// Ask the handler for one token's stage.
pub fn ask(socket: &Path, address: Option<&str>, token: &str) -> Result<Answer, String> {
    let stream = connect(socket, "status service")?;
    (&stream)
        .write_all(request_line(address, token).as_bytes())
        .and_then(|()| (&stream).flush())
        .map_err(|e| format!("cannot ask the status service: {e}"))?;
    Answer::parse(&reply(stream, "status service")?)
}

/// File one completed application and return the token the handler drew.
pub fn file(
    socket: &Path,
    address: Option<&str>,
    form: &BTreeMap<String, String>,
) -> Result<String, String> {
    let body =
        serde_json::to_string(form).map_err(|e| format!("cannot encode the application: {e}"))?;
    let stream = connect(socket, "file service")?;
    let mut request = file_request(address);
    request.push_str(&body);
    request.push('\n');
    (&stream)
        .write_all(request.as_bytes())
        .and_then(|()| (&stream).flush())
        .map_err(|e| format!("cannot file the application: {e}"))?;
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
            parse_file_answer("ERR this is needed\n").unwrap_err(),
            "this is needed"
        );
        assert_eq!(
            file_answer(None, "one\ntwo"),
            "ERR one two\n",
            "a reply is one line"
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
}
