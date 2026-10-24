//! The one request the portal makes of the handler.
//!
//! The portal runs as `hello`, outside the store, and cannot read an
//! application's record itself: the store is `_onboard`'s and the handler is the
//! only process that reads it. The status read is therefore one line over its own
//! socket, because the portal has no network reach but this one and the socket's
//! group is what lets the account connect at all.
//!
//! The protocol is a request line and a reply line, both bounded. It carries no
//! answer and no address but the one the portal took from `SSH_CONNECTION`, which
//! the handler uses as the counter key and logs as the front-ends' own log line
//! already does.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// The longest request or reply line. The token is 26 characters, an address is
/// at most 45, and the stage is a sentence the handler writes; anything past this
/// is not one of these messages.
pub const MAX_LINE: usize = 512;

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

/// Ask the handler for one token's stage.
pub fn ask(socket: &Path, address: Option<&str>, token: &str) -> Result<Answer, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| {
        format!(
            "cannot reach the status service at {}: {e}",
            socket.display()
        )
    })?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
        .map_err(|e| format!("cannot set the status service's timeout: {e}"))?;
    stream
        .write_all(request_line(address, token).as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|e| format!("cannot ask the status service: {e}"))?;

    let mut line = String::new();
    // The cap is on the wire, before the buffer grows: a reply past it is a
    // handler that is not speaking this protocol.
    BufReader::new(stream.take(MAX_LINE as u64))
        .read_line(&mut line)
        .map_err(|e| format!("cannot read the status service's answer: {e}"))?;
    if !line.ends_with('\n') {
        return Err("the status service closed the connection before answering".to_string());
    }
    Answer::parse(&line)
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
