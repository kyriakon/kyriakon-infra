//! The Titan upload transport.

use super::*;

use super::connection::say;
use super::gemini::capsule_not_found;
use super::reply::{too_many, Which};
use kyriakon_onboard_core::flow::applicant::flow_path;

use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use crate::fastcgi::Reply;
use kyriakon_onboard_core::config::HOST;
use kyriakon_onboard_core::{flow::rate, mail::keycheck, store::draft};

/// Accept Titan connections for as long as the listener holds. One connection
/// carries one upload and closes, like the gemini front-end's.
///
/// An accept error does not stop this loop: `accept(2)` reports transient
/// failures a connection flood can provoke (`EMFILE`, `ECONNABORTED`), and
/// returning the error would cancel `try_join!` and take the web form and both
/// unix front-ends down with it. The three unix listeners can share that shape
/// safely because their sockets are 0660; a public TCP listener cannot.
pub(super) async fn titan_accept(listener: TcpListener, app: Arc<App>) -> Result<(), Error> {
    let slots = Arc::new(tokio::sync::Semaphore::new(TITAN_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                Error::Io {
                    what: "accept a titan connection",
                    path: None,
                    source: e,
                }
                .report("accepting a titan connection");
                // A short pause keeps a hard failure from spinning the loop.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let app = app.clone();
        let slots = slots.clone();
        tokio::spawn(async move {
            // A permit bounds the tasks that hold a socket. Waiting tasks are
            // cheap; unbounded sockets are not.
            let Ok(_permit) = slots.acquire().await else {
                return;
            };
            if let Err(e) = titan_connection(stream, &app, &peer.ip().to_string()).await {
                e.report("the titan request");
            }
        });
    }
}

/// One Titan request: relayd's PROXY line (when there is one), the Titan request
/// line, then the body. The reply is gemini's framing written straight to the
/// stream, because this listener is this service's own and has no front-end to
/// frame for it.
///
/// Both halves are bounded: a stranger can open the connection and send nothing,
/// and a reply to a client that has stopped reading must not hold a task
/// forever.
pub(super) async fn titan_connection(
    stream: TcpStream,
    app: &App,
    peer: &str,
) -> Result<(), Error> {
    let (mut reader, mut writer) = stream.into_split();
    let (reply, address) =
        match tokio::time::timeout(TITAN_TIMEOUT, titan_answer(&mut reader, app, Some(peer))).await
        {
            Ok(Ok(reply)) => reply,
            Ok(Err(e)) => return Err(e),
            Err(_) => (
                Reply::gemini(59, "The upload timed out", String::new()),
                peer.to_string(),
            ),
        };
    // The route never carries the token: the token is the capability, and the
    // log line is as long-lived as the rest of the service's.
    eprintln!("kyriakon-onboard: titan /key {} {address}", reply.code());
    let head = reply.head();
    let write = say(&mut writer, &head);
    match tokio::time::timeout(TITAN_TIMEOUT, write).await {
        Ok(result) => result,
        Err(_) => Err(Error::Failed("the titan reply timed out".to_string())),
    }
}

/// The three checks this route exists for happen before the body is read: the
/// token must name a live draft, the size must be inside the cap, and the
/// mailbox the upload belongs to must not already hold a key. A refusal consumes
/// the request line only, so a client that sent a body is not made to wait for it
/// to be read first.
pub(super) async fn titan_answer<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    app: &App,
    peer: Option<&str>,
) -> Result<(Reply, String), Error> {
    let first = match titan_line(reader, MAX_TITAN_LINE).await {
        Ok(Some(line)) => line,
        Ok(None) => {
            return Ok((
                Reply::gemini(59, "Empty titan request", String::new()),
                peer.unwrap_or("").to_string(),
            ))
        }
        Err(why) => {
            return Ok((
                Reply::gemini(59, &why.to_string(), String::new()),
                peer.unwrap_or("").to_string(),
            ))
        }
    };
    let (line, address, key) = if first.starts_with("PROXY ") {
        let address = proxy_address(&first);
        let line = match titan_line(reader, MAX_TITAN_LINE).await {
            Ok(Some(line)) => line,
            Ok(None) => {
                return Ok((
                    Reply::gemini(59, "Empty titan request", String::new()),
                    address.unwrap_or_default(),
                ))
            }
            Err(why) => {
                return Ok((
                    Reply::gemini(59, &why.to_string(), String::new()),
                    address.unwrap_or_default(),
                ))
            }
        };
        // Only a PROXY line relayd wrote gives a client address. With none, or
        // one that does not parse, the request shares `UnknownForward` rather
        // than collapsing onto the socket peer: the peer here is relayd, and one
        // bucket for every client in the world is worse than one bucket for the
        // requests that never reached relayd.
        //
        // The listener is loopback-only, so relayd is the only expected
        // connector. A local process can send a PROXY line naming any address
        // and get a fresh bucket; that is not a defence this route can carry,
        // and a local process on this box has worse to hand.
        let key = match address.as_deref() {
            Some(address) => rate::key(None, Some(address)),
            None => rate::Key::UnknownForward,
        };
        (line, address.unwrap_or_default(), key)
    } else {
        (
            first,
            peer.unwrap_or("").to_string(),
            rate::Key::UnknownForward,
        )
    };

    if !app.counter.allow_request(key) {
        return Ok((too_many(FrontEnd::Gemini, Which::Minute), address));
    }

    let upload = match titan_params(&line) {
        Ok(upload) => upload,
        Err(why) => return Ok((Reply::gemini(59, why, String::new()), address)),
    };
    let token = upload.token.as_deref().unwrap_or("");
    let record = match draft::load(&app.store, token).await {
        Ok(record) => record,
        Err(e) => {
            e.report("the titan request");
            return Ok((Reply::gemini(40, TEMP_FAILURE, String::new()), address));
        }
    };
    let Some(record) = record else {
        return Ok((capsule_not_found(), address));
    };
    let size = match upload.size {
        Some(size) if size <= MAX_TITAN_BODY => size,
        _ => {
            return Ok((
                Reply::gemini(59, "Upload size is missing or over the cap", String::new()),
                address,
            ))
        }
    };
    // A bare titan:// navigation is a zero-byte upload, so a link to the
    // endpoint opens rather than failing: nothing is read and nothing is filed.
    if size == 0 {
        return Ok((Reply::gemini(20, "text/gemini", String::new()), address));
    }
    // The mailbox this upload would fill. When every mailbox in the draft holds
    // a key, there is nothing left to fill and the refusal is the draft's own
    // state, not the request's.
    if titan_mailbox(app, &record).is_none() {
        return Ok((
            Reply::gemini(
                59,
                "Every mailbox in this draft already has a key",
                String::new(),
            ),
            address,
        ));
    }

    let mut body = vec![0u8; size];
    if reader.read_exact(&mut body).await.is_err() {
        return Ok((Reply::gemini(40, TEMP_FAILURE, String::new()), address));
    }

    // The checks run again under the draft lock before anything is written, so
    // two uploads that both read a keyless draft cannot both file a key. The
    // lock is held across the read-modify-write and not across the body read.
    let _lock = match app.store.lock("drafts/.lock").await {
        Ok(lock) => lock,
        Err(e) => {
            e.report("the titan request");
            return Ok((Reply::gemini(40, TEMP_FAILURE, String::new()), address));
        }
    };
    let record = match draft::load(&app.store, token).await {
        Ok(record) => record,
        Err(e) => {
            e.report("the titan request");
            return Ok((Reply::gemini(40, TEMP_FAILURE, String::new()), address));
        }
    };
    let Some(mut record) = record else {
        return Ok((capsule_not_found(), address));
    };
    let Some(mailbox) = titan_mailbox(app, &record) else {
        return Ok((
            Reply::gemini(
                59,
                "Every mailbox in this draft already has a key",
                String::new(),
            ),
            address,
        ));
    };
    let blocks = keycheck::blocks(&String::from_utf8_lossy(&body));
    if blocks.len() != 1 {
        return Ok((
            Reply::gemini(59, "Upload one public key block", String::new()),
            address,
        ));
    }
    // The same retain-then-push the capsule's key page uses, so a retry for one
    // mailbox replaces its key rather than adding a second.
    record.mail_keys.retain(|k| k.mailbox != mailbox);
    record
        .mail_keys
        .push(keycheck::mail_key(mailbox.clone(), &blocks[0]));
    if let Err(e) = draft::save(&app.store, &mut record).await {
        e.report("the titan request");
        return Ok((Reply::gemini(40, TEMP_FAILURE, String::new()), address));
    }
    let link = format!("gemini://{HOST}/status/{token}");
    Ok((
        Reply::gemini(
            20,
            "text/gemini",
            format!("Key received for {mailbox}.\n{link}\n"),
        ),
        address,
    ))
}

/// The mailbox an upload belongs to: the first key page without a key. A draft
/// whose flow has a key page for every mailbox answers `None` once each holds a
/// key, which is the refusal the caller answers with.
pub(super) fn titan_mailbox(app: &App, record: &draft::Draft) -> Option<String> {
    flow_path(&app.questions, &record.answers)
        .into_iter()
        .find_map(|page| {
            let mailbox = page.mailbox?;
            (!record.mail_keys.iter().any(|k| k.mailbox == mailbox.name)).then_some(mailbox.name)
        })
        .filter(|name| !name.is_empty())
}

/// One CRLF- or LF-terminated line, read a byte at a time. A buffered reader
/// would pull body bytes in with the line, which is exactly what the three checks
/// must not do, so this reads only the line and leaves the rest on the stream.
pub(super) async fn titan_line<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<Option<String>, Error> {
    let mut bytes = Vec::new();
    loop {
        let mut b = [0u8; 1];
        match reader.read(&mut b).await {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => {
                return Err(Error::Refused(
                    "the titan request line was cut short".to_string(),
                ))
            }
            Ok(_) => bytes.push(b[0]),
            Err(source) => {
                return Err(Error::Io {
                    what: "read the titan request",
                    path: None,
                    source,
                })
            }
        }
        if b[0] == b'\n' {
            break;
        }
        if bytes.len() > limit {
            return Err(Error::Line {
                what: "the titan request line",
                limit,
            });
        }
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|source| Error::context("the titan request line is not text", source))
}

/// The Titan request line's URL and its three parameters. `size` is mandatory;
/// `mime` and `token` are optional. An unrecognised parameter is refused rather
/// than ignored: this route reads a body from a stranger, and a parameter the
/// handler does not understand is one it cannot bound.
#[derive(Debug)]
pub(super) struct TitanUpload {
    pub(super) token: Option<String>,
    pub(super) size: Option<usize>,
}

pub(super) fn titan_params(line: &str) -> Result<TitanUpload, &'static str> {
    let mut parts = line.split(';');
    let url = parts.next().unwrap_or("");
    if !url.starts_with("titan://") {
        return Err("Not a titan request");
    }
    let mut upload = TitanUpload {
        token: None,
        size: None,
    };
    for param in parts {
        let (key, value) = param
            .split_once('=')
            .ok_or("Titan parameter has no value")?;
        match key {
            "size" => upload.size = Some(value.parse().map_err(|_| "Size is not a number")?),
            // Accepted and ignored: the payload is a key whatever it says.
            "mime" => {}
            "token" => upload.token = Some(value.to_string()),
            _ => return Err("Unknown titan parameter"),
        }
    }
    Ok(upload)
}

/// The client address relayd passes ahead of the request, in PROXY protocol v1.
/// The address is the one the counters key on; a line this cannot read leaves
/// the caller's fallback rather than inventing one.
pub(super) fn proxy_address(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "PROXY" {
        return None;
    }
    match parts.next()? {
        "TCP4" | "TCP6" => parts.next().map(str::to_string),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
