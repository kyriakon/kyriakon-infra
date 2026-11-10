//! The portal status socket.

use super::*;

use std::collections::BTreeMap;

use time::OffsetDateTime;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

use crate::{portal_ipc, rate, store};

/// Answer to a portal status read past the per-address counter. It is the
/// portal's screen that shows it, so the words are the screen's.
pub(super) const SLOW_STATUS: &str =
    "Too many status reads from this address. Wait a minute and try again.";

/// One line from the portal, capped before the buffer grows. `None` is a
/// connection that closed before the line was finished.
pub(super) async fn portal_line<R>(reader: &mut R, limit: usize) -> Result<Option<String>, String>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut bytes = Vec::new();
    loop {
        let mut b = [0u8; 1];
        match reader.read(&mut b).await {
            Ok(0) => return Ok(None),
            Ok(_) => bytes.push(b[0]),
            Err(e) => return Err(format!("cannot read the portal request: {e}")),
        }
        if b[0] == b'\n' {
            break;
        }
        if bytes.len() > limit {
            return Err(format!("the portal request is longer than {limit} bytes"));
        }
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|e| format!("the portal request is not text: {e}"))
}

/// Answer one portal request: a status read is one line in, one line out, and a
/// filed application adds one line of JSON. The portal is not a web front-end,
/// and the one question it asks is answered in a line.
pub(super) async fn portal_connection(stream: UnixStream, app: &App) -> Result<(), String> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let Some(line) = portal_line(&mut reader, portal_ipc::MAX_LINE).await? else {
        return Ok(());
    };
    if let Some(address) = portal_ipc::parse_file_request(&line) {
        let address = address.to_string();
        let body = match portal_line(&mut reader, portal_ipc::MAX_BODY).await {
            Ok(Some(body)) => body,
            Ok(None) => return Err("the portal closed before sending the application".to_string()),
            // Answer rather than just closing: the portal can tell the reader
            // what happened at the end of a long session.
            Err(e) => {
                let reply = portal_ipc::file_answer(None, &e);
                return say(&mut writer, reply.as_bytes()).await;
            }
        };
        let reply = portal_file(app, &address, &body).await;
        // The route and the address are the log line every front-end gets; the
        // answers and the token never are. The code a refusal gets is not 200,
        // because a count of filed applications reads this line.
        let code = if reply.starts_with("OK ") { 200 } else { 422 };
        eprintln!("kyriakon-onboard: portal /apply {code} {address}");
        return say(&mut writer, reply.as_bytes()).await;
    }
    let Some((address, token)) = portal_ipc::parse_request(&line) else {
        return Err("the portal sent no status request".to_string());
    };
    let answer = portal_answer(app, address, token).await;
    // The route carries the token and the address, which is the log line every
    // other front-end gets; the answer never does.
    eprintln!("kyriakon-onboard: portal /status/{token} 200 {address}");
    say(&mut writer, answer.line().as_bytes()).await
}

/// File one completed application the portal checked, through the same builder
/// and writer the web form and the capsule use. The handler validates every
/// field again, so a bug in the portal cannot become a filed record the web form
/// would have refused.
pub(super) async fn portal_file(app: &App, address: &str, body: &str) -> String {
    let key = rate::key(None, Some(address));
    if !app.counter.allow_request(key) {
        return portal_ipc::file_answer(None, SLOW_STATUS);
    }
    let form: BTreeMap<String, String> = match serde_json::from_str(body) {
        Ok(form) => form,
        Err(e) => return portal_ipc::file_answer(None, &format!("the application: {e}")),
    };
    let errors = application_problems(app, &form);
    if !errors.is_empty() {
        return portal_ipc::file_answer(None, &errors.join(" "));
    }
    if !app.counter.allow_draft(key) {
        return portal_ipc::file_answer(
            None,
            "Too many applications have been started from this address today. Try again tomorrow.",
        );
    }
    let token = match store::status_token().await {
        Ok(token) => token,
        Err(e) => {
            eprintln!("kyriakon-onboard: {e}");
            return portal_ipc::file_answer(None, "Temporary failure. Try again in a moment.");
        }
    };
    let body_branch = form.get("whose").map(String::as_str) == Some("body");
    let record = match build_record(app, &form, body_branch, &token, "tui") {
        Ok(record) => record,
        Err(e) => {
            eprintln!("kyriakon-onboard: {e}");
            return portal_ipc::file_answer(None, "Temporary failure. Try again in a moment.");
        }
    };
    if let Err(e) = file_application(app, &record).await {
        eprintln!("kyriakon-onboard: {e}");
        return portal_ipc::file_answer(None, "Temporary failure. Try again in a moment.");
    }
    portal_ipc::file_answer(Some(&token), "")
}

/// The stage a token names, or the one notice an unknown, expired or
/// rate-limited read gets. The same counter and the same record read as the two
/// front-ends, so the portal cannot learn more than the status page says.
pub(super) async fn portal_answer(app: &App, address: &str, token: &str) -> portal_ipc::Answer {
    if !app.counter.allow_request(rate::key(None, Some(address))) {
        return portal_ipc::Answer::Notice(SLOW_STATUS.to_string());
    }
    let page = status_page(
        record_for(app, token).await,
        None,
        OffsetDateTime::now_utc(),
    );
    if page.notice.is_empty() {
        portal_ipc::Answer::Stage(page.stage)
    } else {
        portal_ipc::Answer::Notice(page.notice)
    }
}

#[cfg(test)]
mod tests;
