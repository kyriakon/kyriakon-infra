//! The portal status socket.

use super::*;

use super::connection::say;
use super::flow::{application_problems, build_record, file_application, mail_keys_from_form};
use super::status::{record_for, status_page};

use std::collections::BTreeMap;

use time::OffsetDateTime;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

use kyriakon_control_core::flow::rate;
use kyriakon_control_core::ipc;
use kyriakon_control_core::mail::pgp;
use kyriakon_control_core::store;

/// Answer to a portal status read past the per-address counter. It is the
/// portal's screen that shows it, so the words are the screen's.
pub(super) const SLOW_STATUS: &str =
    "Too many status reads from this address. Wait a minute and try again.";

/// One line from the portal, capped before the buffer grows. `None` is a
/// connection that closed before the line was finished.
pub(super) async fn portal_line<R>(reader: &mut R, limit: usize) -> Result<Option<String>, Error>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut bytes = Vec::new();
    loop {
        let mut b = [0u8; 1];
        match reader.read(&mut b).await {
            Ok(0) => return Ok(None),
            Ok(_) => bytes.push(b[0]),
            Err(source) => {
                return Err(Error::Io {
                    what: "read the portal request",
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
                what: "the portal request",
                limit,
            });
        }
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|source| Error::context("the portal request is not text", source))
}

/// Answer one portal request: a status read is one line in, one line out, and a
/// filed application adds one line of JSON. The portal is not a web front-end,
/// and the one question it asks is answered in a line.
pub(super) async fn portal_connection(stream: UnixStream, app: &App) -> Result<(), Error> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let Some(line) = portal_line(&mut reader, ipc::MAX_LINE).await? else {
        return Ok(());
    };
    if let Some(address) = ipc::parse_check_request(&line) {
        let address = address.to_string();
        let body = match portal_line(&mut reader, ipc::MAX_BODY).await {
            Ok(Some(body)) => body,
            // Answer rather than just closing: a session that lost the handler
            // mid-way still gets the advisory and can file.
            Ok(None) => return Err(Error::Refused(Refusal::PortalClosedBeforeApplication)),
            Err(e) => {
                let reply = ipc::CheckAnswer::Advisory(e.to_string());
                return say(&mut writer, reply.line().as_bytes()).await;
            }
        };
        let reply = portal_check(app, &address, &body).await;
        // The route and the address are the log line; the verdict text may
        // quote a User ID, so it is not logged.
        kyriakon_control_core::util::log(&format!("kyriakon-control: portal /check {address}"));
        return say(&mut writer, reply.line().as_bytes()).await;
    }
    if let Some(address) = ipc::parse_file_request(&line) {
        let address = address.to_string();
        let body = match portal_line(&mut reader, ipc::MAX_BODY).await {
            Ok(Some(body)) => body,
            Ok(None) => return Err(Error::Refused(Refusal::PortalClosedBeforeApplication)),
            // Answer rather than just closing: the portal can tell the reader
            // what happened at the end of a long session.
            Err(e) => {
                let reply = ipc::file_answer(None, &e.to_string());
                return say(&mut writer, reply.as_bytes()).await;
            }
        };
        let reply = portal_file(app, &address, &body).await;
        // The route and the address are the log line every front-end gets; the
        // answers and the token never are. The code a refusal gets is not 200,
        // because a count of filed applications reads this line.
        let code = if reply.starts_with("OK ") { 200 } else { 422 };
        kyriakon_control_core::util::log(&format!(
            "kyriakon-control: portal /apply {code} {address}"
        ));
        return say(&mut writer, reply.as_bytes()).await;
    }
    let Some((address, token)) = ipc::parse_request(&line) else {
        return Err(Error::Refused(Refusal::PortalNoStatusRequest));
    };
    let answer = portal_answer(app, address, token).await;
    // The route carries the token and the address, which is the log line every
    // other front-end gets; the answer never does.
    kyriakon_control_core::util::log(&format!(
        "kyriakon-control: portal /status/{token} 200 {address}"
    ));
    say(&mut writer, answer.line().as_bytes()).await
}

/// File one completed application the portal checked, through the same builder
/// and writer the web form and the capsule use. The handler validates every
/// field again, so a bug in the portal cannot become a filed record the web form
/// would have refused.
pub(super) async fn portal_file(app: &App, address: &str, body: &str) -> String {
    let key = rate::key(None, Some(address));
    if !app.counter.allow_request(key) {
        return ipc::file_answer(None, SLOW_STATUS);
    }
    let form: BTreeMap<String, String> = match serde_json::from_str(body) {
        Ok(form) => form,
        Err(e) => return ipc::file_answer(None, &format!("the application: {e}")),
    };
    let (errors, inspected) = application_problems(app, &form).await;
    if !errors.is_empty() {
        return ipc::file_answer(None, &errors.join(" "));
    }
    match app.counter.allow_draft(key) {
        rate::Admission::Allowed => {}
        rate::Admission::Denied => {
            return ipc::file_answer(
                None,
                "Too many applications have been started from this address today. Try again tomorrow.",
            );
        }
        rate::Admission::Unavailable => {
            return ipc::file_answer(None, "Temporary failure. Try again in a moment.");
        }
    }
    let token = match store::status_token().await {
        Ok(token) => token,
        Err(e) => {
            e.report("the portal");
            return ipc::file_answer(None, "Temporary failure. Try again in a moment.");
        }
    };
    let body_branch = form.get("whose").map(|v| v.trim()) == Some("body");
    let mail_keys = match mail_keys_from_form(&form, body_branch, &inspected) {
        Ok(keys) => keys,
        Err(e) => {
            e.report("the portal");
            return ipc::file_answer(None, "Temporary failure. Try again in a moment.");
        }
    };
    let record = build_record(app, &form, body_branch, &token, "tui", mail_keys);
    if let Err(e) = file_application(app, &record).await {
        e.report("the portal");
        return ipc::file_answer(None, "Temporary failure. Try again in a moment.");
    }
    ipc::file_answer(Some(&token), "")
}

/// Inspect one key answer for the terminal. The terminal runs no helper and
/// holds no exec promise; this is the same inspection the form and the account
/// page use, over the portal's own socket.
pub(super) async fn portal_check(app: &App, address: &str, body: &str) -> ipc::CheckAnswer {
    // The same per-address counter as a status read: an unauthenticated SSH
    // client must not use a check as a fork or CPU amplifier. A client past the
    // limit gets the advisory, so its application still files (ADR 0008).
    if !app.counter.allow_request(rate::key(None, Some(address))) {
        return ipc::CheckAnswer::Advisory(SLOW_STATUS.to_string());
    }
    let material: String = match serde_json::from_str(body) {
        Ok(material) => material,
        Err(e) => return ipc::CheckAnswer::Advisory(format!("the key: {e}")),
    };
    match pgp::public_key_async(&material).await {
        Ok(checked) => {
            if let Some(err) = checked.helper_error() {
                kyriakon_control_core::util::report(err, "keygen-check");
            }
            if let Some(why) = checked.refusal() {
                ipc::CheckAnswer::Refused(why.to_string())
            } else if let Some(why) = checked.advisory() {
                ipc::CheckAnswer::Advisory(why.to_string())
            } else {
                ipc::CheckAnswer::Clean
            }
        }
        // Not a public key block at all is the form's refusal, not an advisory.
        Err(e) => ipc::CheckAnswer::Refused(e.to_string()),
    }
}

/// The stage a token names, or the one notice an unknown, expired or
/// rate-limited read gets. The same counter and the same record read as the two
/// front-ends, so the portal cannot learn more than the status page says.
pub(super) async fn portal_answer(app: &App, address: &str, token: &str) -> ipc::Answer {
    if !app.counter.allow_request(rate::key(None, Some(address))) {
        return ipc::Answer::Notice(SLOW_STATUS.to_string());
    }
    let page = status_page(
        record_for(app, token).await,
        None,
        OffsetDateTime::now_utc(),
    );
    if page.notice.is_empty() {
        ipc::Answer::Stage(page.stage)
    } else {
        ipc::Answer::Notice(page.notice)
    }
}

#[cfg(test)]
mod tests;
