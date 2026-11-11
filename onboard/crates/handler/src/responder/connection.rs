//! The FastCGI connection and the request environment.

use super::*;

use super::portal::portal_connection;
use super::reply::{too_many, Which};
use super::route::{gemini, http};

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::fastcgi::{self, Reply, Request};
use kyriakon_onboard_core::flow::rate;
use kyriakon_onboard_core::store::Certificate;

/// Accept connections for as long as the listener holds, which is until it fails:
/// a socket that has stopped accepting is not something this process can repair,
/// and rc.d's own check is where a human reads that the daemon is gone.
pub(super) async fn accept(
    listener: UnixListener,
    app: Arc<App>,
    channel: Channel,
) -> Result<(), Error> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| Error::context("cannot accept", e))?;
        let app = app.clone();
        tokio::spawn(async move {
            let outcome = match channel {
                Channel::FrontEnd => connection(stream, &app).await,
                Channel::Portal => portal_connection(stream, &app).await,
            };
            if let Err(e) = outcome {
                e.report("serving a connection");
            }
        });
    }
}

/// Answer the requests on one connection. Both front-ends connect for one request
/// and close, and gmid asks for the connection to be kept in case it has another,
/// so the loop runs until the peer closes or a record cannot be read.
pub(super) async fn connection(stream: UnixStream, app: &App) -> Result<(), Error> {
    let (mut reader, mut writer) = stream.into_split();
    loop {
        let request = match fastcgi::read_request(&mut reader, MAX_BODY).await? {
            Some(request) => request,
            None => return Ok(()),
        };
        let outcome = respond(app, &request).await;
        eprintln!(
            "kyriakon-onboard: {} {} {} {}",
            front_end(&request).word(),
            outcome.route,
            outcome.reply.code(),
            outcome.addr
        );
        say(
            &mut writer,
            &fastcgi::reply_bytes(&outcome.reply, request.id()),
        )
        .await?;
        if !request.keep_conn {
            return Ok(());
        }
    }
}

/// Write one reply and flush it, so the front-end reads a whole answer. The
/// connection, the three portal answers and the Titan reply all write here, so
/// a write that fails says the same thing everywhere.
pub(super) async fn say<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> Result<(), Error> {
    writer.write_all(bytes).await.map_err(|source| Error::Io {
        what: "write the reply",
        path: None,
        source,
    })?;
    writer.flush().await.map_err(|source| Error::Io {
        what: "flush the reply",
        path: None,
        source,
    })
}

/// Answer one request.
pub(super) async fn respond(app: &App, request: &Request) -> Outcome {
    let front = front_end(request);
    let incoming = read(front, request);

    // The counters first, so a request refused for being cross-origin or for
    // naming a route the service does not have is still counted.
    if !app.counter.allow_request(incoming.key) {
        return outcome(incoming, too_many(front, Which::Minute));
    }

    let reply = match front {
        FrontEnd::Gemini => gemini(app, request, &incoming).await,
        FrontEnd::Httpd => http(app, request, &incoming).await,
    };
    outcome(incoming, reply)
}

pub(super) fn outcome(incoming: Incoming, reply: Reply) -> Outcome {
    Outcome {
        reply,
        route: format!("/{}", incoming.path),
        addr: incoming.addr,
    }
}

/// The path, the key and the address, from the environment.
pub(super) fn read(front_end: FrontEnd, request: &Request) -> Incoming {
    let path = match front_end {
        // gmid decodes and cleans this before it sends it, and strips every
        // leading slash. Nothing else about it is trusted, so it is trimmed again
        // here and matched as a literal.
        FrontEnd::Gemini => request.value("GEMINI_URL_PATH").to_string(),
        // httpd passes the request URI as the client sent it, so it is decoded
        // here. The query is cut off before the decoding, so a percent-encoded "?"
        // stays part of the path and the query starts at the first real one.
        FrontEnd::Httpd => {
            let path = request.value("REQUEST_URI");
            decode(path.split('?').next().unwrap_or(""), false)
        }
    };
    let path = path.trim_start_matches('/').to_string();

    // httpd's own REMOTE_ADDR is relayd, one hop away, so the web front-end keys
    // on the header relayd `set`s. gmid sends no forwarded header of any kind, so
    // its REMOTE_ADDR is the address and a header read there would be one the
    // applicant wrote.
    let remote = request.value("REMOTE_ADDR");
    let forwarded = match front_end {
        FrontEnd::Httpd => request.get("HTTP_X_FORWARDED_FOR"),
        FrontEnd::Gemini => None,
    };
    let key = rate::key(forwarded, Some(remote));
    // The log line carries the address the counters keyed on, which is the
    // client's for the web front-end and not relayd's.
    let addr = match forwarded {
        Some(value) => value.rsplit(',').next().unwrap_or("").trim().to_string(),
        None => remote.to_string(),
    };
    let query = match front_end {
        FrontEnd::Gemini => request.value("QUERY_STRING").to_string(),
        FrontEnd::Httpd => String::new(),
    };
    Incoming {
        path,
        query,
        key,
        addr,
        certificate: match front_end {
            FrontEnd::Gemini => certificate(request),
            FrontEnd::Httpd => None,
        },
    }
}

/// The certificate a gemini client presented, if it presented one.
///
/// gmid sends `AUTH_TYPE` only when the client presented a certificate, as
/// `CERTIFICATE`; with none it omits the variable, and an absent value reads as
/// the empty string here. Every other field is copied as gmid sent it: nothing
/// verifies a chain, because there is none to verify and no issuer is trusted.
pub(super) fn certificate(request: &Request) -> Option<Certificate> {
    if request.value("AUTH_TYPE") != "CERTIFICATE" {
        return None;
    }
    Some(Certificate {
        hash: request.value("TLS_CLIENT_HASH").to_string(),
        subject: request.value("REMOTE_USER").to_string(),
        issuer: request.value("TLS_CLIENT_ISSUER").to_string(),
        not_before: request.value("TLS_CLIENT_NOT_BEFORE").to_string(),
        not_after: request.value("TLS_CLIENT_NOT_AFTER").to_string(),
    })
}

/// Percent-decode one value. A plus is a space in a form, which is what a browser
/// writes for one in `application/x-www-form-urlencoded`, and an ordinary
/// character in a path, where the specification requires `%20` for a space.
pub(super) fn decode(value: &str, plus_is_space: bool) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match hex(&bytes[i + 1..i + 3]) {
                Some(byte) => {
                    out.push(byte);
                    i += 3;
                }
                None => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(super) fn hex(pair: &[u8]) -> Option<u8> {
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    Some(digit(pair[0])? << 4 | digit(pair[1])?)
}

/// The form's fields, which is where a submission's answers arrive for either
/// method: the query of a GET and the body of a POST are one encoding.
pub(super) fn fields(raw: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = match pair.split_once('=') {
            Some((name, value)) => (name, value),
            None => (pair, ""),
        };
        out.insert(decode(name, true), decode(value, true));
    }
    out
}

/// Whether a POST declares the encoding its body is read as. A browser always
/// does.
pub(super) fn form_post(request: &Request) -> bool {
    request
        .value("CONTENT_TYPE")
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|t| t.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
}

#[cfg(test)]
mod tests;
