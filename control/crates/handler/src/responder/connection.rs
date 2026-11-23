//! The FastCGI connection and the request environment.

use super::*;

use super::reply::{too_many, Which};
use super::route::{gemini, http};

use std::collections::BTreeMap;

use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::fastcgi::{Answer, Reply, Request};
use kyriakon_control_core::flow::rate;
use kyriakon_control_core::store::Certificate;
use kyriakon_control_core::util::percent_decode;

/// Answer one request on a FastCGI listener: the routes' answer, with the log
/// line every front-end gets. The deadline and the connection loop are the core
/// server's.
pub(super) async fn fastcgi_answer(app: Arc<App>, request: Request) -> Answer {
    let outcome = respond(&app, &request).await;
    kyriakon_control_core::util::log(&format!(
        "kyriakon-control: {} {} {} {}",
        front_end(&request).word(),
        outcome.route,
        outcome.reply.code(),
        outcome.addr
    ));
    Answer::Reply(outcome.reply)
}

/// Write one reply and flush it, so the front-end reads a whole answer. The
/// portal's answers and the Titan reply write here, so a write that fails says
/// the same thing everywhere.
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
        // The path is percent-decoded, so `%0A` and `%1B` arrive here as a
        // newline and an escape. The log line is the audit trail: one request
        // must be one line, and a control character would let an unauthenticated
        // client forge a second one.
        route: format!("/{}", kyriakon_control_core::util::clean(&incoming.path)),
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
            percent_decode(path.split('?').next().unwrap_or(""), false)
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
        out.insert(
            percent_decode(name, true),
            line_endings(percent_decode(value, true)),
        );
    }
    out
}

/// Normalise a form value's line breaks to LF, the one form the terminal, the
/// store and the mail body use.
///
/// A browser submits a textarea's line breaks as CRLF: HTML's form submission
/// algorithm normalises them before encoding, so the LF the applicant typed
/// arrives as `%0D%0A`. Every form field crosses this decoder, so this is the
/// one place that has to know; a value that still holds a lone carriage return
/// is normalised too, because the same algorithm turns one into CRLF before
/// sending it.
fn line_endings(value: String) -> String {
    if !value.contains('\r') {
        return value;
    }
    value.replace("\r\n", "\n").replace('\r', "\n")
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

/// The fuzz crate's entry point: the decoders the public form runs on, over an
/// arbitrary string. Nothing in the crate calls it, and the module it lives in
/// stays private.
#[cfg(feature = "fuzz")]
#[doc(hidden)]
pub fn fuzz_decode(raw: &str) {
    let _ = fields(raw);
    let _ = percent_decode(raw, true);
    let _ = percent_decode(raw, false);
}

#[cfg(test)]
mod tests;
