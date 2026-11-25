//! Reply helpers.

use super::*;

use askama::Template;

use crate::fastcgi::Reply;
use crate::page::NoticePage;

/// Served when a template could not be rendered. Static and interpolated with
/// nothing, so the one place with no markup around it cannot become somewhere a
/// field lands unescaped.
pub(super) const RENDER_FALLBACK: &str =
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Kyriakon</title></head><body><main><h2>Something went wrong</h2>\
<p>This is our fault, not yours. Try again in a moment.</p></main></body></html>";

/// A page that carries a capability in its URL or is a capability itself is never
/// stored and its URL is never sent as a referrer.
pub(super) fn capability<T: Template>(t: &T) -> Reply {
    Reply::capability(200, page_html(t))
}

pub(super) enum Which {
    Minute,
    Day,
}

pub(super) fn too_many(front_end: FrontEnd, which: Which) -> Reply {
    let message = match which {
        Which::Minute => {
            "Too many requests have come from this address in a short time. Wait a minute and try again."
        }
        Which::Day => {
            "Too many applications have been started from this address today. Try again tomorrow."
        }
    };
    match front_end {
        // 44 is gemini's own slow-down, and META is where a client shows the
        // reason, so the sentence the web page carries is the whole of it.
        FrontEnd::Gemini => Reply::gemini(44, message, String::new()),
        FrontEnd::Httpd => Reply::html(429, page_html(&notice("Too many requests", message))),
    }
}

/// The draft map is full of sources at their cap. That is a service-wide limit
/// and not one this caller spent, so it answers a temporary failure rather than
/// the per-address message.
pub(super) fn unavailable(front_end: FrontEnd) -> Reply {
    const MESSAGE: &str = "The application form is temporarily unavailable. Try again in a moment.";
    match front_end {
        FrontEnd::Gemini => Reply::gemini(40, TEMP_FAILURE, String::new()),
        FrontEnd::Httpd => Reply::html(503, page_html(&notice("Temporarily unavailable", MESSAGE))),
    }
}

/// A refusal of a request that is well formed and simply asks for something the
/// handler does not do. Not a field-level error: those go back into the form.
pub(super) fn refused(message: &str) -> Reply {
    Reply::html(403, page_html(&notice("Refused", message)))
}

pub(super) fn notice(title: &str, message: &str) -> NoticePage {
    NoticePage {
        title: title.to_string(),
        message: message.to_string(),
    }
}

/// The one place an error becomes a reply. The front end decides the framing;
/// the error kind decides whether the client may retry. The wording is the
/// page and the meta line the handlers already served.
pub(super) fn respond(error: &Error, front_end: FrontEnd) -> Reply {
    error.report("the request failed");
    match front_end {
        FrontEnd::Httpd => match error {
            Error::Refused(message) => refused(message),
            Error::Line { .. } => refused(&error.to_string()),
            _ => Reply::html(
                500,
                page_html(&notice(
                    "Something went wrong",
                    "This is our fault, not yours. Try again in a moment.",
                )),
            ),
        },
        FrontEnd::Gemini => match error {
            Error::Lookup(_) => Reply::gemini(50, "Permanent failure", String::new()),
            Error::Refused(message) => Reply::gemini(59, message, String::new()),
            Error::Line { .. } => Reply::gemini(59, &error.to_string(), String::new()),
            _ => Reply::gemini(40, TEMP_FAILURE, String::new()),
        },
    }
}

pub(super) fn page_html<T: Template>(t: &T) -> String {
    match t.render() {
        Ok(s) => s,
        Err(e) => {
            kyriakon_control_core::util::report(&e, "rendering a page");
            RENDER_FALLBACK.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_failure() -> Error {
        Error::Store(kyriakon_control_core::store::Error::ListedAccountMissing {
            name: "boom".to_string(),
        })
    }

    #[test]
    fn a_refusal_is_a_client_error_and_a_store_failure_is_a_server_error() {
        assert_eq!(
            respond(
                &Error::Refused("not this request".to_string()),
                FrontEnd::Httpd
            )
            .code(),
            403
        );
        assert_eq!(
            respond(
                &Error::Line {
                    what: "the request",
                    limit: 10
                },
                FrontEnd::Httpd
            )
            .code(),
            403
        );
        assert_eq!(respond(&store_failure(), FrontEnd::Httpd).code(), 500);
        assert_eq!(respond(&store_failure(), FrontEnd::Gemini).code(), 40);
        assert_eq!(
            respond(
                &Error::Lookup(kyriakon_control_core::store::Error::ListedAccountMissing {
                    name: "boom".to_string(),
                }),
                FrontEnd::Gemini
            )
            .code(),
            50
        );
        let refusal = respond(
            &Error::Refused("not this request".to_string()),
            FrontEnd::Gemini,
        );
        assert_eq!(refusal.code(), 59);
        match refusal {
            Reply::Gemini { meta, .. } => assert_eq!(meta, "not this request"),
            Reply::Http(_) => panic!("a gemini request got an http reply"),
        }
        assert_eq!(
            respond(
                &Error::Line {
                    what: "the request",
                    limit: 10
                },
                FrontEnd::Gemini
            )
            .code(),
            59
        );
    }

    /// A full draft map is a service-wide limit, so the web page must not tell
    /// the reader that this address has spent a day it never started.
    #[test]
    fn an_unavailable_draft_map_is_not_the_per_address_message() {
        let web = unavailable(FrontEnd::Httpd);
        assert_eq!(web.code(), 503);
        let body = String::from_utf8_lossy(web.body());
        assert!(body.contains("temporarily unavailable"), "{body}");
        assert!(!body.contains("Too many applications"), "{body}");

        let capsule = unavailable(FrontEnd::Gemini);
        assert_eq!(capsule.code(), 40);
        let head = String::from_utf8_lossy(&capsule.head_block()).into_owned();
        assert!(head.starts_with("40 Temporary failure"), "{head}");
    }
}
