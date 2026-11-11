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
            kyriakon_onboard_core::util::report(&e, "rendering a page");
            RENDER_FALLBACK.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_failure() -> Error {
        Error::Store(kyriakon_onboard_core::store::Error::Refused(
            "boom".to_string(),
        ))
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
                &Error::Lookup(kyriakon_onboard_core::store::Error::Refused(
                    "boom".to_string()
                )),
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
}
