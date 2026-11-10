//! Reply helpers.

use super::*;

use askama::Template;

use crate::fcgi::Reply;
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

pub(super) fn server_error(why: &str) -> Reply {
    eprintln!("kyriakon-onboard: {why}");
    Reply::html(
        500,
        page_html(&notice(
            "Something went wrong",
            "This is our fault, not yours. Try again in a moment.",
        )),
    )
}

pub(super) fn page_html<T: Template>(t: &T) -> String {
    match t.render() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kyriakon-onboard: cannot render a page: {e}");
            RENDER_FALLBACK.to_string()
        }
    }
}
