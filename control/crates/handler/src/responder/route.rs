//! The route table and the dispatcher.

use super::*;

use super::account::{account, account_action, account_close, account_export, login, logout};
use super::apply::{apply, webhook};
use super::connection::{fields, form_post};
use super::decide::{decide_confirm, decide_file, password_file, password_page};
use super::flow::{branch_step, own_origin, root};
use super::gemini::{acceptances, capsule_apply, mirrored};
use super::reply::{page_html, refused};
use super::status::status;

use std::collections::BTreeMap;

use crate::capsule;
use crate::fastcgi::{Reply, Request};
use crate::page::LoginPage;

/// Which front ends a route answers on. A route that serves one front end is a
/// row that says so here: the alternative was an arm in each front end's own
/// chain, where a route added to one and not the other answered a page on one
/// and a refusal on the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fronts {
    Both,
    Httpd,
    /// The pages the capsule carries as gemtext and the web front end does not
    /// serve: the staged documents have no HTML rendering, so a web row for them
    /// would have nothing to send.
    Gemini,
}

impl Fronts {
    pub(super) fn serves(self, front: FrontEnd) -> bool {
        match (self, front) {
            (Fronts::Both, _) => true,
            (Fronts::Httpd, FrontEnd::Httpd) => true,
            (Fronts::Gemini, FrontEnd::Gemini) => true,
            (Fronts::Httpd, FrontEnd::Gemini) | (Fronts::Gemini, FrontEnd::Httpd) => false,
        }
    }
}

/// The method a row answers, as the web front end reads it. A capsule request
/// carries no method at all, so a row's method is not checked for one; `Any` is
/// the method of a row only the capsule serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Method {
    Get,
    Post,
    Any,
}

impl Method {
    pub(super) fn accepts(self, front: FrontEnd, method: &str) -> bool {
        match (front, self) {
            // A gemini request has no verb to check.
            (FrontEnd::Gemini, _) | (FrontEnd::Httpd, Method::Any) => true,
            // A browser sends HEAD where it would send GET, and httpd drops the
            // body of a HEAD response on its own, so the two read one route.
            (FrontEnd::Httpd, Method::Get) => method == "GET" || method == "HEAD",
            (FrontEnd::Httpd, Method::Post) => method == "POST",
        }
    }
}

/// What a row answers with. `dispatch` has one arm per variant, so a row cannot
/// name a handler that has no arm, and a new handler cannot be added without the
/// compiler asking where it is called.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Handler {
    Webhook,
    Status,
    DecideConfirm,
    DecideFile,
    PasswordPage,
    PasswordFile,
    Apply,
    LoginPage,
    LoginSubmit,
    Logout,
    AccountClose,
    AccountAction,
    Account,
    AccountExport,
    Root,
    BranchStep,
    CapsuleApply,
    Mirrored,
    Acceptances,
}

impl Handler {
    /// Whether the row acts on the session cookie. These are the routes that
    /// change an account, so they are the ones `own_origin` requires the exact
    /// origin for: the cookie is the identity, and a browser can attach it to a
    /// request whose `Origin` it withholds (Safari does, from a sandboxed frame on
    /// a sibling subdomain). Logging in is not one of them: it opens the session
    /// the request did not have.
    fn takes_session(self) -> bool {
        matches!(
            self,
            Handler::Logout
                | Handler::AccountClose
                | Handler::AccountAction
                | Handler::AccountExport
        )
    }
}

/// One route: the path, the method, and the handler that answers it, with the
/// front ends it exists on. `capsule::PAGES` is the same shape of table, and the
/// tests read both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Route {
    /// The path a request is matched against, with no leading slash. A path
    /// ending in `/` owns the paths under it and hands the handler the rest;
    /// every other row is exact.
    pub(super) path: &'static str,
    pub(super) method: Method,
    pub(super) fronts: Fronts,
    pub(super) handler: Handler,
}

impl Route {
    /// The path after this row's prefix, when the row owns the path.
    pub(super) fn matches<'a>(&self, path: &'a str) -> Option<&'a str> {
        if self.path.ends_with('/') {
            path.strip_prefix(self.path)
        } else {
            (path == self.path).then_some("")
        }
    }
}

/// Every route, once. Order carries no meaning: the longest matching prefix owns
/// the path, and the method picks between rows that share one, so a row cannot be
/// shadowed by where it sits in the list. A route that serves one front end says
/// so in its row rather than in that front end's own chain.
pub(super) static ROUTES: &[Route] = &[
    // The payment webhook is not this form: Stripe's bytes and signature header,
    // and no Origin. It is the one row the form preflight does not precede, and
    // the handler stores what it is given without verifying it: the drain holds
    // the secret and is the half that decides.
    Route {
        path: "stripe/webhook",
        method: Method::Post,
        fronts: Fronts::Httpd,
        handler: Handler::Webhook,
    },
    // The applicant flow's entry. The web form's submission and the capsule's
    // first page are one route, because both front ends start the flow here; each
    // renders its own. A capsule answer continues under `apply/`, which the web
    // front end does not serve.
    Route {
        path: "apply",
        method: Method::Post,
        fronts: Fronts::Both,
        handler: Handler::Apply,
    },
    Route {
        path: "apply/",
        method: Method::Any,
        fronts: Fronts::Gemini,
        handler: Handler::CapsuleApply,
    },
    // The status page, which both front ends serve and each renders.
    Route {
        path: "status/",
        method: Method::Get,
        fronts: Fronts::Both,
        handler: Handler::Status,
    },
    // The account page and the web form's actions on it. A capsule client has no
    // session and no POST: its certificate is its whole identity, so the read is
    // the only account route the capsule carries.
    Route {
        path: "account/close",
        method: Method::Post,
        fronts: Fronts::Httpd,
        handler: Handler::AccountClose,
    },
    Route {
        path: "account/",
        method: Method::Post,
        fronts: Fronts::Httpd,
        handler: Handler::AccountAction,
    },
    Route {
        path: "account",
        method: Method::Get,
        fronts: Fronts::Both,
        handler: Handler::Account,
    },
    Route {
        path: "account",
        method: Method::Post,
        fronts: Fronts::Httpd,
        handler: Handler::AccountExport,
    },
    // Signing in and out, and the two links a decision or a password is filed
    // through: web sessions and web forms, which the capsule does not carry.
    Route {
        path: "login",
        method: Method::Get,
        fronts: Fronts::Httpd,
        handler: Handler::LoginPage,
    },
    Route {
        path: "login",
        method: Method::Post,
        fronts: Fronts::Httpd,
        handler: Handler::LoginSubmit,
    },
    Route {
        path: "logout",
        method: Method::Post,
        fronts: Fronts::Httpd,
        handler: Handler::Logout,
    },
    Route {
        path: "decide/",
        method: Method::Get,
        fronts: Fronts::Httpd,
        handler: Handler::DecideConfirm,
    },
    Route {
        path: "decide/",
        method: Method::Post,
        fronts: Fronts::Httpd,
        handler: Handler::DecideFile,
    },
    Route {
        path: "password/",
        method: Method::Get,
        fronts: Fronts::Httpd,
        handler: Handler::PasswordPage,
    },
    Route {
        path: "password/",
        method: Method::Post,
        fronts: Fronts::Httpd,
        handler: Handler::PasswordFile,
    },
    // The front pages: the web form's applicant page and the capsule's catalogue,
    // from one path. The branch step shares the path under a POST, and is a row
    // of its own for that reason.
    Route {
        path: "",
        method: Method::Get,
        fronts: Fronts::Both,
        handler: Handler::Root,
    },
    Route {
        path: "",
        method: Method::Post,
        fronts: Fronts::Httpd,
        handler: Handler::BranchStep,
    },
    // The staged documents and the acceptances page are gemtext and have no HTML
    // rendering, so they are the capsule's alone. One row per document, and the
    // test compares this list with `capsule::PAGES`, because the route, the file
    // and the label must name the same page.
    Route {
        path: "terms",
        method: Method::Any,
        fronts: Fronts::Gemini,
        handler: Handler::Mirrored,
    },
    Route {
        path: "aup",
        method: Method::Any,
        fronts: Fronts::Gemini,
        handler: Handler::Mirrored,
    },
    Route {
        path: "privacy",
        method: Method::Any,
        fronts: Fronts::Gemini,
        handler: Handler::Mirrored,
    },
    Route {
        path: "keys",
        method: Method::Any,
        fronts: Fronts::Gemini,
        handler: Handler::Mirrored,
    },
    Route {
        path: capsule::ACCEPTANCES,
        method: Method::Any,
        fronts: Fronts::Gemini,
        handler: Handler::Acceptances,
    },
];

/// Whether the form's preflight is this path's. The payment webhook reads its own
/// bytes and carries no Origin, so it is not a form route; every other row is.
pub(super) fn takes_form(path: &str) -> bool {
    !ROUTES
        .iter()
        .any(|row| row.handler == Handler::Webhook && row.matches(path).is_some())
}

/// Whether a session cookie is the identity of the request this path answers.
pub(super) fn takes_session(path: &str) -> bool {
    ROUTES
        .iter()
        .any(|row| row.handler.takes_session() && row.matches(path).is_some())
}

/// What one path resolves to.
#[derive(Debug)]
pub(super) enum Resolution<'a> {
    /// The row that owns the path, and the path after its prefix.
    Row(&'static Route, &'a str),
    /// A row owns the path and not this method, which is the web's 405: a longer
    /// prefix does not fall through to a shorter one.
    WrongMethod,
    /// No row serves this path on this front end.
    Missing,
}

/// The row one request dispatches to, on one front end.
pub(super) fn route<'a>(front: FrontEnd, path: &'a str, method: &str) -> Resolution<'a> {
    let mut depth = 0;
    let mut found = None;
    let mut matched = false;
    for row in ROUTES {
        if !row.fronts.serves(front) {
            continue;
        }
        let Some(rest) = row.matches(path) else {
            continue;
        };
        matched = true;
        if row.path.len() < depth {
            continue;
        }
        if row.path.len() > depth {
            depth = row.path.len();
            found = None;
        }
        if found.is_none() && row.method.accepts(front, method) {
            found = Some((row, rest));
        }
    }
    match found {
        Some((row, rest)) => Resolution::Row(row, rest),
        None if matched => Resolution::WrongMethod,
        None => Resolution::Missing,
    }
}

/// One request as a handler reads it.
pub(super) struct Call<'a> {
    pub(super) front: FrontEnd,
    pub(super) request: &'a Request,
    pub(super) incoming: &'a Incoming,
    /// The path after the matched row's prefix: a token for `status/`, a draft
    /// path for `apply/`, an action for `account/`, nothing for an exact row.
    pub(super) rest: &'a str,
}

impl Call<'_> {
    /// The form's fields as a GET carries them.
    pub(super) fn query(&self) -> BTreeMap<String, String> {
        fields(self.request.value("QUERY_STRING"))
    }

    /// The form's fields as a POST carries them.
    pub(super) fn form(&self) -> BTreeMap<String, String> {
        fields(&String::from_utf8_lossy(&self.request.body))
    }
}

/// The table's answer to one request: the row's handler, or the front end's own
/// refusal for a path or a method it does not serve.
pub(super) async fn answer(
    app: &App,
    front: FrontEnd,
    request: &Request,
    incoming: &Incoming,
) -> Reply {
    let method = request.value("REQUEST_METHOD");
    match route(front, &incoming.path, method) {
        Resolution::Row(row, rest) => {
            let call = Call {
                front,
                request,
                incoming,
                rest,
            };
            dispatch(app, row.handler, &call).await
        }
        // The capsule has no verbs, so a method it does not serve cannot arise.
        Resolution::WrongMethod => method_not_allowed(),
        // An empty body behind a path this service does not serve, as the old
        // HTTP daemon's router left it, and the capsule's status 51.
        Resolution::Missing => match front {
            FrontEnd::Httpd => Reply::html(404, String::new()),
            FrontEnd::Gemini => Reply::gemini(51, "Not found", String::new()),
        },
    }
}

/// One arm per handler. The protocol-specific rendering is inside the handler,
/// which is what lets one row answer both front ends.
pub(super) async fn dispatch(app: &App, handler: Handler, call: &Call<'_>) -> Reply {
    match handler {
        Handler::Webhook => webhook(app, call.request).await,
        Handler::Status => status(app, call).await,
        Handler::DecideConfirm => decide_confirm(app, call).await,
        Handler::DecideFile => decide_file(app, call).await,
        Handler::PasswordPage => password_page(app, call).await,
        Handler::PasswordFile => password_file(app, call).await,
        Handler::Apply => apply(app, call).await,
        Handler::LoginPage => Reply::capability(200, page_html(&LoginPage { error: None })),
        Handler::LoginSubmit => login(app, call.request).await,
        Handler::Logout => logout(app, call.request).await,
        Handler::AccountClose => account_close(app, call.request).await,
        Handler::AccountAction => account_action(app, call).await,
        Handler::Account => account(app, call).await,
        Handler::AccountExport => account_export(app, call.request).await,
        Handler::Root => root(app, call).await,
        Handler::BranchStep => branch_step(app, call.form()),
        Handler::CapsuleApply => capsule_apply(app, call.incoming, call.rest).await,
        Handler::Mirrored => mirrored(app, call),
        Handler::Acceptances => acceptances(app),
    }
}

/// The web front-end: the form's preflight, then the table.
pub(super) async fn http(app: &App, request: &Request, incoming: &Incoming) -> Reply {
    let method = request.value("REQUEST_METHOD");
    // Whether the preflight is this path's. It is the form's, and the payment
    // webhook's body is not the form's: see `takes_form`.
    let preflight = takes_form(&incoming.path);
    // A session route is answered out of the cookie, so it requires this site's
    // own Origin rather than the Sec-Fetch-Site fallback: see `own_origin`.
    let session = takes_session(&incoming.path);
    // A POST from somewhere that is not this form is refused for being that,
    // whatever path it names, as the middleware in front of the old HTTP daemon's
    // router did: the check runs before a route is chosen.
    if preflight && method == "POST" && !own_origin(request, session) {
        // The two values, in the refusal: neither is a secret and the pair is
        // the only way to tell which kind of client was refused.
        return refused(&format!(
            "A submission has to come from this form's own page. This one sent origin {:?} \
             and sec-fetch-site {:?}.",
            request.get("HTTP_ORIGIN").unwrap_or("<none>"),
            request.get("HTTP_SEC_FETCH_SITE").unwrap_or("<none>"),
        ));
    }
    // The front-end is mid-request, so a body over the cap is answered rather than
    // the connection dropped. It is the same refusal a body over the old HTTP
    // daemon's limit drew, and it is the body's whole length that decides it,
    // because a form read from a truncated body is a form the applicant did not
    // write.
    if preflight && request.body_too_large {
        return Reply::html(413, String::new());
    }
    // The body of a POST is read as `application/x-www-form-urlencoded`, so a
    // request that declares something else is not a request either route that
    // takes a body answers.
    if preflight && method == "POST" && !form_post(request) {
        return Reply::html(415, String::new());
    }
    answer(app, FrontEnd::Httpd, request, incoming).await
}

pub(super) fn method_not_allowed() -> Reply {
    Reply::html(405, String::new())
}

/// The gemini front-end: the same table the web's routes are in, read with no
/// method to check and no form to read. The apply route reads an answer from
/// `QUERY_STRING`, which gmid sends still percent-encoded and the responder
/// decodes itself rather than read from `GEMINI_SEARCH_STRING`: that copy is sent
/// only for a query with no `=` in it, and its decoder maps `+` to a space, which
/// is not the reading the specification gives a URI query.
///
/// The certificate, when one was presented, decides one thing: whether an
/// account's pin matches its hash. A certificate that matches nothing gets the
/// same pages a stranger gets, with its own fingerprint and where to register
/// it, and never a page that says the certificate is unknown.
pub(super) async fn gemini(app: &App, request: &Request, incoming: &Incoming) -> Reply {
    answer(app, FrontEnd::Gemini, request, incoming).await
}

#[cfg(test)]
mod tests;
