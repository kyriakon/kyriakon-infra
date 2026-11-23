//! The responder: the face that answers both front-ends.
//!
//! httpd's vhost for `signup.kyriakon.net` and gmid's signup block both reach this
//! over their own unix sockets, and it serves the same routes to both: the applicant page,
//! the branch step, the submission, the account page and the status page. The
//! portal has a socket of its own and one request on it: the stage a filed
//! application has reached, answered without repeating an answer.
//! The routes, the pages and the wording are what the service served when it was an
//! HTTP daemon on a loopback port with relayd in front of it; what changed is the
//! last hop. A request arrives as a CGI environment rather than as an HTTP
//! request, and the reply is framed for whichever front-end asked.
//!
//! Both front ends read one route table (`ROUTES`): a row is a path, a method and
//! a handler, and the row says which front ends serve it. A page the capsule
//! carries and the web does not is a row that says so, not an arm missing from one
//! of two chains, and a handler that both serve renders for whichever asked.
//!
//! Nothing but what a route needs is read from that environment. The variables are
//! built by the front-end out of the request line, out of the client's
//! certificate, or out of its own configuration, and only the last of those is
//! ours, so the reading of each one is stated where it is read:
//!
//! * A Titan connection's first line is relayd's PROXY line, read with the same
//!   line bound as the request line rather than a bound of its own.
//! * The path is `GEMINI_URL_PATH` for gmid, which decodes and cleans it before it
//!   sends it and strips every leading slash, and `REQUEST_URI` for httpd, which
//!   passes the client's own spelling. It matches the route names, indexes the
//!   page map the handler read at startup, or carries a status token that is
//!   checked against the 26-character alphabet. It never names a file on disk and
//!   never builds a path.
//! * `QUERY_STRING` and the body are the form's fields, and both arrive still
//!   percent-encoded. The responder decodes them itself.
//! * `REMOTE_ADDR` is the socket peer, which is the address the counters key on
//!   for gmid, whose requests carry no forwarded header of any kind. httpd's
//!   `REMOTE_ADDR` is relayd, so the web front-end keys on `HTTP_X_FORWARDED_FOR`,
//!   which relayd `set`s rather than appending to.
//! * `SERVER_NAME`, `SERVER_PORT`, `PATH_INFO`, `SCRIPT_NAME`, `PATH_TRANSLATED`,
//!   `SERVER_SOFTWARE`, `GATEWAY_INTERFACE` and `SERVER_PROTOCOL` are the client's
//!   spelling or a constant, and no code path here selects on any of them.
//! * `AUTH_TYPE` is tested for its value rather than for its presence, because
//!   gmid always sends the variable and sets it to `CERTIFICATE` only when a
//!   certificate was provided. The certificate's `TLS_CLIENT_HASH` is compared
//!   against the pins on the account and nothing else is: `REMOTE_USER`,
//!   `TLS_CLIENT_ISSUER` and the validity dates are recorded with the request
//!   and never consulted, because a self-signed certificate can claim any
//!   subject and any issuer.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::capsule;
use crate::fastcgi::{Reply, Request};
use kyriakon_control_core::flow::questions::Question;
use kyriakon_control_core::flow::rate::Key;
use kyriakon_control_core::store::{Certificate, Store};
use kyriakon_control_core::{
    account::session, config, flow::catalogue, flow::questions, flow::rate, flow::validate, ipc,
};

mod account;
mod apply;
mod connection;
mod decide;
mod error;
pub(crate) mod flow;
mod gemini;
mod portal;
mod reply;
mod route;
pub mod status;

/// See `connection::fuzz_decode`. Present only with the `fuzz` feature, which
/// `control/fuzz` turns on and the service never does.
#[cfg(feature = "fuzz")]
#[doc(hidden)]
pub use connection::fuzz_decode;

#[cfg(test)]
pub(crate) mod test_support;
mod titan;

pub use self::error::Error;
use self::portal::portal_connection;
use self::titan::titan_accept;

/// The only origin a submission may carry. The port-80 vhost redirects, so the
/// form is served over TLS and nowhere else.
const OWN_ORIGIN: &str = "https://signup.kyriakon.net";

/// The largest body the responder reads. The largest legitimate field is a pasted
/// public key: an armoured curve25519 key is about a kilobyte, and a body of ten
/// mailboxes pastes ten of them, percent-encoded (up to three bytes on the wire
/// for one byte of content) and beside the free-text answers. A quarter of a
/// megabyte is comfortable for that and bounds a form post well under what the
/// front-ends will carry.
const MAX_BODY: usize = ipc::MAX_BODY;

/// The most a Titan upload may carry. A key is about a kilobyte and a body's
/// application has at most ten mailboxes, so this is far above what the route is
/// for and still bounds what a stranger with a token can make the handler read.
const MAX_TITAN_BODY: usize = 64 * 1024;

/// A Titan request line follows the gemini request limit of 1024 bytes. The
/// PROXY line relayd prepends has its own, shorter bound from the protocol.
const MAX_TITAN_LINE: usize = 1024;

/// How long one FastCGI connection may take, from accept to the reply's last
/// byte. The front-end writes the request and reads the reply without pausing,
/// so a peer that stalls either half is the front-end failing; the deadline
/// keeps it from pinning a task and a descriptor.
const FRONTEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// FastCGI connections served at once per listener. The permit is taken before
/// a task is spawned, so a flood costs the backlog and one socket.
///
/// The four counts here are slices of the login class's `openfiles-cur=128`
/// (`rc.subr` gives the unit the `daemon` class). The sum is 2 * 24 + 16 + 32 =
/// 96, which leaves the process its own descriptors. The test
/// `the_listener_budgets_fit_the_login_class` holds the arithmetic.
const FRONTEND_CONNECTIONS: usize = 24;
/// How long one portal connection may take, from the first byte to the reply.
/// The protocol is one line in and one line out, so a client that connects and
/// sends nothing is gone by this deadline.
const PORTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Portal connections served at once. It shares the 128-descriptor table with
/// the two FastCGI listeners and Titan.
const PORTAL_CONNECTIONS: usize = 16;
/// How long one Titan connection may take, from the first byte to the reply.
const TITAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Titan connections served at once. The rest wait for a permit, so a flood
/// costs waiting tasks rather than open sockets.
// 32, not 64: see the count arithmetic on `PORTAL_CONNECTIONS`.
const TITAN_CONNECTIONS: usize = 32;
/// The reply for a failure the client can retry.
const TEMP_FAILURE: &str = "Temporary failure";

/// What a token the store does not answer for reads as. One constant, because an
/// unknown token, an expired one and a spent one are the same bytes: that is the
/// no-oracle rule the spec fixes, and it is only true if they share one author.
const UNKNOWN_TOKEN: &str =
    "This link is not in use. It may have been cleared away, or it may never have existed.";

/// Everything a request is answered from, read once at startup.
pub(crate) struct App {
    cfg: config::Config,
    questions: Vec<Question>,
    /// The shared service catalogue, parsed once at startup. Read from the path
    /// the config names, and empty only if that file held no `[[service]]` at all,
    /// which `App::load` refuses.
    catalogue: Vec<catalogue::Service>,
    /// The mirrored gemtext pages, keyed by the route that serves them. Read once
    /// at startup from the directory the config names, so a page change is a
    /// deploy and a restart rather than a request that reads a file.
    pages: BTreeMap<String, String>,
    reserved: HashSet<String>,
    counter: rate::Counter,
    store: Store,
    /// The login check: `doas` and the fixed checker in production, and the
    /// checker directly in a test, where no root rule can exist.
    auth: session::Authenticator,
}

impl App {
    /// Read the configuration and the files it names. The question list is the
    /// crate's own, read at build time, so a wording change is a rebuild and the
    /// store holds no copy of it to drift from.
    async fn load(cfg: config::Config) -> Result<App, Error> {
        let list = questions::shipped()?;
        if list.is_empty() {
            return Err(Error::Startup(format!(
                "{} has no questions",
                questions::TRACKED
            )));
        }
        // The catalogue is read the same way and refused the same way: a responder
        // that came up with no services would render an application page that
        // promises nothing, which is the failure the config path exists to
        // prevent.
        let services = catalogue::parse(&Store::read_text(&cfg.catalogue).await?)?;
        if services.is_empty() {
            return Err(Error::Startup(format!(
                "{} has no services",
                catalogue::TRACKED
            )));
        }
        // The mirrored pages are read the same way and refused the same way: a
        // handler that came up without them would answer 51 for the pages the
        // ticket says it serves, which is the failure the named directory exists
        // to prevent.
        let mut pages = BTreeMap::new();
        for (route, file, _) in capsule::PAGES {
            let path = format!("{}/{}", cfg.pages.trim_end_matches('/'), file);
            let text = Store::read_text(&path).await?;
            if text.trim().is_empty() {
                return Err(Error::Startup(format!("{path} is empty")));
            }
            pages.insert((*route).to_string(), text);
        }
        let reserved = validate::reserved(&Store::read_text(&cfg.reserved).await?);
        Ok(App {
            store: Store::new(&cfg.store_root),
            cfg,
            questions: list,
            catalogue: services,
            pages,
            reserved,
            counter: rate::Counter::new(),
            auth: session::Authenticator::default(),
        })
    }
}

/// Which front-end filed a request. One variable decides it: gmid always sends
/// `GEMINI_URL_PATH` and httpd never does.
///
/// `SERVER_SOFTWARE` would answer the question too, and it is not read for it: a
/// version string is not a routing decision, and a front-end that changes how it
/// spells itself must not change which pages a request gets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FrontEnd {
    Httpd,
    Gemini,
}

impl FrontEnd {
    /// The word the log line carries.
    fn word(self) -> &'static str {
        match self {
            FrontEnd::Httpd => "httpd",
            FrontEnd::Gemini => "gemini",
        }
    }
}

fn front_end(request: &Request) -> FrontEnd {
    if request.get("GEMINI_URL_PATH").is_some() {
        FrontEnd::Gemini
    } else {
        FrontEnd::Httpd
    }
}

/// One request, as the routes read it.
struct Incoming {
    /// The path with every leading slash stripped, which is the form gmid sends
    /// and therefore the form the route table is written against.
    path: String,
    /// gmid's `QUERY_STRING`, still percent-encoded. A capsule answer lives here;
    /// the web front-end's fields come in the body instead.
    query: String,
    /// The address the counters key on.
    key: Key,
    /// The address as the front-end observed it, for the log line.
    addr: String,
    /// The certificate the client presented, recorded and not trusted. Only
    /// its `hash` is ever a decision input.
    certificate: Option<Certificate>,
}

/// What one request answered, with the two things the log line carries: the route
/// with its token, and the address the front-end observed. Never the query, which
/// carries an answer, and never the body.
struct Outcome {
    reply: Reply,
    route: String,
    addr: String,
}

/// Run the responder on the three sockets the config names, until one of them
/// stops accepting. The two FastCGI listeners and the portal's line protocol are
/// the core server's; Titan keeps its own loop because its listener is public
/// TCP and a permit timeout there closes the socket rather than queueing it.
pub async fn serve(cfg: config::Config) -> Result<(), Error> {
    let app = Arc::new(App::load(cfg).await?);
    // Every listener is bound before the view narrows: bind(2) removes whatever
    // a previous run left at a path and creates the socket, and neither is an
    // operation a request needs again.
    let httpd = kyriakon_control_core::socket::bind(Path::new(&app.cfg.httpd_socket)).map_err(
        |source| Error::Io {
            what: "listen on",
            path: Some(app.cfg.httpd_socket.clone().into()),
            source,
        },
    )?;
    let gemini = kyriakon_control_core::socket::bind(Path::new(&app.cfg.gemini_socket)).map_err(
        |source| Error::Io {
            what: "listen on",
            path: Some(app.cfg.gemini_socket.clone().into()),
            source,
        },
    )?;
    let portal = kyriakon_control_core::socket::bind(Path::new(&app.cfg.portal_socket)).map_err(
        |source| Error::Io {
            what: "listen on",
            path: Some(app.cfg.portal_socket.clone().into()),
            source,
        },
    )?;
    let titan = TcpListener::bind(&app.cfg.titan_listener)
        .await
        .map_err(|source| Error::Io {
            what: "listen on",
            path: Some(app.cfg.titan_listener.clone().into()),
            source,
        })?;
    crate::sandbox::restrict(&app.cfg).map_err(Error::Failed)?;
    kyriakon_control_core::util::log(&format!(
        "kyriakon-control: httpd {}, gemini {}, portal {}, titan {}, store {}, {} questions",
        app.cfg.httpd_socket,
        app.cfg.gemini_socket,
        app.cfg.portal_socket,
        app.cfg.titan_listener,
        app.cfg.store_root,
        app.questions.len()
    ));
    let limits = kyriakon_control_core::socket::Limits {
        connections: FRONTEND_CONNECTIONS,
        deadline: FRONTEND_TIMEOUT,
        program: "kyriakon-control",
    };
    tokio::try_join!(
        serve_front_end(httpd, app.cfg.httpd_socket.clone(), limits, app.clone()),
        serve_front_end(gemini, app.cfg.gemini_socket.clone(), limits, app.clone()),
        portal_listener(portal, app.clone()),
        titan_accept(titan, app),
    )
    .map(|_| ())
}

/// Answer one FastCGI listener for the life of the process.
async fn serve_front_end(
    listener: tokio::net::UnixListener,
    path: String,
    limits: kyriakon_control_core::socket::Limits,
    app: Arc<App>,
) -> Result<(), Error> {
    crate::fastcgi::serve_listener(listener, limits, MAX_BODY, move |request| {
        let app = app.clone();
        async move { connection::fastcgi_answer(app, request).await }
    })
    .await
    .map_err(|source| Error::Io {
        what: "serve",
        path: Some(path.into()),
        source,
    })
}

/// Answer the portal's line protocol for the life of the process.
async fn portal_listener(listener: tokio::net::UnixListener, app: Arc<App>) -> Result<(), Error> {
    kyriakon_control_core::socket::accept(
        listener,
        kyriakon_control_core::socket::Limits {
            connections: PORTAL_CONNECTIONS,
            deadline: PORTAL_TIMEOUT,
            program: "kyriakon-control",
        },
        "portal",
        move |stream| {
            let app = app.clone();
            async move {
                match tokio::time::timeout(PORTAL_TIMEOUT, portal_connection(stream, &app)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => e.report("serving a portal connection"),
                    Err(_) => kyriakon_control_core::util::log(
                        "kyriakon-control: the portal connection timed out",
                    ),
                }
            }
        },
    )
    .await
    .map_err(|source| Error::Io {
        what: "accept a portal connection",
        path: None,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::responder::test_support::*;

    /// A staging run that missed a page stops the handler rather than leaving a
    /// route that answers 51 for a document the capsule promises.
    #[tokio::test]
    async fn the_handler_refuses_to_start_without_a_staged_page() {
        let dir = fixture_dir("missing-page");
        for (route, file, _) in capsule::PAGES {
            if *route == "aup" {
                continue;
            }
            std::fs::write(dir.join("pages").join(file), "# ok\n").unwrap();
        }
        let Err(err) = App::load(handler_config(&dir)).await else {
            panic!("the handler started without a page");
        };
        assert!(
            matches!(
                &err,
                Error::Store(kyriakon_control_core::store::Error::Io { path, .. })
                    if path.ends_with("pages/aup.gmi")
            ),
            "{err}"
        );
    }

    /// An empty staged file is the same failure as a missing one: the page exists
    /// and says nothing, which a reader would take for the document.
    #[tokio::test]
    async fn the_handler_refuses_an_empty_staged_page() {
        let dir = fixture_dir("empty-page");
        for (route, file, _) in capsule::PAGES {
            let body = if *route == "privacy" {
                String::new()
            } else {
                "# ok\n".to_string()
            };
            std::fs::write(dir.join("pages").join(file), body).unwrap();
        }
        let Err(err) = App::load(handler_config(&dir)).await else {
            panic!("the handler started on an empty page");
        };
        assert!(
            matches!(&err, Error::Startup(message) if message.contains("privacy.gmi")),
            "{err}"
        );
    }

    /// The listener counts are slices of the login class's 128 descriptors. A
    /// listener added without widening the class must fail here rather than at
    /// the first flood ([#877]).
    ///
    /// [#877]: https://github.com/kyriakon/kyriakon-infra/issues/877
    #[test]
    fn the_listener_budgets_fit_the_login_class() {
        use kyriakon_control_core::socket::{OPEN_FILES, RESERVED_FILES};
        let held = 2 * FRONTEND_CONNECTIONS + PORTAL_CONNECTIONS + TITAN_CONNECTIONS;
        assert!(
            held <= OPEN_FILES - RESERVED_FILES,
            "{held} connection permits do not fit in {OPEN_FILES} descriptors"
        );
    }
}
