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
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use tokio::net::{TcpListener, UnixListener};

use crate::flow::questions::Question;
use crate::flow::rate::Key;
use crate::frontend::fastcgi::{Reply, Request};
use crate::store::{Certificate, Store};
use crate::{
    account::session, config, flow::catalogue, flow::questions, flow::rate, flow::validate,
    frontend::capsule, frontend::ipc,
};

mod account;
mod apply;
mod connection;
mod decide;
pub(crate) mod flow;
mod gemini;
mod portal;
mod reply;
mod route;
pub mod status;
#[cfg(test)]
pub(crate) mod test_support;
mod titan;

use self::connection::accept;
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
/// How long one Titan connection may take, from the first byte to the reply.
const TITAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Titan connections served at once. The rest wait for a permit, so a flood
/// costs waiting tasks rather than open sockets.
const TITAN_CONNECTIONS: usize = 64;
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
    async fn load(cfg: config::Config) -> Result<App, String> {
        let list = questions::shipped()?;
        if list.is_empty() {
            return Err(format!("{} has no questions", questions::TRACKED));
        }
        // The catalogue is read the same way and refused the same way: a responder
        // that came up with no services would render an application page that
        // promises nothing, which is the failure the config path exists to
        // prevent.
        let services = catalogue::parse(&Store::read_text(&cfg.catalogue).await?)?;
        if services.is_empty() {
            return Err(format!("{} has no services", catalogue::TRACKED));
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
                return Err(format!("{path} is empty"));
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
/// stops accepting.
pub async fn serve(cfg: config::Config) -> Result<(), String> {
    let app = Arc::new(App::load(cfg).await?);
    let httpd = bind(&app.cfg.httpd_socket)?;
    let gemini = bind(&app.cfg.gemini_socket)?;
    let portal = bind(&app.cfg.portal_socket)?;
    let titan = TcpListener::bind(&app.cfg.titan_listener)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", app.cfg.titan_listener))?;
    eprintln!(
        "kyriakon-onboard: httpd {}, gemini {}, portal {}, titan {}, store {}, {} questions",
        app.cfg.httpd_socket,
        app.cfg.gemini_socket,
        app.cfg.portal_socket,
        app.cfg.titan_listener,
        app.cfg.store_root,
        app.questions.len()
    );
    tokio::try_join!(
        accept(httpd, app.clone(), Channel::FrontEnd),
        accept(gemini, app.clone(), Channel::FrontEnd),
        accept(portal, app.clone(), Channel::Portal),
        titan_accept(titan, app),
    )
    .map(|_| ())
}

/// What a listener speaks. The two FastCGI sockets share a loop; the portal's
/// line protocol is the one difference in the task each connection spawns.
#[derive(Clone, Copy)]
enum Channel {
    FrontEnd,
    Portal,
}

/// Bind one socket, replacing the file a previous run left behind. A socket file
/// outlives the process that made it, so a restart after a crash would otherwise
/// fail to bind until somebody removed it by hand. Only a socket is removed: a
/// path that is something else is a mistake in the config and is left to the
/// error, which names the path.
///
/// The file is mode 0660, and the group it carries comes from the set-group-id
/// directory the front-ends' deploy creates it in: `www` for httpd's socket and
/// `_gmid` for gmid's. A socket any local user could connect to would let that
/// user forge the whole environment, `REMOTE_ADDR` included, which is the key the
/// limits and the audit rest on.
fn bind(path: &str) -> Result<UnixListener, String> {
    let path = Path::new(path);
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.file_type().is_socket() {
            std::fs::remove_file(path)
                .map_err(|e| format!("cannot remove the socket {}: {e}", path.display()))?;
        }
    }
    let listener = UnixListener::bind(path)
        .map_err(|e| format!("cannot listen on {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| format!("cannot set the mode on {}: {e}", path.display()))?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::responder::test_support::*;

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
        assert!(err.contains("aup.gmi"), "{err}");
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
        assert!(err.contains("privacy.gmi"), "{err}");
    }
}
