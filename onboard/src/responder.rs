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
//! Nothing but what a route needs is read from that environment. The variables are
//! built by the front-end out of the request line, out of the client's
//! certificate, or out of its own configuration, and only the last of those is
//! ours, so the reading of each one is stated where it is read:
//!
//! * The path is `GEMINI_URL_PATH` for gmid, which decodes and cleans it before it
//!   sends it and strips every leading slash, and `REQUEST_URI` for httpd, which
//!   passes the client's own spelling. It is used for one comparison against three
//!   literals and one 26-character token check, and never as a path, a file name
//!   or a lookup key.
//! * `QUERY_STRING` and the body are the form's fields, and both arrive still
//!   percent-encoded. The responder decodes them itself.
//! * `REMOTE_ADDR` is the socket peer, which is the address the counters key on
//!   for gmid, whose requests carry no forwarded header of any kind. httpd's
//!   `REMOTE_ADDR` is relayd, so the web front-end keys on `HTTP_X_FORWARDED_FOR`,
//!   which relayd `set`s rather than appending to.
//! * `SERVER_NAME`, `SERVER_PORT`, `PATH_INFO`, `SCRIPT_NAME`, `PATH_TRANSLATED`,
//!   `SERVER_SOFTWARE`, `GATEWAY_INTERFACE` and `SERVER_PROTOCOL` are the client's
//!   spelling or a constant, and no code path here selects on any of them.
//!   `AUTH_TYPE`, `REMOTE_USER`, `TLS_CLIENT_ISSUER` and `TLS_CLIENT_HASH` name a
//!   certificate nobody verified and a subject anyone can mint; the capsule's
//!   member identity is [#377]'s and compares the hash against pins, so nothing
//!   here tests for the presence of one or trusts a value from it.
//!
//! [#377]: https://github.com/kyriakon/kyriakon-infra/issues/377

use std::collections::{BTreeMap, HashSet};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use askama::Template;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::fcgi::{self, Reply, Request};
use crate::page::{AccountPage, DecidePage, NoticePage, PasswordPage, ReceivedPage, StatusPage};
use crate::questions::{Branch, Kind, Question, Rule};
use crate::rate::Key;
use crate::store::{Acceptance, Record, Store};
use crate::{
    capsule, catalogue, config, draft, intents, keycheck, page, portal_ipc, questions, rate, store,
    transitions, util, validate,
};

/// The fixed hostname for the form and the account page, used as itself. It is
/// public because the terminal front-end hands a reader the same host's status
/// route, so the address a session gives out cannot name a different service than
/// the one that answers it.
pub const HOST: &str = "signup.kyriakon.net";

/// The only origin a submission may carry. The port-80 vhost redirects, so the
/// form is served over TLS and nowhere else.
const OWN_ORIGIN: &str = "https://signup.kyriakon.net";

/// The largest body the responder reads. The largest legitimate field is a pasted
/// public key: an armoured curve25519 key is about a kilobyte, and a body of ten
/// mailboxes pastes ten of them, percent-encoded (up to three bytes on the wire
/// for one byte of content) and beside the free-text answers. A quarter of a
/// megabyte is comfortable for that and bounds a form post well under what the
/// front-ends will carry.
const MAX_BODY: usize = portal_ipc::MAX_BODY;

/// What a token the store does not answer for reads as. One constant, because an
/// unknown token, an expired one and a spent one are the same bytes: that is the
/// no-oracle rule the spec fixes, and it is only true if they share one author.
const UNKNOWN_TOKEN: &str =
    "This link is not in use. It may have been cleared away, or it may never have existed.";

/// Answer to a portal status read past the per-address counter. It is the
/// portal's screen that shows it, so the words are the screen's.
const SLOW_STATUS: &str = "Too many status reads from this address. Wait a minute and try again.";

/// Served when a template could not be rendered. Static and interpolated with
/// nothing, so the one place with no markup around it cannot become somewhere a
/// field lands unescaped.
const RENDER_FALLBACK: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Kyriakon</title></head><body><main><h2>Something went wrong</h2>\
<p>This is our fault, not yours. Try again in a moment.</p></main></body></html>";

/// Everything a request is answered from, read once at startup.
struct App {
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
        for (route, file) in capsule::PAGES {
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
    eprintln!(
        "kyriakon-onboard: httpd {}, gemini {}, portal {}, store {}, {} questions",
        app.cfg.httpd_socket,
        app.cfg.gemini_socket,
        app.cfg.portal_socket,
        app.cfg.store_root,
        app.questions.len()
    );
    tokio::try_join!(
        accept(httpd, app.clone(), Channel::FrontEnd),
        accept(gemini, app.clone(), Channel::FrontEnd),
        accept(portal, app, Channel::Portal),
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

/// Accept connections for as long as the listener holds, which is until it fails:
/// a socket that has stopped accepting is not something this process can repair,
/// and rc.d's own check is where a human reads that the daemon is gone.
async fn accept(listener: UnixListener, app: Arc<App>, channel: Channel) -> Result<(), String> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("cannot accept: {e}"))?;
        let app = app.clone();
        tokio::spawn(async move {
            let outcome = match channel {
                Channel::FrontEnd => connection(stream, &app).await,
                Channel::Portal => portal_connection(stream, &app).await,
            };
            if let Err(e) = outcome {
                eprintln!("kyriakon-onboard: {e}");
            }
        });
    }
}

/// Answer the requests on one connection. Both front-ends connect for one request
/// and close, and gmid asks for the connection to be kept in case it has another,
/// so the loop runs until the peer closes or a record cannot be read.
async fn connection(stream: UnixStream, app: &App) -> Result<(), String> {
    let (mut reader, mut writer) = stream.into_split();
    loop {
        let request = match fcgi::read_request(&mut reader, MAX_BODY).await? {
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
        writer
            .write_all(&fcgi::reply_bytes(&outcome.reply, request.id()))
            .await
            .map_err(|e| format!("cannot write the reply: {e}"))?;
        writer
            .flush()
            .await
            .map_err(|e| format!("cannot flush the reply: {e}"))?;
        if !request.keep_conn {
            return Ok(());
        }
    }
}

/// One line from the portal, capped before the buffer grows. `None` is a
/// connection that closed before the line was finished.
async fn portal_line<R>(reader: &mut R, limit: usize) -> Result<Option<String>, String>
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
async fn portal_connection(stream: UnixStream, app: &App) -> Result<(), String> {
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
                writer
                    .write_all(reply.as_bytes())
                    .await
                    .map_err(|e| format!("cannot write the portal answer: {e}"))?;
                return writer
                    .flush()
                    .await
                    .map_err(|e| format!("cannot flush the portal answer: {e}"));
            }
        };
        let reply = portal_file(app, &address, &body).await;
        // The route and the address are the log line every front-end gets; the
        // answers and the token never are. The code a refusal gets is not 200,
        // because a count of filed applications reads this line.
        let code = if reply.starts_with("OK ") { 200 } else { 422 };
        eprintln!("kyriakon-onboard: portal /apply {code} {address}");
        writer
            .write_all(reply.as_bytes())
            .await
            .map_err(|e| format!("cannot write the portal answer: {e}"))?;
        return writer
            .flush()
            .await
            .map_err(|e| format!("cannot flush the portal answer: {e}"));
    }
    let Some((address, token)) = portal_ipc::parse_request(&line) else {
        return Err("the portal sent no status request".to_string());
    };
    let answer = portal_answer(app, address, token).await;
    // The route carries the token and the address, which is the log line every
    // other front-end gets; the answer never does.
    eprintln!("kyriakon-onboard: portal /status/{token} 200 {address}");
    writer
        .write_all(answer.line().as_bytes())
        .await
        .map_err(|e| format!("cannot write the portal answer: {e}"))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("cannot flush the portal answer: {e}"))
}

/// File one completed application the portal checked, through the same builder
/// and writer the web form and the capsule use. The handler validates every
/// field again, so a bug in the portal cannot become a filed record the web form
/// would have refused.
async fn portal_file(app: &App, address: &str, body: &str) -> String {
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
async fn portal_answer(app: &App, address: &str, token: &str) -> portal_ipc::Answer {
    if !app.counter.allow_request(rate::key(None, Some(address))) {
        return portal_ipc::Answer::Notice(SLOW_STATUS.to_string());
    }
    let page = status_page(record_for(app, token).await, OffsetDateTime::now_utc());
    if page.notice.is_empty() {
        portal_ipc::Answer::Stage(page.stage)
    } else {
        portal_ipc::Answer::Notice(page.notice)
    }
}

/// Answer one request.
async fn respond(app: &App, request: &Request) -> Outcome {
    let front = front_end(request);
    let incoming = read(front, request);

    // The counters first, so a request refused for being cross-origin or for
    // naming a route the service does not have is still counted.
    if !app.counter.allow_request(incoming.key) {
        return outcome(incoming, too_many(front, Which::Minute));
    }

    let reply = match front {
        FrontEnd::Gemini => gemini(app, &incoming).await,
        FrontEnd::Httpd => http(app, request, &incoming).await,
    };
    outcome(incoming, reply)
}

fn outcome(incoming: Incoming, reply: Reply) -> Outcome {
    Outcome {
        reply,
        route: format!("/{}", incoming.path),
        addr: incoming.addr,
    }
}

/// The path, the key and the address, from the environment.
fn read(front_end: FrontEnd, request: &Request) -> Incoming {
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
    }
}

/// Percent-decode one value. A plus is a space in a form, which is what a browser
/// writes for one in `application/x-www-form-urlencoded`, and an ordinary
/// character in a path, where the specification requires `%20` for a space.
fn decode(value: &str, plus_is_space: bool) -> String {
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

fn hex(pair: &[u8]) -> Option<u8> {
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
fn fields(raw: &str) -> BTreeMap<String, String> {
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

/// The web front-end, which serves the pages the HTTP daemon served.
async fn http(app: &App, request: &Request, incoming: &Incoming) -> Reply {
    let method = request.value("REQUEST_METHOD");
    // The origin check runs before a route is chosen, as the middleware in front
    // of the old HTTP daemon's router did: a POST from somewhere that is not this
    // form is refused for being that, whatever path it names.
    if method == "POST" && !own_origin(request) {
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
    if request.body_too_large {
        return Reply::html(413, String::new());
    }
    // The body of a POST is read as `application/x-www-form-urlencoded`, so a
    // request that declares something else is not a request either route that
    // takes a body answers.
    if method == "POST" && !form_post(request) {
        return Reply::html(415, String::new());
    }
    // A browser sends HEAD where it would send GET, and httpd drops the body of a
    // HEAD response on its own, so the two read the same route.
    let get = method == "GET" || method == "HEAD";

    if let Some(token) = incoming.path.strip_prefix("status/") {
        return if get {
            status(app, token).await
        } else {
            method_not_allowed()
        };
    }
    // A decision link opens a page that says what it would do, and the button on
    // that page is what files it. See `decide_confirm`.
    if let Some(token) = incoming.path.strip_prefix("decide/") {
        if get {
            let query = fields(request.value("QUERY_STRING"));
            return decide_confirm(app, token, &query).await;
        }
        if method == "POST" {
            let form = fields(&String::from_utf8_lossy(&request.body));
            return decide_file(app, token, &form).await;
        }
        return method_not_allowed();
    }
    // The one-time password link. The page is a form and the submission files an
    // intent; the link's signature is checked by the drain, which holds the key.
    if let Some(token) = incoming.path.strip_prefix("password/") {
        if get {
            let query = fields(request.value("QUERY_STRING"));
            return password_page(app, token, &query).await;
        }
        if method == "POST" {
            let form = fields(&String::from_utf8_lossy(&request.body));
            return password_file(app, token, &form).await;
        }
        return method_not_allowed();
    }
    if incoming.path == "apply" {
        if method != "POST" {
            return method_not_allowed();
        }
        return apply(app, request, incoming).await;
    }
    if incoming.path == "account" {
        return if get {
            account(app)
        } else {
            method_not_allowed()
        };
    }
    if incoming.path.is_empty() {
        if get {
            return applicant(app, fields(request.value("QUERY_STRING")));
        }
        if method == "POST" {
            return branch_step(app, fields(&String::from_utf8_lossy(&request.body)));
        }
        return method_not_allowed();
    }
    // An empty body, as the HTTP daemon's own router left these: there is no
    // rendered page behind a path this service does not serve.
    Reply::html(404, String::new())
}

fn method_not_allowed() -> Reply {
    Reply::html(405, String::new())
}

/// Whether a POST declares the encoding its body is read as. A browser always
/// does.
fn form_post(request: &Request) -> bool {
    request
        .value("CONTENT_TYPE")
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|t| t.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
}

/// The gemini front-end: the catalogue, the status page, and the applicant's
/// draft flow. The apply route reads an answer from `QUERY_STRING`, which gmid
/// sends still percent-encoded and the responder decodes itself rather than read
/// from `GEMINI_SEARCH_STRING`: that copy is sent only for a query with no `=`
/// in it, and its decoder maps `+` to a space, which is not the reading the
/// specification gives a URI query.
async fn gemini(app: &App, incoming: &Incoming) -> Reply {
    if incoming.path == "apply" {
        return capsule_new(app, incoming).await;
    }
    if let Some(rest) = incoming.path.strip_prefix("apply/") {
        return capsule_apply(app, incoming, rest).await;
    }
    if let Some(token) = incoming.path.strip_prefix("status/") {
        let record = record_for(app, token).await;
        let page = status_page(record, OffsetDateTime::now_utc());
        return Reply::gemini(20, "text/gemini", capsule::status(&page));
    }
    if incoming.path.is_empty() {
        return Reply::gemini(20, "text/gemini", capsule::front_page(&app.catalogue, None));
    }
    // The mirrored pages are literals, not paths: the route is a key in the map
    // the handler read at startup, so no request can name a file to read.
    if let Some(text) = app.pages.get(&incoming.path) {
        return Reply::gemini(20, "text/gemini", text.clone());
    }
    if incoming.path == capsule::ACCEPTANCES {
        return Reply::gemini(
            20,
            "text/gemini",
            capsule::acceptances(&app.questions, &app.cfg.release),
        );
    }
    Reply::gemini(51, "Not found", String::new())
}

/// Open a draft and send the client to its first page. The draft token is the
/// status token the application will carry, drawn here and never from anything
/// about the applicant. The 30 is the only way the token reaches the path: a
/// gemini prompt cannot carry one.
async fn capsule_new(app: &App, incoming: &Incoming) -> Reply {
    if !app.counter.allow_draft(incoming.key) {
        return too_many(FrontEnd::Gemini, Which::Day);
    }
    let token = match store::status_token().await {
        Ok(token) => token,
        Err(e) => {
            eprintln!("kyriakon-onboard: {e}");
            return Reply::gemini(40, "Temporary failure", String::new());
        }
    };
    let mut record = draft::Draft::new(token.clone());
    if let Err(e) = draft::save(&app.store, &mut record).await {
        eprintln!("kyriakon-onboard: {e}");
        return Reply::gemini(40, "Temporary failure", String::new());
    }
    capsule_redirect(&token, 1)
}

/// One answer, one page, one redirect. The page number in the path must be the
/// draft's cursor; a replayed page redirects to the cursor rather than applying
/// the answer again, which is what makes a second tap advance nothing.
async fn capsule_apply(app: &App, incoming: &Incoming, rest: &str) -> Reply {
    let mut parts = rest.split('/');
    let token = parts.next().unwrap_or("");
    let page = parts.next();
    if parts.next().is_some() || !draft::valid_token(token) {
        return capsule_not_found();
    }
    let page = match page {
        Some(p) => match p.parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => return capsule_not_found(),
        },
        // The token alone names the draft; the page is the cursor's.
        None => return capsule_redirect(token, 1),
    };
    // One lock around the read and every write: the drain files a mailed key
    // into this same record as root, and two unsynchronised read-modify-writes
    // would lose one of them.
    let _lock = match draft::lock(&app.store).await {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("kyriakon-onboard: {e}");
            return Reply::gemini(40, "Temporary failure", String::new());
        }
    };
    let mut record = match draft::load(&app.store, token).await {
        Ok(Some(d)) => d,
        Ok(None) => return capsule_not_found(),
        Err(e) => {
            eprintln!("kyriakon-onboard: {e}");
            return Reply::gemini(40, "Temporary failure", String::new());
        }
    };
    let path = flow_path(&app.questions, &record.answers);
    if record.cursor >= path.len() {
        return capsule_file(app, &record).await;
    }
    if page != record.cursor + 1 {
        return capsule_redirect(token, record.cursor + 1);
    }
    // A key mailed to apply@ is filed against this draft by the drain. When the
    // flow reaches that page, it is already answered: advance past every such
    // page rather than asking for a key the applicant has sent.
    if capsule_skip_mailed(&path, &mut record) {
        if let Err(e) = draft::save(&app.store, &mut record).await {
            eprintln!("kyriakon-onboard: {e}");
            return Reply::gemini(40, "Temporary failure", String::new());
        }
        if record.cursor >= path.len() {
            return capsule_file(app, &record).await;
        }
        return capsule_redirect(token, record.cursor + 1);
    }

    let index = record.cursor;
    let page = &path[index];
    let q = page.q;
    if incoming.query.is_empty() {
        return Reply::gemini(
            10,
            &capsule_meta(page, index, path.len(), token, None),
            String::new(),
        );
    }

    let value = capsule_value(&incoming.query);
    let value = match q.kind {
        Kind::YesNo | Kind::Acceptance => value.to_ascii_lowercase(),
        _ => value,
    };
    if let Some(why) = flow_problem(page, &value, &app.reserved, q.required, &record.answers) {
        return Reply::gemini(
            10,
            &capsule_meta(page, index, path.len(), token, Some(&why)),
            String::new(),
        );
    }
    match &page.mailbox {
        Some(mailbox) => {
            record.mail_keys.retain(|k| k.mailbox != mailbox.name);
            record
                .mail_keys
                .push(keycheck::mail_key(mailbox.name.clone(), &value));
        }
        None => {
            record.answers.insert(q.id.clone(), value);
        }
    }
    record.cursor = index + 1;

    // The body's two line lists are checked together, because the fault is the
    // count rather than either list. Re-ask the page just answered, so the
    // applicant can correct it; nothing is saved until the pair agrees.
    if q.id == "body_account_names"
        && record.answers.get("whose").map(String::as_str) == Some("body")
        && record.answers.contains_key("body_addresses")
    {
        let mut errors = Vec::new();
        body_cross_checks(&record.answers, &mut errors);
        if !errors.is_empty() {
            record.cursor = index;
            return Reply::gemini(
                10,
                &capsule_meta(page, index, path.len(), token, Some(&errors.join(" "))),
                String::new(),
            );
        }
    }

    let next = flow_path(&app.questions, &record.answers);
    if record.cursor >= next.len() {
        return capsule_file(app, &record).await;
    }
    if let Err(e) = draft::save(&app.store, &mut record).await {
        eprintln!("kyriakon-onboard: {e}");
        return Reply::gemini(40, "Temporary failure", String::new());
    }
    capsule_redirect(token, record.cursor + 1)
}

/// One page of the applicant's path. A mail key is one page per mailbox, with
/// the mailbox in the prompt: a body's key page would otherwise ask for every
/// key at once, and a status 10 answer cannot say which block is whose.
pub(crate) struct Page<'a> {
    pub(crate) q: &'a Question,
    /// Set on a key page, which is generated per mailbox rather than read from
    /// the question list.
    pub(crate) mailbox: Option<Mailbox>,
}

pub(crate) struct Mailbox {
    /// The account name the key is filed under, empty for a person.
    pub(crate) name: String,
    /// The address the page names.
    pub(crate) address: String,
}

/// The pages this applicant's path will ask, in file order: the branch the
/// `whose` answer selects, the blessing only once `orders` says monastic, and
/// one mail-key page per mailbox. The capsule and the terminal both walk it, so
/// the counter and the branches cannot disagree between the two.
pub(crate) fn flow_path<'a>(
    list: &'a [Question],
    answers: &BTreeMap<String, String>,
) -> Vec<Page<'a>> {
    let body = answers.get("whose").map(String::as_str) == Some("body");
    let monastic = questions::is_monastic(answers.get("orders").map(String::as_str));
    let mut out = Vec::new();
    for q in questions::shown(list, !body) {
        if q.branch == Branch::Monastic && !monastic {
            continue;
        }
        if q.id == "mail_key" && !body {
            let name = answers.get("username").cloned().unwrap_or_default();
            let address = if name.is_empty() {
                "your address".to_string()
            } else {
                format!("{name}@kyriakon.net")
            };
            out.push(Page {
                q,
                mailbox: Some(Mailbox { name, address }),
            });
        } else if q.id == "body_mail_key" && body {
            let domain = answers.get("body_domain").cloned().unwrap_or_default();
            for name in questions::account_names(answers) {
                let address = if domain.is_empty() {
                    name.clone()
                } else {
                    format!("{name}@{domain}")
                };
                out.push(Page {
                    q,
                    mailbox: Some(Mailbox { name, address }),
                });
            }
        } else {
            out.push(Page { q, mailbox: None });
        }
    }
    out
}

/// Advance the cursor past key pages whose mailbox already holds a key, which
/// is how a key mailed to apply@ answers the page for the applicant.
fn capsule_skip_mailed(path: &[Page], record: &mut draft::Draft) -> bool {
    let mut moved = false;
    while let Some(page) = path.get(record.cursor) {
        match &page.mailbox {
            Some(mailbox) if record.mail_keys.iter().any(|k| k.mailbox == mailbox.name) => {
                record.cursor += 1;
                moved = true;
            }
            _ => break,
        }
    }
    moved
}

/// The query as the draft stores it. gmid leaves the query percent-encoded, and
/// the handler decodes it itself so a `+` stays a plus and only `%0D%0A` becomes
/// a line break; a bare CR stays an ordinary character. A single full stop is the
/// clients' empty answer.
fn capsule_value(raw: &str) -> String {
    let decoded = decode(raw, false).replace("\r\n", "\n");
    // Only the answer's own padding is removed. `str::trim` also removes `\r`,
    // and the specification says a bare CR is an ordinary character.
    let trimmed = decoded.trim_matches(|c: char| matches!(c, ' ' | '\n' | '\t'));
    if trimmed == "." {
        String::new()
    } else {
        trimmed.to_string()
    }
}

/// Why one page's answer cannot advance the flow, or `None`. The shared rules are
/// the web form's; the type's own shape is added where the shared rules are
/// silent, because a yes/no page that accepted "maybe" would store a value the
/// form never offers.
pub(crate) fn flow_problem(
    page: &Page,
    value: &str,
    reserved: &HashSet<String>,
    required: bool,
    answers: &BTreeMap<String, String>,
) -> Option<String> {
    let q = page.q;
    if page.mailbox.is_some() {
        if value.trim().is_empty() {
            return Some("a public key is needed".to_string());
        }
        let blocks = keycheck::blocks(value);
        if blocks.len() != 1 {
            return Some("one key for one mailbox".to_string());
        }
        return keycheck::pgp_public_key(&blocks[0]).err();
    }
    if let Some(why) = validate::reason(q, value, reserved, required) {
        return Some(why);
    }
    // The shared key check is the web form's, because `validate::reason` only
    // proves the first block parses; it does not count blocks or compare them
    // with the body's account names.
    if q.rule == Rule::MailKey && !value.is_empty() {
        if let Some(why) = mail_key_errors(q, value, answers).into_iter().next() {
            return Some(why);
        }
    }
    match q.kind {
        Kind::YesNo => (!value.is_empty() && !matches!(value, "yes" | "no"))
            .then(|| "answer yes or no".to_string()),
        Kind::Acceptance => {
            (!value.is_empty() && value != "yes").then(|| "this has to be accepted".to_string())
        }
        Kind::Addresses => validate::address_lines(value),
        _ => None,
    }
}

/// A status 10 META: one line, because a newline would end the header. The
/// counter is the applicant's own path length; the hints are the input the prompt
/// alone does not give, and the mail route is here because META is the last text
/// a client shows before it reads an answer.
fn capsule_meta(
    page: &Page,
    index: usize,
    total: usize,
    token: &str,
    reason: Option<&str>,
) -> String {
    let q = page.q;
    let mut out = format!("question {} of {}. ", index + 1, total);
    match &page.mailbox {
        Some(mailbox) => {
            // shortcut: only the apply@ fallback is offered; add the titan://
            // line when #378 creates the listener, because a URL now would name
            // a port nothing serves.
            out.push_str(&format!(
                "Paste the public key for {}. Paste the whole block. If your client refuses the \
                 paste because the address is too long, mail it to apply@kyriakon.net with {token} \
                 as the subject, and name this mailbox in the message.",
                mailbox.address,
            ));
        }
        None => {
            out.push_str(&q.prompt);
            match q.kind {
                Kind::Choice => {
                    if let Rule::Choice(options) = &q.rule {
                        out.push_str(" Answer one of: ");
                        for (i, option) in options.iter().enumerate() {
                            if i > 0 {
                                out.push_str(", ");
                            }
                            out.push_str(&format!("{} ({})", option.value, option.label));
                        }
                        out.push('.');
                    }
                }
                Kind::YesNo => out.push_str(" Answer yes or no."),
                Kind::Acceptance => out.push_str(" Answer yes to accept."),
                Kind::Addresses => {
                    out.push_str(" One per line, as localpart: own or localpart: alias localpart.")
                }
                Kind::Key => out.push_str(" Paste the whole public key block."),
                _ => {}
            }
            if !q.required {
                out.push_str(" Leave a single full stop to skip.");
            }
        }
    }
    // A gemini prompt has no body, so META is the only place a key page can name
    // the walkthrough. The upload key is a key page here as much as the mail key
    // is: the hosting is key-based, so it is a step rather than an extra.
    if q.kind == Kind::Key {
        out.push_str(&format!(" How to make one: gemini://{HOST}/keys"));
    }
    if matches!(
        q.kind,
        Kind::Text | Kind::Multiline | Kind::Addresses | Kind::Key
    ) {
        out.push_str(" Keep the answer under 1024 bytes.");
    }
    if let Some(reason) = reason {
        out.push(' ');
        out.push_str(reason);
    }
    out
}

fn capsule_redirect(token: &str, page: usize) -> Reply {
    Reply::gemini(
        30,
        &format!("gemini://{HOST}/apply/{token}/{page}"),
        String::new(),
    )
}

fn capsule_not_found() -> Reply {
    Reply::gemini(51, "Not found", String::new())
}

/// Draw the intent id and write the application then the intent. The application
/// goes first, so the drain never sees an intent whose application is not on
/// disk. One writer for the web form and the capsule, so the order cannot drift
/// between them.
async fn file_application(app: &App, record: &Record) -> Result<(), String> {
    let id = ulid::Ulid::new().to_string();
    let bytes = serde_json::to_vec_pretty(record)
        .map_err(|e| format!("cannot encode the application: {e}"))?;
    app.store
        .write_record(
            "applications",
            &format!("{}.json", record.status_token),
            &bytes,
        )
        .await?;
    let intent = serde_json::to_vec_pretty(&record.intent(&id))
        .map_err(|e| format!("cannot encode the intent: {e}"))?;
    app.store
        .write_record("intents", &format!("{id}.json"), &intent)
        .await
}

/// Every answer is in hand: file the application and the one intent through the
/// same builder the web form uses, then remove the draft. The token stays the
/// one the draft carried, which is the capability the status link already holds.
async fn capsule_file(app: &App, record: &draft::Draft) -> Reply {
    let body = record.answers.get("whose").map(String::as_str) == Some("body");
    let answers = flow_answers(record, body);
    let application = match build_record(app, &answers, body, &record.token, "capsule") {
        Ok(application) => application,
        Err(e) => {
            eprintln!("kyriakon-onboard: {e}");
            return Reply::gemini(40, "Temporary failure", String::new());
        }
    };
    if let Err(e) = file_application(app, &application).await {
        eprintln!("kyriakon-onboard: {e}");
        return Reply::gemini(40, "Temporary failure", String::new());
    }
    if let Err(e) = draft::remove(&app.store, &record.token).await {
        eprintln!("kyriakon-onboard: {e}");
    }
    let link = format!("gemini://{HOST}/status/{}", record.token);
    Reply::gemini(20, "text/gemini", capsule::filed(&link))
}

/// The draft's answers with the key answer rebuilt from the keys the draft
/// holds, pasted and mailed alike. `build_record` pairs one block per mailbox in
/// account order, so a key the mail route filed and one pasted on the next page
/// cannot disagree about which mailbox they serve.
pub(crate) fn flow_answers(record: &draft::Draft, body: bool) -> BTreeMap<String, String> {
    let mut answers = record.answers.clone();
    let (id, mailboxes) = if body {
        ("body_mail_key", questions::account_names(&record.answers))
    } else {
        (
            "mail_key",
            vec![record.answers.get("username").cloned().unwrap_or_default()],
        )
    };
    let mut materials = Vec::new();
    for mailbox in &mailboxes {
        match record.mail_keys.iter().find(|k| k.mailbox == *mailbox) {
            Some(key) => materials.push(key.material.clone()),
            None => return answers,
        }
    }
    if !materials.is_empty() {
        answers.insert(id.to_string(), materials.join("\n\n"));
    }
    answers
}

/// The applicant page, with the community block open for a body. `branch` is the
/// branch the page was rendered for, which the GET carries so that a link to the
/// body's page opens it.
fn applicant(app: &App, query: BTreeMap<String, String>) -> Reply {
    let body = query.get("branch").map(String::as_str) == Some("body");
    render_applicant(app, body, &BTreeMap::new(), &[])
}

/// The branch question's own step. The continuation button posts the whole form
/// here, so the answer comes back as a submission, the page is rendered again with
/// the community block open or closed to match, and everything already typed comes
/// back with it. This is the whole of the branch mechanism: no script, and the
/// same question is settled the same way when the application is submitted, which
/// is what the terminal and the capsule inherit.
fn branch_step(app: &App, form: BTreeMap<String, String>) -> Reply {
    let body = form.get("whose").map(String::as_str) == Some("body");
    render_applicant(app, body, &form, &[])
}

/// The account page. Its login and its capability list are its own ticket's; what
/// it renders today is the catalogue, from the one file, with no member to render
/// a `<name>` host from until a session identifies one.
fn account(app: &App) -> Reply {
    let page: AccountPage = page::account(&app.catalogue, None);
    Reply::html(200, page_html(&page))
}

/// What a submission is read against.
struct Reading {
    /// Whether it is read as a body's, which decides which questions exist.
    body: bool,
    /// Whether the applicant has already been shown that branch's questions. False
    /// when the answer names a branch the page did not carry, which is a question
    /// the page had not opened and therefore answers it never showed.
    shown: bool,
}

/// The branch a submission is read against, and whether its own answers are the
/// page it was shown. The branch question's answer settles this, from the same
/// field whichever front-end filed the submission: the web form posts its select,
/// and the terminal and the capsule post the same answer.
fn reading(form: &BTreeMap<String, String>) -> Reading {
    let body = form.get("whose").map(String::as_str) == Some("body");
    let shown = match form.get("branch") {
        // The web form posts the branch its page was rendered for. An answer
        // naming the other one means the applicant changed the select without
        // opening the block it asks for, so the page they were shown is not the
        // page their answer asks for.
        Some(page) => (page == "body") == body,
        // No page: a front-end that renders its own has already shown whatever its
        // answer asks for, so its answer is the page.
        None => true,
    };
    Reading { body, shown }
}

/// A submission's origin. `Origin` is sent on every browser POST; a value that is
/// not this service's own is refused. When it is absent, `Sec-Fetch-Site` is the
/// fallback, and a browser that sends neither is a client that is not a browser at
/// all, which is not a cross-site request.
fn own_origin(request: &Request) -> bool {
    // A browser that posts a form sends Origin, and an ordinary tab sends this
    // site as it. An in-app browser, which is what a link tapped in a mail or
    // chat client opens, sends `Origin: null` instead, and `Sec-Fetch-Site:
    // same-origin` beside it. The null origin used to refuse that submission
    // without ever reading the header that would have answered the question, so
    // null falls through to Sec-Fetch-Site now, as an absent Origin already did.
    let origin = request.get("HTTP_ORIGIN");
    let site = request.get("HTTP_SEC_FETCH_SITE");
    if let Some(origin) = origin {
        if origin != "null" {
            return origin == OWN_ORIGIN;
        }
    }
    match site {
        // same-site is the same registrable site as this page, which is what a
        // browser reports when it reads the post as this site's but not this
        // origin's: it is not a cross-site submission and does not need to be.
        Some(site) => site == "same-origin" || site == "same-site" || site == "none",
        None => true,
    }
}

async fn apply(app: &App, request: &Request, incoming: &Incoming) -> Reply {
    let form = fields(&String::from_utf8_lossy(&request.body));
    let Reading { body, shown } = reading(&form);

    // Read before anything else is done with the submission, and before the
    // request is charged as a draft: a front end that names itself wrongly gets
    // its refusal rather than an application recorded under a name nothing
    // recognises. The web form does not post this field at all, so its absence is
    // the web form.
    let label = match label(&form) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("kyriakon-onboard: {e}");
            return refused("A submission has to name its front end as web, tui or capsule.");
        }
    };

    // The answer names a branch the page did not carry, so its questions are ones
    // the applicant has not been shown and answers they have not been given the
    // chance to give. Refusing would list exactly those, which is the refusal the
    // ticket is about: the page is rendered again with the block open instead, and
    // the answers so far come back with it.
    if !shown {
        return render_applicant(app, body, &form, &[]);
    }
    let errors = application_problems(app, &form);
    if !errors.is_empty() {
        let mut page = page::applicant(
            &app.questions,
            &app.catalogue,
            body,
            &form,
            &app.cfg.release,
        );
        page.errors = errors;
        return Reply::html(422, page_html(&page));
    }

    // Charged here, once the submission is a draft and no longer merely an
    // attempt: a refusal spends the request budget, not the day's drafts, and a
    // third-party page cannot burn a visitor's day with junk posts.
    if !app.counter.allow_draft(incoming.key) {
        // The web front-end's own refusal: a draft is filed through this route,
        // which is the form's.
        return too_many(FrontEnd::Httpd, Which::Day);
    }

    let token = match store::status_token().await {
        Ok(t) => t,
        Err(e) => return server_error(&e),
    };
    let record = match build_record(app, &form, body, &token, label) {
        Ok(r) => r,
        Err(e) => return server_error(&e),
    };
    if let Err(e) = file_application(app, &record).await {
        return server_error(&e);
    }

    capability(&ReceivedPage {
        status_url: format!("https://{HOST}/status/{token}"),
    })
}

/// The status page for one token, which is the same page over both front-ends: a
/// capability in the URL is never stored and its URL is never sent as a referrer.
async fn status(app: &App, token: &str) -> Reply {
    let record = record_for(app, token).await;
    capability(&status_page(record, OffsetDateTime::now_utc()))
}

/// The decision a link names, with the signature it carries. A link with no
/// signature, or with one naming an action this build has no decision for, names
/// no decision.
fn decision_from(f: &BTreeMap<String, String>) -> Option<&'static transitions::Decision> {
    let sig = f.get("sig").map(String::as_str).unwrap_or("");
    if sig.is_empty() {
        return None;
    }
    transitions::decision_for(f.get("action").map(String::as_str).unwrap_or(""))
}

/// Why a confirm page cannot name a decision, in the words the reader needs.
///
/// Two ways to get here, and they are not the same problem. A mail client that
/// wraps the line cuts the URL at the wrap, which drops the signature: the link
/// itself is fine and the address the browser got is not. Saying so is the
/// difference between "try the next link" and "use the terminal form".
fn decision_refusal(query: &BTreeMap<String, String>) -> &'static str {
    if query.get("sig").is_none_or(|s| s.is_empty()) {
        return "This address is missing the signature, which a mail client that \
                wrapped the line will cause. Open the link exactly as it appears in \
                the message, or use the onboardctl line in it.";
    }
    "This link does not name a decision the platform knows."
}

/// The confirm step in front of a decision link.
///
/// The links in the review email do not act when they are fetched. Email is
/// fetched by things that are not the operator: a link scanner, a mail client's
/// preview, a corporate rewriter that follows every URL before the human sees it.
/// A GET that filed a decision would let any of them approve or decline an
/// application, and the operator would never know, because a decision they did
/// not make leaves nothing they can see. So the link opens this page, which names
/// what it would do, and the button posts.
///
/// The signature is carried through untouched and is not checked here: the
/// handler holds no key and holds no privilege, and the drain is the half that
/// verifies the signature before carrying anything out.
async fn decide_confirm(app: &App, token: &str, query: &BTreeMap<String, String>) -> Reply {
    let Some(record) = record_for(app, token).await else {
        // The page an unknown, an expired and a spent token all read as.
        return capability(&status_page(None, OffsetDateTime::now_utc()));
    };
    let Some(decision) = decision_from(query) else {
        return refused(decision_refusal(query));
    };
    capability(&DecidePage {
        label: decision.label.to_string(),
        username: record.username,
        token: token.to_string(),
        action: decision.action.to_string(),
        sig: query.get("sig").cloned().unwrap_or_default(),
    })
}

/// The click itself: the decision the confirm page named, filed as an intent the
/// drain verifies and carries out.
///
/// An application that has already been decided is not refused here. Nothing in
/// this handler reads the decision's state, because a click files an intent and
/// that is the whole of its job: the drain is the half with the key, and it is
/// the half that decides whether the click was already seen, so a replay is
/// answered where the rule already lives and is already tested.
async fn decide_file(app: &App, token: &str, form: &BTreeMap<String, String>) -> Reply {
    let Some(record) = record_for(app, token).await else {
        return capability(&status_page(None, OffsetDateTime::now_utc()));
    };
    let Some(decision) = decision_from(form) else {
        return refused("This link does not name a decision the platform knows.");
    };
    let sig = form.get("sig").cloned().unwrap_or_default();
    match intents::file_decision(
        &app.store,
        decision.kind,
        decision.action,
        &record.username,
        token,
        &sig,
    )
    .await
    {
        Ok(_) => capability(&notice(
            "Filed",
            "The decision is filed. The platform carries it out on its next pass, within a minute.",
        )),
        Err(e) => server_error(&format!("the decision could not be filed: {e}")),
    }
}

/// Whether the date a password link carries is still ahead of today. The drain
/// checks the same value under the signature; this is the page's copy of the
/// rule, not the rule itself.
fn password_window_open(until: &str) -> bool {
    until >= crate::util::date_after_days(0).as_str()
}

#[cfg(test)]
mod decision_refusal_tests {
    use super::decision_refusal;
    use std::collections::BTreeMap;

    fn query(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_missing_signature_names_the_wrap_not_the_link() {
        // The wrap is what happened to the first real approval: the URL arrived
        // without its &sig= and the page said the link named nothing.
        let text = decision_refusal(&query(&[("action", "approve-free")]));
        assert!(text.contains("missing the signature"), "{text}");
        assert!(text.contains("onboardctl"), "{text}");
    }

    #[test]
    fn an_unknown_action_keeps_the_link_message() {
        let text = decision_refusal(&query(&[("action", "nonsense"), ("sig", "ab")]));
        assert!(text.contains("does not name a decision"), "{text}");
    }
}

#[cfg(test)]
mod password_window_tests {
    use super::password_window_open;

    #[test]
    fn a_past_date_is_closed_and_today_is_open() {
        // The link's date is signed with its token, so the drain checks the same
        // value; this only decides whether the form is shown.
        assert!(!password_window_open("2000-01-01"));
        assert!(password_window_open(&crate::util::date_after_days(0)));
        assert!(password_window_open(&crate::util::date_after_days(1)));
    }
}

/// The form behind a one-time password link.
///
/// Past its window, or once the record no longer holds a link, this is the
/// unknown-token page byte for byte: that page is a function of nothing, so the
/// two cannot drift apart.
async fn password_page(app: &App, token: &str, query: &BTreeMap<String, String>) -> Reply {
    let Some(record) = record_for(app, token).await else {
        return capability(&status_page(None, OffsetDateTime::now_utc()));
    };
    let (Some(until), Some(sig)) = (query.get("until"), query.get("sig")) else {
        return capability(&status_page(None, OffsetDateTime::now_utc()));
    };
    if record.password_link.is_none() || !password_window_open(until) {
        return capability(&status_page(None, OffsetDateTime::now_utc()));
    }
    capability(&PasswordPage {
        username: record.username,
        token: token.to_string(),
        until: until.clone(),
        sig: sig.clone(),
        error: None,
    })
}

/// The submission: check the password, hash it, and file the intent the drain
/// verifies and applies. The signature travels with it, because the handler
/// holds no key and proves nothing on its own.
async fn password_file(app: &App, token: &str, form: &BTreeMap<String, String>) -> Reply {
    let Some(record) = record_for(app, token).await else {
        return capability(&status_page(None, OffsetDateTime::now_utc()));
    };
    let (Some(until), Some(sig)) = (form.get("until"), form.get("sig")) else {
        return capability(&status_page(None, OffsetDateTime::now_utc()));
    };
    if record.password_link.is_none() || !password_window_open(until) {
        return capability(&status_page(None, OffsetDateTime::now_utc()));
    }
    let password = form.get("password").map(String::as_str).unwrap_or("");
    let confirm = form.get("confirm").map(String::as_str).unwrap_or("");
    let problem = if password != confirm {
        Some("The two passwords do not match.".to_string())
    } else {
        crate::password::validate(password).err()
    };
    if let Some(problem) = problem {
        return capability(&PasswordPage {
            username: record.username,
            token: token.to_string(),
            until: until.clone(),
            sig: sig.clone(),
            error: Some(problem),
        });
    }
    let hash = match crate::password::make(password) {
        Ok(hash) => hash,
        Err(e) => return server_error(&e),
    };
    match intents::file_password(&app.store, &record.username, token, until, sig, &hash).await {
        Ok(_) => capability(&notice(
            "Password set",
            "The platform sets it on its next pass, within a minute. This link will not work again.",
        )),
        Err(e) => server_error(&format!("the password could not be filed: {e}")),
    }
}

/// The page one token's record renders, or the one notice that covers a token
/// that is unknown, expired or spent alike. The window is read here and not in the
/// store, because a record is still on disk after its link has stopped answering:
/// nothing is deleted for it, the page simply stops.
fn status_page(record: Option<Record>, now: OffsetDateTime) -> StatusPage {
    let live = record.filter(|r| match r.decided_at.as_deref() {
        // The drain sets `decided_at` when it decides. Until it does, the
        // application has not been decided and the link answers.
        Some(decided_at) => util::link_answers(decided_at, now),
        None => true,
    });
    match live {
        Some(record) => StatusPage {
            stage: record.stage,
            filed_at: record.filed_at,
            notice: String::new(),
            password_link: record.password_link,
        },
        None => StatusPage {
            stage: String::new(),
            filed_at: String::new(),
            notice: UNKNOWN_TOKEN.to_string(),
            password_link: None,
        },
    }
}

/// The record a token answers for, or `None` for one that is unknown, expired or
/// spent. A token is a path component, so it is checked against the alphabet
/// before it is used as one: a probe cannot walk the directory with "..".
async fn record_for(app: &App, token: &str) -> Option<Record> {
    let well_formed = token.len() == 26
        && token
            .bytes()
            .all(|b| b"0123456789abcdefghjkmnpqrstvwxyz".contains(&b));
    if !well_formed {
        return None;
    }
    app.store
        .read_record("applications", &format!("{token}.json"))
        .await
        .and_then(|s| serde_json::from_str::<Record>(&s).ok())
}

/// The front end that filed a submission: `web`, `tui` or `capsule`, and the web
/// form when the field is not sent at all, since the browser form does not carry
/// one. It is a label and nothing more, so nothing reads it but the reviewer and
/// the intent: that is also why an unknown value is refused rather than recorded,
/// because a value no reader recognises is a value that cannot be read at all.
fn label(form: &BTreeMap<String, String>) -> Result<&'static str, String> {
    match form.get("front_end").map(String::as_str) {
        None | Some("web") => Ok("web"),
        Some("tui") => Ok("tui"),
        Some("capsule") => Ok("capsule"),
        Some(other) => Err(format!("unknown front_end {other:?}")),
    }
}

/// Every refusal a submission has earned, in the form's own order. The web form
/// posts it, and the terminal's completed application is checked with it before
/// the handler files anything, so the two cannot disagree about what is
/// acceptable.
fn application_problems(app: &App, form: &BTreeMap<String, String>) -> Vec<String> {
    let body = form.get("whose").map(String::as_str) == Some("body");
    let monastic = questions::is_monastic(form.get("orders").map(String::as_str));
    let mut errors = Vec::new();
    for q in questions::shown(&app.questions, !body) {
        let value = form.get(&q.id).cloned().unwrap_or_default();
        // A monastic-branch question belongs to the monastic path, so its
        // requirement is read from the file's own column and applied only when the
        // orders answer selects that path.
        let required = match q.branch {
            Branch::Monastic => monastic && q.required,
            _ => q.required,
        };
        if q.rule == Rule::MailKey {
            for why in mail_key_errors(q, &value, form) {
                errors.push(format!("{}: {why}", q.prompt));
            }
        } else if let Some(why) = validate::reason(q, &value, &app.reserved, required) {
            errors.push(format!("{}: {why}", q.prompt));
        }
    }
    if body {
        body_cross_checks(form, &mut errors);
    }
    errors
}

/// The body's addresses against its account names: the same number of lines, at
/// most ten, and each address line `localpart: own` or `localpart: alias
/// localpart`, which is the form the spec's community-block table gives.
pub(crate) fn body_cross_checks(form: &BTreeMap<String, String>, errors: &mut Vec<String>) {
    let addresses = form.get("body_addresses").map(String::as_str).unwrap_or("");
    let a = addresses.lines().filter(|l| !l.trim().is_empty()).count();
    let n = questions::account_names(form).len();
    if a != n {
        errors.push(format!(
            "The addresses, one per line: {a} addresses and {n} account names; there is one account name per address"
        ));
    }
    if let Some(why) = validate::address_lines(addresses) {
        errors.push(format!("The addresses, one per line: {why}"));
    }
}

fn build_record(
    app: &App,
    form: &BTreeMap<String, String>,
    body: bool,
    token: &str,
    front_end: &str,
) -> Result<Record, String> {
    let answers: BTreeMap<String, String> = questions::shown(&app.questions, !body)
        .iter()
        .map(|q| (q.id.clone(), form.get(&q.id).cloned().unwrap_or_default()))
        .collect();
    let rail = form.get("rail").cloned().unwrap_or_default();

    let mail_key_id = if body { "body_mail_key" } else { "mail_key" };
    let blocks = keycheck::blocks(form.get(mail_key_id).map(String::as_str).unwrap_or(""));
    let mailboxes: Vec<String> = if body {
        questions::account_names(form)
    } else {
        vec![String::new()]
    };
    let mut mail_keys = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        mail_keys.push(keycheck::mail_key(
            mailboxes.get(i).cloned().unwrap_or_default(),
            block,
        ));
    }

    let upload_key_id = if body {
        "body_upload_key"
    } else {
        "upload_key"
    };
    let upload = form
        .get(upload_key_id)
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    let upload_key = (!upload.is_empty()).then(|| keycheck::upload_key(upload));

    Ok(Record {
        username: form.get("username").cloned().unwrap_or_default(),
        status_token: token.to_string(),
        filed_at: util::filed_at(),
        front_end: front_end.to_string(),
        stage: "received".to_string(),
        // Both are the drain's to write when it decides: the handler files an
        // undecided application and has no decision to record.
        decided_at: None,
        password_link: None,
        domain: body
            .then(|| form.get("body_domain").cloned().unwrap_or_default())
            .filter(|d| !d.trim().is_empty()),
        outside_address: form
            .get("address_outside")
            .cloned()
            .filter(|a| !a.trim().is_empty()),
        answers,
        mail_keys,
        upload_key,
        rail: rail.clone(),
        no_charge: rail == "no_charge",
        acceptances: capsule::ACCEPTED
            .iter()
            .map(|(document, _)| Acceptance {
                document: (*document).to_string(),
                version: app.cfg.release.clone(),
            })
            .collect(),
        question_list: app.cfg.release.clone(),
    })
}

/// The refusals for a mail-key answer. A person's key is one block; a body's is
/// one block per mailbox, paired with the account names in the order given.
fn mail_key_errors(q: &Question, value: &str, form: &BTreeMap<String, String>) -> Vec<String> {
    let blocks = keycheck::blocks(value);
    if blocks.is_empty() {
        return vec!["a public key is needed".to_string()];
    }
    if q.id == "body_mail_key" {
        let mailboxes = questions::account_names(form).len();
        if blocks.len() != mailboxes {
            return vec![format!(
                "one key per mailbox: {mailboxes} mailboxes and {} keys",
                blocks.len()
            )];
        }
        blocks
            .iter()
            .filter_map(|b| keycheck::pgp_public_key(b).err())
            .collect()
    } else if blocks.len() > 1 {
        vec!["one key for one address".to_string()]
    } else {
        keycheck::pgp_public_key(&blocks[0])
            .err()
            .into_iter()
            .collect()
    }
}

fn render_applicant(
    app: &App,
    body: bool,
    answers: &BTreeMap<String, String>,
    errors: &[String],
) -> Reply {
    let mut page = page::applicant(
        &app.questions,
        &app.catalogue,
        body,
        answers,
        &app.cfg.release,
    );
    page.errors = errors.to_vec();
    Reply::html(200, page_html(&page))
}

/// A page that carries a capability in its URL or is a capability itself is never
/// stored and its URL is never sent as a referrer.
fn capability<T: Template>(t: &T) -> Reply {
    Reply::capability(200, page_html(t))
}

enum Which {
    Minute,
    Day,
}

fn too_many(front_end: FrontEnd, which: Which) -> Reply {
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
fn refused(message: &str) -> Reply {
    Reply::html(403, page_html(&notice("Refused", message)))
}

fn notice(title: &str, message: &str) -> NoticePage {
    NoticePage {
        title: title.to_string(),
        message: message.to_string(),
    }
}

fn server_error(why: &str) -> Reply {
    eprintln!("kyriakon-onboard: {why}");
    Reply::html(
        500,
        page_html(&notice(
            "Something went wrong",
            "This is our fault, not yours. Try again in a moment.",
        )),
    )
}

fn page_html<T: Template>(t: &T) -> String {
    match t.render() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kyriakon-onboard: cannot render a page: {e}");
            RENDER_FALLBACK.to_string()
        }
    }
}

#[cfg(test)]
mod tests;
