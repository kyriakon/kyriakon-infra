//! The responder: the face that answers both front-ends.
//!
//! httpd's vhost for `signup.kyriakon.net` and gmid's signup block both reach this
//! over a unix socket, and it serves the same routes to both: the applicant page,
//! the branch step, the submission, the account page and the status page. The
//! routes, the pages and the wording are what the service served when it was an
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
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};

use crate::fcgi::{self, Reply, Request};
use crate::page::{AccountPage, DecidePage, NoticePage, PasswordPage, ReceivedPage, StatusPage};
use crate::questions::{Branch, Question, Rule};
use crate::rate::Key;
use crate::store::{Acceptance, KeyRecord, Record, Store};
use crate::{
    capsule, catalogue, config, intents, keycheck, page, questions, rate, store, transitions, util,
    validate,
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
const MAX_BODY: usize = 256 * 1024;

/// What a token the store does not answer for reads as. One constant, because an
/// unknown token, an expired one and a spent one are the same bytes: that is the
/// no-oracle rule the spec fixes, and it is only true if they share one author.
const UNKNOWN_TOKEN: &str =
    "This link is not in use. It may have been cleared away, or it may never have existed.";

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
        let reserved = validate::reserved(&Store::read_text(&cfg.reserved).await?);
        Ok(App {
            store: Store::new(&cfg.store_root),
            cfg,
            questions: list,
            catalogue: services,
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

/// Run the responder on the two sockets the config names, until one of them stops
/// accepting.
pub async fn serve(cfg: config::Config) -> Result<(), String> {
    let app = Arc::new(App::load(cfg).await?);
    let httpd = bind(&app.cfg.httpd_socket)?;
    let gemini = bind(&app.cfg.gemini_socket)?;
    eprintln!(
        "kyriakon-onboard: httpd {}, gemini {}, store {}, {} questions",
        app.cfg.httpd_socket,
        app.cfg.gemini_socket,
        app.cfg.store_root,
        app.questions.len()
    );
    tokio::try_join!(accept(httpd, app.clone()), accept(gemini, app)).map(|_| ())
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
async fn accept(listener: UnixListener, app: Arc<App>) -> Result<(), String> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("cannot accept: {e}"))?;
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = connection(stream, &app).await {
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
    Incoming { path, key, addr }
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

/// The gemini front-end, which serves the capsule's pages: the catalogue the
/// capsule lists, and the status page for a filed application. Nothing else is
/// here yet, because the rest of the capsule is its own front-end's ticket: the
/// applicant flow over gemini asks one question per page and keeps a draft, which
/// is a page shape the web form does not have.
///
/// No route on this face reads a query yet. When one does it is `QUERY_STRING`,
/// which gmid sends still percent-encoded and decodes by the responder rather
/// than read from `GEMINI_SEARCH_STRING`: that copy is sent only for a query with
/// no `=` in it, and its decoder maps `+` to a space, which is not the reading the
/// specification gives a URI query.
async fn gemini(app: &App, incoming: &Incoming) -> Reply {
    if let Some(token) = incoming.path.strip_prefix("status/") {
        let record = record_for(app, token).await;
        let page = status_page(record, OffsetDateTime::now_utc());
        return Reply::gemini(20, "text/gemini", capsule::status(&page));
    }
    if incoming.path.is_empty() {
        return Reply::gemini(20, "text/gemini", capsule::gemtext(&app.catalogue, None));
    }
    Reply::gemini(51, "Not found", String::new())
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
    let monastic = questions::is_monastic(form.get("orders").map(String::as_str));
    let applicable: Vec<&Question> = questions::shown(&app.questions, !body);

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

    let mut errors = Vec::new();
    // The answer names a branch the page did not carry, so its questions are ones
    // the applicant has not been shown and answers they have not been given the
    // chance to give. Refusing would list exactly those, which is the refusal the
    // ticket is about: the page is rendered again with the block open instead, and
    // the answers so far come back with it.
    if !shown {
        return render_applicant(app, body, &form, &[]);
    }
    for q in &applicable {
        let value = form.get(&q.id).cloned().unwrap_or_default();
        // A monastic-branch question belongs to the monastic path, so its
        // requirement is read from the file's own column and applied only when the
        // orders answer selects that path.
        let required = match q.branch {
            Branch::Monastic => monastic && q.required,
            _ => q.required,
        };
        if q.rule == Rule::MailKey {
            for why in mail_key_errors(q, &value, &form) {
                errors.push(format!("{}: {why}", q.prompt));
            }
        } else if let Some(why) = validate::reason(q, &value, &app.reserved, required) {
            errors.push(format!("{}: {why}", q.prompt));
        }
    }
    if body {
        body_cross_checks(&form, &mut errors);
    }
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
    let id = ulid::Ulid::new().to_string();
    let record = match build_record(app, &form, body, &token, label) {
        Ok(r) => r,
        Err(e) => return server_error(&e),
    };

    // The application record first, so the drain never sees an intent whose
    // application is not on disk yet, then the one intent.
    let app_bytes = match serde_json::to_vec_pretty(&record) {
        Ok(b) => b,
        Err(e) => return server_error(&format!("cannot encode the application: {e}")),
    };
    if let Err(e) = app
        .store
        .write_record("applications", &format!("{token}.json"), &app_bytes)
        .await
    {
        return server_error(&e);
    }
    let intent_bytes = match serde_json::to_vec_pretty(&record.intent(&id)) {
        Ok(b) => b,
        Err(e) => return server_error(&format!("cannot encode the intent: {e}")),
    };
    if let Err(e) = app
        .store
        .write_record("intents", &format!("{id}.json"), &intent_bytes)
        .await
    {
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

/// The body's addresses against its account names: the same number of lines, at
/// most ten, and each address line `localpart: own` or `localpart: alias
/// localpart`, which is the form the spec's community-block table gives.
fn body_cross_checks(form: &BTreeMap<String, String>, errors: &mut Vec<String>) {
    let addresses = form.get("body_addresses").map(String::as_str).unwrap_or("");
    let names = form
        .get("body_account_names")
        .map(String::as_str)
        .unwrap_or("");
    let count = |v: &str| v.lines().filter(|l| !l.trim().is_empty()).count();
    let (a, n) = (count(addresses), count(names));
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
    let blocks = key_blocks(form.get(mail_key_id).map(String::as_str).unwrap_or(""));
    let mailboxes: Vec<String> = if body {
        form.get("body_account_names")
            .map(|s| {
                s.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![String::new()]
    };
    let mut mail_keys = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        mail_keys.push(key_record(
            mailboxes.get(i).cloned().unwrap_or_default(),
            block,
            KeyKind::Mail,
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
    let upload_key =
        (!upload.is_empty()).then(|| key_record(String::new(), upload, KeyKind::Upload));

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
        acceptances: ["terms", "aup", "privacy"]
            .iter()
            .map(|d| Acceptance {
                document: (*d).to_string(),
                version: app.cfg.release.clone(),
            })
            .collect(),
        question_list: app.cfg.release.clone(),
    })
}

/// Which of the two fingerprints a key's material carries: an OpenPGP certificate
/// has the one gpg prints, and an OpenSSH public key the one ssh-keygen prints.
/// They are different numbers over different things.
#[derive(Clone, Copy)]
enum KeyKind {
    Mail,
    Upload,
}

/// A key as the record carries it. The fingerprint is computed here, over the
/// material stored beside it, because the handler is the only place that holds
/// both: the web form has no script and cannot compute one, and the walkthrough
/// that would have computed it in the browser never posts to a field nothing
/// fills. A number that names material it was not computed from is worse than
/// none, and the reviewer compares this one with the key they will be sent.
fn key_record(mailbox: String, material: &str, kind: KeyKind) -> KeyRecord {
    let verdict = keycheck::pgp_public_key(material)
        .map(|c| c.verdict)
        .unwrap_or_else(|_| "unchecked".to_string());
    let fingerprint = match kind {
        KeyKind::Mail => keycheck::pgp_fingerprint(material),
        KeyKind::Upload => keycheck::openssh_fingerprint(material),
    }
    .unwrap_or_default();
    KeyRecord {
        mailbox,
        fingerprint,
        material: material.trim().to_string(),
        verdict,
    }
}

/// The refusals for a mail-key answer. A person's key is one block; a body's is
/// one block per mailbox, paired with the account names in the order given.
fn mail_key_errors(q: &Question, value: &str, form: &BTreeMap<String, String>) -> Vec<String> {
    let blocks = key_blocks(value);
    if blocks.is_empty() {
        return vec!["a public key is needed".to_string()];
    }
    if q.id == "body_mail_key" {
        let mailboxes = form
            .get("body_account_names")
            .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0);
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

/// Split a key answer into armoured blocks, one per mailbox.
fn key_blocks(value: &str) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    const END: &str = "-----END PGP PUBLIC KEY BLOCK-----";
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_block = false;
    for line in value.lines() {
        let t = line.trim();
        if t.starts_with(BEGIN) {
            in_block = true;
            cur.clear();
        }
        if in_block {
            cur.push_str(line);
            cur.push('\n');
        }
        if t.starts_with(END) && in_block {
            in_block = false;
            out.push(cur.trim().to_string());
        }
    }
    out
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
