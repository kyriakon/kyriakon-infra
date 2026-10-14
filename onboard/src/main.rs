//! The onboarding handler. It listens on loopback only, holds no privilege and
//! no secret, validates what it is given, writes one JSON intent per submission
//! by rename, and answers with the status link. Every privileged thing is the
//! root drain's, on its next run.
//!
//! The modules it shares with the drain and `onboardctl` (the store, the config,
//! the questions and the validation) live in the crate's library, so a second
//! reader of the store cannot drift from the first.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use askama::Template;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Form, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use time::OffsetDateTime;

use kyriakon_onboard::page::{AccountPage, NoticePage, ReceivedPage, StatusPage};
use kyriakon_onboard::questions::{Branch, Question, Rule};
use kyriakon_onboard::rate::Key;
use kyriakon_onboard::store::{Acceptance, KeyRecord, Record, Store};
use kyriakon_onboard::{catalogue, config, keycheck, page, questions, rate, store, util, validate};

/// The fixed hostname for the form and the account page, used as itself.
const HOST: &str = "signup.kyriakon.net";
/// The only origin a submission may carry. The port-80 vhost redirects, so the
/// form is served over TLS and nowhere else.
const OWN_ORIGIN: &str = "https://signup.kyriakon.net";

/// The largest body the handler reads. The largest legitimate field is a pasted
/// public key: an armoured curve25519 key is about a kilobyte, and a body of ten
/// mailboxes pastes ten of them, percent-encoded (up to three bytes on the wire
/// for one byte of content) and beside the free-text answers. A quarter of a
/// megabyte is comfortable for that and bounds a form post well under the two
/// megabytes axum would otherwise accept.
const MAX_BODY: usize = 256 * 1024;

/// What a token the store does not answer for reads as. One constant, because
/// an unknown token, an expired one and a spent one are the same bytes: that is
/// the no-oracle rule the spec fixes, and it is only true if they share one
/// author.
const UNKNOWN_TOKEN: &str =
    "This link is not in use. It may have been cleared away, or it may never have existed.";

/// Served when a template could not be rendered. Static and interpolated with
/// nothing, so the one place with no markup around it cannot become somewhere a
/// field lands unescaped.
const RENDER_FALLBACK: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Kyriakon</title></head><body><main><h2>Something went wrong</h2>\
<p>This is our fault, not yours. Try again in a moment.</p></main></body></html>";

struct App {
    cfg: config::Config,
    questions: Vec<Question>,
    /// The shared service catalogue, parsed once at startup. Read from the path
    /// the config names, and empty only if that file held no `[[service]]` at
    /// all, which `run` refuses.
    catalogue: Vec<catalogue::Service>,
    reserved: HashSet<String>,
    counter: rate::Counter,
    store: Store,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kyriakon-onboard: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("serve") => {}
        Some(other) => {
            return Err(format!(
                "unknown command {other:?}; usage: kyriakon-onboard serve [--config PATH]"
            ))
        }
        None => return Err("usage: kyriakon-onboard serve [--config PATH]".to_string()),
    }
    let mut cfg_path = PathBuf::from("/etc/onboard/onboard.toml");
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => {
                cfg_path = PathBuf::from(args.next().ok_or("--config needs a path")?);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    let cfg = config::Config::load(&cfg_path)?;
    let list = questions::parse(&Store::read_text(&cfg.questions).await?)?;
    if list.is_empty() {
        return Err("the question list has no questions".to_string());
    }
    // The catalogue is read the same way and refused the same way: a handler
    // that came up with no services would render an application page that
    // promises nothing, which is the failure the config path exists to prevent.
    let services = catalogue::parse(&Store::read_text(&cfg.catalogue).await?)?;
    if services.is_empty() {
        return Err(format!("{} has no services", catalogue::TRACKED));
    }
    let reserved = validate::reserved(&Store::read_text(&cfg.reserved).await?);
    let addr = format!("{}:{}", cfg.listen, cfg.port);
    let app = Arc::new(App {
        store: Store::new(&cfg.store_root),
        cfg,
        questions: list,
        catalogue: services,
        reserved,
        counter: rate::Counter::new(),
    });

    // Loopback only: relayd terminates TLS for the hostname and passes the
    // request here, so the handler must never be reachable off the box.
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    eprintln!(
        "kyriakon-onboard: listening on {addr}, store {}, question list {} questions",
        app.cfg.store_root,
        app.questions.len()
    );

    let router = Router::new()
        // The branch question is answered by using the form: this route renders
        // the page again with the answer, and gets its submission from the
        // form's own continuation button.
        .route("/", get(applicant).post(branch_step))
        .route("/apply", post(apply))
        .route("/account", get(account))
        .route("/status/{token}", get(status))
        // The counters are a layer rather than a check inside each handler, so a
        // request an extractor rejects is still counted. The body limit is set
        // here rather than inherited, because the default is two megabytes.
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app);
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| format!("server stopped: {e}"))
}

/// Count the request, refuse a cross-origin submission, and pass the key on.
async fn guard(State(app): State<Arc<App>>, mut req: Request, next: Next) -> Response {
    let key = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| rate::key(c.0, req.headers()))
        .unwrap_or(Key::UnknownForward);
    if !app.counter.allow_request(key) {
        return too_many(Which::Minute);
    }
    if req.method() == Method::POST && !own_origin(req.headers()) {
        return refused(
            StatusCode::FORBIDDEN,
            "A submission has to come from this form's own page.",
        );
    }
    req.extensions_mut().insert(key);
    next.run(req).await
}

/// A submission's origin. `Origin` is sent on every browser POST; a value that
/// is not this service's own is refused. When it is absent, `Sec-Fetch-Site` is
/// the fallback, and a browser that sends neither is a client that is not a
/// browser at all, which is not a cross-site request.
fn own_origin(headers: &HeaderMap) -> bool {
    if let Some(origin) = headers.get("origin") {
        return origin.to_str().map(|o| o == OWN_ORIGIN).unwrap_or(false);
    }
    match headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        Some(site) => site == "same-origin" || site == "none",
        None => true,
    }
}

#[derive(Deserialize)]
struct BranchQuery {
    branch: Option<String>,
}

async fn applicant(State(app): State<Arc<App>>, Query(q): Query<BranchQuery>) -> Response {
    let body = q.branch.as_deref() == Some("body");
    render_applicant(&app, body, &BTreeMap::new(), &[]).into_response()
}

/// The account page. Its login and its capability list are its own ticket's; what
/// it renders today is the catalogue, from the one file, with no member to
/// render a `<name>` host from until a session identifies one.
async fn account(State(app): State<Arc<App>>) -> Response {
    let page: AccountPage = page::account(&app.catalogue, None);
    html(&page).into_response()
}

/// The branch question's own step. The continuation button posts the whole form
/// here, so the answer comes back as a submission, the page is rendered again
/// with the community block open or closed to match, and everything already
/// typed comes back with it. This is the whole of the branch mechanism: no
/// script, and the same question is settled the same way when the application is
/// submitted, which is what the terminal and the capsule inherit.
async fn branch_step(
    State(app): State<Arc<App>>,
    Form(form): Form<BTreeMap<String, String>>,
) -> Response {
    let body = form.get("whose").map(String::as_str) == Some("body");
    render_applicant(&app, body, &form, &[]).into_response()
}

/// What a submission is read against.
struct Reading {
    /// Whether it is read as a body's, which decides which questions exist.
    body: bool,
    /// Whether the applicant has already been shown that branch's questions.
    /// False when the answer names a branch the page did not carry, which is a
    /// question the page had not opened and therefore answers it never showed.
    shown: bool,
}

/// The branch a submission is read against, and whether its own answers are the
/// page it was shown. The branch question's answer settles this, from the same
/// field whichever front-end filed the submission: the web form posts its
/// select, and the terminal and the capsule post the same answer.
fn reading(form: &BTreeMap<String, String>) -> Reading {
    let body = form.get("whose").map(String::as_str) == Some("body");
    let shown = match form.get("branch") {
        // The web form posts the branch its page was rendered for. An answer
        // naming the other one means the applicant changed the select without
        // opening the block it asks for, so the page they were shown is not the
        // page their answer asks for.
        Some(page) => (page == "body") == body,
        // No page: a front-end that renders its own has already shown whatever
        // its answer asks for, so its answer is the page.
        None => true,
    };
    Reading { body, shown }
}

async fn status(State(app): State<Arc<App>>, Path(token): Path<String>) -> Response {
    // A token is a path component, so it is checked against the alphabet before
    // it is used as one: a probe cannot walk the directory with "..".
    let well_formed = token.len() == 26
        && token
            .bytes()
            .all(|b| b"0123456789abcdefghjkmnpqrstvwxyz".contains(&b));
    let found = if well_formed {
        app.store
            .read_record("applications", &format!("{token}.json"))
            .await
            .and_then(|s| serde_json::from_str::<Record>(&s).ok())
    } else {
        None
    };
    capability_page(&status_page(found, OffsetDateTime::now_utc()))
}

/// The page one token's record renders, or the one notice that covers a token
/// that is unknown, expired or spent alike. The window is read here and not in
/// the store, because a record is still on disk after its link has stopped
/// answering: nothing is deleted for it, the page simply stops.
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

async fn apply(
    State(app): State<Arc<App>>,
    Extension(key): Extension<Key>,
    // Every question id is one field, and `branch` beside them is the branch the
    // page that posted them was rendered for.
    Form(form): Form<BTreeMap<String, String>>,
) -> Response {
    let Reading { body, shown } = reading(&form);
    let monastic = questions::is_monastic(form.get("orders").map(String::as_str));
    let applicable: Vec<&Question> = questions::shown(&app.questions, !body);

    // Read before anything else is done with the submission, and before the
    // request is charged as a draft: a front end that names itself wrongly gets
    // its refusal rather than an application recorded under a name nothing
    // recognises. The web form does not post this field at all, so its absence
    // is the web form.
    let front_end = match front_end(&form) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("kyriakon-onboard: {e}");
            return refused(
                StatusCode::BAD_REQUEST,
                "A submission has to name its front end as web, tui or capsule.",
            );
        }
    };

    let mut errors = Vec::new();
    // The answer names a branch the page did not carry, so its questions are
    // ones the applicant has not been shown and answers they have not been given
    // the chance to give. Refusing would list exactly those, which is the
    // refusal the ticket is about: the page is rendered again with the block
    // open instead, and the answers so far come back with it.
    if !shown {
        return render_applicant(&app, body, &form, &[]).into_response();
    }
    for q in &applicable {
        let value = form.get(&q.id).cloned().unwrap_or_default();
        // A monastic-branch question belongs to the monastic path, so its
        // requirement is read from the file's own column and applied only when
        // the orders answer selects that path.
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
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            render_applicant(&app, body, &form, &errors),
        )
            .into_response();
    }

    // Charged here, once the submission is a draft and no longer merely an
    // attempt: a refusal spends the request budget, not the day's drafts, and a
    // third-party page cannot burn a visitor's day with junk posts.
    if !app.counter.allow_draft(key) {
        return too_many(Which::Day);
    }

    let token = match store::status_token().await {
        Ok(t) => t,
        Err(e) => return server_error(&e),
    };
    let id = ulid::Ulid::new().to_string();
    let record = match build_record(&app, &form, body, &token, front_end) {
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

    capability_page(&ReceivedPage {
        status_url: format!("https://{HOST}/status/{token}"),
    })
}

/// The front end that filed a submission: `web`, `tui` or `capsule`, and the
/// web form when the field is not sent at all, since the browser form does not
/// carry one. It is a label and nothing more, so nothing reads it but the
/// reviewer and the intent: that is also why an unknown value is refused rather
/// than recorded, because a value no reader recognises is a value that cannot
/// be read at all.
fn front_end(form: &BTreeMap<String, String>) -> Result<&'static str, String> {
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

    let upload_key_id = if body { "body_upload_key" } else { "upload_key" };
    let upload = form.get(upload_key_id).map(String::as_str).unwrap_or("").trim();
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

/// Which of the two fingerprints a key's material carries: an OpenPGP
/// certificate has the one gpg prints, and an OpenSSH public key the one
/// ssh-keygen prints. They are different numbers over different things.
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
        keycheck::pgp_public_key(&blocks[0]).err().into_iter().collect()
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
) -> Html<String> {
    let mut page =
        page::applicant(&app.questions, &app.catalogue, body, answers, &app.cfg.release);
    page.errors = errors.to_vec();
    html(&page)
}

/// A page that carries a capability in its URL or is a capability itself is
/// never stored and its URL is never sent as a referrer.
fn capability_page<T: Template>(t: &T) -> Response {
    let mut response = html(t).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

enum Which {
    Minute,
    Day,
}

fn too_many(which: Which) -> Response {
    let message = match which {
        Which::Minute => {
            "Too many requests have come from this address in a short time. Wait a minute and try again."
        }
        Which::Day => {
            "Too many applications have been started from this address today. Try again tomorrow."
        }
    };
    (
        StatusCode::TOO_MANY_REQUESTS,
        html(&NoticePage {
            title: "Too many requests".to_string(),
            message: message.to_string(),
        }),
    )
        .into_response()
}

/// A refusal of a request that is well formed and simply asks for something the
/// handler does not do. Not a field-level error: those go back into the form.
fn refused(code: StatusCode, message: &str) -> Response {
    (
        code,
        html(&NoticePage {
            title: "Refused".to_string(),
            message: message.to_string(),
        }),
    )
        .into_response()
}

fn server_error(why: &str) -> Response {
    eprintln!("kyriakon-onboard: {why}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        html(&NoticePage {
            title: "Something went wrong".to_string(),
            message: "This is our fault, not yours. Try again in a moment.".to_string(),
        }),
    )
        .into_response()
}

fn html<T: Template>(t: &T) -> Html<String> {
    match t.render() {
        Ok(s) => Html(s),
        Err(e) => {
            eprintln!("kyriakon-onboard: cannot render a page: {e}");
            Html(RENDER_FALLBACK.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::format_description::well_known::Rfc3339;

    fn at(s: &str) -> OffsetDateTime {
        OffsetDateTime::parse(s, &Rfc3339).unwrap()
    }

    /// A record of the shape the store holds, as the drain leaves one when it
    /// decides. The two fields the drain owns are the caller's.
    fn decided(stage: &str, decided_at: Option<&str>, password_link: Option<&str>) -> Record {
        let mut r: Record = serde_json::from_str(
            r#"{"username": "secretary", "status_token": "00000000000000000000000000",
                 "filed_at": "2026-10-01T09:00:00Z", "front_end": "tui", "stage": "received",
                 "answers": {}, "mail_keys": [], "rail": "no_charge", "no_charge": true,
                 "acceptances": [], "question_list": "2026-10-01 1a2b3c4"}"#,
        )
        .expect("a record the store could hold");
        r.stage = stage.to_string();
        r.decided_at = decided_at.map(str::to_string);
        r.password_link = password_link.map(str::to_string);
        r
    }

    #[test]
    fn a_decided_application_answers_for_seven_days_and_then_reads_as_unknown() {
        let now = at("2026-10-05T09:00:00Z");
        // Filed and not yet decided: the link answers.
        let filed = status_page(Some(decided("received", None, None)), now);
        assert_eq!(filed.notice, "");
        assert_eq!(filed.stage, "received");

        // Decided inside the window: answers, with the drain's own word for the
        // stage, and the link it wrote.
        let inside = status_page(
            Some(decided(
                "decided: an account without charge",
                Some("2026-10-01T09:00:00Z"),
                Some("https://signup.kyriakon.net/password/abcdefghjkmnpqrstvwxyz"),
            )),
            now,
        );
        assert_eq!(inside.notice, "");
        assert_eq!(inside.stage, "decided: an account without charge");
        assert_eq!(
            inside.password_link.as_deref(),
            Some("https://signup.kyriakon.net/password/abcdefghjkmnpqrstvwxyz")
        );

        // A record without a password link renders none.
        let without = status_page(Some(decided("received", None, None)), now);
        assert_eq!(without.password_link, None);

        // Past the window the record's page is the unknown-token page, byte for
        // byte, so a live token cannot be told from a dead one.
        let password_link = Some("https://signup.kyriakon.net/password/abcdefghjkmnpqrstvwxyz");
        let expired = status_page(
            Some(decided(
                "decided: an account on the paid tier",
                Some("2026-10-01T09:00:00Z"),
                password_link,
            )),
            at("2026-10-08T09:00:01Z"),
        );
        let unknown = status_page(None, now);
        assert_eq!(expired.notice, UNKNOWN_TOKEN);
        assert_eq!(expired.stage, "");
        assert_eq!(expired.filed_at, "");
        assert_eq!(expired.password_link, None, "an expired link renders no password link either");
        assert_eq!(
            (expired.notice, expired.stage, expired.filed_at),
            (unknown.notice, unknown.stage, unknown.filed_at)
        );
    }

    #[test]
    fn a_front_end_is_web_tui_or_capsule_and_nothing_else() {
        let mut form = BTreeMap::new();
        // The web form posts no such field, so its absence is the web form.
        assert_eq!(front_end(&form).unwrap(), "web");
        for v in ["web", "tui", "capsule"] {
            form.insert("front_end".to_string(), v.to_string());
            assert_eq!(front_end(&form).unwrap(), v);
        }
        for v in ["", "Capsule", "capsule ", "ssh", "http"] {
            form.insert("front_end".to_string(), v.to_string());
            assert!(front_end(&form).is_err(), "{v:?} should be refused");
        }
    }

    #[test]
    fn key_blocks_splits_one_per_mailbox() {
        let two = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAA\n-----END PGP PUBLIC KEY BLOCK-----\n\n-----BEGIN PGP PUBLIC KEY BLOCK-----\nBBB\n-----END PGP PUBLIC KEY BLOCK-----\n";
        assert_eq!(key_blocks(two).len(), 2);
        assert!(key_blocks("nothing here").is_empty());
    }

    #[test]
    fn a_submission_must_come_from_this_form() {
        let mut h = HeaderMap::new();
        assert!(own_origin(&h), "a client that is not a browser is allowed");
        h.insert("origin", OWN_ORIGIN.parse().unwrap());
        assert!(own_origin(&h));
        h.insert("origin", "https://elsewhere.example".parse().unwrap());
        assert!(!own_origin(&h));
        h.remove("origin");
        h.insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert!(!own_origin(&h));
        h.insert("sec-fetch-site", "same-origin".parse().unwrap());
        assert!(own_origin(&h));
    }

    #[test]
    fn the_body_addresses_are_counted_against_its_account_names() {
        let mut errors = Vec::new();
        let mut form = BTreeMap::new();
        form.insert("body_addresses".into(), "secretary: own\nhall: alias secretary".into());
        form.insert("body_account_names".into(), "secretary".into());
        body_cross_checks(&form, &mut errors);
        assert!(errors.iter().any(|e| e.contains("2 addresses and 1 account names")), "{errors:?}");

        errors.clear();
        form.insert("body_account_names".into(), "secretary\nhall".into());
        body_cross_checks(&form, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
    }

    /// A public key block with the structure of a key that can be encrypted to.
    const GOOD_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
mAYEAAAAABK4BgQAAAAAEg==\n-----END PGP PUBLIC KEY BLOCK-----\n";

    /// A handler over a store under a temporary directory, reading the shipped
    /// question list: the page these tests answer is the page an applicant is
    /// served, and the answers are the ones it asks for.
    fn handler(name: &str) -> (Arc<App>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("onboard-apply-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["applications", "intents"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let cfg = config::Config {
            store_root: dir.to_str().unwrap().to_string(),
            // All three are read once at startup, by `run`, which is not what
            // these tests exercise: the two lists are parsed here and the
            // reserved set is empty.
            questions: String::new(),
            reserved: String::new(),
            catalogue: String::new(),
            listen: "127.0.0.1".to_string(),
            port: 0,
            release: "2026-10-13 test".to_string(),
        };
        let app = Arc::new(App {
            store: Store::new(&cfg.store_root),
            cfg,
            questions: questions::parse(include_str!(
                "../../openbsd/etc/onboard/questions.toml"
            ))
            .expect("the shipped question list"),
            catalogue: catalogue::parse(include_str!(
                "../../openbsd/etc/onboard/catalogue.toml"
            ))
            .expect("the shipped catalogue"),
            reserved: HashSet::new(),
            counter: rate::Counter::new(),
        });
        (app, dir)
    }

    /// The HTML a response carries.
    async fn page_of(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// The answers the body's page asks for, and nothing a body's page does not
    /// carry: no mail_key, no upload_key, no monastic blessing.
    fn body_answers() -> BTreeMap<String, String> {
        [
            ("branch", "body"),
            ("whose", "body"),
            ("username", "theophilus"),
            ("body_name", "The Parish of Example"),
            ("body_kind", "parish"),
            ("vat", ""),
            ("body_domain", "example.invalid"),
            ("body_records", "yes"),
            ("body_addresses", "secretary: own"),
            ("body_account_names", "secretary"),
            ("body_mail_key", GOOD_KEY),
            ("body_upload_key", ""),
            ("body_dns_contact", ""),
            ("address_outside", ""),
            ("address_ack", ""),
            ("rail", "no_charge"),
            ("diocese", ""),
            ("orders", ""),
            ("blessing", ""),
            ("cannot_pay", ""),
            ("intended_use", ""),
            ("anything_else", ""),
            ("accept_terms", "yes"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn form(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn the_branch_question_opens_the_block_by_being_answered() {
        let (app, _dir) = handler("branch");
        let no_branch = || BranchQuery { branch: None };

        // The page as it opens: a person's, with no community block on it and
        // the branch its own form carries recorded as a person's.
        let fresh = page_of(applicant(State(app.clone()), Query(no_branch())).await).await;
        assert!(fresh.contains("name=\"branch\" value=\"person\""));
        assert!(!fresh.contains("id=\"body_name\""));

        // Answering for a body: the form's own continuation posts the answers
        // back and the page comes back with the block open, holding them.
        let answered = page_of(
            branch_step(
                State(app.clone()),
                Form(form(&[("username", "theophilus"), ("whose", "body")])),
            )
            .await,
        )
        .await;
        assert!(answered.contains("id=\"body_name\""), "the block is open");
        assert!(answered.contains("name=\"branch\" value=\"body\""));
        assert!(
            answered.contains("value=\"theophilus\""),
            "what was already typed comes back"
        );

        // Answering for a person closes it again.
        let closed = page_of(
            branch_step(State(app.clone()), Form(form(&[("whose", "person")]))).await,
        )
        .await;
        assert!(!closed.contains("id=\"body_name\""));
        assert!(closed.contains("name=\"branch\" value=\"person\""));
    }

    #[tokio::test]
    async fn a_body_submission_that_was_shown_the_block_is_filed() {
        let (app, dir) = handler("body-filed");

        // The block is opened the way an applicant opens it, by answering the
        // branch question, and the page that comes back is the one submitted to.
        let page = page_of(
            branch_step(State(app.clone()), Form(form(&[("whose", "body")]))).await,
        )
        .await;
        let answers = body_answers();
        assert!(page.contains("id=\"body_name\""), "the block is open");
        assert!(
            !page.contains("name=\"mail_key\""),
            "a body is not shown the person's key"
        );
        for id in answers.keys() {
            assert!(page.contains(&format!("name=\"{id}\"")), "{id} is on the page");
        }
        for q in questions::shown(&app.questions, false).iter().filter(|q| q.required) {
            assert!(
                page.contains(&format!("name=\"{}\"", q.id)),
                "the required question {} is on the page",
                q.id
            );
        }

        // Submitting it is not a refusal for a question the page did not show,
        // and it files the application.
        let response = apply(
            State(app.clone()),
            Extension(Key::UnknownForward),
            Form(answers),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a body applicant who filled in the block is not refused"
        );
        assert_eq!(
            std::fs::read_dir(dir.join("applications")).unwrap().count(),
            1,
            "one application, filed"
        );
    }

    #[tokio::test]
    async fn an_answer_the_page_did_not_carry_is_shown_rather_than_refused() {
        let (app, dir) = handler("body-unshown");

        // The select was changed to a body without opening the block, so the
        // page the applicant was shown was the person's: the body's questions
        // are ones they have never seen. The handler renders that page for them
        // instead of refusing for answers they were not asked for.
        let response = apply(
            State(app.clone()),
            Extension(Key::UnknownForward),
            Form(form(&[
                ("branch", "person"),
                ("whose", "body"),
                ("username", "theophilus"),
                ("rail", "no_charge"),
                ("accept_terms", "yes"),
            ])),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let page = page_of(response).await;
        assert!(page.contains("id=\"body_name\""), "the block is open");
        assert!(page.contains("name=\"branch\" value=\"body\""));
        assert_eq!(
            std::fs::read_dir(dir.join("applications")).unwrap().count(),
            0,
            "nothing is filed from a submission that was refused the page"
        );
    }
}
