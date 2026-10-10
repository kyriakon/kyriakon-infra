//! The onboarding handler. It listens on loopback only, holds no privilege and
//! no secret, validates what it is given, writes one JSON intent per submission
//! by rename, and answers with the status link. Every privileged thing is the
//! root drain's, on its next run.

mod config;
mod keycheck;
mod page;
mod questions;
mod rate;
mod store;
mod util;
mod validate;

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

use crate::page::{NoticePage, ReceivedPage, StatusPage};
use crate::questions::{Branch, Question, Rule};
use crate::rate::Key;
use crate::store::{Acceptance, KeyRecord, Record, Store};

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

/// Served when a template could not be rendered. Static and interpolated with
/// nothing, so the one place with no markup around it cannot become somewhere a
/// field lands unescaped.
const RENDER_FALLBACK: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Kyriakon</title></head><body><main><h2>Something went wrong</h2>\
<p>This is our fault, not yours. Try again in a moment.</p></main></body></html>";

struct App {
    cfg: config::Config,
    questions: Vec<Question>,
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
    let reserved = validate::reserved(&Store::read_text(&cfg.reserved).await?);
    let addr = format!("{}:{}", cfg.listen, cfg.port);
    let app = Arc::new(App {
        store: Store::new(&cfg.store_root),
        cfg,
        questions: list,
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
        .route("/", get(applicant))
        .route("/apply", post(apply))
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
        return (
            StatusCode::FORBIDDEN,
            html(&NoticePage {
                title: "Refused".to_string(),
                message: "A submission has to come from this form's own page.".to_string(),
            }),
        )
            .into_response();
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
    let page = match found {
        Some(record) => StatusPage {
            stage: record.stage,
            filed_at: record.filed_at,
            notice: String::new(),
        },
        // An unknown token and an expired one read the same, so the path is not
        // a token oracle.
        None => StatusPage {
            stage: String::new(),
            filed_at: String::new(),
            notice: "This link is not in use. It may have been cleared away, or it may never have existed.".to_string(),
        },
    };
    capability_page(&page)
}

async fn apply(
    State(app): State<Arc<App>>,
    Extension(key): Extension<Key>,
    // Every question id is one field, plus a `<id>_fingerprint` beside each key.
    Form(form): Form<BTreeMap<String, String>>,
) -> Response {
    let body = form.get("whose").map(String::as_str) == Some("body");
    let monastic = questions::is_monastic(form.get("orders").map(String::as_str));
    let applicable: Vec<&Question> = questions::shown(&app.questions, !body);

    let mut errors = Vec::new();
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
    let record = match build_record(&app, &form, body, &token) {
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
) -> Result<Record, String> {
    let answers: BTreeMap<String, String> = questions::shown(&app.questions, !body)
        .iter()
        .map(|q| (q.id.clone(), form.get(&q.id).cloned().unwrap_or_default()))
        .collect();
    let rail = form.get("rail").cloned().unwrap_or_default();

    let mail_key_id = if body { "body_mail_key" } else { "mail_key" };
    let blocks = key_blocks(form.get(mail_key_id).map(String::as_str).unwrap_or(""));
    let fingerprints = form
        .get(&format!("{mail_key_id}_fingerprint"))
        .map(|s| s.lines().map(str::trim).map(str::to_string).collect::<Vec<_>>())
        .unwrap_or_default();
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
            fingerprints.get(i).cloned().unwrap_or_default(),
        ));
    }

    let upload_key_id = if body { "body_upload_key" } else { "upload_key" };
    let upload = form.get(upload_key_id).map(String::as_str).unwrap_or("").trim();
    let upload_key = (!upload.is_empty()).then(|| {
        key_record(
            String::new(),
            upload,
            form.get(&format!("{upload_key_id}_fingerprint"))
                .cloned()
                .unwrap_or_default(),
        )
    });

    Ok(Record {
        username: form.get("username").cloned().unwrap_or_default(),
        status_token: token.to_string(),
        filed_at: util::filed_at(),
        front_end: "web".to_string(),
        stage: "received".to_string(),
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

fn key_record(mailbox: String, material: &str, fingerprint: String) -> KeyRecord {
    let verdict = keycheck::pgp_public_key(material)
        .map(|c| c.verdict)
        .unwrap_or_else(|_| "unchecked".to_string());
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
    let mut page = page::applicant(&app.questions, body, answers, &app.cfg.release);
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
}
