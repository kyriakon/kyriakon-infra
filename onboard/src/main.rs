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
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use askama::Template;
use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;

use crate::page::{NoticePage, ReceivedPage, StatusPage};
use crate::questions::{Branch, Question, Rule};
use crate::store::{Acceptance, KeyRecord, Record, Store};

/// The fixed hostname for the form and the account page, used as itself.
const HOST: &str = "signup.kyriakon.net";

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
        Some(other) => return Err(format!("unknown command {other:?}; usage: kyriakon-onboard serve [--config PATH]")),
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
    let list = questions::parse(&Store::read_text(&cfg.questions)?)?;
    if list.is_empty() {
        return Err("the question list has no questions".to_string());
    }
    let reserved = validate::reserved(&Store::read_text(&cfg.reserved)?);
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
        .with_state(app);
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| format!("server stopped: {e}"))
}

#[derive(Deserialize)]
struct BranchQuery {
    branch: Option<String>,
}

async fn applicant(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<BranchQuery>,
) -> Response {
    if !app.counter.allow_request(client_ip(peer, &headers)) {
        return too_many();
    }
    let body = q.branch.as_deref() == Some("body");
    render_applicant(&app, body, &BTreeMap::new(), &[]).into_response()
}

async fn status(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    if !app.counter.allow_request(client_ip(peer, &headers)) {
        return too_many();
    }
    // A token is a path component, so it is checked against the alphabet before
    // it is used as one: a probe cannot walk the directory with "..".
    let well_formed = token.len() == 26
        && token
            .bytes()
            .all(|b| b"0123456789abcdefghjkmnpqrstvwxyz".contains(&b));
    let found = well_formed
        .then(|| app.store.read_record("applications", &format!("{token}.json")))
        .flatten()
        .and_then(|s| serde_json::from_str::<Record>(&s).ok());
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
    html(&page).into_response()
}

async fn apply(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    // Every question id is one field, plus a `<id>_fingerprint` beside each key.
    Form(form): Form<BTreeMap<String, String>>,
) -> Response {
    let ip = client_ip(peer, &headers);
    if !app.counter.allow_request(ip) || !app.counter.allow_draft(ip) {
        return too_many();
    }

    let body = form.get("whose").map(String::as_str) == Some("body");
    let monastic = questions::is_monastic(form.get("orders").map(String::as_str));
    let applicable: Vec<&Question> = questions::shown(&app.questions, !body);

    let mut errors = Vec::new();
    for q in &applicable {
        let value = form.get(&q.id).cloned().unwrap_or_default();
        // A monastic-branch question is shown on both paths and is required only
        // on the monastic path, which the orders answer selects. The file's own
        // required flag cannot express that, so it is not read for one.
        let required = match q.branch {
            Branch::Monastic => monastic,
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
    if !errors.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            render_applicant(&app, body, &form, &errors),
        )
            .into_response();
    }

    let token = match store::status_token() {
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
    {
        return server_error(&e);
    }

    html(&ReceivedPage {
        status_url: format!("https://{HOST}/status/{token}"),
    })
    .into_response()
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
            .map(|s| s.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect())
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
            form.get(&format!("{upload_key_id}_fingerprint")).cloned().unwrap_or_default(),
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

/// The client's address. `X-Forwarded-For` is trusted only because the listener
/// is loopback and relayd is the only thing that can reach it: the front end
/// sets the header the counters key on. A listener opened beyond loopback would
/// let a caller forge it, which is why the address is loopback in the config.
fn client_ip(peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or_else(|| peer.ip())
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

fn too_many() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        html(&NoticePage {
            title: "Too many requests".to_string(),
            message: "Too many requests have come from this address in a short time. Wait a minute and try again.".to_string(),
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
        Err(e) => Html(format!("<!doctype html><p>The page could not be rendered: {e}</p>")),
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
    fn the_forwarded_address_wins_only_when_it_parses() {
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let mut h = HeaderMap::new();
        assert_eq!(client_ip(peer, &h), "127.0.0.1".parse::<IpAddr>().unwrap());
        h.insert("x-forwarded-for", "203.0.113.10, 127.0.0.1".parse().unwrap());
        assert_eq!(client_ip(peer, &h), "203.0.113.10".parse::<IpAddr>().unwrap());
        h.insert("x-forwarded-for", "not an address".parse().unwrap());
        assert_eq!(client_ip(peer, &h), "127.0.0.1".parse::<IpAddr>().unwrap());
    }
}
