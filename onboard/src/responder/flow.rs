//! The shared applicant flow and the web form handlers.

use super::*;

use std::collections::{BTreeMap, HashSet};

use crate::fcgi::{Reply, Request};
use crate::questions::{Branch, Kind, Question, Rule};
use crate::store::{Acceptance, Record};
use crate::{capsule, draft, keycheck, page, questions, util, validate};

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

/// Draw the intent id and write the application then the intent. The application
/// goes first, so the drain never sees an intent whose application is not on
/// disk. One writer for the web form and the capsule, so the order cannot drift
/// between them.
pub(super) async fn file_application(app: &App, record: &Record) -> Result<(), String> {
    let id = ulid::Ulid::new().to_string();
    let name = format!("{}.json", record.status_token);
    // Both encodings first: an encoding failure must leave no record either.
    let bytes = serde_json::to_vec_pretty(record)
        .map_err(|e| format!("cannot encode the application: {e}"))?;
    let intent = serde_json::to_vec_pretty(&record.intent(&id))
        .map_err(|e| format!("cannot encode the intent: {e}"))?;
    app.store
        .write_record("applications", &name, &bytes)
        .await?;
    if let Err(e) = app
        .store
        .write_record("intents", &format!("{id}.json"), &intent)
        .await
    {
        // A record whose intent was never written is never reviewed and never
        // purged, and the applicant retries under a fresh token. Remove it so
        // the retry starts clean; a failure to remove is reported beside the
        // original error rather than replacing it.
        if let Err(remove) = app.store.remove("applications", &name).await {
            eprintln!("kyriakon-onboard: the orphaned application record {name} stays: {remove}");
        }
        return Err(e);
    }
    Ok(())
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
pub(super) fn applicant(app: &App, query: BTreeMap<String, String>) -> Reply {
    let body = query.get("branch").map(String::as_str) == Some("body");
    render_applicant(app, body, &BTreeMap::new(), &[])
}

/// The branch question's own step. The continuation button posts the whole form
/// here, so the answer comes back as a submission, the page is rendered again with
/// the community block open or closed to match, and everything already typed comes
/// back with it. This is the whole of the branch mechanism: no script, and the
/// same question is settled the same way when the application is submitted, which
/// is what the terminal and the capsule inherit.
pub(super) fn branch_step(app: &App, form: BTreeMap<String, String>) -> Reply {
    let body = form.get("whose").map(String::as_str) == Some("body");
    render_applicant(app, body, &form, &[])
}

/// The front page: the web form's applicant page, and the capsule's catalogue
/// with its links. The branch step is the same path under a POST, and a row of
/// its own for that reason.
pub(super) async fn root(app: &App, call: &Call<'_>) -> Reply {
    match call.front {
        FrontEnd::Httpd => applicant(app, call.query()),
        FrontEnd::Gemini => capsule_front(app, call.incoming).await,
    }
}

/// What a submission is read against.
pub(super) struct Reading {
    /// Whether it is read as a body's, which decides which questions exist.
    pub(super) body: bool,
    /// Whether the applicant has already been shown that branch's questions. False
    /// when the answer names a branch the page did not carry, which is a question
    /// the page had not opened and therefore answers it never showed.
    pub(super) shown: bool,
}

/// The branch a submission is read against, and whether its own answers are the
/// page it was shown. The branch question's answer settles this, from the same
/// field whichever front-end filed the submission: the web form posts its select,
/// and the terminal and the capsule post the same answer.
pub(super) fn reading(form: &BTreeMap<String, String>) -> Reading {
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
pub(super) fn own_origin(request: &Request) -> bool {
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

/// The front end that filed a submission: `web`, `tui` or `capsule`, and the web
/// form when the field is not sent at all, since the browser form does not carry
/// one. It is a label and nothing more, so nothing reads it but the reviewer and
/// the intent: that is also why an unknown value is refused rather than recorded,
/// because a value no reader recognises is a value that cannot be read at all.
pub(super) fn label(form: &BTreeMap<String, String>) -> Result<&'static str, String> {
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
pub(super) fn application_problems(app: &App, form: &BTreeMap<String, String>) -> Vec<String> {
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

pub(super) fn build_record(
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

    // The first checkbox records the three documents; the second records the
    // request for immediate supply and the digital-content acknowledgement in
    // the same list, so the confirmation email quotes both and nothing has a
    // second home.
    let mut acceptances: Vec<Acceptance> = capsule::ACCEPTED
        .iter()
        .map(|(document, _)| Acceptance {
            document: (*document).to_string(),
            version: app.cfg.release.clone(),
        })
        .collect();
    if form.get("accept_supply").map(String::as_str) == Some("yes") {
        acceptances.push(Acceptance {
            document: "immediate supply and the digital-content acknowledgement".to_string(),
            version: app.cfg.release.clone(),
        });
    }

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
        // The drain copies the account's block here at approval, which is the
        // only way the unprivileged handler can render it.
        payment: None,
        answers,
        mail_keys,
        upload_key,
        rail: rail.clone(),
        no_charge: rail == "no_charge",
        // The drain writes this when it sends the confirmation, which is before
        // it files anything the handler sees.
        confirmation_at: None,
        acceptances,
        question_list: app.cfg.release.clone(),
    })
}

/// The refusals for a mail-key answer. A person's key is one block; a body's is
/// one block per mailbox, paired with the account names in the order given.
pub(super) fn mail_key_errors(
    q: &Question,
    value: &str,
    form: &BTreeMap<String, String>,
) -> Vec<String> {
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

pub(super) fn render_applicant(
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

#[cfg(test)]
mod tests;
