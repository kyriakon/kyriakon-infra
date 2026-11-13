//! The shared applicant flow and the web form handlers.

use super::*;

use super::gemini::capsule_front;
use super::reply::page_html;
use super::route::Call;

use std::collections::BTreeMap;

use crate::fastcgi::{Reply, Request};
use crate::{capsule, page};
use kyriakon_control_core::flow::applicant::{body_cross_checks, mail_key_errors};
use kyriakon_control_core::flow::questions::{Branch, Rule};
use kyriakon_control_core::store::{Acceptance, Record};
use kyriakon_control_core::{flow::questions, flow::validate, mail::keycheck, util};

/// Draw the intent id and write the application then the intent. The application
/// goes first, so the drain never sees an intent whose application is not on
/// disk. One writer for the web form and the capsule, so the order cannot drift
/// between them.
pub(super) async fn file_application(app: &App, record: &Record) -> Result<(), Error> {
    let id = ulid::Ulid::new().to_string();
    let name = format!("{}.json", record.status_token);
    // Both encodings first: an encoding failure must leave no record either.
    let bytes = serde_json::to_vec_pretty(record)
        .map_err(|e| Error::context("cannot encode the application", e))?;
    let intent = serde_json::to_vec_pretty(&record.intent(&id))
        .map_err(|e| Error::context("cannot encode the intent", e))?;
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
            remove.report(&format!("the orphaned application record {name} stays"));
        }
        return Err(e.into());
    }
    Ok(())
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

pub(super) fn build_record(
    app: &App,
    form: &BTreeMap<String, String>,
    body: bool,
    token: &str,
    front_end: &str,
) -> Result<Record, Error> {
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
        let mailbox = mailboxes.get(i).cloned().unwrap_or_default();
        // A person's key is filed under no mailbox, but its identity is the
        // username answer; a body mailbox's identity is its own address.
        let address = if body {
            let domain = form.get("body_domain").cloned().unwrap_or_default();
            if domain.is_empty() {
                mailbox.clone()
            } else {
                format!("{mailbox}@{domain}")
            }
        } else {
            let name = answers.get("username").cloned().unwrap_or_default();
            if name.is_empty() {
                String::new()
            } else {
                format!("{name}@kyriakon.net")
            }
        };
        mail_keys.push(keycheck::mail_key(mailbox, &address, block));
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
    if form.get("accept_supply").map(|v| v.trim()) == Some("yes") {
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
