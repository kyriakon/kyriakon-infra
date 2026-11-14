//! The gemini front-end handlers.

use super::*;

use super::account::{group_recipe, group_state};
use super::connection::decode;
use super::flow::{build_record, file_application};
use super::reply::{respond, too_many, Which};
use super::route::Call;
use super::status::card_link;
use kyriakon_control_core::flow::applicant::{
    body_cross_checks, flow_answers, flow_path, flow_problem, Page,
};

use time::OffsetDateTime;

use crate::fastcgi::Reply;
use crate::{capsule, page};
use kyriakon_control_core::config::HOST;
use kyriakon_control_core::flow::questions::{Kind, Rule};
use kyriakon_control_core::store::{Account, Certificate, Notice};
use kyriakon_control_core::{mail::keycheck, store, store::draft};

/// The account page for a gemini client: the member its certificate is pinned
/// to, or the stranger's page carrying the certificate's own fingerprint.
pub(super) async fn capsule_account(app: &App, incoming: &Incoming) -> Reply {
    let member = match member_for(app, incoming).await {
        Ok(member) => member,
        Err(e) => return respond(&e, FrontEnd::Gemini),
    };
    let body = match &member {
        Some(account) => {
            let notices = account_notices(app, &account.username).await;
            let recipe = group_recipe(app, account);
            let group = match group_state(app, account.group.as_deref()).await {
                Ok(group) => group,
                Err(e) => return respond(&e, FrontEnd::Gemini),
            };
            let payment = account.payment_state().map(|block| {
                page::payment(
                    &account.state,
                    &account.rail,
                    &block,
                    &app.cfg.price_gbp,
                    &app.cfg.postal_address,
                    card_link(app, block.token_ref.as_deref(), false).as_deref(),
                    OffsetDateTime::now_utc(),
                )
            });
            capsule::account(
                account,
                &notices,
                recipe.as_ref(),
                payment.as_ref(),
                group.as_ref(),
            )
        }
        None => capsule::account_stranger(presented(incoming)),
    };
    Reply::gemini(20, "text/gemini", body)
}

/// The capsule's front page: the catalogue, and the one line a presented
/// certificate earns when no pin matched it. It carries no word for "known" or
/// "unknown": the client learns its own fingerprint and nothing else.
pub(super) async fn capsule_front(app: &App, incoming: &Incoming) -> Reply {
    let member = match member_for(app, incoming).await {
        Ok(member) => member,
        Err(e) => return respond(&e, FrontEnd::Gemini),
    };
    let member_name = member.as_ref().map(|account| account.username.as_str());
    let mut page = capsule::front_page(&app.catalogue, member_name);
    if member.is_none() {
        if let Some(certificate) = presented(incoming) {
            page.push('\n');
            page.push_str(&capsule::registration(certificate));
        }
    }
    Reply::gemini(20, "text/gemini", page)
}

/// A mirrored document: a literal, not a path. The route is a key in the map the
/// handler read at startup, so no request can name a file to read. `App::load`
/// refuses to start without one, so the lookup cannot fail for a row in the
/// table; it answers 51 if it ever does rather than panicking in a handler.
pub(super) fn mirrored(app: &App, call: &Call<'_>) -> Reply {
    match app.pages.get(&call.incoming.path) {
        Some(text) => Reply::gemini(20, "text/gemini", text.clone()),
        None => Reply::gemini(51, "Not found", String::new()),
    }
}

/// The acceptances page: the three documents and the release the handler carries,
/// generated rather than staged.
pub(super) fn acceptances(app: &App) -> Reply {
    Reply::gemini(
        20,
        "text/gemini",
        capsule::acceptances(&app.questions, &app.cfg.release),
    )
}

/// The account a presented certificate is pinned to. Only the two routes that
/// read as a member call this: a certificate-bearing request for any other page
/// pays nothing for a lookup it would throw away.
pub(super) async fn member_for(app: &App, incoming: &Incoming) -> Result<Option<Account>, Error> {
    match &incoming.certificate {
        Some(certificate) => app
            .store
            .account_for_certificate(&certificate.hash)
            .await
            .map_err(Error::Lookup),
        None => Ok(None),
    }
}

/// The certificate a client presented, when there is one to show a
/// fingerprint of. A certificate with no hash is not something to fingerprint.
pub(super) fn presented(incoming: &Incoming) -> Option<&Certificate> {
    incoming
        .certificate
        .as_ref()
        .filter(|certificate| !certificate.hash.is_empty())
}

/// The notices an account has been sent, read from its own `notices.jsonl`. A
/// line that does not parse is skipped: a notice that cannot be read is not a
/// reason to refuse the account page.
pub(super) async fn account_notices(app: &App, username: &str) -> Vec<Notice> {
    // A page that cannot read the notices shows none; nothing is decided from
    // this list, and failing the page would hide the account over a display gap.
    app.store
        .log(&format!("accounts/{username}/notices.jsonl"))
        .raw_lines()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// Open a draft and send the client to its first page. The draft token is the
/// status token the application will carry, drawn here and never from anything
/// about the applicant. The 30 is the only way the token reaches the path: a
/// gemini prompt cannot carry one.
pub(super) async fn capsule_new(app: &App, incoming: &Incoming) -> Reply {
    if !app.counter.allow_draft(incoming.key) {
        return too_many(FrontEnd::Gemini, Which::Day);
    }
    let token = match store::status_token().await {
        Ok(token) => token,
        Err(e) => return respond(&Error::from(e), FrontEnd::Gemini),
    };
    let mut record = draft::Draft::new(token.clone());
    if let Err(e) = draft::save(&app.store, &mut record).await {
        return respond(&Error::from(e), FrontEnd::Gemini);
    }
    capsule_redirect(&token, 1)
}

/// One answer, one page, one redirect. The page number in the path must be the
/// draft's cursor; a replayed page redirects to the cursor rather than applying
/// the answer again, which is what makes a second tap advance nothing.
pub(super) async fn capsule_apply(app: &App, incoming: &Incoming, rest: &str) -> Reply {
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
    let _lock = match app.store.lock("drafts/.lock").await {
        Ok(lock) => lock,
        Err(e) => return respond(&Error::from(e), FrontEnd::Gemini),
    };
    let mut record = match draft::load(&app.store, token).await {
        Ok(Some(d)) => d,
        Ok(None) => return capsule_not_found(),
        Err(e) => return respond(&Error::from(e), FrontEnd::Gemini),
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
            return respond(&Error::from(e), FrontEnd::Gemini);
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
            let address = if mailbox.address.is_empty() {
                mailbox.name.clone()
            } else {
                mailbox.address.clone()
            };
            record.mail_keys.retain(|k| k.mailbox != mailbox.name);
            record
                .mail_keys
                .push(keycheck::mail_key(mailbox.name.clone(), &address, &value));
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
        return respond(&Error::from(e), FrontEnd::Gemini);
    }
    capsule_redirect(token, record.cursor + 1)
}

/// Advance the cursor past key pages whose mailbox already holds a key, which
/// is how a key mailed to apply@ answers the page for the applicant.
pub(super) fn capsule_skip_mailed(path: &[Page], record: &mut draft::Draft) -> bool {
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
/// a line break. A single full stop is the clients' empty answer.
pub(super) fn capsule_value(raw: &str) -> String {
    let decoded = decode(raw, false).replace("\r\n", "\n");
    // `validate::validate` trims with `str::trim`, and the stored answer must be
    // the value validation checked, so this uses the same set. That also trims a
    // bare CR, which the gemini spec calls an ordinary character; keeping it
    // would store a value the validator never saw, the #807 class.
    let trimmed = decoded.trim();
    if trimmed == "." {
        String::new()
    } else {
        trimmed.to_string()
    }
}

/// A status 10 META: one line, because a newline would end the header. The
/// counter is the applicant's own path length; the hints are the input the prompt
/// alone does not give, and the mail route is here because META is the last text
/// a client shows before it reads an answer.
pub(super) fn capsule_meta(
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
            // shortcut: only the apply@ fallback is offered while the relayd
            // Titan listener stays commented; add the titan:// line when an
            // operator opens the relay and its pf rule.
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

pub(super) fn capsule_redirect(token: &str, page: usize) -> Reply {
    Reply::gemini(
        30,
        &format!("gemini://{HOST}/apply/{token}/{page}"),
        String::new(),
    )
}

pub(super) fn capsule_not_found() -> Reply {
    Reply::gemini(51, "Not found", String::new())
}

/// Every answer is in hand: file the application and the one intent through the
/// same builder the web form uses, then remove the draft. The token stays the
/// one the draft carried, which is the capability the status link already holds.
pub(super) async fn capsule_file(app: &App, record: &draft::Draft) -> Reply {
    let body = record.answers.get("whose").map(String::as_str) == Some("body");
    let answers = flow_answers(record, body);
    let application = match build_record(app, &answers, body, &record.token, "capsule") {
        Ok(application) => application,
        Err(e) => return respond(&e, FrontEnd::Gemini),
    };
    if let Err(e) = file_application(app, &application).await {
        return respond(&e, FrontEnd::Gemini);
    }
    if let Err(e) = draft::remove(&app.store, &record.token).await {
        e.report("removing the draft");
    }
    let link = format!("gemini://{HOST}/status/{}", record.token);
    Reply::gemini(20, "text/gemini", capsule::filed(&link))
}

#[cfg(test)]
mod tests;
