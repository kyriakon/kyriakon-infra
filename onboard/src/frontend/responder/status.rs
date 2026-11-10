//! The status page.

use super::*;

use super::reply::capability;
use super::route::Call;

use time::OffsetDateTime;

use crate::frontend::fastcgi::Reply;
use crate::frontend::page::StatusPage;
use crate::store::Record;
use crate::{frontend::capsule, frontend::page, payments::rails, util};

/// The status page for one token, which is the same page over both front-ends: a
/// capability in the URL is never stored and its URL is never sent as a referrer.
/// The web page is the capability itself and the capsule renders it as gemtext.
pub(super) async fn status(app: &App, call: &Call<'_>) -> Reply {
    let record = record_for(app, call.rest).await;
    let payment = payment_for(app, record.as_ref());
    let page = status_page(record, payment, OffsetDateTime::now_utc());
    match call.front {
        FrontEnd::Httpd => capability(&page),
        FrontEnd::Gemini => Reply::gemini(20, "text/gemini", capsule::status(&page)),
    }
}

/// The payment block a decided application's status page carries. The drain
/// writes it into this record at approval, so the unprivileged handler renders
/// it without reading the root-owned account, and a filed or declined
/// application — which names whatever username its applicant typed — carries
/// none. A free approval carries none anywhere.
pub(super) fn payment_for(app: &App, record: Option<&Record>) -> Option<page::PaymentView> {
    let record = record?;
    let payment = record.payment.as_ref()?;
    Some(page::payment(
        "active",
        &record.rail,
        payment,
        &app.cfg.price_gbp,
        &app.cfg.postal_address,
        card_link(app, payment.token_ref.as_deref()).as_deref(),
        OffsetDateTime::now_utc(),
    ))
}

/// The card rail's Payment Link for a page, or `None` when the rail is not card,
/// there is no token yet, or the box's link is unconfigured. A page is not the
/// place to refuse an approval for a placeholder: the approval email already
/// does, and the page simply shows no link rather than a broken one.
pub(super) fn card_link(app: &App, token: Option<&str>) -> Option<String> {
    rails::card_link(&app.cfg.stripe_payment_link, token?)
        .ok()
        .flatten()
}

/// The page one token's record renders, or the one notice that covers a token
/// that is unknown, expired or spent alike. The window is read here and not in the
/// store, because a record is still on disk after its link has stopped answering:
/// nothing is deleted for it, the page simply stops.
///
/// `payment` is the account's block, and it is dropped with the record: a page
/// that has stopped answering shows no payment state either, so a dead token
/// cannot be told from a live one by what the page carries.
pub fn status_page(
    record: Option<Record>,
    payment: Option<page::PaymentView>,
    now: OffsetDateTime,
) -> StatusPage {
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
            payment,
        },
        None => StatusPage {
            stage: String::new(),
            filed_at: String::new(),
            notice: UNKNOWN_TOKEN.to_string(),
            password_link: None,
            payment: None,
        },
    }
}

/// The record a token answers for, or `None` for one that is unknown, expired or
/// spent. A token is a path component, so it is checked against the alphabet
/// before it is used as one: a probe cannot walk the directory with "..".
pub(super) async fn record_for(app: &App, token: &str) -> Option<Record> {
    let well_formed = token.len() == 26
        && token
            .bytes()
            .all(|b| b"0123456789abcdefghjkmnpqrstvwxyz".contains(&b));
    if !well_formed {
        return None;
    }
    match app.store.application(token).await {
        Ok(record) => record,
        // The status path is not a token oracle: a damaged record answers the
        // same as an unknown token, and the operator gets the reason on stderr.
        Err(e) => {
            eprintln!("kyriakon-onboard: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests;
