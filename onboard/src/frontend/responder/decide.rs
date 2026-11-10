//! Decision and password links.

use super::*;

use super::reply::{capability, notice, refused, server_error};
use super::route::Call;
use super::status::{record_for, status_page};

use std::collections::BTreeMap;

use time::OffsetDateTime;

use crate::frontend::fastcgi::Reply;
use crate::frontend::page::{DecidePage, PasswordPage};
use crate::{drain, store};

/// The decision a link names, with the signature it carries. A link with no
/// signature, or with one naming an action this build has no decision for, names
/// no decision.
pub(super) fn decision_from(f: &BTreeMap<String, String>) -> Option<&'static drain::Decision> {
    let sig = f.get("sig").map(String::as_str).unwrap_or("");
    if sig.is_empty() {
        return None;
    }
    drain::decision_for(f.get("action").map(String::as_str).unwrap_or(""))
}

/// Why a confirm page cannot name a decision, in the words the reader needs.
///
/// Two ways to get here, and they are not the same problem. A mail client that
/// wraps the line cuts the URL at the wrap, which drops the signature: the link
/// itself is fine and the address the browser got is not. Saying so is the
/// difference between "try the next link" and "use the terminal form".
pub(super) fn decision_refusal(query: &BTreeMap<String, String>) -> &'static str {
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
pub(super) async fn decide_confirm(app: &App, call: &Call<'_>) -> Reply {
    let token = call.rest;
    let query = call.query();
    let Some(record) = record_for(app, token).await else {
        // The page an unknown, an expired and a spent token all read as.
        return capability(&status_page(None, None, OffsetDateTime::now_utc()));
    };
    let Some(decision) = decision_from(&query) else {
        return refused(decision_refusal(&query));
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
pub(super) async fn decide_file(app: &App, call: &Call<'_>) -> Reply {
    let token = call.rest;
    let form = call.form();
    let Some(record) = record_for(app, token).await else {
        return capability(&status_page(None, None, OffsetDateTime::now_utc()));
    };
    let Some(decision) = decision_from(&form) else {
        return refused("This link does not name a decision the platform knows.");
    };
    let sig = form.get("sig").cloned().unwrap_or_default();
    match drain::Intent::Decision(drain::DecisionIntent {
        kind: decision.kind.to_string(),
        application: store::ApplicationRef::application(record.username.clone(), token.to_string()),
        action: decision.action.to_string(),
        sig,
        ..Default::default()
    })
    .file(&app.store)
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
pub(super) fn password_window_open(until: &str) -> bool {
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
pub(super) async fn password_page(app: &App, call: &Call<'_>) -> Reply {
    let token = call.rest;
    let query = call.query();
    let Some(record) = record_for(app, token).await else {
        return capability(&status_page(None, None, OffsetDateTime::now_utc()));
    };
    let (Some(until), Some(sig)) = (query.get("until"), query.get("sig")) else {
        return capability(&status_page(None, None, OffsetDateTime::now_utc()));
    };
    if record.password_link.is_none() || !password_window_open(until) {
        return capability(&status_page(None, None, OffsetDateTime::now_utc()));
    }
    capability(&PasswordPage {
        username: record.username,
        token: token.to_string(),
        until: until.to_string(),
        sig: sig.clone(),
        error: None,
    })
}

/// The submission: check the password and file the plaintext for the drain to
/// hash, because a handler that supplies the stored hash is a handler that can
/// choose one the member never typed. The signature travels with it, because the
/// handler holds no key and proves nothing on its own.
pub(super) async fn password_file(app: &App, call: &Call<'_>) -> Reply {
    let token = call.rest;
    let form = call.form();
    let Some(record) = record_for(app, token).await else {
        return capability(&status_page(None, None, OffsetDateTime::now_utc()));
    };
    let (Some(until), Some(sig)) = (form.get("until"), form.get("sig")) else {
        return capability(&status_page(None, None, OffsetDateTime::now_utc()));
    };
    if record.password_link.is_none() || !password_window_open(until) {
        return capability(&status_page(None, None, OffsetDateTime::now_utc()));
    }
    let password = form.get("password").map(String::as_str).unwrap_or("");
    let confirm = form.get("confirm").map(String::as_str).unwrap_or("");
    let problem = if password != confirm {
        Some("The two passwords do not match.".to_string())
    } else {
        crate::account::password::validate(password).err()
    };
    if let Some(problem) = problem {
        return capability(&PasswordPage {
            username: record.username,
            token: token.to_string(),
            until: until.to_string(),
            sig: sig.clone(),
            error: Some(problem),
        });
    }
    match drain::Intent::Password(drain::PasswordIntent {
        application: store::ApplicationRef::application(record.username.clone(), token.to_string()),
        until: until.to_string(),
        sig: sig.clone(),
        password: password.to_string(),
        ..Default::default()
    })
    .file(&app.store)
    .await
    {
        Ok(_) => capability(&notice(
            "Password set",
            "The platform sets it on its next pass, within a minute. This link will not work again.",
        )),
        Err(e) => server_error(&format!("the password could not be filed: {e}")),
    }
}

#[cfg(test)]
mod tests;
