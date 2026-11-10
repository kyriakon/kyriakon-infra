//! The account page and its actions.

use super::*;

use time::OffsetDateTime;

use crate::frontend::fastcgi::{Http, Reply, Request};
use crate::frontend::page::LoginPage;
use crate::store::Account;
use crate::{account::session, drain, flow::validate, frontend::page, mail::keycheck};

/// The account page, which each front end renders for the identity it has: the
/// web's session cookie and the capsule's certificate.
pub(super) async fn account(app: &App, call: &Call<'_>) -> Reply {
    match call.front {
        FrontEnd::Httpd => account_web(app, call.request).await,
        FrontEnd::Gemini => capsule_account(app, call.incoming).await,
    }
}

/// The account page, for the member its session cookie names. A request with no
/// live session, and one whose session names no readable account, both get the
/// login page: the page never says which of the two it was.
///
/// No key admits anyone here. The mail password is checked by `doveadm auth test`
/// through the one fixed `doas` rule, and the session is a server-side file the
/// cookie's own signature names.
pub(super) async fn account_web(app: &App, request: &Request) -> Reply {
    let now = OffsetDateTime::now_utc();
    let cookie = session::from_header(request.value("HTTP_COOKIE"), session::COOKIE);
    let member = match cookie {
        Some(cookie) => session::lookup(&app.store, &cookie, now).await,
        None => None,
    };
    let Some(member) = member else {
        return Reply::capability(200, page_html(&LoginPage { error: None }));
    };
    // The record the session names is a path under the store, so the name is
    // checked against the charset the platform makes before it builds one. A
    // record with anything else in it is not a record this route will read.
    if validate::username_shape(&member.username).is_some() {
        return Reply::capability(200, page_html(&LoginPage { error: None }));
    }
    let account = match app.store.account(&member.username).await {
        Ok(Some(account)) => account,
        Ok(None) => return Reply::capability(200, page_html(&LoginPage { error: None })),
        Err(e) => return server_error(&e),
    };
    let notices = account_notices(app, &account.username).await;
    let group = match group_state(app, account.group.as_deref()).await {
        Ok(group) => group,
        Err(e) => return server_error(&e),
    };
    let dns = group_recipe(app, &account);
    let payment = account.payment_state().map(|block| {
        page::payment(
            &account.state,
            &account.rail,
            &block,
            &app.cfg.price_gbp,
            &app.cfg.postal_address,
            card_link(app, block.token_ref.as_deref()).as_deref(),
            now,
        )
    });
    let page = page::member_page(&app.catalogue, &account, &notices, group, dns, payment);
    // A member's page carries an outside address, notices and an unpaid token:
    // it is never stored by a cache or sent as a referrer.
    Reply::capability(200, page_html(&page))
}

/// The login submission. A correct password opens a session and sends the
/// member to their page; a wrong one, an unknown username and a submission with
/// a field missing all return the same login page with no cookie set.
pub(super) async fn login(app: &App, request: &Request) -> Reply {
    let form = fields(&String::from_utf8_lossy(&request.body));
    let username = form.get("username").map(String::as_str).unwrap_or("");
    let password = form.get("password").map(String::as_str).unwrap_or("");
    // The shape is checked before the check runs: a name the platform could not
    // have made is not passed to `doveadm`, and the answer is the same one a
    // wrong password gets. The checker mints the proof in the root-owned
    // directory and prints its token; the handler stores it and cannot make one.
    let proof_dir = std::path::Path::new(&app.cfg.proof_dir);
    let proof = if username.is_empty()
        || password.is_empty()
        || validate::username_shape(username).is_some()
    {
        None
    } else {
        app.auth.authenticate(username, password, proof_dir).await
    };
    let Some(proof) = proof else {
        return Reply::capability(200, page_html(&LoginPage {
            error: Some(
                "That username and password did not match. Check the mail password and try again."
                    .to_string(),
            ),
        }));
    };
    match session::open(&app.store, username, &proof, OffsetDateTime::now_utc()).await {
        Ok(cookie) => Reply::Http(
            Http::redirect("/account").with_header("Set-Cookie", session::cookie(&cookie)),
        ),
        Err(e) => server_error(&e),
    }
}

/// End the session the cookie names and send the browser back to the login
/// page. The cookie is cleared even when the record is already gone.
pub(super) async fn logout(app: &App, request: &Request) -> Reply {
    if let Some(cookie) = session::from_header(request.value("HTTP_COOKIE"), session::COOKIE) {
        session::close(&app.store, &cookie).await;
    }
    Reply::Http(Http::redirect("/account").with_header("Set-Cookie", session::clear_cookie()))
}

/// The live page session and the account it names. The closure route needs the
/// session id as well as the account, because the intent carries it for the
/// drain to verify.
pub(super) async fn session_account(
    app: &App,
    request: &Request,
) -> Result<Option<(String, Account)>, String> {
    let Some(cookie) = session::from_header(request.value("HTTP_COOKIE"), session::COOKIE) else {
        return Ok(None);
    };
    let Some(member) = session::lookup(&app.store, &cookie, OffsetDateTime::now_utc()).await else {
        return Ok(None);
    };
    Ok(app
        .store
        .account(&member.username)
        .await?
        .map(|account| (cookie, account)))
}

/// The refund the erasure answer names when the closure falls inside the
/// cancellation right: the token's latest credit, its `received_on` and its
/// amount. The ledger is the only place the payment date exists, so this reads
/// it rather than the account record.
pub(super) async fn closure_refund(app: &App, account: &Account) -> Option<String> {
    let token = account.payment_state()?.token_ref?;
    let mut latest: Option<(time::Date, String)> = None;
    // Display only, like `account_notices`: `ledger/` belongs to root and the
    // handler runs as `_onboard`, so this read can fail for every paying
    // member. The line on the page is an estimate, and the drain's
    // `erasure_refund`, which reads as root, is the authoritative answer; a
    // refund it cannot read must not stop the closure being filed.
    for value in crate::payments::ledger::Ledger::open(&app.store)
        .lines_for(&token)
        .await
        .unwrap_or_default()
    {
        if value.kind != "payment" {
            continue;
        }
        let Some(received) = value.received_on.as_deref() else {
            continue;
        };
        let Ok(received) = crate::account::requests::parse_date(received) else {
            continue;
        };
        let amount = value
            .amount_gbp
            .as_deref()
            .unwrap_or("0.00")
            .trim_start_matches('-')
            .to_string();
        if latest
            .as_ref()
            .map(|(date, _)| received > *date)
            .unwrap_or(true)
        {
            latest = Some((received, amount));
        }
    }
    let (received, amount) = latest?;
    let today = OffsetDateTime::now_utc().date();
    let days = (today - received).whole_days();
    (0..=14).contains(&days).then(|| {
        format!(
            "A refund of GBP {amount} is due under the 14-day cancellation right; it is settled separately."
        )
    })
}

/// The account page's action controls. Each is a POST for the same reason the
/// closure is: a GET that changed a password or a key would be fired by any
/// image tag. The path's remainder is the control's name.
pub(super) async fn account_action(app: &App, call: &Call<'_>) -> Reply {
    match call.rest {
        "password" => account_password(app, call.request).await,
        "upload-key" => account_upload_key(app, call.request).await,
        "address" => account_address(app, call.request).await,
        "serving" => account_serving(app, call.request).await,
        "renewal" => account_renewal(app, call.request).await,
        "mail-key" => account_mail_key(app, call.request).await,
        _ => Reply::html(404, String::new()),
    }
}

/// The member's own "Close my account": check the session and the password
/// again, file one close intent carrying the session id, and answer with the
/// erasure text. The handler holds no privilege and writes nothing but the
/// intent; the drain verifies the session, owns the state change and runs the
/// deletion.
pub(super) async fn account_close(app: &App, request: &Request) -> Reply {
    let (cookie, account) = match session_account(app, request).await {
        Ok(Some(found)) => found,
        Ok(None) => return refused("Sign in to the account you want to close."),
        Err(e) => return server_error(&e),
    };
    let form = fields(&String::from_utf8_lossy(&request.body));
    let password = form.get("password").map(String::as_str).unwrap_or("");
    if password.is_empty()
        || !app
            .auth
            .authenticate(
                &account.username,
                password,
                std::path::Path::new(&app.cfg.proof_dir),
            )
            .await
            .is_some()
    {
        return refused(
            "That password did not match. The closure is the irreversible one, so enter the mail password again.",
        );
    }
    let Some(session_id) = cookie.split_once('.').map(|(id, _)| id) else {
        return refused("Sign in to the account you want to close.");
    };
    let refund = closure_refund(app, &account).await;
    let intent = drain::Intent::Close(drain::CloseIntent {
        username: account.username.clone(),
        session: session_id.to_string(),
        ..Default::default()
    });
    match intent.file(&app.store).await {
        Ok(_) => {
            let message = crate::account::requests::erasure_answer(refund.as_deref());
            Reply::html(200, page_html(&notice("Closing your account", &message)))
        }
        Err(e) => server_error(&format!("the closure could not be filed: {e}")),
    }
}

/// The page's password form: the current password re-entered, then the new one
/// twice. The current one is checked against the real system account through
/// `doveadm auth test`, the same proof the login is; the new one is validated
/// here and filed as plaintext for the drain to hash, because a handler that
/// supplies the stored hash can choose one the member never typed. The drain
/// writes the hash as root because the check only verifies.
pub(super) async fn account_password(app: &App, request: &Request) -> Reply {
    let (cookie, account) = match session_account(app, request).await {
        Ok(Some(found)) => found,
        Ok(None) => return refused("Sign in to the account whose password you want to change."),
        Err(e) => return server_error(&e),
    };
    let Some(session_id) = session::id(&cookie) else {
        return refused("Sign in to the account whose password you want to change.");
    };
    let form = fields(&String::from_utf8_lossy(&request.body));
    let current = form.get("password").map(String::as_str).unwrap_or("");
    let new = form.get("new_password").map(String::as_str).unwrap_or("");
    let confirm = form
        .get("confirm_password")
        .map(String::as_str)
        .unwrap_or("");
    // The password is re-entered however fresh the session is: a borrowed
    // browser should not be able to change the password that locks the owner
    // out of their own account.
    if current.is_empty()
        || !app
            .auth
            .authenticate(
                &account.username,
                current,
                std::path::Path::new(&app.cfg.proof_dir),
            )
            .await
            .is_some()
    {
        return refused(
            "That password did not match. Enter your current mail password to change it.",
        );
    }
    if let Err(why) = crate::account::password::validate(new) {
        return refused(&why);
    }
    if new != confirm {
        return refused("The two new passwords do not match.");
    }
    match drain::Intent::ChangePassword(drain::ChangePasswordIntent {
        username: account.username.clone(),
        session: session_id.to_string(),
        password: new.to_string(),
        ..Default::default()
    })
    .file(&app.store)
    .await
    {
        Ok(_) => {
            let page = notice(
                "Your password is changing",
                "The platform is setting the new password now, and it takes effect within a \
                 minute. Until it does, the old password still works. No key or client \
                 setting changes.",
            );
            Reply::html(200, page_html(&page))
        }
        Err(e) => server_error(&format!("the password change could not be filed: {e}")),
    }
}

/// The upload key form: add one key or remove the one on the account. One key
/// serves sftp and git, so adding replaces rather than accumulates, and the
/// page shows the fingerprint and the day it was added.
pub(super) async fn account_upload_key(app: &App, request: &Request) -> Reply {
    let (cookie, account) = match session_account(app, request).await {
        Ok(Some(found)) => found,
        Ok(None) => return refused("Sign in to the account whose upload key you want to change."),
        Err(e) => return server_error(&e),
    };
    let Some(session_id) = session::id(&cookie) else {
        return refused("Sign in to the account whose upload key you want to change.");
    };
    let form = fields(&String::from_utf8_lossy(&request.body));
    match form.get("action").map(String::as_str) {
        Some("add") => {
            let material = form.get("key").map(String::as_str).unwrap_or("").trim();
            if let Err(why) = keycheck::openssh_public_key(material) {
                return refused(&why);
            }
            if keycheck::openssh_fingerprint(material).is_none() {
                return refused("That line carries no key material.");
            }
            match drain::Intent::UploadKey(drain::UploadKeyIntent {
                username: account.username.clone(),
                session: session_id.to_string(),
                action: "add".to_string(),
                material: material.to_string(),
                ..Default::default()
            })
            .file(&app.store)
            .await
            {
                Ok(_) => {
                    let page = notice(
                        "Your upload key is being added",
                        "The platform is installing the key and rebuilding your sftp and git \
                         access now; it takes effect within a minute. The page shows the new \
                         fingerprint once it has.",
                    );
                    Reply::html(200, page_html(&page))
                }
                Err(e) => server_error(&format!("the upload key could not be filed: {e}")),
            }
        }
        Some("remove") => {
            let fingerprint = form
                .get("fingerprint")
                .map(String::as_str)
                .unwrap_or("")
                .trim();
            if !account
                .upload_keys
                .iter()
                .any(|key| key.fingerprint == fingerprint)
            {
                return refused("That key is not on the account.");
            }
            match drain::Intent::UploadKey(drain::UploadKeyIntent {
                username: account.username.clone(),
                session: session_id.to_string(),
                action: "remove".to_string(),
                fingerprint: fingerprint.to_string(),
                ..Default::default()
            })
            .file(&app.store)
            .await
            {
                Ok(_) => {
                    let page = notice(
                        "Your upload key is being removed",
                        "sftp and git stop working for that key within a minute. Mail, your \
                         published site and your repositories are not touched.",
                    );
                    Reply::html(200, page_html(&page))
                }
                Err(e) => server_error(&format!("the key removal could not be filed: {e}")),
            }
        }
        _ => refused("That is not an upload-key action this page carries out."),
    }
}

/// The contact and recovery address form. It is the one address the platform
/// writes to outside the platform, and the only channel a password reset has
/// when the mailbox is unreachable, so it is validated here and again by the
/// drain. An empty field clears it.
pub(super) async fn account_address(app: &App, request: &Request) -> Reply {
    let (cookie, account) = match session_account(app, request).await {
        Ok(Some(found)) => found,
        Ok(None) => return refused("Sign in to the account whose address you want to change."),
        Err(e) => return server_error(&e),
    };
    let Some(session_id) = session::id(&cookie) else {
        return refused("Sign in to the account whose address you want to change.");
    };
    let form = fields(&String::from_utf8_lossy(&request.body));
    let address = form.get("address").map(String::as_str).unwrap_or("").trim();
    if !address.is_empty() {
        if let Some(why) = validate::address(address) {
            return refused(&format!(
                "That is not one address outside the platform. {why}"
            ));
        }
    }
    match drain::Intent::OutsideAddress(drain::OutsideAddressIntent {
        username: account.username.clone(),
        session: session_id.to_string(),
        address: address.to_string(),
        ..Default::default()
    })
    .file(&app.store)
    .await
    {
        Ok(_) => {
            let message = if address.is_empty() {
                "The platform is removing the address outside the platform. From now on it can \
                 only reach you inside this account."
            } else {
                "The platform is recording the new address. Notices go there as well as to your \
                 address on this platform, including if the account is ever in trouble."
            };
            Reply::html(
                200,
                page_html(&notice("Your contact address is changing", message)),
            )
        }
        Err(e) => server_error(&format!("the address change could not be filed: {e}")),
    }
}

/// The serving toggles. Two checkboxes and one submit: a box that is ticked is
/// on, and an absent box is off. The drain writes the account's two booleans,
/// removes or regenerates the member's generated include for the lane that
/// changed, and reloads the daemons once.
pub(super) async fn account_serving(app: &App, request: &Request) -> Reply {
    let (cookie, account) = match session_account(app, request).await {
        Ok(Some(found)) => found,
        Ok(None) => return refused("Sign in to the account whose serving you want to change."),
        Err(e) => return server_error(&e),
    };
    let Some(session_id) = session::id(&cookie) else {
        return refused("Sign in to the account whose serving you want to change.");
    };
    let form = fields(&String::from_utf8_lossy(&request.body));
    let http = form.contains_key("http");
    let gemini = form.contains_key("gemini");
    match drain::Intent::Serving(drain::ServingIntent {
        username: account.username.clone(),
        session: session_id.to_string(),
        http,
        gemini,
        ..Default::default()
    })
    .file(&app.store)
    .await
    {
        Ok(_) => {
            let page = notice(
                "Your serving is changing",
                "The platform is writing the change and reloading the daemons now; it takes \
                 effect within a minute. Your files are untouched either way, so turning a \
                 lane back on serves what is already there.",
            );
            Reply::html(200, page_html(&page))
        }
        Err(e) => server_error(&format!("the serving change could not be filed: {e}")),
    }
}

/// Stop the card subscription's yearly renewal. Stripe's
/// `cancel_at_period_end` runs to the end of the period, so the paid-until date
/// is unchanged and nothing stops early. A prepaid member has no subscription
/// and nothing that renews itself, which the page says instead of offering this.
pub(super) async fn account_renewal(app: &App, request: &Request) -> Reply {
    let (cookie, account) = match session_account(app, request).await {
        Ok(Some(found)) => found,
        Ok(None) => return refused("Sign in to the account whose renewal you want to stop."),
        Err(e) => return server_error(&e),
    };
    let Some(session_id) = session::id(&cookie) else {
        return refused("Sign in to the account whose renewal you want to stop.");
    };
    let form = fields(&String::from_utf8_lossy(&request.body));
    if form.get("action").map(String::as_str) != Some("cancel") {
        return refused("That is not a renewal action this page carries out.");
    }
    let card = account
        .payment
        .as_ref()
        .map(|payment| payment.stripe.subscription.is_some())
        .unwrap_or(false);
    if !card {
        return refused(
            "This account has no card subscription to stop. A prepaid membership renews when you \
             pay again, and nothing is charged automatically.",
        );
    }
    match drain::Intent::CancelRenewal(drain::CancelRenewalIntent {
        username: account.username.clone(),
        session: session_id.to_string(),
        ..Default::default()
    })
    .file(&app.store)
    .await
    {
        Ok(_) => {
            let page = notice(
                "Your renewal is being stopped",
                "The platform is telling Stripe to stop the yearly renewal now. The subscription \
                 runs to the end of the period you have paid for, so nothing stops before then.",
            );
            Reply::html(200, page_html(&page))
        }
        Err(e) => server_error(&format!("the cancellation could not be filed: {e}")),
    }
}

/// Replace the mail key, or cancel a replacement already waiting. A replacement
/// signed by the current key applies at once, because the signature is the
/// proof that the holder of the old private key asked for it; one that is not
/// signed waits 72 hours, and the page cancels it before then.
///
/// The signature is checked by the drain, which is the half that holds the
/// keyring. Nothing here promises which of the two paths the request took.
pub(super) async fn account_mail_key(app: &App, request: &Request) -> Reply {
    let (cookie, account) = match session_account(app, request).await {
        Ok(Some(found)) => found,
        Ok(None) => return refused("Sign in to the account whose mail key you want to replace."),
        Err(e) => return server_error(&e),
    };
    let Some(session_id) = session::id(&cookie) else {
        return refused("Sign in to the account whose mail key you want to replace.");
    };
    let form = fields(&String::from_utf8_lossy(&request.body));
    match form.get("action").map(String::as_str) {
        Some("replace") => {
            let material = form.get("key").map(String::as_str).unwrap_or("").trim();
            if let Err(why) = keycheck::pgp_public_key(material) {
                return refused(&why);
            }
            let Some(fingerprint) = keycheck::pgp_fingerprint(material) else {
                return refused("That block carries no public key packet.");
            };
            if account.mail_key.as_deref() == Some(fingerprint.as_str()) {
                return refused("That is the key already in use.");
            }
            let signature = form
                .get("signature")
                .map(String::as_str)
                .unwrap_or("")
                .trim();
            let signed = !signature.is_empty();
            match drain::Intent::MailKey(drain::MailKeyIntent {
                username: account.username.clone(),
                session: session_id.to_string(),
                action: "replace".to_string(),
                material: material.to_string(),
                signature: signature.to_string(),
                ..Default::default()
            })
            .file(&app.store)
            .await
            {
                Ok(_) => {
                    let message = if signed {
                        "The platform is checking the signature against the key you use now. If it \
                         verifies, the new key is in use within a minute; if it does not, nothing \
                         changes and no replacement starts."
                    } else {
                        "The replacement waits 72 hours. A warning goes to every address on the \
                         account, and until the new key applies you can cancel it on this page. \
                         If you did not ask for this, cancel it now."
                    };
                    Reply::html(
                        200,
                        page_html(&notice("Your mail key is being replaced", message)),
                    )
                }
                Err(e) => server_error(&format!("the key replacement could not be filed: {e}")),
            }
        }
        Some("cancel") => {
            if account.rotation.is_none() {
                return refused("No replacement is waiting to be cancelled.");
            }
            match drain::Intent::MailKey(drain::MailKeyIntent {
                username: account.username.clone(),
                session: session_id.to_string(),
                action: "cancel".to_string(),
                ..Default::default()
            })
            .file(&app.store)
            .await
            {
                Ok(_) => {
                    let page = notice(
                        "The replacement is being cancelled",
                        "The key in use stays as it is, and no new key is installed. Mail keeps \
                         arriving to the key you already hold.",
                    );
                    Reply::html(200, page_html(&page))
                }
                Err(e) => server_error(&format!("the cancellation could not be filed: {e}")),
            }
        }
        _ => refused("That is not a mail-key action this page carries out."),
    }
}

/// The member a request's live session names, with the account it names. The
/// page's actions use it: `REMOTE_USER` is not an identity here, because no
/// HTTP authentication is configured for the host.
pub(super) async fn session_member(
    app: &App,
    request: &Request,
) -> Result<Option<Account>, String> {
    let Some(cookie) = session::from_header(request.value("HTTP_COOKIE"), session::COOKIE) else {
        return Ok(None);
    };
    let Some(member) = session::lookup(&app.store, &cookie, OffsetDateTime::now_utc()).await else {
        return Ok(None);
    };
    app.store.account(&member.username).await
}

/// "Take my data out": file the export intent for the account the session names.
/// The handler holds no privilege and does nothing but file it; the drain writes
/// the bundle into the member's own chroot within its next minute. A request
/// with no live session files nothing.
pub(super) async fn account_export(app: &App, request: &Request) -> Reply {
    let form = fields(&String::from_utf8_lossy(&request.body));
    if form.get("action").map(String::as_str) != Some("export") {
        return refused("That is not an export action this page carries out.");
    }
    let account = match session_member(app, request).await {
        Ok(Some(account)) => account,
        Ok(None) => return refused("Sign in to the account you want to export."),
        Err(e) => return server_error(&e),
    };
    let cookie = session::from_header(request.value("HTTP_COOKIE"), session::COOKIE);
    let Some(session_id) = cookie.as_deref().and_then(session::id) else {
        return refused("Sign in to the account you want to export.");
    };
    match drain::Intent::Export(drain::ExportIntent {
        username: account.username.clone(),
        session: session_id.to_string(),
        ..Default::default()
    })
    .file(&app.store)
    .await
    {
        Ok(_) => {
            let page = notice(
                "Your data export is on its way",
                "The platform is gathering the written record of your account. It will \
                 appear in your sftp space as export/<timestamp>/ beside www/ and \
                 gemini/, and a notice will say when it is ready.",
            );
            Reply::html(200, page_html(&page))
        }
        Err(e) => {
            eprintln!("kyriakon-onboard: the export intent: {e}");
            Reply::html(500, String::new())
        }
    }
}

/// The group a signed-in mailbox belongs to, from the group's own record. The
/// payment lives on the group so one renewal writes one date. A record that
/// cannot be read is an error: a page without its payment block would read as a
/// group that owes nothing.
pub(super) async fn group_state(
    app: &App,
    domain: Option<&str>,
) -> Result<Option<page::GroupView>, String> {
    let Some(domain) = domain else {
        return Ok(None);
    };
    Ok(app
        .store
        .group(domain)
        .await?
        .as_ref()
        .map(page::GroupView::from_record))
}

/// The DNS recipe for an account that names a group. `account.group` already
/// holds the domain, and the group record is root-only (the handler runs as
/// `_onboard`), so reading it here would return None and drop the recipe: the
/// reference is the whole input. An account with no group gets `None`, which is
/// every person's account.
pub(super) fn group_recipe(app: &App, account: &Account) -> Option<crate::account::dns::Recipe> {
    let domain = account.group.as_deref()?;
    let values = crate::account::dns::Values::from(&app.cfg);
    if let Err(e) = values.check() {
        eprintln!("kyriakon-onboard: {e}");
        return None;
    }
    Some(crate::account::dns::recipe(domain, &values))
}

#[cfg(test)]
mod tests;
