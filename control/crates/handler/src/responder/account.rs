//! The account page and its actions.

use super::*;

use super::connection::fields;
use super::gemini::{account_notices, capsule_account};
use super::reply::{notice, page_html, refused, respond};
use super::route::Call;
use super::status::card_link;

use time::OffsetDateTime;

use crate::fastcgi::{Http, Reply, Request};
use crate::page;
use crate::page::LoginPage;
use kyriakon_control_core::store::Account;
use kyriakon_control_core::{
    account::session,
    flow::validate,
    intent,
    mail::{keycheck, notice},
};

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
        Err(e) => return respond(&Error::from(e), FrontEnd::Httpd),
    };
    let notices = account_notices(app, &account.username).await;
    let group = match group_state(app, account.group.as_deref()).await {
        Ok(group) => group,
        Err(e) => return respond(&e, FrontEnd::Httpd),
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
        Err(e) => respond(&Error::from(e), FrontEnd::Httpd),
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
) -> Result<Option<(String, Account)>, Error> {
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
    for value in kyriakon_control_core::payments::ledger::Ledger::open(&app.store)
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
        let Ok(received) = kyriakon_control_core::account::requests::parse_date(received) else {
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
        "test-mail" => account_test_mail(app, call.request).await,
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
        Err(e) => return respond(&e, FrontEnd::Httpd),
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
    let intent = intent::Intent::Close(intent::CloseIntent {
        username: account.username.clone(),
        session: session_id.to_string(),
        ..Default::default()
    });
    match intent.file(&app.store).await {
        Ok(_) => {
            let message =
                kyriakon_control_core::account::requests::erasure_answer(refund.as_deref());
            Reply::html(200, page_html(&notice("Closing your account", &message)))
        }
        Err(e) => respond(
            &Error::Failed(format!("the closure could not be filed: {e}")),
            FrontEnd::Httpd,
        ),
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
        Err(e) => return respond(&e, FrontEnd::Httpd),
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
    if let Err(why) = kyriakon_control_core::account::password::validate(new) {
        return refused(&why.to_string());
    }
    if new != confirm {
        return refused("The two new passwords do not match.");
    }
    match intent::Intent::ChangePassword(intent::ChangePasswordIntent {
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
        Err(e) => respond(
            &Error::Failed(format!("the password change could not be filed: {e}")),
            FrontEnd::Httpd,
        ),
    }
}

/// The upload key form: add one key or remove the one on the account. One key
/// serves sftp and git, so adding replaces rather than accumulates, and the
/// page shows the fingerprint and the day it was added.
pub(super) async fn account_upload_key(app: &App, request: &Request) -> Reply {
    let (cookie, account) = match session_account(app, request).await {
        Ok(Some(found)) => found,
        Ok(None) => return refused("Sign in to the account whose upload key you want to change."),
        Err(e) => return respond(&e, FrontEnd::Httpd),
    };
    let Some(session_id) = session::id(&cookie) else {
        return refused("Sign in to the account whose upload key you want to change.");
    };
    let form = fields(&String::from_utf8_lossy(&request.body));
    match form.get("action").map(String::as_str) {
        Some("add") => {
            let material = form.get("key").map(String::as_str).unwrap_or("").trim();
            if let Err(why) = keycheck::openssh_public_key(material) {
                return refused(&why.to_string());
            }
            if keycheck::openssh_fingerprint(material).is_none() {
                return refused("That line carries no key material.");
            }
            match intent::Intent::UploadKey(intent::UploadKeyIntent {
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
                Err(e) => respond(
                    &Error::Failed(format!("the upload key could not be filed: {e}")),
                    FrontEnd::Httpd,
                ),
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
            match intent::Intent::UploadKey(intent::UploadKeyIntent {
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
                Err(e) => respond(
                    &Error::Failed(format!("the key removal could not be filed: {e}")),
                    FrontEnd::Httpd,
                ),
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
        Err(e) => return respond(&e, FrontEnd::Httpd),
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
    match intent::Intent::OutsideAddress(intent::OutsideAddressIntent {
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
        Err(e) => respond(
            &Error::Failed(format!("the address change could not be filed: {e}")),
            FrontEnd::Httpd,
        ),
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
        Err(e) => return respond(&e, FrontEnd::Httpd),
    };
    let Some(session_id) = session::id(&cookie) else {
        return refused("Sign in to the account whose serving you want to change.");
    };
    let form = fields(&String::from_utf8_lossy(&request.body));
    let http = form.contains_key("http");
    let gemini = form.contains_key("gemini");
    match intent::Intent::Serving(intent::ServingIntent {
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
        Err(e) => respond(
            &Error::Failed(format!("the serving change could not be filed: {e}")),
            FrontEnd::Httpd,
        ),
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
        Err(e) => return respond(&e, FrontEnd::Httpd),
    };
    let Some(session_id) = session::id(&cookie) else {
        return refused("Sign in to the account whose renewal you want to stop.");
    };
    let form = fields(&String::from_utf8_lossy(&request.body));
    if form.get("action").map(String::as_str) != Some("cancel") {
        return refused("That is not a renewal action this page carries out.");
    }
    let own_card = account
        .payment
        .as_ref()
        .is_some_and(|payment| payment.stripe.subscription.is_some());
    // A group's subscription is the body's, so only its site owner may stop it:
    // another mailbox reads the body's billing but is offered no control over
    // its card.
    let owns_group_card = match group_state(app, account.group.as_deref()).await {
        Ok(Some(group)) => {
            group.site_owner == account.username && (group.renews || group.renewal_stopped)
        }
        Ok(None) => false,
        Err(e) => return respond(&e, FrontEnd::Httpd),
    };
    if account.group.is_some() && !owns_group_card {
        return refused("Only the group's site owner can stop the body's yearly renewal.");
    }
    if !own_card && !owns_group_card {
        return refused(
            "This account has no card subscription to stop. A prepaid membership renews when you \
             pay again, and nothing is charged automatically.",
        );
    }
    match intent::Intent::CancelRenewal(intent::CancelRenewalIntent {
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
        Err(e) => respond(
            &Error::Failed(format!("the cancellation could not be filed: {e}")),
            FrontEnd::Httpd,
        ),
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
        Err(e) => return respond(&e, FrontEnd::Httpd),
    };
    let Some(session_id) = session::id(&cookie) else {
        return refused("Sign in to the account whose mail key you want to replace.");
    };
    let form = fields(&String::from_utf8_lossy(&request.body));
    match form.get("action").map(String::as_str) {
        Some("replace") => {
            let material = form.get("key").map(String::as_str).unwrap_or("").trim();
            let checked = match keycheck::pgp_public_key(material) {
                Ok(checked) => checked,
                Err(why) => return refused(&why.to_string()),
            };
            // The drain refuses a key that cannot serve mail, and a refusal
            // settles before any notice, so the page must say it here or the
            // member is never told. A block the parser could not inspect is an
            // advisory, not a finding: it files with the warning shown.
            if let Some(why) = checked.refusal() {
                return refused(why);
            }
            let advisory = (!checked.inspected).then_some(checked.verdict.as_str());
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
            match intent::Intent::MailKey(intent::MailKeyIntent {
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
                    let mut message = if signed {
                        "The platform is checking the signature against the key you use now. If it \
                         verifies, the new key is in use within a minute; if it does not, nothing \
                         changes and no replacement starts."
                            .to_string()
                    } else {
                        "The replacement waits 72 hours. A warning goes to every address on the \
                         account, and until the new key applies you can cancel it on this page. \
                         If you did not ask for this, cancel it now."
                            .to_string()
                    };
                    if let Some(advisory) = advisory {
                        message.push(' ');
                        message.push_str(advisory);
                    }
                    Reply::html(
                        200,
                        page_html(&notice("Your mail key is being replaced", &message)),
                    )
                }
                Err(e) => respond(
                    &Error::Failed(format!("the key replacement could not be filed: {e}")),
                    FrontEnd::Httpd,
                ),
            }
        }
        Some("cancel") => {
            if account.rotation.is_none() {
                return refused("No replacement is waiting to be cancelled.");
            }
            match intent::Intent::MailKey(intent::MailKeyIntent {
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
                Err(e) => respond(
                    &Error::Failed(format!("the cancellation could not be filed: {e}")),
                    FrontEnd::Httpd,
                ),
            }
        }
        _ => refused("That is not a mail-key action this page carries out."),
    }
}

/// The page's "send a test encrypted email". The message itself is the drain's,
/// because only root's half can enqueue mail; the handler files the same
/// session-proved intent every other `/account` form does.
///
/// One a day: a test-mail intent for this account still in the queue already
/// holds the slot, and once the drain has settled one today its notice line
/// refuses a second. Either way a member who clicks again is told to look in the
/// mailbox rather than filling the queue with messages the drain would drop.
pub(super) async fn account_test_mail(app: &App, request: &Request) -> Reply {
    let (cookie, account) = match session_account(app, request).await {
        Ok(Some(found)) => found,
        Ok(None) => return refused("Sign in to the account you want the test message sent to."),
        Err(e) => return respond(&e, FrontEnd::Httpd),
    };
    let Some(session_id) = session::id(&cookie) else {
        return refused("Sign in to the account you want the test message sent to.");
    };
    if account.mail_key.is_none() {
        return refused(
            "The platform has not recorded a mail key for this account yet, so there is nothing \
             to encrypt a test message to.",
        );
    }
    let stamp = kyriakon_control_core::util::filed_at();
    let day = stamp.get(..10).unwrap_or(&stamp);
    match test_mail_queued(app, &account.username, day).await {
        Ok(true) => {
            return refused(
                "A test message is already on its way today. It arrives within a minute; check \
                 the mailbox it was sent to before asking for another.",
            )
        }
        Ok(false) => {}
        Err(e) => return respond(&e, FrontEnd::Httpd),
    }
    match notice::already_sent(
        &app.store,
        &account.username,
        notice::TEST_MAIL_NOTICE,
        &notice::test_mail_subject(day),
    )
    .await
    {
        Ok(true) => {
            return refused(
                "A test message has already gone out today. Check the mailbox it was sent to \
                 before asking for another.",
            )
        }
        Ok(false) => {}
        Err(e) => return respond(&Error::from(e), FrontEnd::Httpd),
    }
    match intent::Intent::TestMail(intent::TestMailIntent {
        username: account.username.clone(),
        session: session_id.to_string(),
        ..Default::default()
    })
    .file(&app.store)
    .await
    {
        Ok(_) => {
            let page = notice(
                "Your test message is on its way",
                "The platform is sending one message to your address on this platform now. It is \
                 encrypted to the mail key above, with its Subject: protected, so opening it and \
                 seeing the real subject is the proof your client is set up. It arrives within a \
                 minute.",
            );
            Reply::html(200, page_html(&page))
        }
        Err(e) => respond(
            &Error::Failed(format!("the test message could not be filed: {e}")),
            FrontEnd::Httpd,
        ),
    }
}

/// Whether this account already has a test-mail intent filed today waiting for
/// the drain. `intents/` is the handler's own directory and the drain removes
/// each file it settles, so this is the queue's record of what is still to do;
/// the day check keeps an abandoned file from blocking the next day's test.
async fn test_mail_queued(app: &App, username: &str, day: &str) -> Result<bool, Error> {
    for name in app.store.list("intents").await.map_err(Error::from)? {
        if !name.ends_with(".json") {
            continue;
        }
        let Some(text) = app.store.read_record("intents", &name).await else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        if value.get("kind").and_then(|v| v.as_str()) != Some("test-mail")
            || value.get("username").and_then(|v| v.as_str()) != Some(username)
        {
            continue;
        }
        let filed = value.get("filed_at").and_then(|v| v.as_str()).unwrap_or("");
        if filed.get(..10) == Some(day) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The member a request's live session names, with the account it names. The
/// page's actions use it: `REMOTE_USER` is not an identity here, because no
/// HTTP authentication is configured for the host.
pub(super) async fn session_member(app: &App, request: &Request) -> Result<Option<Account>, Error> {
    let Some(cookie) = session::from_header(request.value("HTTP_COOKIE"), session::COOKIE) else {
        return Ok(None);
    };
    let Some(member) = session::lookup(&app.store, &cookie, OffsetDateTime::now_utc()).await else {
        return Ok(None);
    };
    app.store
        .account(&member.username)
        .await
        .map_err(Error::from)
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
        Err(e) => return respond(&e, FrontEnd::Httpd),
    };
    let cookie = session::from_header(request.value("HTTP_COOKIE"), session::COOKIE);
    let Some(session_id) = cookie.as_deref().and_then(session::id) else {
        return refused("Sign in to the account you want to export.");
    };
    match intent::Intent::Export(intent::ExportIntent {
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
            Error::from(e).report("the export intent");
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
) -> Result<Option<page::GroupView>, Error> {
    let Some(domain) = domain else {
        return Ok(None);
    };
    Ok(app
        .store
        .group(domain)
        .await
        .map_err(Error::Lookup)?
        .as_ref()
        .map(page::GroupView::from_record))
}

/// The DNS recipe for an account that names a group. `account.group` already
/// holds the domain, and the group record is root-only (the handler runs as
/// `_onboard`), so reading it here would return None and drop the recipe: the
/// reference is the whole input. An account with no group gets `None`, which is
/// every person's account.
pub(super) fn group_recipe(
    app: &App,
    account: &Account,
) -> Option<kyriakon_control_core::account::dns::Recipe> {
    let domain = account.group.as_deref()?;
    let values = kyriakon_control_core::account::dns::Values::from(&app.cfg);
    if let Err(e) = values.check() {
        Error::from(e).report("the account page");
        return None;
    }
    Some(kyriakon_control_core::account::dns::recipe(domain, &values))
}

#[cfg(test)]
mod tests;
