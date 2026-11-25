//! One job of the operator console.

use crate::Error;
use crate::*;
use kyriakon_control_core::account::requests as account_requests;
use kyriakon_control_core::mail::pgp;

pub(crate) async fn request(
    cfg: &DrainConfig,
    store: &Store,
    args: &[String],
) -> Result<(), Error> {
    match args.first().map(String::as_str) {
        Some("record") => request_record(store, &args[1..]).await,
        Some("verify") => request_verify(cfg, store, &args[1..]).await,
        Some("extend") => request_extend(store, &args[1..]).await,
        Some("close") => request_close(store, &args[1..]).await,
        Some("list") => request_list(store).await,
        _ => Err(Error::Usage),
    }
}

pub(crate) async fn request_record(store: &Store, args: &[String]) -> Result<(), Error> {
    let flags = flags(
        args,
        &[
            "username",
            "kind",
            "received",
            "evidence",
            "identity",
            "note",
            "identity-at",
            "fee-at",
            "id",
        ],
    )?;
    let line = account_requests::record(
        store,
        account_requests::NewRequest {
            username: need(&flags, "username")?,
            kind: need(&flags, "kind")?,
            received: need(&flags, "received")?,
            evidence: need(&flags, "evidence")?,
            identity: need(&flags, "identity")?,
            note: flags.get("note").map(String::as_str),
            identity_at: flags.get("identity-at").map(String::as_str),
            fee_at: flags.get("fee-at").map(String::as_str),
            id: flags.get("id").map(String::as_str),
        },
    )
    .await?;
    println!(
        "recorded {}; answer due {}",
        safe(&line.id),
        safe(&line.due)
    );
    Ok(())
}

/// `request verify`: the mail-key route's check. It reads a message and an
/// optional detached signature, refuses anything not from the account's own
/// platform address, and verifies the signature against the keyring entry the
/// platform encrypts to. It writes nothing: verification is the check the
/// operator records afterwards with `request record --identity mail-key`.
pub(crate) async fn request_verify(
    cfg: &DrainConfig,
    store: &Store,
    args: &[String],
) -> Result<(), Error> {
    let flags = flags(args, &["username", "message", "signature"])?;
    let username = need(&flags, "username")?;
    if let Some(why) = validate::username_shape(username) {
        return Err(Error::InvalidUsername {
            username: username.to_string(),
            why,
        });
    }
    let account = store
        .account(username)
        .await?
        .ok_or_else(|| Error::NoAccount {
            username: username.to_string(),
        })?;
    let own = account.platform_address();

    let message_path = std::path::Path::new(need(&flags, "message")?);
    let message = std::fs::read(message_path).map_err(|source| Error::ReadMessage {
        path: message_path.to_path_buf(),
        source,
    })?;
    let signature = match flags.get("signature") {
        Some(path) => Some(std::fs::read(path).map_err(|source| Error::ReadSignature {
            path: path.into(),
            source,
        })?),
        None => None,
    };

    let key_file = keycheck::keyring_file(&cfg.keyring_dir, username);
    if !key_file.is_file() {
        return Err(Error::NoKeyringKey {
            username: username.to_string(),
            path: key_file,
        });
    }
    // The keyring entry the box delivers with is the expected signer, read from
    // the exact material installed rather than from the record beside it. A
    // block carrying a second primary key is refused here, so the hidden key
    // cannot sign a request as though it were the visible one (#918).
    let material = std::fs::read_to_string(&key_file).map_err(|source| Error::ReadKeyring {
        path: key_file.clone(),
        source,
    })?;
    let expected = pgp::inspect_single_cert(&material)
        .map_err(|source| Error::KeyringUnusable {
            username: username.to_string(),
            source,
        })?
        .fingerprint;
    // A clearsigned file is verified over its armour alone, and the text shown
    // is GnuPG's own plaintext for that verification. Slicing the text out of
    // the file let a forged marker and signature line hide the real message and
    // show unsigned request text (#820, #924).
    let (fingerprint, from, text) = match &signature {
        Some(detached) => {
            if !pgp::verify_detached(&cfg.gpg, &key_file, &expected, &message, detached).await? {
                return Err(Error::SignatureMismatch {
                    username: username.to_string(),
                });
            }
            let from = pgp::header_from(pgp::message_headers(&message)?)?.ok_or(Error::NoFrom)?;
            (
                expected,
                from,
                String::from_utf8_lossy(&message).into_owned(),
            )
        }
        None => {
            let verified = pgp::verify_clearsigned(&cfg.gpg, &key_file, &expected, &message)
                .await?
                .ok_or(Error::NotClearsigned)?;
            let armour_from = pgp::header_from(verified.plaintext.as_bytes())?;
            let outer = pgp::header_from(pgp::outer_headers(&message)?)?;
            let from = signed_from(outer, armour_from)?;
            (verified.fingerprint, from, verified.plaintext)
        }
    };
    if !from.eq_ignore_ascii_case(&own) {
        let outside = account
            .outside_address
            .as_deref()
            .is_some_and(|address| address.eq_ignore_ascii_case(&from));
        return Err(if outside {
            Error::SenderOutside {
                from,
                own: own.clone(),
            }
        } else {
            Error::SenderOther { from, own }
        });
    }
    println!("verified {fingerprint}; From: {}", safe(&from));
    // What was signed is what the operator records, so it is printed rather
    // than described.
    println!("signed text:");
    for line in text.lines() {
        println!("  {}", safe(line));
    }
    Ok(())
}

/// The sender of a message: the outer header if the file carries one, the
/// verified plaintext's otherwise, and a refusal when the two disagree. Only
/// the verified plaintext's value is proof; the outer header is a hint that must
/// not contradict it.
pub(crate) fn signed_from(outer: Option<String>, armour: Option<String>) -> Result<String, Error> {
    match (outer, armour) {
        (Some(outer), Some(armour)) if !outer.eq_ignore_ascii_case(&armour) => {
            Err(Error::FromMismatch { outer, armour })
        }
        (Some(outer), _) => Ok(outer),
        (None, Some(armour)) => Ok(armour),
        (None, None) => Err(Error::NoFrom),
    }
}

pub(crate) async fn request_extend(store: &Store, args: &[String]) -> Result<(), Error> {
    let (id, rest) = match args {
        [id, rest @ ..] if !id.starts_with("--") => (id.as_str(), rest),
        _ => return Err(Error::Usage),
    };
    let flags = flags(rest, &["reason", "extended-on"])?;
    let line = account_requests::extend(
        store,
        id,
        need(&flags, "reason")?,
        flags.get("extended-on").map(String::as_str),
    )
    .await?;
    println!(
        "extended {}; answer due {} (was {})",
        safe(&line.id),
        safe(line.effective_due()),
        safe(&line.due)
    );
    Ok(())
}

pub(crate) async fn request_close(store: &Store, args: &[String]) -> Result<(), Error> {
    let (id, rest) = match args {
        [id, rest @ ..] if !id.starts_with("--") => (id.as_str(), rest),
        _ => return Err(Error::Usage),
    };
    let flags = flags(rest, &["done", "note"])?;
    let line =
        account_requests::close(store, id, need(&flags, "done")?, need(&flags, "note")?).await?;
    println!(
        "closed {} (done {})",
        safe(&line.id),
        safe(line.done_at.as_deref().unwrap_or(""))
    );
    Ok(())
}

pub(crate) async fn request_list(store: &Store) -> Result<(), Error> {
    let open = account_requests::open(store).await?;
    if open.is_empty() {
        println!("no open requests");
        return Ok(());
    }
    let today = account_requests::today();
    let mut nearly = 0;
    let mut overdue = 0;
    let mut rows = Vec::new();
    for line in open {
        let state = match line
            .state(today)
            .map_err(|source| Error::RequestStateUnreadable {
                id: safe(&line.id),
                source,
            })? {
            account_requests::DueState::Overdue => {
                overdue += 1;
                "OVERDUE"
            }
            account_requests::DueState::NearlyDue => {
                nearly += 1;
                "nearly due"
            }
            account_requests::DueState::Open => "open",
        };
        let due = if line.extended_until.is_some() {
            format!("{} (extended from {})", line.effective_due(), line.due)
        } else {
            line.effective_due().to_string()
        };
        rows.push((line, due, state));
    }
    println!(
        "{} open request(s), {nearly} nearly due, {overdue} overdue",
        rows.len()
    );
    for (line, due, state) in rows {
        let identity = if line.identity.is_empty() {
            "unrecorded"
        } else {
            &line.identity
        };
        println!(
            "{}  {}  {}  identity {}  received {}  due {}  {state}",
            safe(&line.id),
            safe(&line.username),
            safe(&line.kind),
            safe(identity),
            safe(&line.received),
            safe(&due)
        );
    }
    Ok(())
}
