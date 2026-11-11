//! One job of the operator console.

use crate::Error;
use crate::*;
use kyriakon_onboard_core::account::requests as account_requests;

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
        _ => Err(Error::Failed(usage())),
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
    println!("recorded {}; answer due {}", line.id, line.due);
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
        return Err(Error::Failed(format!("the username {username:?}: {why}")));
    }
    let account = store
        .account(username)
        .await?
        .ok_or_else(|| Error::Failed(format!("no account for {username}")))?;
    let own = account.platform_address();

    let message_path = std::path::Path::new(need(&flags, "message")?);
    let message = std::fs::read(message_path)
        .map_err(|e| Error::context(format!("cannot read {}", message_path.display()), e))?;
    let signature = match flags.get("signature") {
        Some(path) => Some(
            std::fs::read(path).map_err(|e| Error::context(format!("cannot read {path}"), e))?,
        ),
        None => None,
    };

    let from = message_from(&String::from_utf8_lossy(&message))?;
    if !from.eq_ignore_ascii_case(&own) {
        let outside = account
            .outside_address
            .as_deref()
            .is_some_and(|address| address.eq_ignore_ascii_case(&from));
        return Err(Error::Failed(if outside {
            format!(
                "the message is from {from}, the account's outside contact address; \
                 ask for a message from {own} signed with the mail key, or for the \
                 password route on the account page"
            )
        } else {
            format!("the message is from {from}, not the account's own address {own}")
        }));
    }
    let key_file = keycheck::keyring_file(&cfg.keyring_dir, username);
    if !key_file.is_file() {
        return Err(Error::Failed(format!(
            "the box holds no key for {username} at {}",
            key_file.display()
        )));
    }
    if signature.is_none() && !String::from_utf8_lossy(&message).contains(CLEARSIGNED) {
        return Err(Error::Failed(
            "the message is not clearsigned; pass --signature with its detached signature \
             or export the message clearsigned from the client"
                .to_string(),
        ));
    }
    let fingerprint =
        keycheck::verify_signature(&cfg.gpg, &key_file, &message, signature.as_deref())
            .await?
            .ok_or_else(|| {
                Error::Failed(format!(
                    "the signature does not verify against {username}'s keyring entry"
                ))
            })?;
    println!("verified {fingerprint}; From: {own}");
    Ok(())
}

/// The address in a message's `From:` header. A delivered message carries its
/// own headers outside the armour, and a client's clearsigned export carries
/// them inside it. The outer block is read first and the armour's is the
/// fallback, and a `From:` in both that disagrees is refused: the signature is
/// the proof, so the outer header adds no forgeable path.
pub(crate) fn message_from(message: &str) -> Result<String, Error> {
    let message = message.replace("\r\n", "\n");
    let (outer, armour) = match message.split_once(CLEARSIGNED) {
        Some((outer, rest)) => {
            let body = rest
                .split_once("\n\n")
                .map(|(_, body)| body)
                .ok_or_else(|| {
                    Error::Failed(
                        "the clearsigned message has no blank line after its armour".to_string(),
                    )
                })?;
            let body = body
                .split_once("\n-----BEGIN PGP SIGNATURE-----")
                .map(|(body, _)| body)
                .unwrap_or(body);
            (outer, Some(body))
        }
        None => (message.as_str(), None),
    };
    let outer = header_from(outer)?;
    let armour = match armour {
        Some(armour) => header_from(armour)?,
        None => None,
    };
    match (outer, armour) {
        (Some(outer), Some(armour)) if !outer.eq_ignore_ascii_case(&armour) => Err(Error::Failed(
            format!("the message's own From: is {outer} but the clearsigned one is {armour}"),
        )),
        (Some(outer), _) => Ok(outer),
        (None, Some(armour)) => Ok(armour),
        (None, None) => Err(Error::Failed("the message has no From: header".to_string())),
    }
}

/// The address in one header block's `From:`, with RFC 5322 continuation lines
/// unfolded first. `None` when the block carries no `From:`.
pub(crate) fn header_from(block: &str) -> Result<Option<String>, Error> {
    let mut headers: Vec<String> = Vec::new();
    for line in block.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() {
                last.push(' ');
                last.push_str(line.trim());
            }
        } else {
            headers.push(line.trim_end().to_string());
        }
    }
    let mut values = headers.iter().filter_map(|header| {
        let (name, value) = header.split_once(':')?;
        name.eq_ignore_ascii_case("from")
            .then(|| value.trim().to_string())
    });
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Error::Failed(
            "the message has more than one From: header".to_string(),
        ));
    }
    let address = match (value.rfind('<'), value.rfind('>')) {
        (Some(open), Some(close)) if open < close => &value[open + 1..close],
        _ => value.as_str(),
    };
    if address.trim().is_empty() {
        return Err(Error::Failed(
            "the message's From: header holds no address".to_string(),
        ));
    }
    Ok(Some(address.trim().to_string()))
}

pub(crate) async fn request_extend(store: &Store, args: &[String]) -> Result<(), Error> {
    let (id, rest) = match args {
        [id, rest @ ..] if !id.starts_with("--") => (id.as_str(), rest),
        _ => return Err(Error::Failed(usage())),
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
        line.id,
        line.effective_due(),
        line.due
    );
    Ok(())
}

pub(crate) async fn request_close(store: &Store, args: &[String]) -> Result<(), Error> {
    let (id, rest) = match args {
        [id, rest @ ..] if !id.starts_with("--") => (id.as_str(), rest),
        _ => return Err(Error::Failed(usage())),
    };
    let flags = flags(rest, &["done", "note"])?;
    let line =
        account_requests::close(store, id, need(&flags, "done")?, need(&flags, "note")?).await?;
    println!(
        "closed {} (done {})",
        line.id,
        line.done_at.as_deref().unwrap_or("")
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
            .map_err(|e| Error::context(format!("request {}", line.id), e))?
        {
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
            line.id, line.username, line.kind, identity, line.received, due
        );
    }
    Ok(())
}

pub(crate) const CLEARSIGNED: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
