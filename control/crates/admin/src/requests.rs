//! One job of the operator console.

use crate::Error;
use crate::*;
use kyriakon_control_core::account::requests as account_requests;

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

    let parsed = split_message(&String::from_utf8_lossy(&message))?;
    let key_file = keycheck::keyring_file(&cfg.keyring_dir, username);
    if !key_file.is_file() {
        return Err(Error::Failed(format!(
            "the box holds no key for {username} at {}",
            key_file.display()
        )));
    }
    if signature.is_none() && !parsed.clearsigned {
        return Err(Error::Failed(
            "the message is not clearsigned; pass --signature with its detached signature \
             or export the message clearsigned from the client"
                .to_string(),
        ));
    }
    // A clearsigned file is verified over its armour alone, and the text shown
    // is GnuPG's own plaintext for that verification. Slicing the text out of
    // the file let a forged marker and signature line hide the real message and
    // show unsigned request text (#820, #924).
    let (fingerprint, from, text) = match &signature {
        Some(detached) => {
            let fingerprint =
                keycheck::verify_signature(&cfg.gpg, &key_file, &message, Some(detached))
                    .await?
                    .ok_or_else(|| {
                        Error::Failed(format!(
                            "the signature does not verify against {username}'s keyring entry"
                        ))
                    })?;
            let from = parsed
                .from
                .ok_or_else(|| Error::Failed("the message has no From: header".to_string()))?;
            (fingerprint, from, parsed.signed)
        }
        None => {
            let verified =
                keycheck::verify_clearsigned(&cfg.gpg, &key_file, parsed.signed.as_bytes())
                    .await?
                    .ok_or_else(|| {
                        Error::Failed(format!(
                            "the clearsigned message's signature does not verify against \
                             {username}'s keyring entry, so there is no verified text to show"
                        ))
                    })?;
            let armour_from = header_from(&verified.plaintext)?;
            let from = signed_from(parsed.from, armour_from)?;
            (verified.fingerprint, from, verified.plaintext)
        }
    };
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
    println!("verified {fingerprint}; From: {}", safe(&from));
    // What was signed is what the operator records, so it is printed rather
    // than described.
    println!("signed text:");
    for line in text.lines() {
        println!("  {}", safe(line));
    }
    Ok(())
}

/// One request file, split where its signature must be checked.
#[derive(Debug)]
pub(crate) struct Message {
    /// The `From:` outside the armour, if the file carries one. A clearsigned
    /// export has none: its `From:` is inside the verified plaintext.
    pub from: Option<String>,
    /// What gpg is given: the clearsigned block for a clearsigned file, and the
    /// whole file for the detached form, which still carries its own headers.
    pub signed: String,
    /// Whether the file carries a clearsigned block, so a file with neither form
    /// is refused as unsigned.
    pub clearsigned: bool,
}

/// Split a request file into the outer headers and the armour to verify.
///
/// A delivered message carries its own headers outside the armour, and a
/// client's clearsigned export carries them inside it. The outer block is read
/// here and the verified plaintext's is read after gpg runs, and a `From:` in
/// both that disagrees is refused: the signature is the proof, so the outer
/// header adds no forgeable path.
///
/// The armour marker must be a complete line after the header block's blank
/// line. `gpg --verify` finds the armour wherever it sits and ignores the plain
/// text above it, so an unanchored search let a marker inside a header line pull
/// a forged signature line into the text the operator read (#820, #924). The
/// detached form is unchanged: its signature covers the whole file, headers
/// included.
pub(crate) fn split_message(message: &str) -> Result<Message, Error> {
    let normalised = message.replace("\r\n", "\n");
    let Some(at) = line_index(&normalised, CLEARSIGNED) else {
        // The detached form's headers are its own; read them the same way a
        // clearsigned file's outer headers are read.
        let from = header_from(&normalised)?
            .ok_or_else(|| Error::Failed("the message has no From: header".to_string()))?;
        return Ok(Message {
            from: Some(from),
            signed: message.to_string(),
            clearsigned: false,
        });
    };
    let (outer, block) = normalised.split_at(at);
    headers_only(outer)?;
    // A delivered message ends its headers with a blank line; a client's
    // clearsigned export has no outer headers at all.
    if !outer.is_empty() && !outer.ends_with("\n\n") {
        return Err(Error::Failed(
            "the clearsigned block does not follow the message's blank line".to_string(),
        ));
    }
    Ok(Message {
        from: header_from(outer)?,
        signed: block.to_string(),
        clearsigned: true,
    })
}

/// The sender of a message: the outer header if the file carries one, the
/// verified plaintext's otherwise, and a refusal when the two disagree. Only
/// the verified plaintext's value is proof; the outer header is a hint that must
/// not contradict it.
pub(crate) fn signed_from(outer: Option<String>, armour: Option<String>) -> Result<String, Error> {
    match (outer, armour) {
        (Some(outer), Some(armour)) if !outer.eq_ignore_ascii_case(&armour) => Err(Error::Failed(
            format!("the message's own From: is {outer} but the clearsigned one is {armour}"),
        )),
        (Some(outer), _) => Ok(outer),
        (None, Some(armour)) => Ok(armour),
        (None, None) => Err(Error::Failed("the message has no From: header".to_string())),
    }
}

/// The byte index of the first line that is exactly `line`. An armour marker
/// inside a longer line is not the marker gpg would treat as the block's start.
fn line_index(text: &str, line: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(found) = text[from..].find(line) {
        let at = from + found;
        let after = at + line.len();
        let starts_line = at == 0 || text.as_bytes()[at - 1] == b'\n';
        let ends_line = after == text.len() || text.as_bytes()[after] == b'\n';
        if starts_line && ends_line {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// The region before a clearsigned block: header lines, the blank line that ends
/// them, and nothing else. Every non-blank line before the blank line must look
/// like a header (`Name: value`, or a continuation), and nothing may follow the
/// blank line. gpg verifies the armour wherever it sits, so a colon-less line of
/// request text above it would otherwise be read as part of the request.
fn headers_only(region: &str) -> Result<(), Error> {
    let mut ended = false;
    let mut saw_header = false;
    for (index, line) in region.lines().enumerate() {
        if line.trim().is_empty() {
            ended = true;
            continue;
        }
        if ended {
            return Err(unsigned_text(index, line));
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if saw_header {
                continue;
            }
            return Err(unsigned_text(index, line));
        }
        let Some((name, _)) = line.split_once(':') else {
            return Err(unsigned_text(index, line));
        };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(unsigned_text(index, line));
        }
        saw_header = true;
    }
    Ok(())
}

fn unsigned_text(index: usize, line: &str) -> Error {
    Error::Failed(format!(
        "the message has unsigned text before the clearsigned block, at line {}: {:?}",
        index + 1,
        line.chars().take(80).collect::<String>()
    ))
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
        safe(&line.id),
        safe(line.effective_due()),
        safe(&line.due)
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
            .map_err(|e| Error::context(format!("request {}", safe(&line.id)), e))?
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

pub(crate) const CLEARSIGNED: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
