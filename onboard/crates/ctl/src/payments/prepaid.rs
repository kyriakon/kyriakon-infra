//! One job of the operator console.

use crate::*;

/// `prepaid list --window open [--expiring <days>]`: the first command of the
/// operator's weekly pass. Only an open window is asked for; any other value is
/// refused rather than answered with a list that means something else.
pub(crate) async fn prepaid(store: &Store, args: &[String]) -> Result<(), String> {
    let (verb, rest) = match args {
        [verb, rest @ ..] => (verb.as_str(), rest),
        _ => return Err(usage()),
    };
    if verb != "list" {
        return Err(usage());
    }
    let flags = flags(rest, &["window", "expiring"])?;
    let window = need(&flags, "window")?;
    if window != "open" {
        return Err(format!(
            "--window {window:?} is not open; only the open windows are listed"
        ));
    }
    let expiring = match flags.get("expiring") {
        Some(text) => Some(
            text.parse::<i64>()
                .ok()
                .filter(|days| *days >= 0)
                .ok_or_else(|| format!("--expiring {text:?} is not a whole number of days"))?,
        ),
        None => None,
    };
    let rows: Vec<_> = prepaid::open_windows(store, OffsetDateTime::now_utc())
        .await?
        .into_iter()
        .filter(|row| prepaid::closes_within(row.days_left, expiring))
        .collect();
    println!("{} open window(s)", rows.len());
    for row in rows {
        println!(
            "{}  {}  {}  closes {}  {} days left",
            row.token, row.username, row.rail, row.closes_on, row.days_left
        );
    }
    Ok(())
}

/// `reconcile`: the queue of money that arrived with no token.
pub(crate) async fn reconcile(
    cfg: &DrainConfig,
    store: &Store,
    args: &[String],
) -> Result<(), String> {
    match args {
        [verb] if verb == "list" => reconcile_list(store).await,
        [verb, rest @ ..] if verb == "attribute" => reconcile_attribute(cfg, store, rest).await,
        [verb, rest @ ..] if verb == "return" => reconcile_return(cfg, store, rest).await,
        _ => Err(usage()),
    }
}

/// Print every held item: what the operator can still join to an account or
/// close with the evidence.
pub(crate) async fn reconcile_list(store: &Store) -> Result<(), String> {
    let held: Vec<_> = store
        .held()
        .await?
        .into_iter()
        .filter(|line| line.state == "held")
        .collect();
    if held.is_empty() {
        println!("nothing held");
        return Ok(());
    }
    println!("{} held payment(s)", held.len());
    for line in held {
        println!(
            "{}  {}  {}  received {}  {}",
            line.id,
            line.rail,
            line.amount_gbp,
            line.received_on,
            line.note.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

/// `reconcile attribute <UN-id> --token <t>`: join held money to an account as
/// an ordinary credit. Both shapes are checked here, so a mistyped id or token
/// is a refusal at the terminal rather than an intent the drain refuses later.
pub(crate) async fn reconcile_attribute(
    cfg: &DrainConfig,
    store: &Store,
    args: &[String],
) -> Result<(), String> {
    let (item, rest) = match args {
        [item, rest @ ..] if !item.starts_with("--") => (item.as_str(), rest),
        _ => return Err(usage()),
    };
    if !store::is_unattributed_id(item) {
        return Err(format!(
            "the held item {item:?} is not an unattributed payment id"
        ));
    }
    // `--confirm-double` is a bare switch, which the pair reader does not take.
    let confirm_double = rest.iter().any(|a| a == "--confirm-double");
    let paired: Vec<String> = rest
        .iter()
        .filter(|a| a.as_str() != "--confirm-double")
        .cloned()
        .collect();
    let flags = flags(&paired, &["token", "override"])?;
    let token = need(&flags, "token")?;
    if !store::is_payment_token(token) {
        return Err(format!("the token {token:?} is not a payment token"));
    }
    let override_reason = flags.get("override").map(String::as_str);
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(
        &key,
        &sign::reconcile_attribute_payload(item, token, confirm_double, override_reason),
    )?;
    let id = intent::Intent::ReconcileAttribute(intent::AttributeIntent {
        item: item.to_string(),
        token: token.to_string(),
        confirm_double,
        override_reason: override_reason.map(str::to_string),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!("filed reconcile attribute for {item} as intent {id}");
    Ok(())
}

/// `reconcile return <UN-id> --note <evidence>`: close held money with what
/// happened to it. The evidence is the record, so an empty one is refused here.
pub(crate) async fn reconcile_return(
    cfg: &DrainConfig,
    store: &Store,
    args: &[String],
) -> Result<(), String> {
    let (item, rest) = match args {
        [item, rest @ ..] if !item.starts_with("--") => (item.as_str(), rest),
        _ => return Err(usage()),
    };
    if !store::is_unattributed_id(item) {
        return Err(format!(
            "the held item {item:?} is not an unattributed payment id"
        ));
    }
    let flags = flags(rest, &["note"])?;
    let note = need(&flags, "note")?;
    if note.trim().is_empty() {
        return Err("--note is empty; name the evidence the return was made on".to_string());
    }
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(&key, &sign::reconcile_return_payload(item, note))?;
    let id = intent::Intent::ReconcileReturn(intent::ReturnIntent {
        item: item.to_string(),
        note: note.to_string(),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!("filed reconcile return for {item} as intent {id}");
    Ok(())
}
