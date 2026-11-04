//! Bodies and the accounts they are made of: group records, provisioning,
//! address changes and the mail virtual tables.
//!
//! A verb writes its `applying` line through the seam's `write_journal` and
//! returns a [`Settlement`](super::Settlement); the seam writes the outcome line
//! and removes the intent. A retry finds the records this pass already wrote
//! rather than making them twice.
//!
//! [`append_ledger`] writes the window-open line a paid approval or a group
//! provisioning starts. `review` takes it from here so `groups` does not import
//! `payments` for one line.

use super::boxrun::{
    publish_mail_keys, publish_mail_keys_publicly, run_script, run_script_tolerating,
    write_public_key,
};
use super::{write_journal, Settlement};
use crate::config::DrainConfig;
use crate::intents::ADDRESS_ACTIONS;
use crate::journal::Journal;
use crate::ledger::{Ledger, LedgerLine};
use crate::questions;
use crate::store::{
    self, Account, ApplicationRef, FlatPayment, GroupAddress, GroupAddressIntent, GroupIntent,
    GroupPayment, GroupRecord, GroupRemoveIntent, KeyRecord, Record, Store, TokenRecord, Window,
};
use crate::util;
use crate::validate;
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The address table the community block answered, paired with the account
/// names. An `own` line names a mailbox; an `alias` line points at one already
/// named, and the address shares that mailbox. The name on an alias line is not
/// used: the mailbox is the one its `own` target names.
pub(super) fn group_addresses(record: &Record) -> Result<(Vec<GroupAddress>, Vec<String>), String> {
    let text = record
        .answers
        .get("body_addresses")
        .map(String::as_str)
        .unwrap_or("");
    if let Some(why) = validate::address_lines(text) {
        return Err(format!("the address table: {why}"));
    }
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let names = questions::account_names(&record.answers);
    if names.len() != lines.len() {
        return Err(format!(
            "{} addresses and {} account names; there is one name per address",
            lines.len(),
            names.len()
        ));
    }

    let mut own: BTreeMap<&str, &str> = BTreeMap::new();
    let mut seen = HashSet::new();
    let mut mailboxes: Vec<String> = Vec::new();
    for (line, name) in lines.iter().zip(&names) {
        let (local, rest) = line.split_once(':').ok_or_else(|| {
            format!("the address line {line:?} is not localpart: own or localpart: alias localpart")
        })?;
        let local = local.trim();
        if !seen.insert(local) {
            return Err(format!("the address {local} is in the table twice"));
        }
        if rest.trim() == "own" {
            if mailboxes.iter().any(|m| m == name) {
                return Err(format!(
                    "the mailbox {name} is named by two mailboxes; an alias shares a mailbox instead"
                ));
            }
            own.insert(local, name);
            mailboxes.push(name.clone());
        }
    }

    let mut addresses = Vec::new();
    for (line, name) in lines.iter().zip(&names) {
        let (local, rest) = line.split_once(':').ok_or_else(|| {
            format!("the address line {line:?} is not localpart: own or localpart: alias localpart")
        })?;
        let local = local.trim();
        if rest.trim() != "own" {
            let target = rest
                .trim()
                .strip_prefix("alias ")
                .map(str::trim)
                .unwrap_or_default();
            let shared = own.get(target).ok_or_else(|| {
                format!("the address {local} is an alias into {target}, which is not a mailbox in the table")
            })?;
            addresses.push(GroupAddress {
                address: local.to_string(),
                mailbox: (*shared).to_string(),
            });
            continue;
        }
        addresses.push(GroupAddress {
            address: local.to_string(),
            mailbox: name.clone(),
        });
    }
    Ok((addresses, mailboxes))
}

/// The account that owns the site. The community block names no site owner of
/// its own yet, so it is the applicant's account when the address table holds
/// it, and the first mailbox otherwise.
///
/// shortcut: the community block has no site-owner question yet, so the site is
/// the applicant's account when the table names it and the first mailbox
/// otherwise; add the question and read it here.
pub(super) fn site_owner(record: &Record, mailboxes: &[String]) -> Result<String, String> {
    if mailboxes.iter().any(|m| m == &record.username) {
        return Ok(record.username.clone());
    }
    mailboxes.first().cloned().ok_or_else(|| {
        "the address table names no mailbox, so no account owns the site".to_string()
    })
}

/// The group record, when one is already there. A record that cannot be read or
/// parsed is an error rather than "no group": treating it as absent would let an
/// approval adopt accounts the record names.
pub async fn group_record(store: &Store, domain: &str) -> Result<Option<GroupRecord>, String> {
    let Some(record) = store.group(domain).await? else {
        return Ok(None);
    };
    if record.version != 1 {
        return Err(format!(
            "groups/{domain}/group.json has version {}, which this build does not read",
            record.version
        ));
    }
    Ok(Some(record))
}

/// Refuse a mailbox name this group did not make. It runs before anything is
/// journaled or written, so a refusal records nothing; a retry finds its own
/// accounts named by the group record or by their group reference.
pub(super) async fn check_group_names(
    cfg: &DrainConfig,
    store: &Store,
    domain: &str,
    mailboxes: &[String],
    record: Option<&GroupRecord>,
) -> Result<(), String> {
    for mailbox in mailboxes {
        name_allowed(cfg, mailbox).await?;
        let in_record = record
            .map(|g| g.accounts.iter().any(|a| a == mailbox))
            .unwrap_or(false);
        let existing = store.account(mailbox).await?;
        let in_account = existing
            .as_ref()
            .map(|a| a.group.as_deref() == Some(domain))
            .unwrap_or(false);
        if in_record || in_account {
            continue;
        }
        // A name a removed mailbox left is held for ninety days before the
        // group can reuse it. Both the approval and an add-mailbox pass here.
        if let Some(until) = name_held(store, mailbox).await? {
            return Err(format!(
                "the account name {mailbox} is held until {until}, so it cannot be reused yet"
            ));
        }
        if existing.is_some() {
            return Err(format!("the account name {mailbox} is already taken"));
        }
        if account_on_box(cfg, mailbox)? {
            return Err(format!(
                "the account name {mailbox} is already in use on this box"
            ));
        }
    }
    Ok(())
}

/// Apply one `provision-group` intent: the record, the accounts, the mail table
/// entries and the site owner's key. Everything is idempotent, so a retry after
/// a crash makes nothing twice.
pub async fn provision_group(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    intent: GroupIntent,
) -> Result<Settlement, String> {
    if intent.kind != "provision-group" {
        return Err(format!("kind {:?} is not a group intent", intent.kind));
    }
    if let Some(why) = validate::domain(&intent.domain) {
        return Err(format!("the domain {:?}: {why}", intent.domain));
    }
    if intent.mailboxes.is_empty() {
        return Err("the intent names no mailbox, so there is nothing to provision".to_string());
    }
    if !intent.mailboxes.iter().any(|m| m == &intent.site_owner) {
        return Err(format!(
            "the site owner {} is not one of the mailboxes",
            intent.site_owner
        ));
    }
    let mut mailboxes = HashSet::new();
    for mailbox in &intent.mailboxes {
        if !mailboxes.insert(mailbox.as_str()) {
            return Err(format!("the mailbox {mailbox} is named twice"));
        }
    }
    for address in &intent.addresses {
        if let Some(why) = validate::username_shape(&address.address) {
            return Err(format!("the address {:?}: {why}", address.address));
        }
        if !intent.mailboxes.iter().any(|m| m == &address.mailbox) {
            return Err(format!(
                "the address {}@{} points at {}, which is not a mailbox",
                address.address, intent.domain, address.mailbox
            ));
        }
    }
    let mut seen = HashSet::new();
    for address in &intent.addresses {
        if !seen.insert(address.address.as_str()) {
            return Err(format!(
                "the address {} is in the table twice",
                address.address
            ));
        }
    }

    // Every mailbox's key must be in hand before anything is made, so a missing
    // one cannot leave a half-made group whose mail bounces.
    let mut keys: BTreeMap<String, Vec<KeyRecord>> = BTreeMap::new();
    for mailbox in &intent.mailboxes {
        let mine: Vec<KeyRecord> = intent
            .mail_keys
            .iter()
            .filter(|k| &k.mailbox == mailbox)
            .cloned()
            .collect();
        if mine.is_empty() {
            return Err(format!(
                "the mailbox {mailbox} has no mail key, so its mail would bounce"
            ));
        }
        keys.insert(mailbox.clone(), mine);
    }

    // Names, before anything is written or journaled. A name this group did not
    // make is refused rather than adopted: the box and the account record are
    // both oracles, and a retry finds its own accounts named by the group record
    // or by their group reference.
    let record = group_record(store, &intent.domain).await?;
    check_group_names(
        cfg,
        store,
        &intent.domain,
        &intent.mailboxes,
        record.as_ref(),
    )
    .await?;

    write_journal(
        store,
        journal,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &intent.application,
        "applying",
        None,
    )
    .await?;

    // The record first: it is what tells a retry which accounts on the box are
    // this group's. A charged group's one token and one window are drawn here,
    // and a retry keeps what the first pass wrote, so applying the intent twice
    // cannot leave two tokens, two windows or a renewal's date overwritten.
    let now = util::filed_at();
    let payment = GroupPayment {
        rail: intent.payment.rail.clone(),
        no_charge: intent.payment.no_charge,
        token_ref: if intent.payment.no_charge {
            None
        } else {
            match record.as_ref().and_then(|g| g.payment.token_ref.clone()) {
                Some(token) => Some(token),
                None => Some(store::payment_token().await?),
            }
        },
        window: if intent.payment.no_charge {
            None
        } else {
            match record.as_ref().and_then(|g| g.payment.window.clone()) {
                Some(window) => Some(window),
                None => Some(Window {
                    opened_at: now.clone(),
                    closes_at: util::after_days(14),
                    state: "open".to_string(),
                    extensions: 0,
                }),
            }
        },
        paid_until: record
            .as_ref()
            .and_then(|g| g.payment.paid_until.clone())
            .or_else(|| intent.payment.paid_until.clone()),
        stripe: match record.as_ref() {
            Some(g) if g.payment.stripe.subscription.is_some() => g.payment.stripe.clone(),
            _ => intent.payment.stripe.clone(),
        },
    };
    let group = GroupRecord {
        version: 1,
        domain: intent.domain.clone(),
        name: intent.name.clone(),
        kind: intent.body_kind.clone(),
        payment: payment.clone(),
        accounts: intent.mailboxes.clone(),
        site_owner: intent.site_owner.clone(),
        space_used: None,
        grace_until: record.as_ref().and_then(|g| g.grace_until.clone()),
        created_at: record
            .as_ref()
            .map(|g| g.created_at.clone())
            .filter(|stamp| !stamp.is_empty())
            .unwrap_or_else(|| now.clone()),
    };
    write_group_record(store, &group).await?;

    // The mail tables before the accounts: provision-member.sh restarts smtpd
    // when it adds a new account's platform address, and that restart is what
    // makes these lines live.
    ensure_table_line(&cfg.mail_domains, &intent.domain, None)?;
    ensure_table_line(&cfg.dkim_domains, &intent.domain, None)?;
    for address in &intent.addresses {
        ensure_table_line(
            &cfg.virtuals,
            &format!("{}@{}", address.address, intent.domain),
            Some(&address.mailbox),
        )?;
    }

    let app_copy = application_copy(
        store,
        intent
            .application
            .status_token
            .as_deref()
            .ok_or("the group intent names no application token")?,
    )
    .await?;

    // Every account and its keyring entry first. The public publish is a network
    // call to the forge, and it runs in a second loop so a forge outage cannot
    // leave a later mailbox uncreated while its virtual entry already accepts
    // mail.
    for mailbox in &intent.mailboxes {
        if let Some(mine) = keys.get(mailbox) {
            publish_mail_keys(cfg, mailbox, mine).await?;
        }
        if !account_on_box(cfg, mailbox)? {
            run_script_tolerating(cfg, "add-user.sh", &[mailbox], "already exists").await?;
        }
        // The block's upload key is the site owner's, and only theirs: it fills
        // the site tree and reaches the repositories, so it goes in the one
        // account named to own the site.
        if mailbox == &intent.site_owner && !intent.upload_key.trim().is_empty() {
            write_public_key(store, mailbox, &intent.upload_key).await?;
        }
        run_script(cfg, "provision-member.sh", &[mailbox]).await?;
        write_group_account(
            store,
            mailbox,
            &intent.domain,
            &intent.payment,
            keys.get(mailbox).and_then(|k| k.first()),
        )
        .await?;
        write_group_application(store, mailbox, app_copy.as_deref()).await?;
    }
    // The published set is what the drift check compares the keyring against.
    for mailbox in &intent.mailboxes {
        if let Some(mine) = keys.get(mailbox) {
            publish_mail_keys_publicly(cfg, mailbox, mine).await?;
        }
    }

    // The group's one token, after the accounts it pays for exist. The index
    // resolves the token to the group, so the prepaid credit and the card rail
    // both write the one date every mailbox shares. A free group has neither a
    // token nor a ledger line. Both writes are idempotent, so a retry adds
    // nothing.
    if let (Some(token), Some(window)) = (&payment.token_ref, &payment.window) {
        let join = TokenRecord {
            token: token.clone(),
            username: intent.site_owner.clone(),
            group: Some(intent.domain.clone()),
            issued_at: now.clone(),
            window_closes_at: window.closes_at.clone(),
            state: "issued".to_string(),
        };
        let bytes = serde_json::to_vec_pretty(&join)
            .map_err(|e| format!("cannot encode the token record: {e}"))?;
        store.ensure_dir("tokens").await?;
        store
            .write_record("tokens", &format!("{token}.json"), &bytes)
            .await?;
        append_ledger(
            store,
            token,
            &payment.rail,
            &intent.id,
            &now,
            &cfg.group_price_gbp,
        )
        .await?;
    }

    // The body's hosting, rooted in the site owner's own tree. The upload key
    // decides hosting the way it does for a member: provision-member.sh builds
    // no tree without one, so a group that left it empty has no site to serve
    // and the lanes would refuse.
    if !intent.upload_key.trim().is_empty() {
        run_script(
            cfg,
            "provision-group-web.sh",
            &[&intent.domain, &intent.site_owner],
        )
        .await?;
        run_script(
            cfg,
            "provision-group-capsule.sh",
            &[&intent.domain, &intent.site_owner],
        )
        .await?;
        run_script(
            cfg,
            "provision-group-acme.sh",
            &[&intent.domain, &intent.site_owner],
        )
        .await?;
        // New daemon files, so the index and reload pass runs, the same one a
        // person's hosting approval runs.
        run_script(cfg, "cron-apply.sh", &["--web"]).await?;
    }

    Ok(Settlement::line(
        "applied",
        intent.application.clone(),
        None,
    ))
}

/// The application's own copy, written into each mailbox's account so the block's
/// answers sit inside the ninety-day purge with the rest of the application. The
/// status link's end is stamped the way the person path's copy is.
async fn application_copy(store: &Store, token: &str) -> Result<Option<String>, String> {
    let Some(text) = store.filed_application_text(token).await? else {
        return Ok(None);
    };
    let mut value: Value =
        serde_json::from_str(&text).map_err(|e| format!("the application record: {e}"))?;
    value["status_link_until"] = json!(util::after_days(7));
    let bytes = serde_json::to_string_pretty(&value)
        .map_err(|e| format!("cannot encode the application copy: {e}"))?;
    Ok(Some(bytes))
}

/// One mailbox's copy of the application, when the application record is still
/// there. A retry rewrites the same bytes.
async fn write_group_application(
    store: &Store,
    mailbox: &str,
    copy: Option<&str>,
) -> Result<(), String> {
    let Some(copy) = copy else {
        return Ok(());
    };
    store.ensure_dir(&format!("accounts/{mailbox}")).await?;
    store
        .write_record(
            &format!("accounts/{mailbox}"),
            "application.json",
            copy.as_bytes(),
        )
        .await
}

/// The mailbox's account record: a reference to its group and no payment block
/// of its own, which the group holds. A retry keeps the dates the first run
/// wrote, so applying the same intent twice changes nothing.
async fn write_group_account(
    store: &Store,
    mailbox: &str,
    domain: &str,
    payment: &GroupPayment,
    mail_key: Option<&KeyRecord>,
) -> Result<(), String> {
    let existing = store.account(mailbox).await?;
    let now = util::filed_at();
    let account = Account {
        version: 1,
        username: mailbox.to_string(),
        state: "active".to_string(),
        decision: "approve".to_string(),
        decided_at: existing
            .as_ref()
            .map(|a| a.decided_at.clone())
            .unwrap_or_else(|| now.clone()),
        rail: if payment.no_charge {
            "no_charge".to_string()
        } else {
            payment.rail.clone()
        },
        no_charge: payment.no_charge,
        created_at: existing
            .as_ref()
            .map(|a| a.created_at.clone())
            .unwrap_or_else(|| now.clone()),
        // The group holds the payment state, so the mailbox's record has no
        // block for one at all rather than a paid-until that could be mistaken
        // for an unpaid person's.
        payment: None,
        legacy_payment: FlatPayment::default(),
        outside_address: None,
        certificates: Vec::new(),
        site_served: None,
        capsule_served: None,
        space_used: None,
        upload_keys: Vec::new(),
        mail_key: mail_key
            .map(|key| key.fingerprint.clone())
            .filter(|f| !f.is_empty())
            .or_else(|| existing.as_ref().and_then(|a| a.mail_key.clone())),
        rotation: existing.as_ref().and_then(|a| a.rotation.clone()),
        suspension_reason: None,
        group: Some(domain.to_string()),
        closing_until: None,
        grace_until: None,
    };
    let bytes = serde_json::to_vec_pretty(&account)
        .map_err(|e| format!("cannot encode the account: {e}"))?;
    store.ensure_dir(&format!("accounts/{mailbox}")).await?;
    write_account_record(store, mailbox, &bytes).await
}

/// Write one group's record. The caller owns the directory name, which is the
/// validated domain, so a record can never land outside `groups/`.
pub(super) async fn write_group_record(store: &Store, group: &GroupRecord) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(group)
        .map_err(|e| format!("cannot encode the group record: {e}"))?;
    store
        .ensure_dir(&format!("groups/{}", group.domain))
        .await?;
    write_group_state(store, &group.domain, &bytes).await
}

/// Write one account's record, readable by the handler and not writable by it.
/// The page is rendered by `_onboard`, which cannot read a 0600 root file, and
/// the record holds no secret: the group's token stays in `tokens/` and the
/// ledger. The directory's own group is the owner, so the deploy's modes are
/// what decide who can read it rather than a second list here.
pub async fn write_account_record(
    store: &Store,
    username: &str,
    bytes: &[u8],
) -> Result<(), String> {
    store
        .write_record_mode(
            &format!("accounts/{username}"),
            "account.json",
            bytes,
            store.dir_owner("accounts"),
            0o640,
        )
        .await
}

/// The same for a group's record, for the same reason: the account page of any
/// mailbox in the group reads it, and a root-only 0600 file would leave the
/// billing block blank.
pub(super) async fn write_group_state(
    store: &Store,
    domain: &str,
    bytes: &[u8],
) -> Result<(), String> {
    store
        .write_record_mode(
            &format!("groups/{domain}"),
            "group.json",
            bytes,
            store.dir_owner("groups"),
            0o640,
        )
        .await
}

/// The lock every writer of a mail table holds: a `<table>.lock` directory with
/// the owner's pid inside. The shell scripts take the same directory in lib.sh's
/// table_lock, with the same pid file and the same stale rule, so a drain append
/// and an operator deploy or delete exclude each other. Releasing is the Drop
/// impl, so an early return cannot leave it behind.
struct TableLock {
    dir: std::path::PathBuf,
}

impl TableLock {
    fn acquire(path: &str) -> Result<TableLock, String> {
        let dir = std::path::PathBuf::from(format!("{path}.lock"));
        let mut reaped = false;
        for attempt in 0..5 {
            match std::fs::create_dir(&dir) {
                Ok(()) => {
                    if let Err(e) =
                        std::fs::write(dir.join("pid"), format!("{}\n", std::process::id()))
                    {
                        let _ = std::fs::remove_dir_all(&dir);
                        return Err(format!(
                            "cannot write the owner pid into {}: {e}",
                            dir.display()
                        ));
                    }
                    return Ok(TableLock { dir });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if !reaped {
                        if let Some(reason) = stale_table_lock(&dir) {
                            eprintln!("reaping stale lock {}: {reason}", dir.display());
                            let _ = std::fs::remove_dir_all(&dir);
                            reaped = true;
                            continue;
                        }
                    }
                }
                Err(e) => {
                    return Err(format!("cannot lock {path}: {e}"));
                }
            }
            if attempt < 4 {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        Err(format!(
            "could not lock {path}: {} exists and did not clear; remove it if no writer is running",
            dir.display()
        ))
    }
}

impl Drop for TableLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Why `<table>.lock` is not being held by a live writer, or `None` when it
/// looks live. The pid file is the first answer; a lock old enough that no
/// legitimate write could still hold it is the second, which also covers a
/// writer killed between mkdir and the pid write.
fn stale_table_lock(dir: &std::path::Path) -> Option<String> {
    if let Ok(text) = std::fs::read_to_string(dir.join("pid")) {
        let pid = text.trim();
        if !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) {
            let alive = std::process::Command::new("/bin/kill")
                .arg("-0")
                .arg(pid)
                .stderr(std::process::Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(true);
            if !alive {
                return Some(format!("pid {pid} is gone"));
            }
            // A live owner is holding it, however long the write is taking.
            return None;
        }
    }
    let held = std::fs::metadata(dir)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| std::time::SystemTime::now().duration_since(modified).ok());
    if let Some(held) = held {
        if held.as_secs() > 30 {
            return Some(format!("it has been held for {} seconds", held.as_secs()));
        }
    }
    None
}

/// Ensure one line is in a virtual table: a bare value when `value` is `None`
/// (a `mail_domains` line), and `name: value` otherwise (a `virtuals` entry). A
/// key already present with the same value is left alone; one present with a
/// different value is a refusal, because overruling it would silently redirect
/// somebody's mail. Written through a temporary in the same directory, so smtpd
/// never reads half a table.
fn ensure_table_line(path: &str, name: &str, value: Option<&str>) -> Result<(), String> {
    let _lock = TableLock::acquire(path)?;
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {path}; run scripts/deploy-mail.sh first: {e}"))?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match value {
            None if line == name => return Ok(()),
            None => {}
            Some(want) => {
                let (key, have) = line.split_once(':').unwrap_or((line, ""));
                if key.trim() == name {
                    if have.trim() == want {
                        return Ok(());
                    }
                    return Err(format!(
                        "{path} already maps {name} to {}, not {want}",
                        have.trim()
                    ));
                }
            }
        }
    }
    let line = match value {
        Some(v) => format!("{name}: {v}"),
        None => name.to_string(),
    };
    // Append rather than rewrite. A rewrite reads the whole table and renames a
    // copy over it, so a line another writer appended between the read and the
    // rename is lost; one approval runs subprocesses and a network call, so two
    // passes overlap. The lock above is what excludes a shell writer, and the
    // append itself cannot lose a line. The newline guard is the same one
    // deploy-mail.sh uses: a hand edit may have left the last line unterminated.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("cannot open {path}: {e}"))?;
    let mut entry = String::new();
    if !text.is_empty() && !text.ends_with('\n') {
        entry.push('\n');
    }
    entry.push_str(&line);
    entry.push('\n');
    std::io::Write::write_all(&mut file, entry.as_bytes())
        .map_err(|e| format!("cannot append to {path}: {e}"))
}

/// The value a virtual table maps `name` to, or `None` when the key is absent.
fn table_value(path: &str, name: &str) -> Result<Option<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {path}; run scripts/deploy-mail.sh first: {e}"))?;
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim() == name {
                return Ok(Some(value.trim().to_string()));
            }
        }
    }
    Ok(None)
}

/// How many addresses the body's domain has: every `<localpart>@<domain>` line,
/// mailboxes and aliases alike, which is the ten-address cap's count.
fn address_count(path: &str, domain: &str) -> Result<usize, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {path}; run scripts/deploy-mail.sh first: {e}"))?;
    let suffix = format!("@{domain}");
    Ok(text
        .lines()
        .filter(|line| {
            line.split_once(':')
                .map(|(key, _)| key.trim().ends_with(&suffix))
                .unwrap_or(false)
        })
        .count())
}

/// Rewrite a table through a temporary beside it, then rename it into place.
/// The `TableLock` argument is the proof that the caller holds the table's lock
/// for the read that produced `text` as well as this write: an unlocked rewrite
/// would drop a line another writer appended between the two.
fn write_table(path: &str, text: &str, _lock: &TableLock) -> Result<(), String> {
    let candidate = format!("{path}.onboard.{}", std::process::id());
    std::fs::write(&candidate, text).map_err(|e| format!("cannot write {candidate}: {e}"))?;
    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("cannot set the mode on {candidate}: {e}"))?;
    std::fs::rename(&candidate, path).map_err(|e| format!("cannot replace {path}: {e}"))
}

/// Repoint an existing virtual entry, keeping every other line. A value that is
/// already right is left alone, so an upgrade intent applied twice changes
/// nothing. `ensure_table_line` refuses a different value on purpose (it must
/// not overrule a line somebody else made), so this is the explicit repoint.
///
fn repoint_table_line(path: &str, name: &str, want: &str) -> Result<(), String> {
    let lock = TableLock::acquire(path)?;
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {path}; run scripts/deploy-mail.sh first: {e}"))?;
    let mut out = String::new();
    let mut found = false;
    for line in text.lines() {
        if let Some((key, have)) = line.split_once(':') {
            if key.trim() == name {
                if have.trim() == want {
                    return Ok(());
                }
                out.push_str(&format!("{name}: {want}\n"));
                found = true;
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if !found {
        out.push_str(&format!("{name}: {want}\n"));
    }
    write_table(path, &out, &lock)
}

/// Drop every line for `domain` that points at `mailbox`. That is the mailbox's
/// own address and any alias into it, so no entry is left delivering nowhere.
/// Returns whether the table changed.
fn remove_addresses(path: &str, domain: &str, mailbox: &str) -> Result<bool, String> {
    let lock = TableLock::acquire(path)?;
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {path}; run scripts/deploy-mail.sh first: {e}"))?;
    let suffix = format!("@{domain}");
    let mut out = String::new();
    let mut changed = false;
    for line in text.lines() {
        let remove = line
            .split_once(':')
            .map(|(key, value)| key.trim().ends_with(&suffix) && value.trim() == mailbox)
            .unwrap_or(false);
        if remove {
            changed = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if changed {
        write_table(path, &out, &lock)?;
    }
    Ok(changed)
}

/// A username's hold, while it still has time to run. The date is the record's;
/// a record that cannot be read is an error rather than no hold, because a
/// broken hold file must not release a name the platform is still holding. A
/// readable record with no usable date is no hold.
pub(super) async fn name_held(store: &Store, username: &str) -> Result<Option<String>, String> {
    let Some(value) = store.hold(username).await? else {
        return Ok(None);
    };
    let Some(until) = value.get("until").and_then(Value::as_str) else {
        return Ok(None);
    };
    match OffsetDateTime::parse(until, &Rfc3339) {
        Ok(at) if at > OffsetDateTime::now_utc() => Ok(Some(until.to_string())),
        _ => Ok(None),
    }
}

/// Hold a closed account's name for ninety days. Written only when there is no
/// live hold, so a retry keeps the date the removal first set rather than
/// pushing the release out by another pass.
pub(super) async fn hold_name(store: &Store, username: &str) -> Result<(), String> {
    if name_held(store, username).await?.is_some() {
        return Ok(());
    }
    let bytes = serde_json::to_vec_pretty(&json!({
        "username": username,
        "until": util::after_days(90),
    }))
    .map_err(|e| format!("cannot encode the hold: {e}"))?;
    store.ensure_dir("holds").await?;
    store
        .write_record("holds", &format!("{username}.json"), &bytes)
        .await
}

/// The three steps that close one mailbox: its name held for ninety days, its
/// stored upload key dropped, and scripts/delete-user.sh, which removes the box
/// account, its tree, its quota record and its store record. Shared by a
/// mailbox leaving a group and a whole group going, so the two cannot disagree
/// about what a closed account is. The caller removes the virtual entry first,
/// because it is the one that knows which table line belongs to the account.
async fn close_mailbox(cfg: &DrainConfig, store: &Store, username: &str) -> Result<(), String> {
    hold_name(store, username).await?;
    store.remove("keys", &format!("{username}.pub")).await?;
    run_script(cfg, "delete-user.sh", &[username]).await
}

/// The mail key a new mailbox carries, checked before anything is written: the
/// material must be there and must be the mailbox's own key.
fn address_key(intent: &GroupAddressIntent) -> Result<KeyRecord, String> {
    let Some(key) = intent.mail_key.as_ref() else {
        return Err(format!(
            "the mailbox {} has no mail key, so its mail would bounce",
            intent.mailbox
        ));
    };
    if !key.mailbox.is_empty() && key.mailbox != intent.mailbox {
        return Err(format!(
            "the mail key names {}, not {}",
            key.mailbox, intent.mailbox
        ));
    }
    if key.material.trim().is_empty() {
        return Err(format!("the mail key for {} is empty", intent.mailbox));
    }
    // The console carries whatever file the operator named. A private key, an
    // SSH key or a truncated block would reach the encryptor's keyring and
    // fail closed, so the shared check refuses it before the journal line.
    let checked = crate::keycheck::pgp_public_key(&key.material)
        .map_err(|e| format!("the mail key for {}: {e}", intent.mailbox))?;
    let mut key = key.clone();
    key.mailbox = intent.mailbox.clone();
    key.verdict = checked.verdict;
    Ok(key)
}

/// Apply one `group-address` intent: a change inside a body's group that must
/// not touch the price or the group's paid-until date. Every step is idempotent,
/// and every check runs before the journal line and the first write, so a
/// refused intent changes nothing.
pub async fn group_address(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    intent: GroupAddressIntent,
) -> Result<Settlement, String> {
    if intent.kind != "group-address" {
        return Err(format!("kind {:?} is not an address intent", intent.kind));
    }
    if !ADDRESS_ACTIONS.contains(&intent.action.as_str()) {
        return Err(format!("{:?} is not an address change", intent.action));
    }
    if let Some(why) = validate::domain(&intent.domain) {
        return Err(format!("the domain {:?}: {why}", intent.domain));
    }
    let Some(mut group) = group_record(store, &intent.domain).await? else {
        return Err(format!(
            "there is no group for {}, so there is no address to change",
            intent.domain
        ));
    };
    if let Some(why) = validate::username_shape(&intent.mailbox) {
        return Err(format!("the mailbox {:?}: {why}", intent.mailbox));
    }
    if intent.action != "remove" {
        if let Some(why) = validate::username_shape(&intent.address) {
            return Err(format!("the address {:?}: {why}", intent.address));
        }
    }

    let entry = format!("{}@{}", intent.address, intent.domain);
    let current = match intent.action.as_str() {
        "remove" => None,
        _ => table_value(&cfg.virtuals, &entry)?,
    };
    let in_group = |mailbox: &str| group.accounts.iter().any(|a| a == mailbox);

    match intent.action.as_str() {
        "add-alias" => {
            if !in_group(&intent.mailbox) {
                return Err(format!(
                    "the alias {}@{} points at {}, which is not a mailbox in the group",
                    intent.address, intent.domain, intent.mailbox
                ));
            }
            match &current {
                Some(have) if have == &intent.mailbox => {}
                Some(have) => {
                    return Err(format!(
                        "{} already maps {entry} to {have}, not {}",
                        cfg.virtuals, intent.mailbox
                    ))
                }
                None if address_count(&cfg.virtuals, &intent.domain)? >= 10 => {
                    return Err(format!(
                        "{} already carries ten addresses, so {entry} cannot be added",
                        intent.domain
                    ))
                }
                None => {}
            }
        }
        "add-mailbox" => {
            address_key(&intent)?;
            if let Some(have) = &current {
                if have != &intent.mailbox {
                    return Err(format!(
                        "{} already maps {entry} to {have}, not {}",
                        cfg.virtuals, intent.mailbox
                    ));
                }
            }
            if !in_group(&intent.mailbox) {
                check_group_names(
                    cfg,
                    store,
                    &intent.domain,
                    std::slice::from_ref(&intent.mailbox),
                    Some(&group),
                )
                .await?;
            }
            // The cap counts new entries, whether or not the mailbox itself is
            // already in the group: a second address into an existing mailbox
            // still costs one of the ten.
            if current.is_none() && address_count(&cfg.virtuals, &intent.domain)? >= 10 {
                return Err(format!(
                    "{} already carries ten addresses, so {} cannot be added",
                    intent.domain, entry
                ));
            }
        }
        "upgrade" => {
            address_key(&intent)?;
            match &current {
                None => {
                    return Err(format!(
                        "{} is not an address in {}, so there is no alias to upgrade",
                        entry, intent.domain
                    ))
                }
                Some(have) if have == &intent.mailbox => {}
                Some(have) => {
                    if !in_group(have) {
                        return Err(format!(
                            "{} points at {have}, which is not a mailbox in the group",
                            entry
                        ));
                    }
                }
            }
            if !in_group(&intent.mailbox) {
                check_group_names(
                    cfg,
                    store,
                    &intent.domain,
                    std::slice::from_ref(&intent.mailbox),
                    Some(&group),
                )
                .await?;
            }
        }
        "remove" => {
            if group.site_owner == intent.mailbox {
                let Some(replacement) = intent.site_owner.as_deref() else {
                    return Err(format!(
                        "{} owns the site, so the intent must name the account that takes it",
                        intent.mailbox
                    ));
                };
                if replacement == intent.mailbox || !in_group(replacement) {
                    return Err(format!(
                        "the replacement site owner {replacement} is not another mailbox in the group"
                    ));
                }
            }
            let existing = store.account(&intent.mailbox).await?;
            let ours = existing
                .as_ref()
                .map(|a| a.group.as_deref() == Some(intent.domain.as_str()))
                .unwrap_or(false);
            if !in_group(&intent.mailbox) && !ours && account_on_box(cfg, &intent.mailbox)? {
                return Err(format!(
                    "the account {} is not a mailbox in {}",
                    intent.mailbox, intent.domain
                ));
            }
        }
        _ => unreachable!("the action was checked against ADDRESS_ACTIONS"),
    }

    let application = ApplicationRef::group(intent.mailbox.clone(), intent.domain.clone());
    write_journal(
        store,
        journal,
        &cfg.release,
        &intent.id,
        &intent.kind,
        &application,
        "applying",
        None,
    )
    .await?;

    match intent.action.as_str() {
        "add-alias" => {
            ensure_table_line(&cfg.virtuals, &entry, Some(&intent.mailbox))?;
            // smtpd reads the table at start and has no reload verb, so the
            // alias does not deliver until it restarts.
            run_script(cfg, "reload-smtpd.sh", &[]).await?;
        }
        "add-mailbox" => {
            // The record first, as a group's own provisioning does: it is what
            // tells a retry that an account on the box is this group's.
            if !in_group(&intent.mailbox) {
                group.accounts.push(intent.mailbox.clone());
                write_group_record(store, &group).await?;
            }
            let key = address_key(&intent)?;
            ensure_table_line(&cfg.virtuals, &entry, Some(&intent.mailbox))?;
            publish_mail_keys(cfg, &intent.mailbox, std::slice::from_ref(&key)).await?;
            if !account_on_box(cfg, &intent.mailbox)? {
                run_script_tolerating(cfg, "add-user.sh", &[&intent.mailbox], "already exists")
                    .await?;
            }
            run_script(cfg, "provision-member.sh", &[&intent.mailbox]).await?;
            write_group_account(
                store,
                &intent.mailbox,
                &intent.domain,
                &group.payment,
                Some(&key),
            )
            .await?;
            publish_mail_keys_publicly(cfg, &intent.mailbox, std::slice::from_ref(&key)).await?;
        }
        "upgrade" => {
            if !in_group(&intent.mailbox) {
                group.accounts.push(intent.mailbox.clone());
                write_group_record(store, &group).await?;
            }
            let key = address_key(&intent)?;
            publish_mail_keys(cfg, &intent.mailbox, std::slice::from_ref(&key)).await?;
            if !account_on_box(cfg, &intent.mailbox)? {
                run_script_tolerating(cfg, "add-user.sh", &[&intent.mailbox], "already exists")
                    .await?;
            }
            run_script(cfg, "provision-member.sh", &[&intent.mailbox]).await?;
            write_group_account(
                store,
                &intent.mailbox,
                &intent.domain,
                &group.payment,
                Some(&key),
            )
            .await?;
            repoint_table_line(&cfg.virtuals, &entry, &intent.mailbox)?;
            // The repoint is a table rewrite after the builder's own restart,
            // and a retry that finds the account already made restarts nothing.
            // Without this the upgraded address keeps reaching the shared
            // mailbox.
            run_script(cfg, "reload-smtpd.sh", &[]).await?;
            publish_mail_keys_publicly(cfg, &intent.mailbox, std::slice::from_ref(&key)).await?;
        }
        "remove" => {
            // What this pass actually closes. A mistyped name that is neither in
            // the group nor on the box closes nothing, so it must not start a
            // ninety-day hold either.
            let closing = in_group(&intent.mailbox)
                || store.account(&intent.mailbox).await?.is_some()
                || account_on_box(cfg, &intent.mailbox)?;
            // Only a pass that still sees the departing mailbox owning the site
            // moves the upload key and the lanes. Once the group record names
            // the replacement, a retry must not copy anything: an intent that
            // merely named the sitting owner while removing somebody else would
            // otherwise hand that member's key to the site.
            let site_owner_leaving = group.site_owner == intent.mailbox;
            if site_owner_leaving {
                let replacement = intent
                    .site_owner
                    .as_deref()
                    .ok_or("the site owner is leaving without a replacement")?;
                let old_key = store
                    .read_record("keys", &format!("{}.pub", intent.mailbox))
                    .await;
                if let Some(material) = &old_key {
                    write_public_key(store, replacement, material).await?;
                }
                run_script(cfg, "provision-member.sh", &[replacement]).await?;
                group.site_owner = replacement.to_string();
            }
            group.accounts.retain(|a| a != &intent.mailbox);
            write_group_record(store, &group).await?;
            if remove_addresses(&cfg.virtuals, &intent.domain, &intent.mailbox)? {
                // delete-user.sh restarts smtpd only when it removed a line;
                // the lines have gone here, so this pass makes them live.
                run_script(cfg, "reload-smtpd.sh", &[]).await?;
            }
            // The box keyring entry stays, as delete-user.sh leaves it:
            // check-keyring-drift.sh reports a published key absent from the
            // box, and the published key's removal is the operator's step
            // (there is no unpublish path in this tree yet).
            if intent.site_owner.is_some() {
                // After the record names the replacement and before the old
                // tree goes: the vhost root must not point at a directory
                // delete-user.sh is about to remove.
                run_script(cfg, "cron-apply.sh", &["--web"]).await?;
            }
            if closing {
                close_mailbox(cfg, store, &intent.mailbox).await?;
            } else {
                store
                    .remove("keys", &format!("{}.pub", intent.mailbox))
                    .await?;
                run_script(cfg, "delete-user.sh", &[&intent.mailbox]).await?;
            }
        }
        _ => unreachable!("the action was checked against ADDRESS_ACTIONS"),
    }

    Ok(Settlement::line("applied", application, None))
}

/// Apply one `remove-group` intent: take a body's domain off the box whole.
///
/// The order is the deletion transition's. The host files go first through
/// scripts/remove-group.sh, then the index and reload pass, so nothing is
/// served from a tree the accounts' deletion is about to remove. The accounts
/// close through the same three steps a mailbox leaving a group takes, and the
/// group record is the last store write: while it is there a retry can still
/// find every account it has to close.
///
/// Idempotent on replay and after a partial crash. The journal is the marker: a
/// line that says `applied` means the domain is down, so the pass only clears
/// the record directory and the intent file. A crash before that line leaves
/// the group record in place, so the next pass finds its accounts again and
/// every step below is a no-op over what is already gone.
pub async fn remove_group(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    intent: GroupRemoveIntent,
) -> Result<Settlement, String> {
    if intent.kind != "remove-group" {
        return Err(format!(
            "kind {:?} is not a remove-group intent",
            intent.kind
        ));
    }
    if let Some(why) = validate::domain(&intent.domain) {
        return Err(format!("the domain {:?}: {why}", intent.domain));
    }

    let Some(group) = group_record(store, &intent.domain).await? else {
        return Err(format!(
            "there is no group for {}, so there is no domain to remove",
            intent.domain
        ));
    };
    let application = ApplicationRef::group(group.site_owner.clone(), intent.domain.clone());
    if !journal.has(&intent.id, "applying") {
        write_journal(
            store,
            journal,
            &cfg.release,
            &intent.id,
            &intent.kind,
            &application,
            "applying",
            None,
        )
        .await?;
    }

    // The mail tables, the generated blocks, the certificate material and the
    // queued order. Then the pass that rewrites the indexes and drops the
    // relayd keypair line the httpd file carried, which only the reload applies.
    take_group_down(cfg, store, &intent.domain).await?;

    // The record is after-line work: it goes once the line is written, so a
    // retry after a crash still finds the accounts it has to close.
    Ok(Settlement::applied(application, None))
}

/// The host files, the index and reload pass, every mailbox's closure and the
/// token index entries: what "the domain is down" is. Shared by a `remove-group`
/// intent and the end of a lapsed group's grace, so the two cannot disagree
/// about what removing a body takes. The group record is the caller's to remove
/// last, so a retry after a crash still finds the accounts it has to close.
pub(super) async fn take_group_down(
    cfg: &DrainConfig,
    store: &Store,
    domain: &str,
) -> Result<(), String> {
    run_script(cfg, "remove-group.sh", &[domain]).await?;
    run_script(cfg, "cron-apply.sh", &["--web"]).await?;
    let Some(group) = group_record(store, domain).await? else {
        return Ok(());
    };
    for account in &group.accounts {
        close_mailbox(cfg, store, account).await?;
    }
    // After the accounts, so a crash between the two steps leaves the record
    // that names them and the retry finds the token again. The group's own
    // token is not an account's, and closing it is this transition's job.
    close_group_tokens(store, &group.accounts).await?;
    if let Some(token) = group.payment.token_ref.as_deref() {
        store.remove("tokens", &format!("{token}.json")).await?;
    }
    Ok(())
}

/// Remove the group's directory, record and all. A directory that is not there
/// reads as done, the same rule `Store::remove` applies to a file.
pub(super) async fn remove_group_record(store: &Store, domain: &str) -> Result<(), String> {
    let dir = store.path(&format!("groups/{domain}"));
    match tokio::fs::remove_dir_all(&dir).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot remove {}: {e}", dir.display())),
    }
}

/// Drop every token index entry that resolves to one of the group's accounts,
/// so the ledger rows keyed by those tokens no longer name an account. The scan
/// is by `TokenRecord.username` rather than by the filename, because the
/// directory also holds tokens that are not these accounts' and the record is
/// what says whose one is.
pub(super) async fn close_group_tokens(store: &Store, accounts: &[String]) -> Result<(), String> {
    for name in store.list("tokens").await? {
        if !name.ends_with(".json") {
            continue;
        }
        let Some(token) = store.token(name.trim_end_matches(".json")).await? else {
            continue;
        };
        // A group's token is indexed under the site owner's name, but it pays
        // for the whole body: closing that one account must not strand the
        // group's payments. The group's own removal drops it.
        if token.group.is_some() {
            continue;
        }
        if accounts.iter().any(|account| account == &token.username) {
            store.remove("tokens", &name).await?;
        }
    }
    Ok(())
}

/// Whether the box itself holds an account for a username, read from the passwd
/// file rather than by running `id(1)`. This is the oracle the account record is
/// not: an account the operator made, or one `provision-member.sh` made by hand,
/// has no `account.json`, and the drain must neither adopt it nor release its
/// name. An unreadable file is an error rather than a "no", so the drain fails
/// closed instead of acting on a box it cannot see.
pub(super) fn account_on_box(cfg: &DrainConfig, username: &str) -> Result<bool, String> {
    let text = std::fs::read_to_string(&cfg.passwd)
        .map_err(|e| format!("cannot read {}: {e}", cfg.passwd))?;
    Ok(text
        .lines()
        .any(|line| line.split(':').next() == Some(username)))
}

/// The names the platform holds back, read from the path the config names.
///
/// Read where it is used rather than held for the pass: it is a short file, read
/// at most twice a minute by a cron job, and a read that fails must refuse the
/// work rather than let it through on an empty list.
async fn reserved_names(cfg: &DrainConfig) -> Result<HashSet<String>, String> {
    Ok(validate::reserved(&Store::read_text(&cfg.reserved).await?))
}

/// Refuse a username the platform holds back, naming it. Both gates that can
/// create an account go through this: the filing, and the approval.
///
/// The name is in the message because a failed pass is journalled against an
/// empty application and mailed to the operator, so the message is the only
/// place either of them can read which name was refused.
pub(super) async fn name_allowed(cfg: &DrainConfig, username: &str) -> Result<(), String> {
    let reserved = reserved_names(cfg).await?;
    match validate::username(username, &reserved) {
        None => Ok(()),
        Some(why) => Err(format!("the username {username}: {why}")),
    }
}

/// Append the ledger line a paid approval opens with: the amount owed and the
/// window it falls due in, keyed by the token and holding no username. A rerun
/// finds the line already there and writes none.
pub(super) async fn append_ledger(
    store: &Store,
    token: &str,
    rail: &str,
    intent: &str,
    at: &str,
    amount_gbp: &str,
) -> Result<(), String> {
    let ledger = Ledger::open(store);
    if ledger.has_window_open(token).await? {
        return Ok(());
    }
    let mut line = LedgerLine::empty(token, "window_open", rail);
    line.amount_gbp = Some(amount_gbp.to_string());
    line.applied_gbp = Some("0.00".to_string());
    line.rate_at = Some(at.to_string());
    line.intent = Some(intent.to_string());
    line.note = Some("the window opened at approval; no money has arrived yet".to_string());
    ledger.append(line).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign;
    use crate::store::GroupIntent;
    use serde_json::json;

    /// The `provision-group` payload covers every field the transition acts on:
    /// changing any one of them changes the payload, so a signature made for one
    /// body cannot be replayed with another's mailbox, key or payment.
    #[test]
    fn a_group_payload_covers_every_field_the_drain_acts_on() {
        let base = json!({
            "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "kind": "provision-group",
            "filed_at": "2026-11-01T09:00:00Z",
            "application": {"username": "warden", "status_token": "abcdefghjkmnpqrstvwxyz0123"},
            "domain": "parish.example",
            "name": "Parish of Example",
            "body_kind": "parish",
            "payment": {"rail": "cash", "no_charge": false, "paid_until": null},
            "addresses": [{"address": "secretary", "mailbox": "parish-secretary"}],
            "mailboxes": ["parish-secretary"],
            "site_owner": "parish-secretary",
            "upload_key": "ssh-ed25519 AAAA first@example",
            "mail_keys": [{"mailbox": "parish-secretary", "fingerprint": "1111 2222",
                           "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n",
                           "verdict": "works"}],
            "sig": "",
        });
        let payload = |value: &Value| {
            let intent: GroupIntent = serde_json::from_value(value.clone()).unwrap();
            sign::group_provision_payload(&intent)
        };
        let original = payload(&base);
        let changes = [
            ("domain", json!("other.example")),
            ("name", json!("Another Parish")),
            ("body_kind", json!("monastery")),
            (
                "payment",
                json!({"rail": "card", "no_charge": false, "paid_until": null}),
            ),
            (
                "payment",
                json!({"rail": "cash", "no_charge": true, "paid_until": null}),
            ),
            (
                "payment",
                json!({"rail": "cash", "no_charge": false, "paid_until": "2027-01-01"}),
            ),
            (
                "addresses",
                json!([{"address": "office", "mailbox": "parish-secretary"}]),
            ),
            ("mailboxes", json!(["parish-office"])),
            ("site_owner", json!("parish-office")),
            ("upload_key", json!("ssh-ed25519 AAAA second@example")),
            (
                "mail_keys",
                json!([{"mailbox": "parish-secretary", "fingerprint": "3333 4444",
                        "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nyy\n",
                        "verdict": "works"}]),
            ),
            (
                "application",
                json!({"username": "other", "status_token": "abcdefghjkmnpqrstvwxyz0123"}),
            ),
            (
                "application",
                json!({"username": "warden", "status_token": "fedcba98765432100123456789"}),
            ),
        ];
        for (field, value) in changes {
            let mut changed = base.clone();
            changed[field] = value.clone();
            assert_ne!(original, payload(&changed), "changing {field} to {value}");
        }

        // Every payment field the transition copies into the group record: the
        // token reference, the window's four fields and the Stripe block's
        // eight. The base payment carries none of them, so a field missing from
        // the payload leaves these two payloads equal.
        let with_payment = |payment: Value| {
            let mut changed = base.clone();
            changed["payment"] = payment;
            payload(&changed)
        };
        let base_payment = base["payment"].clone();
        for (label, value) in [
            ("token_ref", json!("KYR-AAAA-BBBB-CCCC")),
            ("paid_until", json!("2027-01-01")),
            ("no_charge", json!(true)),
            ("rail", json!("card")),
        ] {
            let mut payment = base_payment.clone();
            payment[label] = value;
            assert_ne!(original, with_payment(payment), "payment.{label}");
        }

        let window = json!({"opened_at": "2026-11-01T09:00:00Z",
                            "closes_at": "2026-11-15T09:00:00Z",
                            "state": "open", "extensions": 0});
        let mut with_window = base_payment.clone();
        with_window["window"] = window.clone();
        let windowed = with_payment(with_window);
        assert_ne!(original, windowed, "payment.window presence");
        for (label, value) in [
            ("opened_at", json!("2026-10-01T09:00:00Z")),
            ("closes_at", json!("2026-11-20T09:00:00Z")),
            ("state", json!("paid")),
            ("extensions", json!(1)),
        ] {
            let mut changed = window.clone();
            changed[label] = value;
            let mut payment = base_payment.clone();
            payment["window"] = changed;
            assert_ne!(windowed, with_payment(payment), "payment.window.{label}");
        }

        for (label, value) in [
            ("subscription", json!("sub_example")),
            ("customer", json!("cus_example")),
            ("status", json!("active")),
            ("cancel_at_period_end", json!(true)),
            ("current_period_end", json!("2027-01-01T00:00:00Z")),
            ("next_payment_attempt", json!("2026-12-01T00:00:00Z")),
            ("failed_attempts", json!(2)),
            ("last_invoice", json!("in_example")),
        ] {
            let mut stripe = json!({});
            stripe[label] = value;
            let mut payment = base_payment.clone();
            payment["stripe"] = stripe;
            assert_ne!(original, with_payment(payment), "payment.stripe.{label}");
        }
    }

    /// The lock the shell takes is `<table>.lock` with the owner's pid inside, so
    /// this asserts the Rust side uses that path and file, and that dropping the
    /// guard releases it. That shared shape is what lets a drain append and a
    /// deploy's table_set exclude each other.
    #[test]
    fn the_mail_table_lock_is_a_pid_directory_beside_the_table() {
        let dir = std::env::temp_dir().join(format!("onboard-table-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let table = dir.join("virtuals");
        std::fs::write(&table, "hello: oliver\n").unwrap();
        let path = table.to_str().unwrap();

        let lock = TableLock::acquire(path).unwrap();
        let lock_dir = dir.join("virtuals.lock");
        assert!(
            lock_dir.is_dir(),
            "the lock is a directory beside the table"
        );
        assert_eq!(
            std::fs::read_to_string(lock_dir.join("pid"))
                .unwrap()
                .trim(),
            std::process::id().to_string(),
            "the owner pid is inside, which is what the shell reads"
        );
        drop(lock);
        assert!(!lock_dir.exists(), "releasing removes the directory");
        drop(TableLock::acquire(path).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A lock whose owner is gone is reaped rather than left to wedge every
    /// later writer, which is the shell's rule too.
    #[test]
    fn a_stale_mail_table_lock_is_reaped() {
        let dir = std::env::temp_dir().join(format!("onboard-table-reap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let table = dir.join("mail_domains");
        std::fs::write(&table, "kyriakon.net\n").unwrap();
        let lock_dir = dir.join("mail_domains.lock");
        std::fs::create_dir(&lock_dir).unwrap();
        std::fs::write(lock_dir.join("pid"), "999999\n").unwrap();

        let lock = TableLock::acquire(table.to_str().unwrap()).unwrap();
        assert_eq!(
            std::fs::read_to_string(lock_dir.join("pid"))
                .unwrap()
                .trim(),
            std::process::id().to_string()
        );
        drop(lock);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Three writers at once, the case the lock exists for: every appended line
    /// is in the table afterwards, with no candidate left beside it. The retry is
    /// in whole seconds, so the count is kept under the five-second wait.
    #[test]
    fn concurrent_table_appends_all_land() {
        let dir = std::env::temp_dir().join(format!("onboard-table-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let table = dir.join("virtuals");
        std::fs::write(&table, "hello: oliver\n").unwrap();
        let path = table.to_str().unwrap().to_string();

        let mut handles = Vec::new();
        for i in 0..3 {
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                ensure_table_line(&path, &format!("user{i}"), Some("mailbox"))
            }));
        }
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
        let text = std::fs::read_to_string(&table).unwrap();
        assert_eq!(text.lines().count(), 4, "{text}");
        assert!(!dir.join("virtuals.lock").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
