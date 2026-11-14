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
    cancel_stripe_if_active, publish_mail_keys, publish_mail_keys_publicly, run_script,
    run_script_tolerating, write_public_key,
};
use super::lifecycle::dns_contact;
use super::Error;
use super::{write_journal, Settlement};
use kyriakon_control_core::config::DrainConfig;
use kyriakon_control_core::flow::questions;
use kyriakon_control_core::flow::validate;
use kyriakon_control_core::intent::ADDRESS_ACTIONS;
use kyriakon_control_core::mail::notice;
use kyriakon_control_core::payments::ledger::{Ledger, LedgerLine};
use kyriakon_control_core::store::journal::Journal;
use kyriakon_control_core::store::{
    self, Account, ApplicationRef, FlatPayment, GroupAddress, GroupAddressIntent, GroupIntent,
    GroupPayment, GroupRecord, GroupRemoveIntent, KeyRecord, PasswordLink, Record, Store,
    TokenRecord, Window,
};
use kyriakon_control_core::util;
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
pub(super) fn group_addresses(record: &Record) -> Result<(Vec<GroupAddress>, Vec<String>), Error> {
    let text = record
        .answers
        .get("body_addresses")
        .map(String::as_str)
        .unwrap_or("");
    if let Some(why) = validate::address_lines(text) {
        return Err(Error::Failed(format!("the address table: {why}")));
    }
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let names = questions::account_names(&record.answers)?;
    if names.len() != lines.len() {
        return Err(Error::Failed(format!(
            "{} addresses and {} account names; there is one name per address",
            lines.len(),
            names.len()
        )));
    }

    let mut own: BTreeMap<&str, &str> = BTreeMap::new();
    let mut seen = HashSet::new();
    let mut mailboxes: Vec<String> = Vec::new();
    for (line, name) in lines.iter().zip(&names) {
        let (local, rest) = line.split_once(':').ok_or_else(|| {
            Error::Failed(format!(
                "the address line {line:?} is not localpart: own or localpart: alias localpart"
            ))
        })?;
        let local = local.trim();
        if !seen.insert(local) {
            return Err(Error::Failed(format!(
                "the address {local} is in the table twice"
            )));
        }
        if rest.trim() == "own" {
            if mailboxes.iter().any(|m| m == name) {
                return Err(Error::Failed(format!(
                    "the mailbox {name} is named by two mailboxes; an alias shares a mailbox instead"
                )));
            }
            own.insert(local, name);
            mailboxes.push(name.clone());
        }
    }

    let mut addresses = Vec::new();
    for (line, name) in lines.iter().zip(&names) {
        let (local, rest) = line.split_once(':').ok_or_else(|| {
            Error::Failed(format!(
                "the address line {line:?} is not localpart: own or localpart: alias localpart"
            ))
        })?;
        let local = local.trim();
        if rest.trim() != "own" {
            let target = validate::alias_target(rest).ok_or_else(|| {
                Error::Failed(format!(
                    "the address line {line:?} is not localpart: own or localpart: alias localpart"
                ))
            })?;
            let shared = own.get(target).ok_or_else(|| {
                Error::Failed(format!(
                    "the address {local} is an alias into {target}, which is not a mailbox in the table"
                ))
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
pub(super) fn site_owner(record: &Record, mailboxes: &[String]) -> Result<String, Error> {
    if mailboxes.iter().any(|m| m == &record.username) {
        return Ok(record.username.clone());
    }
    mailboxes.first().cloned().ok_or_else(|| {
        Error::Failed("the address table names no mailbox, so no account owns the site".to_string())
    })
}

/// The group record, when one is already there. A record that cannot be read or
/// parsed is an error rather than "no group": treating it as absent would let an
/// approval adopt accounts the record names.
pub async fn group_record(store: &Store, domain: &str) -> Result<Option<GroupRecord>, Error> {
    let Some(record) = store.group(domain).await? else {
        return Ok(None);
    };
    if record.version != 1 {
        return Err(Error::Failed(format!(
            "groups/{domain}/group.json has version {}, which this build does not read",
            record.version
        )));
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
) -> Result<(), Error> {
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
            return Err(Error::Failed(format!(
                "the account name {mailbox} is held until {until}, so it cannot be reused yet"
            )));
        }
        if existing.is_some() {
            return Err(Error::Failed(format!(
                "the account name {mailbox} is already taken"
            )));
        }
        if account_on_box(cfg, mailbox)? {
            return Err(Error::Failed(format!(
                "the account name {mailbox} is already in use on this box"
            )));
        }
    }
    Ok(())
}

/// The platform's own domain: the first line of `mail_domains`, the line
/// `scripts/lib.sh`'s `mail_domains_first` reads and `provision-member.sh`
/// addresses a new member on. Read rather than configured, so the drain and the
/// scripts can never disagree about which name belongs to the operator.
async fn platform_domain(cfg: &DrainConfig) -> Result<String, Error> {
    let text = Store::read_text(&cfg.mail_domains).await?;
    match text.lines().next().map(str::trim) {
        Some(first) if !first.is_empty() => Ok(first.to_string()),
        _ => Err(Error::Failed(format!(
            "{} has no first line, so the platform's own domain is unknown",
            cfg.mail_domains
        ))),
    }
}

/// Why a body may not have `domain`, or `None` when it may. The platform's own
/// domain and anything under it are the operator's: a body there would shadow
/// the platform's own addresses in `virtuals`, and removing it would take the
/// platform's mail table lines, vhosts and certificate with it. The comparison
/// is by label boundary, so a name that merely ends in the same letters is a
/// different domain.
pub(super) async fn body_domain_refusal(
    cfg: &DrainConfig,
    domain: &str,
) -> Result<Option<String>, Error> {
    let platform = platform_domain(cfg).await?;
    // The defensive registrations are the platform's too: `kyriakon.com` is
    // served with the platform's own certificate and relayd keypair, so a body
    // there would shadow them and its removal would take them with it.
    const PLATFORM_DOMAINS: [&str; 1] = ["kyriakon.com"];
    let owned = std::iter::once(platform.as_str())
        .chain(PLATFORM_DOMAINS)
        .any(|name| domain == name || domain.ends_with(&format!(".{name}")));
    Ok(owned.then(|| format!("{domain} is the platform's own domain")))
}

/// Apply one `provision-group` intent: the record, the accounts, the mail table
/// entries and the site owner's key. Everything is idempotent, so a retry after
/// a crash makes nothing twice.
pub async fn provision_group(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    intent: GroupIntent,
) -> Result<Settlement, Error> {
    if intent.kind != "provision-group" {
        return Err(Error::Failed(format!(
            "kind {:?} is not a group intent",
            intent.kind
        )));
    }
    if let Some(why) = validate::domain(&intent.domain) {
        return Err(Error::Failed(format!(
            "the domain {:?}: {why}",
            intent.domain
        )));
    }
    if let Some(reason) = body_domain_refusal(cfg, &intent.domain).await? {
        return Ok(Settlement::refused(reason));
    }
    if intent.mailboxes.is_empty() {
        return Err(Error::Failed(
            "the intent names no mailbox, so there is nothing to provision".to_string(),
        ));
    }
    if !intent.mailboxes.iter().any(|m| m == &intent.site_owner) {
        return Err(Error::Failed(format!(
            "the site owner {} is not one of the mailboxes",
            intent.site_owner
        )));
    }
    let mut mailboxes = HashSet::new();
    for mailbox in &intent.mailboxes {
        if !mailboxes.insert(mailbox.as_str()) {
            return Err(Error::Failed(format!(
                "the mailbox {mailbox} is named twice"
            )));
        }
    }
    for address in &intent.addresses {
        if let Some(why) = validate::address_localpart_shape(&address.address) {
            return Err(Error::Failed(format!(
                "the address {:?}: {why}",
                address.address
            )));
        }
        if !intent.mailboxes.iter().any(|m| m == &address.mailbox) {
            return Err(Error::Failed(format!(
                "the address {}@{} points at {}, which is not a mailbox",
                address.address, intent.domain, address.mailbox
            )));
        }
    }
    let mut seen = HashSet::new();
    for address in &intent.addresses {
        if !seen.insert(address.address.as_str()) {
            return Err(Error::Failed(format!(
                "the address {} is in the table twice",
                address.address
            )));
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
            return Err(Error::Failed(format!(
                "the mailbox {mailbox} has no mail key, so its mail would bounce"
            )));
        }
        if mine.len() > 1 {
            return Err(Error::Failed(format!(
                "the mailbox {mailbox} has {} keys; there is one key per mailbox",
                mine.len()
            )));
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

    let app_copy = application_copy(
        store,
        intent.application.status_token.as_deref().ok_or_else(|| {
            Error::Failed("the group intent names no application token".to_string())
        })?,
    )
    .await?;

    // Every account and its keyring entry first. The public publish is a network
    // call to the forge, and it runs in a second loop so a forge outage cannot
    // stand between a mailbox and the account that delivers to it.
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
    // The mail tables only after every account and keyring entry is in place.
    // provision-member.sh restarts smtpd inside the loop above, so a virtuals
    // line written first would make the rest of the group's addresses live while
    // their accounts and keys do not exist yet: mail to them would be accepted
    // and then bounce at LMTP. Written here, a partial failure exposes nothing,
    // and the restart below is what makes them live.
    ensure_group_domain(cfg, &intent.domain)?;
    for address in &intent.addresses {
        let entry = format!("{}@{}", address.address, intent.domain);
        ensure_table_line(&cfg.virtuals, &entry, Some(&address.mailbox))?;
        // The sender mapping: the mailbox may submit as the address it publishes,
        // and only as an address on its own line. deploy-mail.sh generates the
        // same shape for an address a virtuals entry delivers into.
        ensure_sender(&cfg.mail_from, &address.mailbox, &entry)?;
    }
    // One restart for the new route and for the filter's -d list, which the
    // script re-expands from dkim_domains before it checks the configuration.
    run_script(cfg, "reload-smtpd.sh", &[]).await?;
    // spamd reads the pass-through list at start and has no reload verb, so the
    // body's line is not live until it restarts. Without this, mail to a group
    // provisioned between deploys is still trapped and its senders blocklisted.
    run_script(cfg, "reload-spamd.sh", &[]).await?;

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
        let bytes = serde_json::to_vec_pretty(&join).map_err(|source| Error::Json {
            context: "encode the token record",
            source,
        })?;
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
async fn application_copy(store: &Store, token: &str) -> Result<Option<String>, Error> {
    let Some(text) = store.filed_application_text(token).await? else {
        return Ok(None);
    };
    let mut value: Value =
        serde_json::from_str(&text).map_err(|e| Error::context("the application record", e))?;
    value["status_link_until"] = json!(util::after_days(7));
    let bytes = serde_json::to_string_pretty(&value).map_err(|source| Error::Json {
        context: "encode the application copy",
        source,
    })?;
    Ok(Some(bytes))
}

/// One mailbox's copy of the application, when the application record is still
/// there. A retry rewrites the same bytes.
async fn write_group_application(
    store: &Store,
    mailbox: &str,
    copy: Option<&str>,
) -> Result<(), Error> {
    let Some(copy) = copy else {
        return Ok(());
    };
    store
        .ensure_dir_owned(
            &format!("accounts/{mailbox}"),
            0o750,
            store.dir_owner("accounts"),
        )
        .await?;
    store
        .write_record(
            &format!("accounts/{mailbox}"),
            "application.json",
            copy.as_bytes(),
        )
        .await
        .map_err(Error::from)
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
) -> Result<(), Error> {
    let existing = store.account(mailbox).await?;
    let now = util::filed_at();
    // A new mailbox gets its own one-time link; a retry keeps the token the
    // first pass wrote, because the mail that carries it may already have left.
    let password_link = match existing.as_ref().and_then(|a| a.password_link.clone()) {
        Some(link) => link,
        None => PasswordLink::fresh().await?,
    };
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
        password_link: Some(password_link),
        group: Some(domain.to_string()),
        closing_until: None,
        grace_until: None,
        notice_stopped: None,
    };
    let bytes = serde_json::to_vec_pretty(&account).map_err(|source| Error::Json {
        context: "encode the account",
        source,
    })?;
    store
        .ensure_dir_owned(
            &format!("accounts/{mailbox}"),
            0o750,
            store.dir_owner("accounts"),
        )
        .await?;
    write_account_record(store, mailbox, &bytes).await
}

/// Write one group's record. The caller owns the directory name, which is the
/// validated domain, so a record can never land outside `groups/`.
pub(super) async fn write_group_record(store: &Store, group: &GroupRecord) -> Result<(), Error> {
    let bytes = serde_json::to_vec_pretty(group).map_err(|source| Error::Json {
        context: "encode the group record",
        source,
    })?;
    store
        .ensure_dir_owned(
            &format!("groups/{}", group.domain),
            0o750,
            store.dir_owner("groups"),
        )
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
) -> Result<(), Error> {
    // The repair lives here, not only at creation: a directory an earlier build
    // left at 0700 must become readable on the next record write.
    store
        .ensure_dir_owned(
            &format!("accounts/{username}"),
            0o750,
            store.dir_owner("accounts"),
        )
        .await?;
    store
        .write_record_mode(
            &format!("accounts/{username}"),
            "account.json",
            bytes,
            store.dir_owner("accounts"),
            0o640,
        )
        .await
        .map_err(Error::from)
}

/// The same for a group's record, for the same reason: the account page of any
/// mailbox in the group reads it, and a root-only 0600 file would leave the
/// billing block blank.
pub(super) async fn write_group_state(
    store: &Store,
    domain: &str,
    bytes: &[u8],
) -> Result<(), Error> {
    store
        .ensure_dir_owned(
            &format!("groups/{domain}"),
            0o750,
            store.dir_owner("groups"),
        )
        .await?;
    store
        .write_record_mode(
            &format!("groups/{domain}"),
            "group.json",
            bytes,
            store.dir_owner("groups"),
            0o640,
        )
        .await
        .map_err(Error::from)
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
    fn acquire(path: &str) -> Result<TableLock, Error> {
        let dir = std::path::PathBuf::from(format!("{path}.lock"));
        let mut reaped = false;
        for attempt in 0..5 {
            match std::fs::create_dir(&dir) {
                Ok(()) => {
                    if let Err(e) =
                        std::fs::write(dir.join("pid"), format!("{}\n", std::process::id()))
                    {
                        let _ = std::fs::remove_dir_all(&dir);
                        return Err(Error::Failed(format!(
                            "cannot write the owner pid into {}: {e}",
                            dir.display()
                        )));
                    }
                    return Ok(TableLock { dir });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if !reaped {
                        if let Some(reason) = stale_table_lock(&dir) {
                            Error::Failed(reason)
                                .report(&format!("reaping stale lock {}", dir.display()));
                            let _ = std::fs::remove_dir_all(&dir);
                            reaped = true;
                            continue;
                        }
                    }
                }
                Err(e) => {
                    return Err(Error::Failed(format!("cannot lock {path}: {e}")));
                }
            }
            if attempt < 4 {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        Err(Error::Failed(format!(
            "could not lock {path}: {} exists and did not clear; remove it if no writer is running",
            dir.display()
        )))
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

/// The group's domain in the three tables that name it: smtpd's domain table,
/// the DKIM filter's list and spamd's greylist pass-through list. The last is
/// not a mail route: a destination domain absent from it is not greylisted, it
/// is trapped and the sender blocklisted, so the domain goes in with the other
/// two rather than waiting for an operator to notice. smtpd's configuration is
/// re-expanded from the DKIM list by the reload that follows.
fn ensure_group_domain(cfg: &DrainConfig, domain: &str) -> Result<(), Error> {
    ensure_table_line(&cfg.mail_domains, domain, None)?;
    ensure_table_line(&cfg.dkim_domains, domain, None)?;
    ensure_table_line(&cfg.spamd_alloweddomains, &format!("@{domain}"), None)
}

/// Ensure one line is in a virtual table: a bare value when `value` is `None`
/// (a `mail_domains` line), and `name: value` otherwise (a `virtuals` entry). A
/// key already present with the same value is left alone; one present with a
/// different value is a refusal, because overruling it would silently redirect
/// somebody's mail. Written through a temporary in the same directory, so smtpd
/// never reads half a table.
fn ensure_table_line(path: &str, name: &str, value: Option<&str>) -> Result<(), Error> {
    let _lock = TableLock::acquire(path)?;
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::context(
            format!("cannot read {path}; run scripts/deploy-mail.sh first"),
            e,
        )
    })?;
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
                    return Err(Error::Failed(format!(
                        "{path} already maps {name} to {}, not {want}",
                        have.trim()
                    )));
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
        .map_err(|e| Error::context(format!("cannot open {path}"), e))?;
    let mut entry = String::new();
    if !text.is_empty() && !text.ends_with('\n') {
        entry.push('\n');
    }
    entry.push_str(&line);
    entry.push('\n');
    std::io::Write::write_all(&mut file, entry.as_bytes())
        .map_err(|e| Error::context(format!("cannot append to {path}"), e))
}

/// The value a virtual table maps `name` to, or `None` when the key is absent.
fn table_value(path: &str, name: &str) -> Result<Option<String>, Error> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::context(
            format!("cannot read {path}; run scripts/deploy-mail.sh first"),
            e,
        )
    })?;
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
fn address_count(path: &str, domain: &str) -> Result<usize, Error> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::context(
            format!("cannot read {path}; run scripts/deploy-mail.sh first"),
            e,
        )
    })?;
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
fn write_table(path: &str, text: &str, _lock: &TableLock) -> Result<(), Error> {
    let candidate = format!("{path}.onboard.{}", std::process::id());
    std::fs::write(&candidate, text)
        .map_err(|e| Error::context(format!("cannot write {candidate}"), e))?;
    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| Error::context(format!("cannot set the mode on {candidate}"), e))?;
    std::fs::rename(&candidate, path)
        .map_err(|e| Error::context(format!("cannot replace {path}"), e))
}

/// Repoint an existing virtual entry, keeping every other line. A value that is
/// already right is left alone, so an upgrade intent applied twice changes
/// nothing. `ensure_table_line` refuses a different value on purpose (it must
/// not overrule a line somebody else made), so this is the explicit repoint.
///
fn repoint_table_line(path: &str, name: &str, want: &str) -> Result<(), Error> {
    let lock = TableLock::acquire(path)?;
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::context(
            format!("cannot read {path}; run scripts/deploy-mail.sh first"),
            e,
        )
    })?;
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
pub(super) fn remove_addresses(path: &str, domain: &str, mailbox: &str) -> Result<bool, Error> {
    let lock = TableLock::acquire(path)?;
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::context(
            format!("cannot read {path}; run scripts/deploy-mail.sh first"),
            e,
        )
    })?;
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

/// The addresses in a sender mapping line's value: comma-separated, trimmed,
/// with empty entries dropped.
fn sender_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect()
}

/// One sender mapping line in the shape deploy-mail.sh writes.
fn sender_line(account: &str, values: &[String]) -> String {
    format!("{account}: {}\n", values.join(","))
}

/// Add `address` to `account`'s list in the sender mapping, creating the line
/// when the account has none. A list that already names it is left alone, so a
/// retry changes nothing. The mapping is what the listeners' `senders` option
/// checks, so an address here is one this account may submit as.
fn ensure_sender(path: &str, account: &str, address: &str) -> Result<(), Error> {
    let lock = TableLock::acquire(path)?;
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::context(
            format!("cannot read {path}; run scripts/deploy-mail.sh first"),
            e,
        )
    })?;
    let mut out = String::new();
    let mut found = false;
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim() == account {
                found = true;
                let mut values = sender_values(value);
                if !values.iter().any(|v| v == address) {
                    values.push(address.to_string());
                }
                out.push_str(&sender_line(account, &values));
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if !found {
        out.push_str(&sender_line(account, &[address.to_string()]));
    }
    if out != text {
        write_table(path, &out, &lock)?;
    }
    Ok(())
}

/// Give `address` to `keep`'s line in the sender mapping and take it off every
/// other account's, which is what an upgraded address needs: the shared mailbox
/// it came from must stop submitting as it, and the new mailbox must start.
/// `keep` has no line yet on a first upgrade, so one is appended. Returns
/// whether the table changed.
fn repoint_sender(path: &str, address: &str, keep: &str) -> Result<bool, Error> {
    let lock = TableLock::acquire(path)?;
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::context(
            format!("cannot read {path}; run scripts/deploy-mail.sh first"),
            e,
        )
    })?;
    let mut out = String::new();
    let mut changed = false;
    let mut found = false;
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let mut values = sender_values(value);
            if key == keep {
                found = true;
                if !values.iter().any(|v| v == address) {
                    values.push(address.to_string());
                    changed = true;
                    out.push_str(&sender_line(key, &values));
                    continue;
                }
            } else if values.iter().any(|v| v == address) {
                values.retain(|v| v != address);
                changed = true;
                if values.is_empty() {
                    continue;
                }
                out.push_str(&sender_line(key, &values));
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if !found {
        out.push_str(&sender_line(keep, &[address.to_string()]));
        changed = true;
    }
    if changed {
        write_table(path, &out, &lock)?;
    }
    Ok(changed)
}

/// Drop every address on `domain` from `mailbox`'s sender line, dropping the
/// line when no address is left. Other accounts' lines and the mailbox's own
/// platform identity are untouched. Returns whether the table changed.
pub(super) fn remove_senders_for_domain(
    path: &str,
    domain: &str,
    mailbox: &str,
) -> Result<bool, Error> {
    let lock = TableLock::acquire(path)?;
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::context(
            format!("cannot read {path}; run scripts/deploy-mail.sh first"),
            e,
        )
    })?;
    let suffix = format!("@{domain}");
    let mut out = String::new();
    let mut changed = false;
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim() == mailbox {
                let values = sender_values(value);
                let kept: Vec<String> = values
                    .iter()
                    .filter(|v| !v.ends_with(&suffix))
                    .cloned()
                    .collect();
                if kept.len() != values.len() {
                    changed = true;
                }
                if !kept.is_empty() {
                    out.push_str(&sender_line(mailbox, &kept));
                }
                continue;
            }
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
pub(super) async fn name_held(store: &Store, username: &str) -> Result<Option<String>, Error> {
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

/// The account's application status token from its retained application copy,
/// where the copy is still there and readable. `None` leaves the journal prune
/// keeping token-bearing lines rather than guessing whose they are.
pub(super) async fn application_token(store: &Store, username: &str) -> Option<String> {
    let text = store
        .account_application_text(username)
        .await
        .ok()
        .flatten()?;
    let copy: Value = serde_json::from_str(&text).ok()?;
    copy.get("status_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
}

/// Hold a closed account's name for ninety days. Written only when there is no
/// live hold, so a retry keeps the date the removal first set rather than
/// pushing the release out by another pass.
///
/// The hold also records the account's application status token where the
/// account's copy still exists, which is what the journal prune uses to tell
/// this account's lines from another applicant who asks for the same name.
pub(super) async fn hold_name(store: &Store, username: &str) -> Result<(), Error> {
    if name_held(store, username).await?.is_some() {
        return Ok(());
    }
    let token = application_token(store, username).await;
    let mut hold = json!({
        "username": username,
        "until": util::after_days(90),
    });
    if let Some(token) = token {
        hold["token"] = json!(token);
    }
    let bytes = serde_json::to_vec_pretty(&hold).map_err(|source| Error::Json {
        context: "encode the hold",
        source,
    })?;
    store.ensure_dir("holds").await?;
    store
        .write_record("holds", &format!("{username}.json"), &bytes)
        .await
        .map_err(Error::from)
}

/// The three steps that close one mailbox: its name held for ninety days, its
/// stored upload key dropped, and scripts/delete-user.sh, which removes the box
/// account, its tree, its quota record and its store record. Shared by a
/// mailbox leaving a group and a whole group going, so the two cannot disagree
/// about what a closed account is. The caller removes the virtual entry first,
/// because it is the one that knows which table line belongs to the account.
async fn close_mailbox(cfg: &DrainConfig, store: &Store, username: &str) -> Result<(), Error> {
    hold_name(store, username).await?;
    store.remove("keys", &format!("{username}.pub")).await?;
    run_script(cfg, "delete-user.sh", &[username])
        .await
        .map_err(Error::from)
}

/// The mail key a new mailbox carries, checked before anything is written: the
/// material must be there and must be the mailbox's own key.
fn address_key(intent: &GroupAddressIntent) -> Result<KeyRecord, Error> {
    let Some(key) = intent.mail_key.as_ref() else {
        return Err(Error::Failed(format!(
            "the mailbox {} has no mail key, so its mail would bounce",
            intent.mailbox
        )));
    };
    if !key.mailbox.is_empty() && key.mailbox != intent.mailbox {
        return Err(Error::Failed(format!(
            "the mail key names {}, not {}",
            key.mailbox, intent.mailbox
        )));
    }
    if key.material.trim().is_empty() {
        return Err(Error::Failed(format!(
            "the mail key for {} is empty",
            intent.mailbox
        )));
    }
    // The console carries whatever file the operator named. A private key, an
    // SSH key or a truncated block would reach the encryptor's keyring and
    // fail closed, so the shared check refuses it before the journal line.
    let checked = kyriakon_control_core::mail::keycheck::pgp_public_key(&key.material)
        .map_err(|e| Error::context(format!("the mail key for {}", intent.mailbox), e))?;
    // The form and the rotation path refuse a key whose verdict is not "works";
    // the console is the same boundary, so an AEAD advert or an expiring subkey
    // cannot reach the keyring by this route.
    if let Some(why) = checked.refusal() {
        return Err(Error::Failed(format!(
            "the mail key for {} cannot be used: {why}",
            intent.mailbox
        )));
    }
    let mut key = key.clone();
    key.mailbox = intent.mailbox.clone();
    key.verdict = checked.verdict;
    // The signature covers the material, not the fingerprint beside it, so the
    // fingerprint is computed from the parsed key rather than trusted.
    key.fingerprint = kyriakon_control_core::mail::keycheck::pgp_fingerprint(&key.material)
        .ok_or_else(|| {
            Error::Failed(format!(
                "the mail key for {} has no fingerprint this build can derive",
                intent.mailbox
            ))
        })?;
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
    key: &[u8],
    intent: GroupAddressIntent,
) -> Result<Settlement, Error> {
    if intent.kind != "group-address" {
        return Err(Error::Failed(format!(
            "kind {:?} is not an address intent",
            intent.kind
        )));
    }
    if !ADDRESS_ACTIONS.contains(&intent.action.as_str()) {
        return Err(Error::Failed(format!(
            "{:?} is not an address change",
            intent.action
        )));
    }
    if let Some(why) = validate::domain(&intent.domain) {
        return Err(Error::Failed(format!(
            "the domain {:?}: {why}",
            intent.domain
        )));
    }
    let Some(mut group) = group_record(store, &intent.domain).await? else {
        // Settled, not failed: a signed address change left armed would land
        // on a later group on the same domain.
        return Ok(Settlement::refused(format!(
            "there is no group for {}, so there is no address to change",
            intent.domain
        )));
    };
    if let Some(why) = validate::username_shape(&intent.mailbox) {
        return Err(Error::Failed(format!(
            "the mailbox {:?}: {why}",
            intent.mailbox
        )));
    }
    if intent.action != "remove" {
        if let Some(why) = validate::address_localpart_shape(&intent.address) {
            return Err(Error::Failed(format!(
                "the address {:?}: {why}",
                intent.address
            )));
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
                return Err(Error::Failed(format!(
                    "the alias {}@{} points at {}, which is not a mailbox in the group",
                    intent.address, intent.domain, intent.mailbox
                )));
            }
            match &current {
                Some(have) if have == &intent.mailbox => {}
                Some(have) => {
                    return Err(Error::Failed(format!(
                        "{} already maps {entry} to {have}, not {}",
                        cfg.virtuals, intent.mailbox
                    )))
                }
                None if address_count(&cfg.virtuals, &intent.domain)? >= 10 => {
                    return Err(Error::Failed(format!(
                        "{} already carries ten addresses, so {entry} cannot be added",
                        intent.domain
                    )))
                }
                None => {}
            }
        }
        "add-mailbox" => {
            address_key(&intent)?;
            if let Some(have) = &current {
                if have != &intent.mailbox {
                    return Err(Error::Failed(format!(
                        "{} already maps {entry} to {have}, not {}",
                        cfg.virtuals, intent.mailbox
                    )));
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
                return Err(Error::Failed(format!(
                    "{} already carries ten addresses, so {} cannot be added",
                    intent.domain, entry
                )));
            }
        }
        "upgrade" => {
            address_key(&intent)?;
            match &current {
                None => {
                    return Err(Error::Failed(format!(
                        "{} is not an address in {}, so there is no alias to upgrade",
                        entry, intent.domain
                    )))
                }
                Some(have) if have == &intent.mailbox => {}
                Some(have) => {
                    if !in_group(have) {
                        return Err(Error::Failed(format!(
                            "{} points at {have}, which is not a mailbox in the group",
                            entry
                        )));
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
                    return Err(Error::Failed(format!(
                        "{} owns the site, so the intent must name the account that takes it",
                        intent.mailbox
                    )));
                };
                if replacement == intent.mailbox || !in_group(replacement) {
                    return Err(Error::Failed(format!(
                        "the replacement site owner {replacement} is not another mailbox in the group"
                    )));
                }
            }
            let existing = store.account(&intent.mailbox).await?;
            let ours = existing
                .as_ref()
                .map(|a| a.group.as_deref() == Some(intent.domain.as_str()))
                .unwrap_or(false);
            if !in_group(&intent.mailbox) && !ours && account_on_box(cfg, &intent.mailbox)? {
                return Err(Error::Failed(format!(
                    "the account {} is not a mailbox in {}",
                    intent.mailbox, intent.domain
                )));
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
            ensure_sender(&cfg.mail_from, &intent.mailbox, &entry)?;
            // smtpd reads the tables at start and has no reload verb, so the
            // alias neither delivers nor submits until it restarts. The script
            // also re-expands the filter's -d list from dkim_domains.
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
            ensure_sender(&cfg.mail_from, &intent.mailbox, &entry)?;
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
            // The sender identity moves with the route: off the shared
            // mailbox's line and onto the new mailbox's, which may have no line
            // yet on a first upgrade.
            repoint_sender(&cfg.mail_from, &entry, &intent.mailbox)?;
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
                let replacement = intent.site_owner.as_deref().ok_or_else(|| {
                    Error::Failed("the site owner is leaving without a replacement".to_string())
                })?;
                let old_key = store
                    .read_record("keys", &format!("{}.pub", intent.mailbox))
                    .await;
                if let Some(material) = &old_key {
                    write_public_key(store, replacement, material).await?;
                }
                run_script(cfg, "provision-member.sh", &[replacement]).await?;
                // The vhosts root at the site owner's tree, and
                // `cron-apply.sh --web` rewrites only the indexes: without the
                // lanes the new root is never written and the old one is
                // deleted with the departing account. They run before the
                // record is written, so a retry after a lane refusal repeats
                // them; a group with no upload key has no tree and the lanes
                // would refuse.
                if old_key.is_some() {
                    for lane in [
                        "provision-group-web.sh",
                        "provision-group-capsule.sh",
                        "provision-group-acme.sh",
                    ] {
                        run_script(cfg, lane, &[&intent.domain, replacement]).await?;
                    }
                }
                group.site_owner = replacement.to_string();
            }
            group.accounts.retain(|a| a != &intent.mailbox);
            write_group_record(store, &group).await?;
            let routes_changed = remove_addresses(&cfg.virtuals, &intent.domain, &intent.mailbox)?;
            // The sender identities go with the routes: an address left on the
            // mailbox's line after it has gone still lets it submit.
            let senders_changed =
                remove_senders_for_domain(&cfg.mail_from, &intent.domain, &intent.mailbox)?;
            if routes_changed || senders_changed {
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

    // A mailbox an address change makes has no approval mail to carry its link,
    // and no status page of its own to render one, so the mail is the whole
    // delivery: without it the token sits in the account unread and the member
    // cannot set a password. After the arm, so every step that can fail has.
    if matches!(intent.action.as_str(), "add-mailbox" | "upgrade") {
        mail_password_link(cfg, store, key, &group, &intent.mailbox).await?;
    }

    Ok(Settlement::line("applied", application, None))
}

/// Mail one mailbox's one-time password link to the group's contact, the same
/// recipient and account-copy lookup every other group notice uses. A retry
/// mails nothing: the subject is fixed by the mailbox, and the account keeps the
/// token the first pass wrote.
async fn mail_password_link(
    cfg: &DrainConfig,
    store: &Store,
    key: &[u8],
    group: &GroupRecord,
    mailbox: &str,
) -> Result<(), Error> {
    let account = store
        .account(mailbox)
        .await?
        .ok_or_else(|| Error::Failed(format!("the mailbox {mailbox} has no account record")))?;
    let Some(link) = account.password_link else {
        return Ok(());
    };
    let url = kyriakon_control_core::account::sign::password_link(
        &cfg.base_url,
        key,
        &link.token,
        mailbox,
        &link.until,
    )?;
    let to = dns_contact(store, group).await?;
    let subject = format!("Set the mail password for {mailbox}@{}", group.domain);
    let body = format!(
        "{mailbox}@{domain} is ready to receive mail. Set its mail password from this \
         one-time link. It works once, until {until}:\n\n{url}\n\nIf you did not ask for \
         this, write to admin@kyriakon.net and do not use the link.\n",
        domain = group.domain,
        until = link.until
    );
    notice::send_account_notice_retryable(
        cfg,
        store,
        mailbox,
        "password.link",
        &subject,
        &to,
        &body,
    )
    .await?;
    Ok(())
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
) -> Result<Settlement, Error> {
    if intent.kind != "remove-group" {
        return Err(Error::Failed(format!(
            "kind {:?} is not a remove-group intent",
            intent.kind
        )));
    }
    if let Some(why) = validate::domain(&intent.domain) {
        return Err(Error::Failed(format!(
            "the domain {:?}: {why}",
            intent.domain
        )));
    }
    if let Some(reason) = body_domain_refusal(cfg, &intent.domain).await? {
        return Ok(Settlement::refused(reason));
    }

    let Some(group) = group_record(store, &intent.domain).await? else {
        // A refusal, not a failure: there is nothing to retry, and a signed
        // removal left armed would take a new group on this domain down later.
        return Ok(Settlement::refused(format!(
            "there is no group for {}",
            intent.domain
        )));
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
) -> Result<(), Error> {
    run_script(cfg, "remove-group.sh", &[domain]).await?;
    run_script(cfg, "cron-apply.sh", &["--web"]).await?;
    let Some(group) = group_record(store, domain).await? else {
        return Ok(());
    };
    // The body's subscription stops before its token goes: the token is the
    // record that names the card, and a removed body must not be billed again.
    cancel_stripe_if_active(cfg, &group.payment.stripe).await?;
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
pub(super) async fn remove_group_record(store: &Store, domain: &str) -> Result<(), Error> {
    let dir = store.path(&format!("groups/{domain}"));
    match tokio::fs::remove_dir_all(&dir).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Failed(format!(
            "cannot remove {}: {e}",
            dir.display()
        ))),
    }
}

/// Drop every token index entry that resolves to one of the group's accounts,
/// so the ledger rows keyed by those tokens no longer name an account. The scan
/// is by `TokenRecord.username` rather than by the filename, because the
/// directory also holds tokens that are not these accounts' and the record is
/// what says whose one is.
pub(super) async fn close_group_tokens(store: &Store, accounts: &[String]) -> Result<(), Error> {
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
pub(super) fn account_on_box(cfg: &DrainConfig, username: &str) -> Result<bool, Error> {
    let text = std::fs::read_to_string(&cfg.passwd)
        .map_err(|e| Error::context(format!("cannot read {}", cfg.passwd), e))?;
    Ok(text
        .lines()
        .any(|line| line.split(':').next() == Some(username)))
}

/// The names the platform holds back, read from the path the config names.
///
/// Read where it is used rather than held for the pass: it is a short file, read
/// at most twice a minute by a cron job, and a read that fails must refuse the
/// work rather than let it through on an empty list.
async fn reserved_names(cfg: &DrainConfig) -> Result<HashSet<String>, Error> {
    Ok(validate::reserved(&Store::read_text(&cfg.reserved).await?))
}

/// Refuse a username the platform holds back, naming it. Both gates that can
/// create an account go through this: the filing, and the approval.
///
/// The name is in the message because a failed pass is journalled against an
/// empty application and mailed to the operator, so the message is the only
/// place either of them can read which name was refused.
pub(super) async fn name_allowed(cfg: &DrainConfig, username: &str) -> Result<(), Error> {
    let reserved = reserved_names(cfg).await?;
    match validate::username(username, &reserved) {
        None => Ok(()),
        Some(why) => Err(Error::Failed(format!("the username {username}: {why}"))),
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
) -> Result<(), Error> {
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
    use kyriakon_control_core::account::sign;
    use kyriakon_control_core::store::GroupIntent;
    use serde_json::json;

    /// The form accepts a tab between `alias` and its target, and the drain
    /// reads the same line through the same parser, so both verdicts agree.
    #[test]
    fn a_tab_after_alias_names_the_same_mailbox_as_a_space() {
        let record = |addresses: &str| Record {
            username: "warden".into(),
            status_token: "abcdefghjkmnpqrstvwxyz0123".into(),
            filed_at: "2026-10-02T09:00:00Z".into(),
            front_end: "web".into(),
            stage: "received".into(),
            decided_at: None,
            password_link: None,
            domain: Some("parish.example".into()),
            outside_address: None,
            payment: None,
            answers: std::collections::BTreeMap::from([
                ("body_addresses".to_string(), addresses.to_string()),
                (
                    "body_account_names".to_string(),
                    "secretary\nhall".to_string(),
                ),
            ]),
            mail_keys: Vec::new(),
            upload_key: None,
            rail: "cash".into(),
            no_charge: false,
            confirmation_at: None,
            acceptances: Vec::new(),
            question_list: "test".into(),
        };
        let (tabs, mailboxes) =
            group_addresses(&record("secretary: own\noffice: alias\tsecretary")).unwrap();
        let (spaces, _) =
            group_addresses(&record("secretary: own\noffice: alias secretary")).unwrap();
        let pairs = |a: &[GroupAddress]| {
            a.iter()
                .map(|x| (x.address.clone(), x.mailbox.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(pairs(&tabs), pairs(&spaces));
        assert_eq!(
            pairs(&tabs),
            [
                ("secretary".to_string(), "secretary".to_string()),
                ("office".to_string(), "secretary".to_string()),
            ]
        );
        assert_eq!(mailboxes, ["secretary"]);
    }

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

    /// Provisioning writes the body's domain to every table that names it, and
    /// the spamd line is at-prefixed: a destination absent from that file is
    /// trapped rather than greylisted. The second pass is a retry, so it must
    /// add no duplicate, and the header comment and the platform's own line
    /// stay where they were.
    #[test]
    fn a_group_domain_lands_in_the_spamd_allow_list_once() {
        let dir = std::env::temp_dir().join(format!("onboard-group-tables-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = crate::transitions::test_support::quota_config(&dir);
        std::fs::write(&cfg.mail_domains, "kyriakon.net\n").unwrap();
        std::fs::write(&cfg.dkim_domains, "kyriakon.net\n").unwrap();
        std::fs::write(
            &cfg.spamd_alloweddomains,
            "# greylist pass-through\n@kyriakon.net\n",
        )
        .unwrap();

        ensure_group_domain(&cfg, "parish.example").unwrap();
        ensure_group_domain(&cfg, "parish.example").unwrap();

        assert_eq!(
            std::fs::read_to_string(&cfg.mail_domains).unwrap(),
            "kyriakon.net\nparish.example\n"
        );
        assert_eq!(
            std::fs::read_to_string(&cfg.dkim_domains).unwrap(),
            "kyriakon.net\nparish.example\n"
        );
        assert_eq!(
            std::fs::read_to_string(&cfg.spamd_alloweddomains).unwrap(),
            "# greylist pass-through\n@kyriakon.net\n@parish.example\n"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The sender mapping is per account, which is what closes the spoofing gap:
    /// an address added for one account never appears on another's line, an
    /// upgrade takes it off the old line rather than leaving two claims, and a
    /// body leaving empties or drops the line that held its addresses.
    #[test]
    fn the_sender_mapping_keeps_each_account_to_its_own_addresses() {
        let dir = std::env::temp_dir().join(format!("onboard-senders-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let table = dir.join("mail_from");
        std::fs::write(
            &table,
            "alice: alice@kyriakon.net\nbob: bob@kyriakon.net\ncarol: office@parish.example\n",
        )
        .unwrap();
        let path = table.to_str().unwrap();
        let read = || std::fs::read_to_string(&table).unwrap();

        ensure_sender(path, "alice", "secretary@parish.example").unwrap();
        ensure_sender(path, "alice", "secretary@parish.example").unwrap();
        assert_eq!(
            read(),
            "alice: alice@kyriakon.net,secretary@parish.example\nbob: bob@kyriakon.net\ncarol: office@parish.example\n"
        );
        assert!(
            !read().contains("bob: bob@kyriakon.net,secretary@"),
            "one account's address landed on another's line: {}",
            read()
        );

        // An upgrade moves the address to a mailbox that has no line yet; the
        // old line must not keep a claim.
        assert!(repoint_sender(path, "secretary@parish.example", "dave").unwrap());
        assert_eq!(
            read(),
            "alice: alice@kyriakon.net\nbob: bob@kyriakon.net\ncarol: office@parish.example\ndave: secretary@parish.example\n"
        );

        // A body leaving takes its addresses out, dropping a line left empty.
        assert!(remove_senders_for_domain(path, "parish.example", "dave").unwrap());
        assert!(!remove_senders_for_domain(path, "parish.example", "dave").unwrap());
        assert_eq!(
            read(),
            "alice: alice@kyriakon.net\nbob: bob@kyriakon.net\ncarol: office@parish.example\n"
        );
        assert!(remove_senders_for_domain(path, "parish.example", "carol").unwrap());
        assert_eq!(read(), "alice: alice@kyriakon.net\nbob: bob@kyriakon.net\n");
        std::fs::remove_dir_all(&dir).unwrap();
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
