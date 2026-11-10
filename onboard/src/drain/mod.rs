//! The intent loop: what makes a filed application move.
//!
//! Every pass reads `intents/*.json` in ULID order, which is the order they
//! were filed, revalidates each one, appends the journal line before carrying
//! the transition out, and deletes the intent file once it is done. An intent
//! whose kind this build does not implement is refused by name and left in
//! place, never silently dropped: a kind added by a later ticket waits here
//! until the ticket that understands it lands.
//!
//! One type is the contract between the handler's directory and the drain's
//! root work: [`Intent`]. Its variant carries the payload, [`Intent::verify`]
//! says how the intent is authenticated, and [`Intent::apply`] carries it out.
//! `verify`'s match has no catch-all, so a verb cannot ship without answering
//! how it is proved, the hole `provision-group` came through before #506.
//!
//! The wire payloads, [`DECISIONS`] and the rail constants live here too, beside
//! [`Intent`]: the enum and the shape it deserialises are one contract.

pub mod mailbox;
pub mod prepaid;
pub mod transitions;

use serde_json::Value;
use time::OffsetDateTime;

use crate::account::sign;
use crate::config::DrainConfig;
use crate::store::journal::Journal;
use crate::store::{ApplicationRef, GroupAddressIntent, GroupIntent, GroupRemoveIntent, Store};

/// The rails an application may name. `no_charge` is the fourth, and it is a
/// rail rather than a flag because it is one of the four buttons on the form.
pub(crate) const RAILS: [&str; 4] = ["card", "cash", "monero", "no_charge"];

/// The address changes a `group-address` intent carries. The console's
/// `--action` takes one of these and the drain refuses any other.
pub const ADDRESS_ACTIONS: [&str; 4] = ["add-alias", "add-mailbox", "upgrade", "remove"];

/// One of the three decisions a reviewer can make.
pub struct Decision {
    /// The word the console takes and a decision link carries, and the action
    /// the signature covers.
    pub action: &'static str,
    /// The intent kind the drain dispatches on.
    pub kind: &'static str,
    /// The words the operator reads, in the review email and on the confirm page
    /// a link opens.
    pub label: &'static str,
}

/// The three decisions, as one list. Everything that names one takes its words
/// from here: the console's verb, the intent's kind, the action the signature
/// covers and the label the operator reads. They were four tables in four
/// places, which is how a decision comes to be added in one of them and refused
/// by another after the reviewer has already made it.
pub const DECISIONS: [Decision; 3] = [
    Decision {
        action: "approve",
        kind: "approve",
        label: "approve, with the charge",
    },
    Decision {
        action: "approve-free",
        kind: "provision",
        label: "approve, without charge",
    },
    Decision {
        action: "decline",
        kind: "decline",
        label: "decline",
    },
];

/// The decision a console verb or a link named, by the word it carries.
pub fn decision_for(action: &str) -> Option<&'static Decision> {
    DECISIONS.iter().find(|d| d.action == action)
}

/// The decision an intent carries, by its kind.
pub fn decision_for_kind(kind: &str) -> Option<&'static Decision> {
    DECISIONS.iter().find(|d| d.kind == kind)
}

/// A reviewer's decision intent, from `kyriakon-onboardctl` or a signed link.
/// Every
/// decision intent carries the action it performs and the signature over it: the
/// directory it is read from belongs to the unprivileged half, so an unsigned
/// decision would be root work driven by a file any writer of `intents/` could
/// leave. `kyriakon-onboardctl` signs with the same root-only key the links use.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct DecisionIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub application: ApplicationRef,
    /// `approve`, `approve-free` or `decline`, and it must match the kind.
    pub action: String,
    /// The HMAC-SHA256 of `decide:<status_token>:<action>` under the approval
    /// key.
    pub sig: String,
}

/// A password set through the member's one-time link. Everything the drain needs
/// to check it is here, including the signature: the handler holds no key, so
/// the link's signature is the proof and the drain is the half that checks it.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct PasswordIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub application: ApplicationRef,
    /// The date the link carried. In the signed payload, never beside it.
    pub until: String,
    pub sig: String,
    /// The plaintext the member typed, hashed here and nowhere else. An intent
    /// carrying a `hash` is refused rather than parsed, so the handler cannot
    /// choose the stored hash; defaulted so that refusal is reached with the
    /// hash check's own reason rather than a serde error.
    #[serde(default)]
    pub password: String,
}

/// The `token-resend` intent: the member's payment instructions again, and
/// nothing minted. It carries the token the account already holds, so the drain
/// can check the account before it sends, and the console's signature, because
/// `intents/` belongs to the unprivileged half and a second copy of the
/// instructions is not the handler's to file.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct ResendIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub username: String,
    pub token: String,
    pub sig: String,
}

/// A `close` intent: the member's own "Close my account", filed by the handler
/// after it authenticated them. It names the account and nothing else, because
/// the drain owns the state write and the seven-day window; the handler holds no
/// privilege to set either.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CloseIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub username: String,
    /// The id of the page session that filed this. The drain reads
    /// `sessions/<id>.json` and refuses the intent when the record names another
    /// account or the session has expired.
    #[serde(default)]
    pub session: String,
}

/// An `export` intent: the page's "Take my data out", filed by the handler with
/// the account and the session that asked for it and nothing else. The drain
/// proves the session before it writes the bundle as root.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ExportIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub username: String,
    #[serde(default)]
    pub session: String,
}

/// A `change-password` intent: the new mail password as the member typed it,
/// hashed by the drain and nowhere else. The handler re-checked the current
/// password through `doveadm auth test`; the drain re-proves the session before
/// it writes the hash as root, because `intents/` belongs to the unprivileged
/// half. A `hash` field is refused: it is the old shape, where the handler chose
/// what was stored.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ChangePasswordIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub username: String,
    pub session: String,
    #[serde(default)]
    pub password: String,
}

/// An `upload-key` intent: the one key that serves sftp and git, added or
/// removed. The fingerprint is the handler's reading of the material, and the
/// drain recomputes it rather than trusting the intent.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct UploadKeyIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub username: String,
    pub session: String,
    pub action: String,
    /// A bare OpenSSH public key line, for `add`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub material: String,
    /// The key to remove, for `remove`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
}

/// An `outside-address` intent: the contact and recovery address, changed or
/// cleared. An empty address removes it.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct OutsideAddressIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub username: String,
    pub session: String,
    #[serde(default)]
    pub address: String,
}

/// A `serving` intent: the two independent booleans the page's toggles move.
/// The drain writes the account's state, removes or regenerates the member's
/// generated include and reloads the daemons.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ServingIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub username: String,
    pub session: String,
    pub http: bool,
    pub gemini: bool,
}

/// A `cancel-renewal` intent: stop the card subscription's yearly renewal. The
/// prepaid rails have no processor and nothing to cancel, so the handler only
/// files this for a card account with an attached subscription.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CancelRenewalIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub username: String,
    pub session: String,
}

/// A `mail-key` intent: replace the mail key, or cancel a replacement already
/// waiting. A replacement signed by the current key applies at once; one that is
/// not waits out the 72-hour window, which the page can cancel.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct MailKeyIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub username: String,
    pub session: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub material: String,
    /// An armored detached signature over the new key's fingerprint, made with
    /// the current key. Empty means the request is not signed.
    #[serde(default)]
    pub signature: String,
}

/// A manual credit: one payment recorded against the token its account holds.
/// The console resolves a `--username` to that token before filing, and this
/// carries the token, the rail, the money, the day the money arrived and the
/// override reason when the operator gave one. The signature covers all of it,
/// because the intent moves a paid-until date and `intents/` belongs to the
/// unprivileged half.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CreditIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub token: String,
    pub rail: String,
    pub amount_gbp: String,
    pub received: String,
    #[serde(default)]
    pub txid: Option<String>,
    #[serde(default)]
    pub amount_xmr: Option<String>,
    #[serde(default)]
    pub confirm_double: bool,
    #[serde(default)]
    pub override_reason: Option<String>,
    /// What the operator wrote down about a payment that carries no token. Free
    /// text, so it is signed last and never read as a field.
    #[serde(default)]
    pub note: Option<String>,
    pub sig: String,
}

/// A `reconcile-attribute` intent: the held item and the token it is joined to.
/// The console signs it, because the transition writes a paid-until date and
/// `intents/` belongs to the unprivileged half.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct AttributeIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    /// The `UN-` id of the line in `ledger/unattributed.jsonl`.
    pub item: String,
    /// The payment token the held money is joined to.
    pub token: String,
    /// A renewal: the token already has a paid-until date, and the operator has
    /// said this held payment is another year's money.
    #[serde(default)]
    pub confirm_double: bool,
    /// The override reason for a credit that would pass the 24-month ceiling,
    /// as the corresponding credit flag carries it.
    #[serde(default)]
    pub override_reason: Option<String>,
    pub sig: String,
}

/// A `reconcile-return` intent: the held item and the evidence it went back or
/// was kept. The evidence is free text and signed last.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ReturnIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub item: String,
    pub note: String,
    pub sig: String,
}

/// A refund: one negative ledger line naming the payment it reverses, or a
/// settlement of one already recorded. The console resolves a `--username` to
/// the account's token before filing, and this carries the token, the money, the
/// rail, the reason and the `--close`/`--excess` choice. A settlement carries
/// only `settled_on`. The signature covers all of it, because the intent writes
/// the ledger and closes an account, and `intents/` belongs to the unprivileged
/// half.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct RefundIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub token: String,
    #[serde(default)]
    pub amount_gbp: Option<String>,
    #[serde(default)]
    pub rail: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub close: bool,
    #[serde(default)]
    pub excess: bool,
    /// `--rate`, the sterling price of one XMR on the refund date, when the
    /// member asked for sterling rather than the recorded XMR back.
    #[serde(default)]
    pub rate: Option<String>,
    /// The day the refund was paid out, for the settlement form.
    #[serde(default)]
    pub settled_on: Option<String>,
    pub sig: String,
}

/// A `window-extend` intent: the one extension a member with money in the post
/// is given. The token, the days and the operator's reason are signed, because
/// the intent moves the date the account lapses on and `intents/` belongs to the
/// unprivileged half.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct WindowExtendIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub token: String,
    pub days: i64,
    pub reason: String,
    pub sig: String,
}

/// The rails a refund may name. A refund never leaves on a rail the payment did
/// not arrive on, and the check is the original line's own rail.
pub const REFUND_RAILS: [&str; 4] = ["card", "cash", "cash-hand", "monero"];

pub const CREDIT_RAILS: [&str; 3] = ["cash", "cash-hand", "monero"];

/// One pass: every intent, then the sweeps. The drain is a single short-lived
/// process with no listener, so there is no loop inside it; cron runs it again
/// a minute later.
pub async fn run(cfg: &DrainConfig, store: &Store) -> Result<(), String> {
    // Read once for the whole pass: every dedup, backoff and recovery query
    // below asks this index rather than opening the file again, and an
    // unreadable journal is an error here rather than an empty one (#513).
    let journal = Journal::load(store).await?;
    // Read once, before anything is done: the review email's links are signed
    // with it. A missing or unreadable key is a misconfigured box, and it is
    // mailed once rather than on every pass.
    let key = match sign::read_key(std::path::Path::new(&cfg.approval_key)) {
        Ok(k) => k,
        Err(e) => {
            transitions::report_failure(cfg, store, &journal, "config", "config", &e).await;
            return Ok(());
        }
    };
    // The rate cache first, so a window opening later in this pass quotes from
    // it. It asks the source only when the cache is more than a day old, and a
    // failure is not the pass's: a stale cache is exactly what the quote falls
    // back to.
    let _ = crate::payments::xmr::current(cfg, OffsetDateTime::now_utc()).await;
    // The filenames are ULIDs, so a lexical sort is an age sort.
    for name in store.list("intents").await? {
        if !name.ends_with(".json") {
            continue;
        }
        let id = name.trim_end_matches(".json");
        // A failing intent backs off rather than being retried every minute, and
        // its error is mailed once rather than on every pass.
        if !transitions::due(&journal, id, OffsetDateTime::now_utc()) {
            continue;
        }
        if let Err(e) = one(cfg, store, &journal, &key, &name).await {
            transitions::report_failure(cfg, store, &journal, id, "intent", &e).await;
        }
    }
    // The login proofs are root's, so this is the half that clears the expired
    // ones; the handler cannot read the directory and does not try. After the
    // intents, so a close or export filed with a session that has just run out
    // reads as expired rather than as a missing proof.
    crate::account::session::prune_proofs(
        std::path::Path::new(&cfg.proof_dir),
        OffsetDateTime::now_utc(),
    )
    .await;
    transitions::lifecycle::purge_declined(cfg, store, &journal).await?;
    transitions::lifecycle::purge_closing(cfg, store, &journal).await?;
    // The free accounts' yearly note, on the same pass: a free account never
    // lapses, and this is the one message it is sent each year.
    transitions::lifecycle::free_anniversaries(cfg, store, &journal).await?;
    // The prepaid member's own renewal note, thirty days before the date runs
    // out: the rails with no processor have nobody else to send one.
    transitions::lifecycle::prepaid_renewals(cfg, store, &journal).await?;
    // The space used, from the filesystem quota the handler cannot read. Due
    // gated to once an hour, so most passes do no quota work.
    transitions::lifecycle::refresh_space_used(cfg, store, &journal).await?;
    // A mail-key replacement whose 72-hour window has closed applies here, on
    // the same pass its record is read.
    transitions::lifecycle::mail_key_rotations(cfg, store, &journal).await?;
    // A payment window whose day has passed either finds its credit and stays
    // active, or lapses the account and starts the grace. One sweep, so a
    // member who paid on the last day is not lapsed by a later pass.
    transitions::lifecycle::window_sweep(cfg, store, &journal).await?;
    // A lapsed account's grace: the final notice at day 33, and the one
    // deletion transition when the 40 days end.
    transitions::lifecycle::grace_sweep(cfg, store, &journal).await?;
    // The key spool is read after the intents so a filed application is not
    // waiting behind a mailbox pass. The pass handles each message on its own:
    // one that cannot be dealt with is reported and left for the next run.
    crate::drain::mailbox::run(cfg, store, &journal).await?;
    // The groups' own zones are watched last: a record that has stopped
    // resolving is the one thing about a body's domain the platform can see and
    // cannot repair, and it must not delay a filed application or a member's
    // mail. It is due-gated, so most passes do no DNS work.
    transitions::lifecycle::check_group_dns(cfg, store, &journal).await?;
    // The card rail's arriving events are settled after everything else: a
    // misconfigured signing secret must not hold up an approval, and an event
    // that cannot be applied yet is left for the next pass.
    transitions::stripe::stripe_webhooks(cfg, store, &journal).await
}

/// One intent file, deserialised once into its variant, proved, then applied.
async fn one(
    cfg: &DrainConfig,
    store: &Store,
    journal: &Journal,
    key: &[u8],
    file: &str,
) -> Result<(), String> {
    // The listing is one snapshot, and a pass can delete a file another name in
    // that snapshot shares: an approval writes and applies its group intent in
    // the same pass, then removes it. A file that is gone reads as done, the
    // same rule store.remove uses, rather than as a failure the reviewer is
    // mailed about.
    let Some(text) = store.read_record("intents", file).await else {
        return Ok(());
    };
    let value: Value =
        serde_json::from_str(&text).map_err(|e| format!("the intent does not parse: {e}"))?;
    let intent = Intent::parse(&value)?;
    intent.run(cfg, store, journal, key, file, &value).await
}

/// One intent: the variant carries the payload, and the file it was read from
/// carries what the refusal paths need to rewrite or journal it.
///
/// Parsing is by `kind` and lives here, once: the transition a variant applies
/// takes the parsed payload, so no verb can be reached with a shape its own
/// verifier has not looked at.
#[derive(serde::Serialize)]
#[serde(untagged)]
pub enum Intent {
    Application(crate::store::Intent),
    Decision(DecisionIntent),
    Password(PasswordIntent),
    ProvisionGroup(Box<GroupIntent>),
    GroupAddress(GroupAddressIntent),
    RemoveGroup(GroupRemoveIntent),
    Close(CloseIntent),
    Resend(ResendIntent),
    Credit(CreditIntent),
    WindowExtend(WindowExtendIntent),
    ReconcileAttribute(AttributeIntent),
    ReconcileReturn(ReturnIntent),
    Refund(RefundIntent),
    Export(ExportIntent),
    ChangePassword(ChangePasswordIntent),
    UploadKey(UploadKeyIntent),
    OutsideAddress(OutsideAddressIntent),
    Serving(ServingIntent),
    CancelRenewal(CancelRenewalIntent),
    MailKey(MailKeyIntent),
    /// A kind this build does not implement, carried as it was read: `verify`
    /// refuses it by name and leaves the file where a later ticket finds it.
    Unknown {
        kind: String,
        value: Value,
    },
}

impl Intent {
    /// The intent this file holds, by its `kind`. A kind this build does not
    /// implement is `Unknown` rather than an error, because it is left in place
    /// for the release that understands it.
    ///
    /// The parse error keeps the message the verb's own reader used, so a
    /// malformed intent is reported with the same words it always was.
    pub fn parse(value: &Value) -> Result<Intent, String> {
        let kind = value.get("kind").and_then(Value::as_str).unwrap_or("");
        let intent = match kind {
            "application" => Intent::Application(parsed(value, "the intent")?),
            "approve" | "provision" | "decline" => {
                Intent::Decision(parsed(value, "the decision intent")?)
            }
            "set-password" => Intent::Password(parsed(value, "the password intent")?),
            "provision-group" => {
                Intent::ProvisionGroup(Box::new(parsed(value, "the group intent")?))
            }
            "group-address" => Intent::GroupAddress(parsed(value, "the address intent")?),
            "remove-group" => Intent::RemoveGroup(parsed(value, "the remove-group intent")?),
            "close" => Intent::Close(parsed(value, "the close intent")?),
            "token-resend" => Intent::Resend(parsed(value, "the token resend intent")?),
            "credit" => Intent::Credit(parsed(value, "the credit intent")?),
            "window-extend" => Intent::WindowExtend(parsed(value, "the window extension intent")?),
            "reconcile-attribute" => {
                Intent::ReconcileAttribute(parsed(value, "the reconcile-attribute intent")?)
            }
            "reconcile-return" => {
                Intent::ReconcileReturn(parsed(value, "the reconcile-return intent")?)
            }
            "refund" => Intent::Refund(parsed(value, "the refund intent")?),
            "export" => Intent::Export(export_from(value)?),
            "change-password" => Intent::ChangePassword(parsed(value, "the password intent")?),
            "upload-key" => Intent::UploadKey(parsed(value, "the upload key intent")?),
            "outside-address" => Intent::OutsideAddress(parsed(value, "the address intent")?),
            "serving" => Intent::Serving(parsed(value, "the serving intent")?),
            "cancel-renewal" => Intent::CancelRenewal(parsed(value, "the renewal intent")?),
            "mail-key" => Intent::MailKey(parsed(value, "the mail key intent")?),
            other => Intent::Unknown {
                kind: other.to_string(),
                value: value.clone(),
            },
        };
        Ok(intent)
    }

    /// The `kind` this variant is filed under and parsed from. The writer stamps
    /// it, so a caller cannot file a `Close` under a verb it is not, and the
    /// round-trip test walks every variant through it.
    pub fn kind(&self) -> &str {
        match self {
            Intent::Application(_) => "application",
            // The three decisions are kinds of their own: `approve`, `provision`
            // and `decline` are what the dispatcher reads.
            Intent::Decision(intent) => &intent.kind,
            Intent::Password(_) => "set-password",
            Intent::ProvisionGroup(_) => "provision-group",
            Intent::GroupAddress(_) => "group-address",
            Intent::RemoveGroup(_) => "remove-group",
            Intent::Close(_) => "close",
            Intent::Resend(_) => "token-resend",
            Intent::Credit(_) => "credit",
            Intent::WindowExtend(_) => "window-extend",
            Intent::ReconcileAttribute(_) => "reconcile-attribute",
            Intent::ReconcileReturn(_) => "reconcile-return",
            Intent::Refund(_) => "refund",
            Intent::Export(_) => "export",
            Intent::ChangePassword(_) => "change-password",
            Intent::UploadKey(_) => "upload-key",
            Intent::OutsideAddress(_) => "outside-address",
            Intent::Serving(_) => "serving",
            Intent::CancelRenewal(_) => "cancel-renewal",
            Intent::MailKey(_) => "mail-key",
            Intent::Unknown { kind, .. } => kind,
        }
    }

    /// File this intent as `intents/<id>.json`, and hand back the id.
    ///
    /// The id, the kind and the filing time are the writer's: one writer for
    /// every verb keeps the envelope, and the `kind` the drain dispatches on,
    /// from drifting between builders. The payload's own fields are the wire
    /// the handler already writes, and the signature, where there is one,
    /// travels in them. The intent is borrowed so the drain's own approval can
    /// file it and carry it out through the same seam.
    pub async fn file(&self, store: &Store) -> Result<String, String> {
        let id = ulid::Ulid::new().to_string();
        let kind = self.kind().to_string();
        if matches!(self, Intent::Unknown { .. }) {
            return Err(format!("this build does not implement the kind {kind:?}"));
        }
        let mut value =
            serde_json::to_value(self).map_err(|e| format!("cannot encode the intent: {e}"))?;
        let object = value.as_object_mut().ok_or("the intent is not an object")?;
        object.insert("id".to_string(), id.clone().into());
        object.insert("kind".to_string(), kind.into());
        object.insert("filed_at".to_string(), crate::util::filed_at().into());
        let bytes = serde_json::to_vec_pretty(&value)
            .map_err(|e| format!("cannot encode the intent: {e}"))?;
        store
            .write_record("intents", &format!("{id}.json"), &bytes)
            .await?;
        Ok(id)
    }

    /// Prove then apply, as the pass does. A `verify` that refuses the intent
    /// hands its refusal to `settle`, which is the one place the line, the
    /// dedup, the after-line work and the remove happen.
    pub async fn run(
        self,
        cfg: &DrainConfig,
        store: &Store,
        journal: &Journal,
        key: &[u8],
        file: &str,
        value: &Value,
    ) -> Result<(), String> {
        if let Some(settlement) = self.verify(cfg, store, key, file, value).await? {
            let envelope = transitions::Envelope::of(value, file, self.kind());
            return transitions::settle(
                cfg,
                store,
                journal,
                file,
                &envelope,
                self.disposition(),
                async { Ok(settlement) },
            )
            .await;
        }
        self.apply(cfg, store, journal, key, file, value).await
    }

    /// Prove the intent is the authenticated party's, before anything is
    /// applied.
    ///
    /// There is no catch-all arm: a variant added without deciding what proves
    /// it does not compile. `Ok(None)` means the intent is proved and may be
    /// applied. `Ok(Some(settlement))` is a refusal: the settlement is fed to
    /// `settle`, which writes its one line and leaves or removes the file as
    /// the verb's disposition says. `Err` is a pass that failed, which backs off
    /// and is mailed once.
    ///
    /// The signature and session checks are the ones the transitions used to
    /// make themselves; every message and every journal outcome is the same.
    pub async fn verify(
        &self,
        cfg: &DrainConfig,
        store: &Store,
        key: &[u8],
        file: &str,
        value: &Value,
    ) -> Result<Option<transitions::Settlement>, String> {
        let proofs = std::path::Path::new(&cfg.proof_dir);
        match self {
            // The handler files it and the drain only queues a review: nothing
            // is written as root until a reviewer's signed decision, which the
            // `Decision` arm proves.
            Intent::Application(_) => Ok(None),
            Intent::Decision(intent) => {
                let token =
                    intent.application.status_token.as_deref().ok_or_else(|| {
                        "the status token is not 128 bits of Crockford".to_string()
                    })?;
                if !crate::store::is_status_token(token) {
                    return Err("the status token is not 128 bits of Crockford".to_string());
                }
                if let Some(why) =
                    crate::flow::validate::username_shape(&intent.application.username)
                {
                    return Err(format!("the username: {why}"));
                }
                let Some(decision) = decision_for_kind(&intent.kind) else {
                    return Err(format!("kind {:?} is not a decision", intent.kind));
                };
                if intent.action != decision.action {
                    return Err(format!(
                        "the action {:?} does not match the kind {:?}",
                        intent.action, intent.kind
                    ));
                }
                if !sign::verify(
                    key,
                    &sign::decide_payload(token, &intent.action),
                    &intent.sig,
                ) {
                    return Err("the decision intent's signature does not verify".to_string());
                }
                Ok(None)
            }
            Intent::Password(intent) => {
                // The handler files the plaintext and the drain hashes it: a
                // `hash` field is the old shape, where a handler with a valid
                // link chose the stored hash. `settle` owns the replay guards:
                // a settled intent never reaches this problem check again.
                let token = intent.application.status_token.as_deref().unwrap_or("");
                let problem: Option<String> = if value.get("hash").is_some() {
                    Some("the intent carries a hash rather than a plaintext".to_string())
                } else if !sign::verify(
                    key,
                    &sign::password_payload(token, &intent.until),
                    &intent.sig,
                ) {
                    Some("the link's signature does not verify".to_string())
                } else if intent.until.as_str() < crate::util::date_after_days(0).as_str() {
                    Some("the link's date has passed".to_string())
                } else {
                    crate::account::password::validate(&intent.password).err()
                };
                match problem {
                    Some(why) => {
                        // The plaintext is revoked before the file is left in
                        // place, as every password refusal does; a failed
                        // redaction still leaves the refusal recorded, and the
                        // pass reports it.
                        Ok(Some(
                            match transitions::lifecycle::redact_password(store, file, value).await
                            {
                                Ok(()) => transitions::Settlement::refused(why),
                                Err(failure) => transitions::Settlement::Refused {
                                    reason: why,
                                    failure: Some(failure),
                                },
                            },
                        ))
                    }
                    None => Ok(None),
                }
            }
            Intent::ProvisionGroup(intent) => {
                if sign::verify(key, &sign::group_provision_payload(intent), &intent.sig) {
                    Ok(None)
                } else {
                    Err("the group intent's signature does not verify".to_string())
                }
            }
            Intent::GroupAddress(intent) => {
                let payload = sign::address_payload(
                    &intent.domain,
                    &intent.action,
                    &intent.address,
                    &intent.mailbox,
                    intent.site_owner.as_deref().unwrap_or(""),
                    intent
                        .mail_key
                        .as_ref()
                        .map(|k| k.material.as_str())
                        .unwrap_or(""),
                );
                if sign::verify(key, &payload, &intent.sig) {
                    Ok(None)
                } else {
                    Err("the address intent's signature does not verify".to_string())
                }
            }
            Intent::RemoveGroup(intent) => {
                if sign::verify(
                    key,
                    &sign::group_remove_payload(&intent.domain),
                    &intent.sig,
                ) {
                    Ok(None)
                } else {
                    Err("the remove-group intent's signature does not verify".to_string())
                }
            }
            Intent::Close(intent) => {
                // A close reports a name it cannot use as a pass failure, where
                // a page action refuses it; the session proof is shared.
                account_name(&intent.username)?;
                session_proved(store, proofs, &intent.session, &intent.username).await
            }
            Intent::Resend(intent) => {
                if sign::verify(
                    key,
                    &sign::resend_payload(&intent.username, &intent.token),
                    &intent.sig,
                ) {
                    Ok(None)
                } else {
                    Err("the token resend's signature does not verify".to_string())
                }
            }
            Intent::Credit(intent) => {
                let payload = sign::credit_payload(
                    &intent.token,
                    &intent.rail,
                    &intent.amount_gbp,
                    &intent.received,
                    intent.txid.as_deref(),
                    intent.amount_xmr.as_deref(),
                    intent.confirm_double,
                    intent.override_reason.as_deref(),
                    intent.note.as_deref(),
                );
                if sign::verify(key, &payload, &intent.sig) {
                    Ok(None)
                } else {
                    Ok(Some(transitions::Settlement::refused(
                        "the credit intent's signature does not verify",
                    )))
                }
            }
            Intent::WindowExtend(intent) => {
                if sign::verify(
                    key,
                    &sign::window_extend_payload(&intent.token, intent.days, &intent.reason),
                    &intent.sig,
                ) {
                    Ok(None)
                } else {
                    Ok(Some(transitions::Settlement::refused(
                        "the window extension's signature does not verify",
                    )))
                }
            }
            Intent::ReconcileAttribute(intent) => {
                let payload = sign::reconcile_attribute_payload(
                    &intent.item,
                    &intent.token,
                    intent.confirm_double,
                    intent.override_reason.as_deref(),
                );
                if sign::verify(key, &payload, &intent.sig) {
                    Ok(None)
                } else {
                    Ok(Some(transitions::Settlement::refused(
                        "the reconcile-attribute intent's signature does not verify",
                    )))
                }
            }
            Intent::ReconcileReturn(intent) => {
                if sign::verify(
                    key,
                    &sign::reconcile_return_payload(&intent.item, &intent.note),
                    &intent.sig,
                ) {
                    Ok(None)
                } else {
                    Ok(Some(transitions::Settlement::refused(
                        "the reconcile-return intent's signature does not verify",
                    )))
                }
            }
            Intent::Refund(intent) => {
                let payload = sign::refund_payload(
                    &intent.token,
                    intent.amount_gbp.as_deref().unwrap_or(""),
                    intent.rail.as_deref().unwrap_or(""),
                    intent.close,
                    intent.excess,
                    intent.rate.as_deref().unwrap_or(""),
                    intent.settled_on.as_deref().unwrap_or(""),
                    intent.reason.as_deref().unwrap_or(""),
                );
                if sign::verify(key, &payload, &intent.sig) {
                    Ok(None)
                } else {
                    Ok(Some(transitions::Settlement::refused(
                        "the refund intent's signature does not verify",
                    )))
                }
            }
            // A page action like the rest: an unusable name or session is the
            // handler's input refused, journalled once and removed, not a pass
            // that fails and retries forever.
            Intent::Export(intent) => {
                if let Some(why) = crate::flow::validate::username_shape(&intent.username) {
                    return Ok(Some(transitions::Settlement::refused(format!(
                        "the export intent's username {:?}: {why}",
                        intent.username
                    ))));
                }
                session_proved(store, proofs, &intent.session, &intent.username).await
            }
            // A page action is proved by the session the handler filed, and by
            // the account name being one an account record can name.
            Intent::ChangePassword(intent) => {
                if value.get("hash").is_some() {
                    return Ok(Some(transitions::Settlement::refused(
                        "the intent carries a hash rather than a plaintext",
                    )));
                }
                page_proved(store, proofs, &intent.session, &intent.username).await
            }
            Intent::UploadKey(intent) => {
                page_proved(store, proofs, &intent.session, &intent.username).await
            }
            Intent::OutsideAddress(intent) => {
                page_proved(store, proofs, &intent.session, &intent.username).await
            }
            Intent::Serving(intent) => {
                page_proved(store, proofs, &intent.session, &intent.username).await
            }
            Intent::CancelRenewal(intent) => {
                page_proved(store, proofs, &intent.session, &intent.username).await
            }
            Intent::MailKey(intent) => {
                page_proved(store, proofs, &intent.session, &intent.username).await
            }
            Intent::Unknown { .. } => Ok(Some(transitions::Settlement::refused(
                "this build does not implement this kind; the intent is left in place",
            ))),
        }
    }

    /// Carry the intent out. Only reached once `verify` has proved it, so the
    /// transitions behind these arms make no second proof of their own.
    ///
    /// Every root verb is a body passed to `settle`: the dedup, the outcome
    /// line and the remove are the combinator's, and a body that refuses says
    /// so with the line it would have written.
    pub async fn apply(
        self,
        cfg: &DrainConfig,
        store: &Store,
        journal: &Journal,
        key: &[u8],
        file: &str,
        value: &Value,
    ) -> Result<(), String> {
        let kind = self.kind().to_string();
        let envelope = transitions::Envelope::of(value, file, &kind);
        let disposition = self.disposition();
        transitions::settle(cfg, store, journal, file, &envelope, disposition, async {
            match self {
                Intent::Application(intent) => {
                    transitions::review::filed_application(cfg, store, journal, key, intent).await
                }
                Intent::Decision(intent) => {
                    transitions::review::decision(cfg, store, journal, key, intent).await
                }
                Intent::Password(intent) => {
                    transitions::lifecycle::set_password(cfg, store, intent, file, value).await
                }
                Intent::ProvisionGroup(intent) => {
                    transitions::groups::provision_group(cfg, store, journal, *intent).await
                }
                Intent::GroupAddress(intent) => {
                    transitions::groups::group_address(cfg, store, journal, intent).await
                }
                Intent::RemoveGroup(intent) => {
                    transitions::groups::remove_group(cfg, store, journal, intent).await
                }
                Intent::Close(intent) => transitions::lifecycle::close_account(store, intent).await,
                Intent::Resend(intent) => transitions::review::resend(cfg, store, intent).await,
                Intent::Credit(intent) => {
                    transitions::payments::credit(cfg, store, journal, intent).await
                }
                Intent::WindowExtend(intent) => {
                    transitions::lifecycle::window_extend(store, intent).await
                }
                Intent::ReconcileAttribute(intent) => {
                    transitions::payments::reconcile_attribute(cfg, store, journal, intent).await
                }
                Intent::ReconcileReturn(intent) => {
                    transitions::payments::reconcile_return(store, intent).await
                }
                Intent::Refund(intent) => transitions::payments::refund(cfg, store, intent).await,
                Intent::Export(intent) => {
                    transitions::lifecycle::export_account(cfg, store, intent, file).await
                }
                Intent::ChangePassword(intent) => {
                    transitions::lifecycle::change_password(cfg, store, intent).await
                }
                Intent::UploadKey(intent) => {
                    transitions::lifecycle::upload_key(cfg, store, intent).await
                }
                Intent::OutsideAddress(intent) => {
                    transitions::lifecycle::set_outside_address(store, intent).await
                }
                Intent::Serving(intent) => {
                    transitions::lifecycle::set_serving(cfg, store, intent).await
                }
                Intent::CancelRenewal(intent) => {
                    transitions::lifecycle::cancel_renewal(cfg, store, intent).await
                }
                Intent::MailKey(intent) => {
                    transitions::lifecycle::mail_key(cfg, store, intent).await
                }
                // `verify` refuses an unknown kind before this is reached.
                Intent::Unknown { kind, .. } => {
                    Err(format!("this build does not implement the kind {kind:?}"))
                }
            }
        })
        .await
    }

    /// What this verb's settlement owes beyond its body: the work its line must
    /// precede, and what a refusal leaves of its file. Every variant is listed,
    /// so a new one has to say both.
    fn disposition(&self) -> transitions::Disposition {
        // The verbs whose line and record cleanup cannot be one write name that
        // work here, once.
        let after = match self {
            Intent::RemoveGroup(intent) => {
                transitions::AfterLine::RemoveGroupRecord(intent.domain.clone())
            }
            Intent::ReconcileAttribute(intent) => transitions::AfterLine::MarkAttributed {
                item: intent.item.clone(),
                token: intent.token.clone(),
            },
            Intent::Application(_)
            | Intent::Decision(_)
            | Intent::Password(_)
            | Intent::ProvisionGroup(_)
            | Intent::GroupAddress(_)
            | Intent::Close(_)
            | Intent::Resend(_)
            | Intent::Credit(_)
            | Intent::WindowExtend(_)
            | Intent::ReconcileReturn(_)
            | Intent::Refund(_)
            | Intent::Export(_)
            | Intent::ChangePassword(_)
            | Intent::UploadKey(_)
            | Intent::OutsideAddress(_)
            | Intent::Serving(_)
            | Intent::CancelRenewal(_)
            | Intent::MailKey(_)
            | Intent::Unknown { .. } => transitions::AfterLine::Nothing,
        };
        // A page action's refusal is the handler's own input, so its file goes;
        // every other verb keeps a refusal for the operator. A close is a page
        // action too, though its only refusal is the session proof's.
        let refusal = match self {
            Intent::ChangePassword(_)
            | Intent::UploadKey(_)
            | Intent::OutsideAddress(_)
            | Intent::Serving(_)
            | Intent::CancelRenewal(_)
            | Intent::MailKey(_)
            | Intent::Close(_)
            | Intent::Export(_) => transitions::RefusalFile::Remove,
            Intent::Application(_)
            | Intent::Decision(_)
            | Intent::Password(_)
            | Intent::ProvisionGroup(_)
            | Intent::GroupAddress(_)
            | Intent::RemoveGroup(_)
            | Intent::Resend(_)
            | Intent::Credit(_)
            | Intent::WindowExtend(_)
            | Intent::ReconcileAttribute(_)
            | Intent::ReconcileReturn(_)
            | Intent::Refund(_)
            | Intent::Unknown { .. } => transitions::RefusalFile::Keep,
        };
        transitions::Disposition::new(after, refusal)
    }
}

/// One de-serialisation, with the verb's own words for a bad shape.
fn parsed<T: serde::de::DeserializeOwned>(value: &Value, what: &str) -> Result<T, String> {
    serde_json::from_value(value.clone()).map_err(|e| format!("{what} does not parse: {e}"))
}

/// The export intent, read with the words its transition always used: the
/// account and the session are its claim, and a file missing either is refused
/// by name rather than as a serde object error.
fn export_from(value: &Value) -> Result<ExportIntent, String> {
    Ok(ExportIntent {
        id: value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        kind: "export".to_string(),
        filed_at: value
            .get("filed_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        username: value
            .get("username")
            .and_then(Value::as_str)
            .ok_or("the export intent names no account")?
            .to_string(),
        session: value
            .get("session")
            .and_then(Value::as_str)
            .ok_or("the export intent names no session")?
            .to_string(),
    })
}

/// The one rule for a name the drain turns into a path: only an account name
/// may be one, because an intent's username is a path component under the
/// store. `Err` carries the reason, worded for the journal.
fn account_name(username: &str) -> Result<(), String> {
    match crate::flow::validate::username_shape(username) {
        Some(why) => Err(format!("the username {username:?}: {why}")),
        None => Ok(()),
    }
}

/// The page verbs' and close's one session proof: the record's proof names the
/// account. A mismatch, an expiry and a session that has gone are the refusal
/// this returns; `settle` records it once and removes the file.
async fn session_proved(
    store: &Store,
    proofs: &std::path::Path,
    session: &str,
    username: &str,
) -> Result<Option<transitions::Settlement>, String> {
    match verify_session(store, proofs, session, username).await {
        Ok(()) => Ok(None),
        Err(reason) => Ok(Some(transitions::Settlement::refused(reason))),
    }
}

/// A page action's proof: the account name rule, then the session. A refusal is
/// the settlement the caller hands to `settle`.
async fn page_proved(
    store: &Store,
    proofs: &std::path::Path,
    session: &str,
    username: &str,
) -> Result<Option<transitions::Settlement>, String> {
    if let Err(why) = account_name(username) {
        return Ok(Some(transitions::Settlement::refused(why)));
    }
    session_proved(store, proofs, session, username).await
}

/// Whether `id` names a live page session for `username`. The drain runs as
/// root and the session record lives under the handler's store, so this is the
/// one check that turns an unsigned intent into work for an authenticated
/// account. The record is not trusted: it only names the proof token that the
/// root-side login check minted in `proof_dir`, and that file's own username
/// and expiry decide. A forged record, a session for another account and an
/// expired one are refused with the reason the journal records.
pub async fn verify_session(
    store: &Store,
    proof_dir: &std::path::Path,
    id: &str,
    username: &str,
) -> Result<(), String> {
    if !crate::store::is_status_token(id) {
        return Err("the intent carries no usable session id".to_string());
    }
    let Some(text) = store.read_record("sessions", &format!("{id}.json")).await else {
        return Err("the session named by the intent has gone".to_string());
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| format!("the session record does not parse: {e}"))?;
    let proof = value.get("proof").and_then(Value::as_str).unwrap_or("");
    crate::account::session::verify_proof(proof_dir, proof, username, OffsetDateTime::now_utc())
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One pass, many intents, one read: the index is loaded once and nothing
    /// below it opens the file again. A second pass over the same files appends
    /// nothing, because the index carries the first pass's refusal.
    #[test]
    fn a_pass_reads_the_journal_once_however_many_intents_it_carries() {
        let dir = std::env::temp_dir().join(format!("onboard-journal-pass-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("intents")).unwrap();
        let mut cfg: DrainConfig =
            toml::from_str(include_str!("../../../openbsd/etc/onboard/drain.toml")).unwrap();
        cfg.store_root = dir.to_str().unwrap().to_string();
        let store = Store::new_for_test(&cfg.store_root);
        for n in 0..5 {
            std::fs::write(
                dir.join(format!("intents/01H{n}.json")),
                format!(r#"{{"id":"intent-{n}","kind":"not-a-verb"}}"#),
            )
            .unwrap();
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let journal = Journal::load(&store).await.unwrap();
            let loaded = store.journal_reads();
            assert_eq!(loaded, 1, "the load reads the journal once");
            for pass in 0..2 {
                for name in store.list("intents").await.unwrap() {
                    if !name.ends_with(".json") {
                        continue;
                    }
                    let id = name.trim_end_matches(".json");
                    if !transitions::due(&journal, id, OffsetDateTime::now_utc()) {
                        continue;
                    }
                    one(&cfg, &store, &journal, b"key", &name).await.unwrap();
                }
                assert_eq!(
                    store.journal_reads(),
                    loaded,
                    "pass {pass} read the journal again"
                );
            }
        });
        let text = std::fs::read_to_string(dir.join("journal.jsonl")).unwrap();
        assert_eq!(
            text.lines().count(),
            5,
            "each refusal is written once, not once per pass: {text}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
