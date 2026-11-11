//! The intent contract: the payloads the handler files, the kinds the drain
//! dispatches on, and the one writer that stamps an intent's envelope.
//!
//! This module holds data only. `verify`, `apply` and `settle` live in the drain,
//! which is the only half that runs as root.

use serde_json::Value;

use crate::store::{ApplicationRef, GroupAddressIntent, GroupIntent, GroupRemoveIntent, Store};
use crate::Error;

/// The rails an application may name. `no_charge` is the fourth, and it is a
/// rail rather than a flag because it is one of the four buttons on the form.
pub const RAILS: [&str; 4] = ["card", "cash", "monero", "no_charge"];

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

/// A reviewer's decision intent, from `kyriakon-admin` or a signed link.
/// Every
/// decision intent carries the action it performs and the signature over it: the
/// directory it is read from belongs to the unprivileged half, so an unsigned
/// decision would be root work driven by a file any writer of `intents/` could
/// leave. `kyriakon-admin` signs with the same root-only key the links use.
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
    /// `--rate`, the GBP price of one XMR on the receipt date, when the operator
    /// read it from the market rather than the drain's cache.
    #[serde(default)]
    pub rate: Option<String>,
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
    pub fn parse(value: &Value) -> Result<Intent, Error> {
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
    pub async fn file(&self, store: &Store) -> Result<String, Error> {
        let id = ulid::Ulid::new().to_string();
        let kind = self.kind().to_string();
        if matches!(self, Intent::Unknown { .. }) {
            return Err(Error::Failed(format!(
                "this build does not implement the kind {kind:?}"
            )));
        }
        let mut value = serde_json::to_value(self)
            .map_err(|e| Error::context("cannot encode the intent", e))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| Error::Failed("the intent is not an object".to_string()))?;
        object.insert("id".to_string(), id.clone().into());
        object.insert("kind".to_string(), kind.into());
        object.insert("filed_at".to_string(), crate::util::filed_at().into());
        let bytes = serde_json::to_vec_pretty(&value)
            .map_err(|e| Error::context("cannot encode the intent", e))?;
        store
            .write_record("intents", &format!("{id}.json"), &bytes)
            .await?;
        Ok(id)
    }
}

fn parsed<T: serde::de::DeserializeOwned>(value: &Value, what: &str) -> Result<T, Error> {
    serde_json::from_value(value.clone())
        .map_err(|e| Error::context(format!("{what} does not parse"), e))
}

/// The export intent, read with the words its transition always used: the
/// account and the session are its claim, and a file missing either is refused
/// by name rather than as a serde object error.
fn export_from(value: &Value) -> Result<ExportIntent, Error> {
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
            .ok_or_else(|| Error::Failed("the export intent names no account".to_string()))?
            .to_string(),
        session: value
            .get("session")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Failed("the export intent names no session".to_string()))?
            .to_string(),
    })
}
