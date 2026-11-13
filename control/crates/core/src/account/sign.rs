//! The signing the review email and the one-time password link rest on.
//!
//! Both links are HMAC-SHA256 over a canonical payload, keyed from the
//! root-only file `scripts/deploy-control.sh` installs as
//! `/etc/kyriakon/onboard/approval-signing-key`. The drain signs and the drain
//! verifies: the handler only passes a click through as an intent, so the key
//! never leaves root and the unprivileged half never holds it.
//!
//! HMAC rather than a public-key signature because the verifier is the signer.
//! The one thing a signature would add is verification by a party that does not
//! hold the key, and there is no such party here: the links are checked by the
//! same root process that made them, moments later. An HMAC is one small
//! dependency pair rather than a keypair to store, rotate and publish, and it
//! gives exactly the property the links need, which is that a link cannot be
//! fabricated without the key and that a signature from one application cannot
//! be replayed against another.

use crate::store::{KeyRecord, Record};
use crate::Error;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// The key file, as the operator installed it. A trailing newline is the shape
/// a `printf` or an `install` of a generated secret leaves, and it is not part
/// of the key: stripping it here is what lets the same secret be written either
/// way. An empty file is an error rather than an empty key, because an empty
/// key would sign every application with nothing.
///
/// The file must not be readable by group or others, and, when the drain is
/// running as root, it must be owned by root. Both checks are the operator's
/// own rule made enforceable: the config, the deploy script and the spec all
/// describe this as a root-only file, and this is the one place that reads it.
pub fn read_key(path: &std::path::Path) -> Result<Vec<u8>, Error> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| Error::context(format!("cannot read {}", path.display()), e))?;
    if unsafe { libc::geteuid() } == 0 && meta.uid() != 0 {
        return Err(Error::Failed(format!(
            "{} is not owned by root",
            path.display()
        )));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(Error::Failed(format!(
            "{} is readable by group or others; it must be 0600",
            path.display()
        )));
    }
    let bytes = std::fs::read(path)
        .map_err(|e| Error::context(format!("cannot read {}", path.display()), e))?;
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(0);
    let key = bytes[..end].to_vec();
    if key.is_empty() {
        return Err(Error::Failed(format!("{} is empty", path.display())));
    }
    Ok(key)
}

/// The signature of one payload, lowercase hex. Infallible in practice: HMAC
/// accepts a key of any length, and the error path is kept so a caller writes
/// `?` rather than an `unwrap` on a value the OS randomness feeds.
pub fn sign(key: &[u8], payload: &str) -> Result<String, Error> {
    sign_bytes(key, payload.as_bytes())
}

/// The same signature over bytes, for a payload that is not text: a webhook's
/// raw body is verified exactly as it arrived, and a lossy reread of it would
/// not be the bytes Stripe signed.
pub fn sign_bytes(key: &[u8], payload: &[u8]) -> Result<String, Error> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| Error::context("cannot key the HMAC", e))?;
    mac.update(payload);
    Ok(hex(&mac.finalize().into_bytes()))
}

/// Whether a signature is the one this key makes for this payload. The compare
/// is over the recomputed signature byte by byte and not with `==`, so the time
/// it takes does not tell a caller how much of a guess was right.
pub fn verify(key: &[u8], payload: &str, sig: &str) -> bool {
    verify_bytes(key, payload.as_bytes(), sig)
}

/// Whether a signature is the one this key makes for these bytes. Constant time
/// for the reason [`verify`] is.
pub fn verify_bytes(key: &[u8], payload: &[u8], sig: &str) -> bool {
    match sign_bytes(key, payload) {
        Ok(want) => constant_eq(want.as_bytes(), sig.as_bytes()),
        Err(_) => false,
    }
}

/// The payload a review link signs: every field of the application record the
/// decision acts on, plus a digest of the key material the approval installs.
///
/// The token and the action alone were not enough. The record in
/// `applications/<token>.json` belongs to the unprivileged handler, and the
/// approval derives everything it installs from that record at click time. A
/// signature over the token alone would let a rewrite install an account name,
/// keys, a free outcome, an own domain or an outside address the reviewer saw
/// none of: `no_charge` makes a paid application permanently free, `domain`
/// provisions a body under an unreviewed domain, `outside_address` redirects
/// the approval mail that carries the signed one-time password link, and
/// `answers` carries the body's name and its mailboxes. Each is length-
/// prefixed, and the two large fields — the answers and the key material — are
/// covered by a digest so the link stays a link.
pub fn decide_payload(record: &Record, action: &str) -> String {
    format!(
        "decide:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        free_text(&record.status_token),
        free_text(action),
        free_text(&record.username),
        record.no_charge,
        free_text(&record.rail),
        free_text(record.domain.as_deref().unwrap_or("")),
        free_text(record.outside_address.as_deref().unwrap_or("")),
        answers_digest(&record.answers),
        key_digest(&record.mail_keys, record.upload_key.as_ref()),
    )
}

/// A digest of the application's answers. `answers` is a `BTreeMap`, so the
/// keys are already sorted and two equal maps encode identically; each key and
/// value is length-prefixed, so an answer that contains a colon or a boundary
/// marker cannot be read as the start of the next one. A rewritten answer —
/// including a body's `body_name` — changes the payload.
fn answers_digest(answers: &std::collections::BTreeMap<String, String>) -> String {
    let mut canonical = String::new();
    for (key, value) in answers {
        canonical.push_str(&free_text(key));
        canonical.push_str(&free_text(value));
    }
    hex(Sha256::digest(canonical.as_bytes()).as_slice())
}

/// The digest of the key material an approval installs, so one signature covers
/// the keys as well as the account. Every field is length-prefixed before it is
/// joined, so no separator inside a mailbox, a fingerprint, a key's material or
/// its verdict can be read as the boundary before the next field. The signing
/// and verifying halves both build this from the record, so a key swapped after
/// the review mail no longer verifies.
fn key_digest(mail_keys: &[KeyRecord], upload_key: Option<&KeyRecord>) -> String {
    let field = |key: &KeyRecord| {
        format!(
            "{}{}{}{}",
            free_text(&key.mailbox),
            free_text(&key.fingerprint),
            free_text(&key.material),
            free_text(&key.verdict)
        )
    };
    let mut canonical = String::new();
    for key in mail_keys {
        canonical.push_str(&format!("m:{};", field(key)));
    }
    if let Some(key) = upload_key {
        canonical.push_str(&format!("u:{};", field(key)));
    }
    hex(Sha256::digest(canonical.as_bytes()).as_slice())
}

/// The payload the one-time password link signs. The date is in the payload so
/// the expiry is covered by the signature and not merely beside it, and the
/// account is in it because the drain derives the account from a record the
/// unprivileged handler can rewrite: without the name in the payload a signature
/// for one link could be pointed at another account. The password is not, and
/// cannot usefully be: the drain hashes the plaintext the handler files, so the
/// signature proves the link and not the password. A compromised handler can
/// therefore still choose the plaintext it submits, and so set a password it
/// knows; it cannot install a chosen hash without a plaintext that produces it.
pub fn password_payload(token: &str, username: &str, until: &str) -> String {
    format!("password:{token}:{username}:{until}")
}

/// The payload a group-address intent signs: every field the drain acts on, so
/// a signature for one address change cannot be replayed as another. The
/// replacement site owner is empty when the change names none, and a mail key
/// is covered by its SHA-256 so a handler that holds a valid signature cannot
/// swap the key the drain installs and publishes.
pub fn address_payload(
    domain: &str,
    action: &str,
    address: &str,
    mailbox: &str,
    site_owner: &str,
    mail_key: &str,
) -> String {
    let key = if mail_key.is_empty() {
        String::new()
    } else {
        hex(Sha256::digest(mail_key.as_bytes()).as_slice())
    };
    format!("address:{domain}:{action}:{address}:{mailbox}:{site_owner}:{key}")
}

/// The payload a remove-group intent signs: the domain the drain is asked to
/// take down. Nothing else is in the intent for the drain to act on, so a
/// signature for one body's domain cannot be replayed against another's.
pub fn group_remove_payload(domain: &str) -> String {
    format!("remove-group:{domain}")
}

/// The payload a `provision-group` intent signs: every field the drain acts on.
/// The approval files it, because `intents/` and `applications/` both belong to
/// the unprivileged half and this intent creates system accounts as root. The
/// domain, the body's words, the payment, the address table, the mailboxes, the
/// site owner, the upload key, the mail keys and the application the intent
/// claims to come from are all covered, so a signature for one body cannot be
/// replayed with another's mailbox or key. Every text field is length-prefixed,
/// so a colon inside one cannot be read as the separator before the next.
pub fn group_provision_payload(intent: &crate::store::GroupIntent) -> String {
    let addresses = intent
        .addresses
        .iter()
        .map(|a| format!("{}={}", free_text(&a.address), free_text(&a.mailbox)))
        .collect::<Vec<_>>()
        .join(";");
    let mail_keys = intent
        .mail_keys
        .iter()
        .map(|k| {
            format!(
                "{}={}={}={}",
                free_text(&k.mailbox),
                free_text(&k.fingerprint),
                free_text(&k.material),
                free_text(&k.verdict)
            )
        })
        .collect::<Vec<_>>()
        .join(";");
    let payment = &intent.payment;
    let window = payment
        .window
        .as_ref()
        .map(|w| {
            format!(
                "{}={}={}={}",
                free_text(&w.opened_at),
                free_text(&w.closes_at),
                free_text(&w.state),
                w.extensions
            )
        })
        .unwrap_or_default();
    let stripe = &payment.stripe;
    let stripe = format!(
        "{}={}={}={}={}={}={}={}",
        free_text(stripe.subscription.as_deref().unwrap_or("")),
        free_text(stripe.customer.as_deref().unwrap_or("")),
        free_text(stripe.status.as_deref().unwrap_or("")),
        stripe.cancel_at_period_end,
        free_text(stripe.current_period_end.as_deref().unwrap_or("")),
        free_text(stripe.next_payment_attempt.as_deref().unwrap_or("")),
        stripe.failed_attempts,
        free_text(stripe.last_invoice.as_deref().unwrap_or("")),
    );
    format!(
        "provision-group:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        free_text(&intent.domain),
        free_text(&intent.name),
        free_text(&intent.body_kind),
        free_text(&payment.rail),
        payment.no_charge,
        free_text(payment.paid_until.as_deref().unwrap_or("")),
        free_text(payment.token_ref.as_deref().unwrap_or("")),
        free_text(&window),
        free_text(&stripe),
        free_text(&addresses),
        free_text(&intent.mailboxes.join(",")),
        free_text(&intent.site_owner),
        free_text(&intent.upload_key),
        free_text(&mail_keys),
        free_text(&intent.application.username),
        free_text(intent.application.status_token.as_deref().unwrap_or("")),
    )
}

/// The payload a token-resend intent signs: the account and the token it holds.
/// The console signs it, because a second copy of the instructions is the
/// member's to ask for and not the handler's to file.
pub fn resend_payload(username: &str, token: &str) -> String {
    format!("resend:{username}:{token}")
}

/// Free text as one unambiguous field: its byte length, then the text. Two
/// fields whose text contains the separator cannot shift a colon from one field
/// into the next, which a plain `:` join would allow when both are free text.
fn free_text(text: &str) -> String {
    format!("{}:{text}", text.len())
}

/// The payload a credit intent signs: every field the drain acts on, because
/// `intents/` belongs to the unprivileged half and a credit moves a paid-until
/// date. The token, rail, amount and date are validated shapes; the override
/// reason and the note are free text, so each is length-prefixed and cannot
/// shift a colon into the other.
#[allow(clippy::too_many_arguments)]
pub fn credit_payload(
    token: &str,
    rail: &str,
    amount_gbp: &str,
    received: &str,
    txid: Option<&str>,
    amount_xmr: Option<&str>,
    rate: Option<&str>,
    confirm_double: bool,
    override_reason: Option<&str>,
    note: Option<&str>,
) -> String {
    // The rate segment is omitted when absent, so an intent filed before the
    // receipt-date rate existed still verifies with the payload it signed.
    let rate = rate.map(|rate| format!(":{rate}")).unwrap_or_default();
    format!(
        "credit:{token}:{rail}:{amount_gbp}:{received}:{}:{}{rate}:{confirm_double}:{}:{}",
        txid.unwrap_or(""),
        amount_xmr.unwrap_or(""),
        free_text(override_reason.unwrap_or("")),
        free_text(note.unwrap_or("")),
    )
}

/// The payload a `window-extend` intent signs: the token, the number of days and
/// the reason the operator recorded. The reason is free text and last, so no
/// earlier field can be shifted into it by a colon.
pub fn window_extend_payload(token: &str, days: i64, reason: &str) -> String {
    format!("window-extend:{token}:{days}:{reason}")
}

/// The payload a `reconcile-attribute` intent signs: the held item, the token it
/// is joined to, and the two acknowledgements a renewal needs. All are covered,
/// so a signature for one item cannot be replayed with a different token or a
/// different acknowledgement. The override reason is free text and
/// length-prefixed.
#[allow(clippy::too_many_arguments)]
pub fn reconcile_attribute_payload(
    item: &str,
    token: &str,
    confirm_double: bool,
    override_reason: Option<&str>,
) -> String {
    format!(
        "reconcile-attribute:{item}:{token}:{confirm_double}:{}",
        free_text(override_reason.unwrap_or("")),
    )
}

/// The payload a `reconcile-return` intent signs: the held item and the evidence
/// the operator wrote down, which is free text and last.
pub fn reconcile_return_payload(item: &str, note: &str) -> String {
    format!("reconcile-return:{item}:{note}")
}

/// The payload a refund intent signs: every field the drain acts on. A refund
/// writes the ledger and can close an account, and `intents/` belongs to the
/// unprivileged half, so the token, the amount, the rail, the
/// `--close`/`--excess` choice, the rate and the settlement date are all
/// covered. The reason is free text and comes last, so no earlier field can be
/// shifted into it by a colon.
#[allow(clippy::too_many_arguments)]
pub fn refund_payload(
    token: &str,
    amount_gbp: &str,
    rail: &str,
    close: bool,
    excess: bool,
    rate: &str,
    settled_on: &str,
    reason: &str,
) -> String {
    format!("refund:{token}:{amount_gbp}:{rail}:{close}:{excess}:{rate}:{settled_on}:{reason}")
}

/// One decision link, pointing at the handler's click-through path.
pub fn decide_link(base: &str, key: &[u8], record: &Record, action: &str) -> Result<String, Error> {
    let sig = sign(key, &decide_payload(record, action))?;
    Ok(format!(
        "{base}/decide/{}?action={action}&sig={sig}",
        record.status_token
    ))
}

/// The one-time password link, the same mechanism as the review links.
pub fn password_link(
    base: &str,
    key: &[u8],
    token: &str,
    username: &str,
    until: &str,
) -> Result<String, Error> {
    let sig = sign(key, &password_payload(token, username, until))?;
    Ok(format!("{base}/password/{token}?until={until}&sig={sig}"))
}

fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(D[(b >> 4) as usize] as char);
        out.push(D[(b & 15) as usize] as char);
    }
    out
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_is_stable_and_keyed() {
        let a = sign(b"k", "decide:tok:approve").unwrap();
        let b = sign(b"k", "decide:tok:approve").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "{a}");
        assert!(a
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // A different key and a different payload each give a different one.
        assert_ne!(a, sign(b"k2", "decide:tok:approve").unwrap());
        assert_ne!(a, sign(b"k", "decide:tok:decline").unwrap());
    }

    fn key_record(mailbox: &str, fingerprint: &str, material: &str) -> KeyRecord {
        KeyRecord {
            mailbox: mailbox.to_string(),
            fingerprint: fingerprint.to_string(),
            material: material.to_string(),
            verdict: "works".to_string(),
        }
    }

    fn record(mail: Vec<KeyRecord>, upload: Option<KeyRecord>) -> Record {
        serde_json::from_value(serde_json::json!({
            "username": "secretary",
            "status_token": "0123456789abcdefghjkmnpqrs",
            "filed_at": "2026-10-01T09:00:00Z",
            "front_end": "web",
            "stage": "received",
            "domain": null,
            "outside_address": null,
            "answers": {"intended_use": "parish mail"},
            "mail_keys": mail,
            "upload_key": upload,
            "rail": "cash",
            "no_charge": false,
            "acceptances": [],
            "question_list": "2026-10-01 abc1234"
        }))
        .unwrap()
    }

    #[test]
    fn a_signature_verifies_only_for_its_own_payload() {
        let key = b"the approval key";
        let filed = record(vec![key_record("", "1111", "mail material")], None);
        let payload = decide_payload(&filed, "approve");
        let sig = sign(key, &payload).unwrap();
        assert!(verify(key, &payload, &sig));
        // A signature for one application does not verify against another, so a
        // link cannot be replayed across applications.
        let mut other = filed.clone();
        other.status_token = "fedcba98765432100123456789".to_string();
        assert!(!verify(key, &decide_payload(&other, "approve"), &sig));
        assert!(!verify(key, &decide_payload(&filed, "decline"), &sig));
        assert!(!verify(b"other key", &payload, &sig));
        // A truncated or padded signature is refused rather than panicking.
        assert!(!verify(key, &payload, ""));
        assert!(!verify(key, &payload, &format!("{sig}0")));
    }

    /// Every field the approval acts on is signed, so a record rewritten after
    /// the review mail installs none of a different account, outcome, rail,
    /// domain, outside address, answer or key.
    #[test]
    fn a_decision_link_is_bound_to_every_field_it_installs() {
        let key = b"k";
        let filed = record(vec![key_record("", "1111", "mail material")], None);
        let sig = sign(key, &decide_payload(&filed, "approve")).unwrap();
        let refused = |changed: &Record| {
            assert!(
                !verify(key, &decide_payload(changed, "approve"), &sig),
                "a rewritten record verified"
            );
        };
        let mut changed = filed.clone();
        changed.username = "victim".to_string();
        refused(&changed);
        let mut changed = filed.clone();
        changed.no_charge = true;
        refused(&changed);
        let mut changed = filed.clone();
        changed.rail = "monero".to_string();
        refused(&changed);
        let mut changed = filed.clone();
        changed.domain = Some("attacker.example".to_string());
        refused(&changed);
        let mut changed = filed.clone();
        changed.outside_address = Some("attacker@example.invalid".to_string());
        refused(&changed);
        let mut changed = filed.clone();
        changed
            .answers
            .insert("intended_use".to_string(), "changed".to_string());
        refused(&changed);
        let mut changed = filed.clone();
        changed.mail_keys[0].material = "attacker material".to_string();
        refused(&changed);
        let mut changed = filed.clone();
        changed.mail_keys.clear();
        refused(&changed);
        let mut changed = filed.clone();
        changed.upload_key = Some(key_record("", "2222", "ssh-ed25519 AAAA"));
        refused(&changed);
    }

    #[test]
    fn a_key_file_is_read_without_its_trailing_newline() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("onboard-sign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        let write = |bytes: &[u8]| {
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        write(b"secret\n");
        assert_eq!(read_key(&path).unwrap(), b"secret");
        write(b"secret");
        assert_eq!(read_key(&path).unwrap(), b"secret");
        // A key the rest of the machine can read is refused: the file is the
        // one secret the review and password links depend on.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            read_key(&path).is_err(),
            "a group/other-readable key is refused"
        );
        write(b"\n");
        assert!(read_key(&path).is_err(), "an empty key is refused");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn free_text_cannot_shift_a_colon_between_two_fields() {
        let a = credit_payload(
            "KYR-4F2M-9QH7-XT3B",
            "cash",
            "20.00",
            "2026-10-04",
            None,
            None,
            None,
            false,
            Some("a:b"),
            Some("c"),
        );
        let b = credit_payload(
            "KYR-4F2M-9QH7-XT3B",
            "cash",
            "20.00",
            "2026-10-04",
            None,
            None,
            None,
            false,
            Some("a"),
            Some("b:c"),
        );
        assert_ne!(a, b, "two field splits signed the same payload");
    }

    /// The receipt-date rate is one of the fields the credit signs, so editing
    /// it in `intents/` invalidates the signature.
    #[test]
    fn a_credit_rate_is_part_of_the_signed_payload() {
        let payload = |rate: Option<&str>| {
            credit_payload(
                "KYR-4F2M-9QH7-XT3B",
                "monero",
                "20.00",
                "2026-10-04",
                None,
                Some("0.048848"),
                rate,
                false,
                None,
                None,
            )
        };
        assert_ne!(payload(Some("409.44")), payload(Some("410.00")));
        assert!(payload(Some("409.44")).contains(":409.44:"));
        assert!(!payload(None).contains("409.44"));
    }

    #[test]
    fn the_links_put_the_token_in_the_path_and_the_signature_in_the_query() {
        let key = b"k";
        let filed = record(vec![key_record("", "1111", "mail material")], None);
        let link = decide_link("https://signup.kyriakon.net", key, &filed, "approve-free").unwrap();
        assert_eq!(
            link,
            format!(
                "https://signup.kyriakon.net/decide/{}?action=approve-free&sig={}",
                filed.status_token,
                sign(key, &decide_payload(&filed, "approve-free")).unwrap()
            )
        );
        let pw = password_link(
            "https://signup.kyriakon.net",
            key,
            "tok",
            "secretary",
            "2026-10-20",
        )
        .unwrap();
        assert_eq!(
            pw,
            format!(
                "https://signup.kyriakon.net/password/tok?until=2026-10-20&sig={}",
                sign(key, "password:tok:secretary:2026-10-20").unwrap()
            )
        );
    }

    /// The account is signed into the password link, so a signature the drain
    /// issued for one account does not verify when pointed at another.
    #[test]
    fn a_password_link_is_bound_to_the_account_it_sets() {
        let key = b"k";
        let sig = sign(key, &password_payload("tok", "secretary", "2026-10-20")).unwrap();
        assert!(verify(
            key,
            &password_payload("tok", "secretary", "2026-10-20"),
            &sig
        ));
        assert!(!verify(
            key,
            &password_payload("tok", "victim", "2026-10-20"),
            &sig
        ));
    }
}
