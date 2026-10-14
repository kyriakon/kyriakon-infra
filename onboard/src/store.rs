//! The store: the three shared files read at the top, the records written under
//! the root, and the on-disk shapes the drain reads.
//!
//! Every record is written by rename, so a reader never sees half of one. The
//! handler writes `applications/<token>.json` (the record the status page
//! renders) and `intents/<id>.json` (the one filed application). It never writes
//! anything root-owned.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: &str) -> Store {
        Store {
            root: PathBuf::from(root),
        }
    }

    pub async fn read_text(path: &str) -> Result<String, String> {
        tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("cannot read {path}: {e}"))
    }

    /// Read a record, `None` when it is not there. A missing record and an
    /// expired one are the same to the caller, which is what keeps the status
    /// path from being a token oracle.
    pub async fn read_record(&self, dir: &str, name: &str) -> Option<String> {
        tokio::fs::read_to_string(self.root.join(dir).join(name))
            .await
            .ok()
    }

    /// Write one record by rename: a temporary file in the same directory, then
    /// the rename, so a reader never sees half of one and a crash leaves the
    /// temporary file rather than a truncated record. The file is created 0600,
    /// so the umask cannot widen the applicant's own words, keys and outside
    /// address beyond the account that wrote them and root.
    pub async fn write_record(&self, dir: &str, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.write_record_owned(dir, name, bytes, None).await
    }

    /// Like `write_record`, and additionally hands the placed file to `owner`
    /// (uid, gid) before the rename. The drain uses this for the one file it
    /// writes into a directory the unprivileged handler owns: `applications/`,
    /// where a root-created file at 0600 would take the record away from the
    /// process that renders the status page. Everywhere else the writer's own
    /// identity is the right one.
    ///
    /// The temporary is opened with `create_new` (O_CREAT|O_EXCL), so a symlink
    /// planted at its name by the unprivileged half is refused rather than
    /// followed, and O_NOFOLLOW is set on top as belt and braces. A stale
    /// temporary left by an interrupted run is removed first, which is safe
    /// because it can only be one this code left.
    pub async fn write_record_owned(
        &self,
        dir: &str,
        name: &str,
        bytes: &[u8],
        owner: Option<(u32, u32)>,
    ) -> Result<(), String> {
        let d = self.root.join(dir);
        let tmp = d.join(format!(".{name}.tmp"));
        let target = d.join(name);
        let _ = tokio::fs::remove_file(&tmp).await;
        let placed = async {
            let mut opts = tokio::fs::OpenOptions::new();
            opts.write(true).create_new(true).mode(0o600);
            opts.custom_flags(libc::O_NOFOLLOW);
            let mut f = opts.open(&tmp).await?;
            f.write_all(bytes).await?;
            f.sync_all().await?;
            drop(f);
            // chown needs root, and only root ever needs to hand the file to
            // another owner: a test runs as the directory's own owner already.
            if let Some((uid, gid)) = owner {
                if unsafe { libc::geteuid() } == 0 {
                    std::os::unix::fs::chown(&tmp, Some(uid), Some(gid))?;
                }
            }
            tokio::fs::rename(&tmp, &target).await
        }
        .await;
        placed.map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("cannot place a record in {}: {e}", d.display())
        })
    }

    /// The names in one directory, sorted. A missing directory reads as empty,
    /// which is what a first run against a fresh store is: no intents, no
    /// journal, no notices, and none of those is an error to a reader.
    pub async fn list(&self, dir: &str) -> Result<Vec<String>, String> {
        let d = self.root.join(dir);
        let mut rd = match tokio::fs::read_dir(&d).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("cannot read {}: {e}", d.display())),
        };
        let mut out = Vec::new();
        while let Some(entry) = rd
            .next_entry()
            .await
            .map_err(|e| format!("cannot read {}: {e}", d.display()))?
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            // A temporary left by an interrupted write is not a record.
            if name.starts_with('.') {
                continue;
            }
            out.push(name);
        }
        out.sort();
        Ok(out)
    }

    /// Append one line to a store file, creating it 0600 and its directory if
    /// needed. Append is the only write the journal, the notices and the ledger
    /// use: none of the three is ever rewritten, which is what makes them a
    /// record rather than a state.
    pub async fn append(&self, path: &str, bytes: &[u8]) -> Result<(), String> {
        let p = self.root.join(path);
        if let Some(parent) = p.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let mut line = bytes.to_vec();
        if !line.ends_with(b"\n") {
            line.push(b'\n');
        }
        let placed = async {
            let mut f = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&p)
                .await?;
            f.write_all(&line).await?;
            f.sync_all().await
        }
        .await;
        placed.map_err(|e| format!("cannot append to {}: {e}", p.display()))
    }

    /// Create a directory under the root with its parents, 0700. The mode is
    /// passed to `DirBuilder` rather than left to the umask, so the comment and
    /// the code cannot disagree; an existing directory keeps the mode
    /// `scripts/onboard-store.sh` gave it.
    pub async fn ensure_dir(&self, dir: &str) -> Result<(), String> {
        let d = self.root.join(dir);
        let mut builder = tokio::fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder
            .create(&d)
            .await
            .map_err(|e| format!("cannot create {}: {e}", d.display()))
    }

    /// The owner of a directory under the store. The drain uses this to write
    /// into a directory the handler owns without taking the file away from it.
    pub fn dir_owner(&self, dir: &str) -> Option<(u32, u32)> {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(self.root.join(dir)).ok()?;
        Some((md.uid(), md.gid()))
    }

    /// Remove one record. A record that is not there reads as done, so a purge
    /// that is interrupted and rerun completes rather than failing on the files
    /// it already cleared.
    pub async fn remove(&self, dir: &str, name: &str) -> Result<(), String> {
        let p = self.root.join(dir).join(name);
        match tokio::fs::remove_file(&p).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("cannot remove a record in {}: {e}", self.root.join(dir).display())),
        }
    }

    /// The non-empty lines of a store file, with a missing file reading as
    /// nothing.
    pub async fn lines(&self, path: &str) -> Vec<String> {
        match tokio::fs::read_to_string(self.root.join(path)).await {
            Ok(s) => s
                .lines()
                .map(|l| l.trim_end().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

/// A key as the store carries it: the fingerprint the walkthrough computed in
/// the browser beside the material it was computed over, and the structural
/// verdict this handler reached without hashing anything.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRecord {
    /// The mailbox an upload key belongs to, or the mailbox a mail key serves.
    /// Empty for a person's single address.
    pub mailbox: String,
    /// The fingerprint of the material beside it, computed by the handler from
    /// that material rather than taken as a number the client sends: the OpenPGP
    /// fingerprint for a mail key, the SSH one for an upload key. Storing what
    /// was hashed is what keeps a number from naming a key it was not computed
    /// from, and the reviewer sees it beside the material it names while the
    /// drain rechecks before anything is carried out.
    pub fingerprint: String,
    /// The armoured key as submitted.
    pub material: String,
    /// What the structural check here found: "works" or "no encryption subkey".
    pub verdict: String,
}

/// One document accepted, with the version accepted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Acceptance {
    pub document: String,
    pub version: String,
}

/// The filed application. This is `applications/<token>.json`, and it is what
/// the status page renders and what the intent is built from.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub username: String,
    pub status_token: String,
    pub filed_at: String,
    /// Which front end filed this: web, tui or capsule. A label and not a
    /// privilege, so nothing here reads it; the reviewer sees it.
    pub front_end: String,
    /// received | with the reviewer | decided. The handler writes `received`;
    /// only the drain moves it on.
    pub stage: String,
    /// When the drain decided the application, RFC 3339. The drain sets it,
    /// which is the half the status route's seven-day window is read from: the
    /// handler writes nothing here and has no way to. A record without it has
    /// not been decided yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<String>,
    /// The one-time link that sets a mail password, written by the drain for an
    /// applicant who gave no address outside the platform and so cannot be sent
    /// one. The drain signs it; the handler neither signs nor verifies one and
    /// only renders what it finds here, and renders nothing when there is none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outside_address: Option<String>,
    /// Every applicable answer, keyed by the question list's ids.
    pub answers: BTreeMap<String, String>,
    pub mail_keys: Vec<KeyRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_key: Option<KeyRecord>,
    pub rail: String,
    pub no_charge: bool,
    pub acceptances: Vec<Acceptance>,
    /// The version of the question list the application was answered against.
    /// This release carries the deployed commit and date rather than a hash of
    /// the file: no hashing crate is in the build, the list is deployed with the
    /// release, and a version that is a commit is one the drain can look up.
    pub question_list: String,
}

/// The application intent, the fields the spec lists under "An application
/// intent holds". Built from the record and written once, at file time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Intent {
    pub id: String,
    pub kind: String,
    pub filed_at: String,
    pub front_end: String,
    pub application: ApplicationRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outside_address: Option<String>,
    pub answers: BTreeMap<String, String>,
    pub mail_keys: Vec<KeyRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_key: Option<KeyRecord>,
    pub rail: String,
    pub no_charge: bool,
    pub acceptances: Vec<Acceptance>,
    pub question_list: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationRef {
    pub username: String,
    pub status_token: String,
}

impl Record {
    /// The intent for a filed application. `id` is the ULID the directory sorts
    /// by.
    pub fn intent(&self, id: &str) -> Intent {
        Intent {
            id: id.to_string(),
            kind: "application".to_string(),
            filed_at: self.filed_at.clone(),
            front_end: self.front_end.clone(),
            application: ApplicationRef {
                username: self.username.clone(),
                status_token: self.status_token.clone(),
            },
            domain: self.domain.clone(),
            outside_address: self.outside_address.clone(),
            answers: self.answers.clone(),
            mail_keys: self.mail_keys.clone(),
            upload_key: self.upload_key.clone(),
            rail: self.rail.clone(),
            no_charge: self.no_charge,
            acceptances: self.acceptances.clone(),
            question_list: self.question_list.clone(),
        }
    }
}

/// The status token: 128 bits of lowercase Crockford base32, drawn from the
/// kernel pool. It is a bearer capability, so it is 128 real bits of randomness
/// and not a ULID: a ULID spends 48 of its bits on a timestamp, which a
/// capability must not do.
pub async fn status_token() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    let mut f = tokio::fs::File::open("/dev/urandom")
        .await
        .map_err(|e| format!("cannot open /dev/urandom: {e}"))?;
    f.read_exact(&mut bytes)
        .await
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
    Ok(crockford128(bytes))
}

/// A 128-bit value as 26 lowercase Crockford base32 characters. The same
/// encoding the ULID carries, so the two tokens sit in one alphabet in a URL.
fn crockford128(bytes: [u8; 16]) -> String {
    const A: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let v = u128::from_be_bytes(bytes);
    let mut out = String::with_capacity(26);
    for i in (0..26).rev() {
        out.push(A[((v >> (5 * i)) & 31) as usize] as char);
    }
    out
}

/// The status token's shape, checked before a token is used as a path or looked
/// up: 26 lowercase Crockford characters, which is 128 bits.
pub fn is_status_token(token: &str) -> bool {
    token.len() == 26
        && token
            .bytes()
            .all(|b| b"0123456789abcdefghjkmnpqrstvwxyz".contains(&b))
}

/// The payment token, `KYR-` and twelve Crockford characters in three groups of
/// four, e.g. `KYR-4F2M-9QH7-XT3B`. Twelve characters at five bits each are 60
/// bits, drawn here from the same kernel pool the status token uses: the token
/// is a bearer secret and must not be derived from anything about the member,
/// which is what keeps the ledger unlinkable once the account is gone.
///
/// The masking is bias-free because 2^60 is an exact multiple of 32, so every
/// five-bit group of the low 60 bits of a uniform 64-bit draw is uniform.
pub async fn payment_token() -> Result<String, String> {
    let mut bytes = [0u8; 8];
    let mut f = tokio::fs::File::open("/dev/urandom")
        .await
        .map_err(|e| format!("cannot open /dev/urandom: {e}"))?;
    f.read_exact(&mut bytes)
        .await
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
    Ok(crockford12(u64::from_be_bytes(bytes) & ((1 << 60) - 1)))
}

/// Twelve Crockford characters, grouped four-four-four, with the `KYR-` prefix
/// the spec fixes. Uppercase, because that is how the spec writes the example
/// and how a token read off an envelope is meant to read; Crockford itself is
/// case-insensitive, so a member may write it either way and the store holds
/// one canonical form.
fn crockford12(v: u64) -> String {
    const A: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut body = String::with_capacity(14);
    for i in (0..12).rev() {
        body.push(A[((v >> (5 * i)) & 31) as usize] as char);
    }
    format!("KYR-{}-{}-{}", &body[0..4], &body[4..8], &body[8..12])
}

/// Whether a value is the shape of a payment token, for revalidation before a
/// token reaches the ledger or a file name.
pub fn is_payment_token(token: &str) -> bool {
    let b = token.as_bytes();
    if b.len() != 18 || &b[..4] != b"KYR-" {
        return false;
    }
    for (i, c) in b.iter().enumerate().skip(4) {
        // The two inner hyphens of `KYR-XXXX-XXXX-XXXX`; everything else is
        // Crockford, which is what makes a token read off paper unambiguous.
        if i == 8 || i == 13 {
            if *c != b'-' {
                return false;
            }
        } else if !b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c) {
            return false;
        }
    }
    true
}

/// The account record, `accounts/<username>/account.json`. It holds what this
/// ticket writes and is deliberately open to the fields later tickets add: the
/// rails put `payment.*`, the group tier puts a `group` reference, and neither
/// is a reason to re-read this shape. So there is no `deny_unknown_fields` here,
/// unlike the configs: an account written by a later release must still be
/// readable by this one, and the reverse.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub version: u32,
    pub username: String,
    /// `active` after an approval; the lifecycle's other states are #153's.
    pub state: String,
    /// `approve` or `decline`, and never why: an account the reviewer gave
    /// without charge records only that it is free.
    pub decision: String,
    pub decided_at: String,
    /// The rail the member chose, or `no_charge`.
    pub rail: String,
    pub no_charge: bool,
    pub created_at: String,
    /// The payment token, present only on a paid approval. A bearer secret: it
    /// is never logged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_issued_at: Option<String>,
    /// Null while the window runs, which is the state a paid approval opens in.
    /// The free path has no window and leaves this null too: nothing lapses
    /// without a window.
    pub paid_until: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<Window>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outside_address: Option<String>,
}

/// The 14-day payment window a paid approval opens.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Window {
    pub opened_at: String,
    pub closes_at: String,
    /// `open`, `closed` or `paid`; the window's own transitions are #302's.
    pub state: String,
    pub extensions: u32,
}

/// `tokens/<token>.json`, the join from a token to an account. Created at a paid
/// approval and deleted with the account, which is what makes the ledger's row
/// unlinkable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRecord {
    pub token: String,
    pub username: String,
    pub issued_at: String,
    pub window_closes_at: String,
    pub state: String,
}

/// One line of `journal.jsonl`. Appended before a transition is carried out, so
/// a crash leaves a record a rerun can read; and appended again, with a
/// different `outcome`, when a click finds the application already decided,
/// which is how the journal records that a replay was seen.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JournalLine {
    pub version: u32,
    pub at: String,
    /// The intent that caused this line, which is also the dedup key.
    pub intent: String,
    pub kind: String,
    /// The deployed release the drain was running, so a transition can be
    /// traced to the build that carried it out.
    pub release: String,
    /// The application the line concerns, by username and status token.
    pub application: ApplicationRef,
    /// `applying`, `applied`, `already-decided`, `refused`, `review-sent` or
    /// `purged`.
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One line of an account's `notices.jsonl`: recorded before the message is
/// enqueued, so a crash loses an email rather than sending two. The dedup key is
/// the pair of `type` and `subject`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notice {
    pub version: u32,
    pub at: String,
    #[serde(rename = "type")]
    pub notice_type: String,
    pub subject: String,
    /// The address it went to, so the account page is an audit of what the
    /// platform told the member and where.
    pub to: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_128_bit_token_is_26_crockford_characters() {
        let t = status_token().await.unwrap();
        assert_eq!(t.len(), 26, "{t}");
        assert!(t
            .bytes()
            .all(|b| b"0123456789abcdefghjkmnpqrstvwxyz".contains(&b)));
        // Crockford leaves out I, L, O and U, so no token can carry one.
        assert!(!t.contains(['i', 'l', 'o', 'u']));
        assert_ne!(t, status_token().await.unwrap());
    }

    #[test]
    fn crockford_pads_at_the_high_end_like_a_ulid() {
        assert_eq!(crockford128([0u8; 16]), "0".repeat(26));
        assert_eq!(
            crockford128([0xffu8; 16]),
            format!("7{}", "z".repeat(25))
        );
    }

    #[tokio::test]
    async fn a_record_is_written_by_rename_at_0600_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("onboard-store-test-{}", std::process::id()));
        let apps = dir.join("applications");
        std::fs::create_dir_all(&apps).unwrap();
        let store = Store::new(dir.to_str().unwrap());
        store
            .write_record("applications", "tok.json", b"{\"a\":1}")
            .await
            .unwrap();
        assert_eq!(
            store.read_record("applications", "tok.json").await.as_deref(),
            Some("{\"a\":1}")
        );
        // The umask did not widen it.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(apps.join("tok.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "record mode is {mode:o}");
        // No temporary file is left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&apps)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "left a temporary file");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_missing_record_is_none_not_an_error() {
        let store = Store::new("/tmp");
        assert!(store.read_record("applications", "nope.json").await.is_none());
    }

    #[tokio::test]
    async fn a_payment_token_is_kyr_and_twelve_crockford_characters() {
        let t = payment_token().await.unwrap();
        assert_eq!(t.len(), 18, "{t}");
        assert!(t.starts_with("KYR-"), "{t}");
        assert!(is_payment_token(&t), "{t}");
        assert!(!t.contains(['I', 'L', 'O', 'U']), "{t}");
        assert!(
            t[4..].chars().all(|c| c == '-' || c.is_ascii_uppercase() || c.is_ascii_digit()),
            "{t}"
        );
        assert_ne!(t, payment_token().await.unwrap());
    }

    #[test]
    fn the_payment_token_shape_is_checked_positively() {
        assert!(is_payment_token("KYR-4F2M-9QH7-XT3B"));
        for bad in [
            "KYR-4F2M-9QH7-XT3",
            "KYR-4F2M-9QH7-XT3BB",
            "KYR4F2M-9QH7-XT3B",
            "KYR-4F2M-9QH7-XT3I",
            "KYR-4F2M9QH7-XT3B",
            "kyr-4f2m-9qh7-xt3b",
        ] {
            assert!(!is_payment_token(bad), "{bad:?} should be refused");
        }
    }

    #[test]
    fn the_status_token_shape_is_checked_positively() {
        assert!(is_status_token("0123456789abcdefghjkmnpqrs"));
        assert!(!is_status_token("0123456789abcdefghjkmnpqrst"));
        assert!(!is_status_token("0123456789abcdefghjkmnpqrsT"));
    }

    #[tokio::test]
    async fn a_store_file_appends_and_reads_back_line_by_line() {
        let dir = std::env::temp_dir().join(format!("onboard-append-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.to_str().unwrap());
        assert!(store.lines("journal.jsonl").await.is_empty(), "missing reads as empty");
        store.append("journal.jsonl", b"{\"a\":1}").await.unwrap();
        store.append("journal.jsonl", b"{\"a\":2}\n").await.unwrap();
        assert_eq!(store.lines("journal.jsonl").await, vec!["{\"a\":1}", "{\"a\":2}"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
