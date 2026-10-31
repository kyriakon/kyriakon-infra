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

/// The queue money with no token is held in, append-only except for the one
/// line `reconcile` completes under its lock.
pub const UNATTRIBUTED: &str = "ledger/unattributed.jsonl";

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: &str) -> Store {
        Store {
            root: PathBuf::from(root),
        }
    }

    /// The absolute path of one store path, for a caller that has to open the
    /// file itself. The request record takes its lock on a path, not on a handle.
    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
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

    /// The account a pinned client certificate belongs to, or `None` when no
    /// account carries the hash.
    ///
    /// The scan reads each `account.json` rather than an index beside the pins:
    /// an index would be a second list that can disagree with the account, and
    /// the account directory is small enough that one read answers it. An
    /// account that cannot be read is skipped rather than failing the lookup,
    /// so a damaged record answers anonymously instead of breaking the page
    /// for everyone.
    pub async fn account_for_certificate(&self, hash: &str) -> Option<Account> {
        if hash.is_empty() {
            return None;
        }
        for username in self.list("accounts").await.ok()? {
            let Some(text) = self
                .read_record(&format!("accounts/{username}"), "account.json")
                .await
            else {
                continue;
            };
            let Ok(account) = serde_json::from_str::<Account>(&text) else {
                continue;
            };
            if account.certificates.iter().any(|c| c.hash == hash) {
                return Some(account);
            }
        }
        None
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
    /// needed. Append is the write the journal, the notices and the ledger use.
    /// A record is never rewritten except to complete a line that has to be
    /// completed later, under the lock `transitions::lock_store_file` takes, as
    /// a request close and a refund settlement do.
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
            Err(e) => Err(format!(
                "cannot remove a record in {}: {e}",
                self.root.join(dir).display()
            )),
        }
    }

    /// The unattributed queue, one held payment per line. A missing file reads
    /// as empty; a read error or a line that does not parse is an error, because
    /// `reconcile list` must not report a clear queue it cannot read.
    pub async fn held(&self) -> Result<Vec<HeldItem>, String> {
        let abs = self.root.join(UNATTRIBUTED);
        let text = match tokio::fs::read_to_string(&abs).await {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("cannot read {}: {e}", abs.display())),
        };
        let mut out = Vec::new();
        for (i, line) in text
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty())
            .enumerate()
        {
            out.push(
                serde_json::from_str(line)
                    .map_err(|e| format!("{UNATTRIBUTED}: line {} does not parse: {e}", i + 1))?,
            );
        }
        Ok(out)
    }

    /// The JSON lines of a record, strictly: a missing file is empty, but an
    /// unreadable file or a line that does not parse is an error rather than an
    /// empty result. A reader that reports "nothing" for a record it could not
    /// read is a check that cannot see what it is checking.
    pub async fn json_lines(&self, path: &str) -> Result<Vec<serde_json::Value>, String> {
        let abs = self.root.join(path);
        let text = match tokio::fs::read_to_string(&abs).await {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("cannot read {}: {e}", abs.display())),
        };
        let mut out = Vec::new();
        for (i, line) in text
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty())
            .enumerate()
        {
            out.push(
                serde_json::from_str(line)
                    .map_err(|e| format!("{path}: line {} does not parse: {e}", i + 1))?,
            );
        }
        Ok(out)
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

/// A key as the store carries it: the fingerprint computed here over the
/// material it names, and the verdict the shared key check reached from that
/// material rather than from anything the client sends.
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
    /// What the check found: "works" when the shared inspection returns
    /// nothing, its findings joined when one or more trips, and "unchecked"
    /// when there is no PGP block to inspect: an upload key, or a mail key the
    /// check cannot frame. Never a value the client sends.
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
    /// The payment block the drain copied here at approval, so the status page
    /// can show the token without reading the root-owned account. Absent until
    /// the drain approves, and absent for a free approval, which has no block
    /// anywhere: that absence is also what stops an undecided application,
    /// which names whatever username its applicant typed, showing an account's
    /// payment state. A credit updates it beside the account (#300).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment: Option<Payment>,
    /// Every applicable answer, keyed by the question list's ids.
    pub answers: BTreeMap<String, String>,
    pub mail_keys: Vec<KeyRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_key: Option<KeyRecord>,
    pub rail: String,
    pub no_charge: bool,
    /// When the confirmation email left, RFC 3339. It is written before the
    /// enqueue, so a retry of the same approval sends no second copy. The notice
    /// cannot be recorded in `accounts/<username>/notices.jsonl` the way every
    /// later notice is, because the account does not exist yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_at: Option<String>,
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

/// The unattributed payment id, `UN-` and eight Crockford characters, e.g.
/// `UN-3K7QW2M9`. It is the handle `reconcile attribute` and `reconcile return`
/// take, drawn from the kernel pool beside the payment token and for the same
/// reason: an id derived from the date or the amount would be one the operator
/// could guess, and this one names money that has no member yet.
///
/// Eight characters at five bits each are 40 bits, and 2^40 is an exact
/// multiple of 32, so masking the low 40 bits of a uniform 64-bit draw is
/// bias-free.
pub async fn unattributed_id() -> Result<String, String> {
    let mut bytes = [0u8; 8];
    let mut f = tokio::fs::File::open("/dev/urandom")
        .await
        .map_err(|e| format!("cannot open /dev/urandom: {e}"))?;
    f.read_exact(&mut bytes)
        .await
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
    Ok(crockford8(u64::from_be_bytes(bytes) & ((1 << 40) - 1)))
}

fn crockford8(v: u64) -> String {
    const A: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut body = String::with_capacity(11);
    for i in (0..8).rev() {
        body.push(A[((v >> (5 * i)) & 31) as usize] as char);
    }
    format!("UN-{body}")
}

/// Whether a value is the shape of an unattributed payment id, checked before
/// it is used to find a line in the queue.
pub fn is_unattributed_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 11
        && &b[..3] == b"UN-"
        && b[3..]
            .iter()
            .all(|c| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c))
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
/// group tier puts a `group` reference, the rails put a Monero subaddress and a
/// balance beside the payment block, and neither is a reason to re-read this
/// shape. So there is no `deny_unknown_fields` here, unlike the configs: an
/// account written by a later release must still be readable by this one, and
/// the reverse.
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
    /// The payment state, present only on a paid approval. A free account has
    /// no window, no token and no payment block at all, which is why this is an
    /// absent field rather than a block of nulls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment: Option<Payment>,
    /// The flat shape the account carried before the payment block existed,
    /// read and folded into [`Account::payment_state`] and never written back.
    /// Without it a record written by the previous release reads as unpaid: its
    /// token, window and paid-until date would be dropped on the next rewrite,
    /// which for a token is the only link between a payment and its account.
    #[serde(flatten, default, skip_serializing)]
    pub legacy_payment: FlatPayment,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outside_address: Option<String>,
    /// The gemini client certificates pinned to this account, one per device.
    /// A request whose `TLS_CLIENT_HASH` matches one of these is this member;
    /// the hash is over the certificate, so a reissued certificate is a new
    /// entry rather than a preserved one.
    #[serde(default)]
    pub certificates: Vec<Certificate>,
    /// Whether the drain is serving the member's site and capsule, and the bytes
    /// used under the quota. Nothing writes these yet: they are absent until the
    /// hosting side records them, which the capsule renders as exactly that.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_served: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capsule_served: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_used: Option<u64>,
    /// The domain of the group this account belongs to, for a mailbox the
    /// own-domain tier made. The group holds the payment state, so an account
    /// with this set carries no payment block of its own. `None` for a person's
    /// account, and absent from the file, so a record written before this field
    /// existed reads the same.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// The day a cancellation refund's seven-day closing window ends, `YYYY-MM-DD`.
    /// Written only by a `--close` refund, which sets `state` to `closing`; an
    /// excess refund and every other transition leave it absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closing_until: Option<String>,
}

/// One pinned client certificate, as a request described it.
///
/// The hash is the identity. The subject, issuer and validity dates are
/// recorded beside it and are never consulted for a decision: a gemini client
/// certificate is self-signed, so anyone can mint any subject or issuer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Certificate {
    /// `TLS_CLIENT_HASH`: the algorithm and the certificate's digest, which is
    /// the only field a pin is matched on.
    pub hash: String,
    /// `REMOTE_USER`, the subject the certificate claims.
    pub subject: String,
    /// `TLS_CLIENT_ISSUER`, which on a self-signed certificate is that same
    /// claim again.
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
}

/// One address in a group's table: the localpart on the body's domain, and the
/// account its virtual entry points at.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupAddress {
    pub address: String,
    pub mailbox: String,
}

/// The payment block `groups/<domain>/group.json` carries: the rail the
/// application chose, whether it was approved without charge, the date the
/// group's single renewal sets, and the card rail's subscription once one is
/// attached. The group holds the payment for every mailbox in it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupPayment {
    pub rail: String,
    pub no_charge: bool,
    pub paid_until: Option<String>,
    /// The card rail's subscription, when one is attached. Absent on a prepaid
    /// or free group, and absent from a record written before the webhook pass.
    #[serde(default)]
    pub stripe: StripeBilling,
}

/// `groups/<domain>/group.json`: one body's record. The name and kind are the
/// body's own words, used to address it in notices; the accounts are the
/// mailboxes, and the site owner is the account whose public tree holds the
/// site.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupRecord {
    pub version: u32,
    pub domain: String,
    pub name: String,
    pub kind: String,
    pub payment: GroupPayment,
    pub accounts: Vec<String>,
    pub site_owner: String,
}

/// The `provision-group` intent: everything the drain needs to make one body's
/// domain live, filed by the approval and applied in one idempotent pass.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub application: ApplicationRef,
    pub domain: String,
    /// The body's name and kind, as the community block answered them.
    pub name: String,
    pub body_kind: String,
    pub payment: GroupPayment,
    pub addresses: Vec<GroupAddress>,
    /// The mailbox accounts, one system account each.
    pub mailboxes: Vec<String>,
    pub site_owner: String,
    /// The block's upload key, installed into the site owner's
    /// `authorized_keys`. Empty when the body gave none, which leaves the site
    /// there to be filled only once a key is supplied.
    #[serde(default)]
    pub upload_key: String,
    /// One mail key per mailbox, keyed by the mailbox it serves.
    #[serde(default)]
    pub mail_keys: Vec<KeyRecord>,
}

/// The `group-address` intent: one address change inside a body's group, filed
/// by the reviewer's console and applied in one idempotent pass.
///
///   add-alias   one virtual entry pointing at an existing mailbox; nothing else.
///   add-mailbox one account, its key and its virtual entry, inside the cap.
///   upgrade     an alias becomes a mailbox: the same entry is repointed.
///   remove      one mailbox's account, key, quota line and virtual entries.
///
/// It carries a signature over every field the drain acts on, because
/// `intents/` is writable by the unprivileged handler and this is root work:
/// without one, a compromised handler could file a mailbox or a removal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupAddressIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub domain: String,
    /// `add-alias`, `add-mailbox`, `upgrade` or `remove`.
    pub action: String,
    /// The address's localpart. Unused for `remove`, which names the mailbox.
    #[serde(default)]
    pub address: String,
    /// The mailbox the change concerns: the alias target, the new account, or
    /// the account being removed.
    pub mailbox: String,
    /// The key a new mailbox carries. Required by `add-mailbox` and `upgrade`.
    #[serde(default)]
    pub mail_key: Option<KeyRecord>,
    /// The account that takes the site when `remove` takes the current owner.
    #[serde(default)]
    pub site_owner: Option<String>,
    /// The HMAC-SHA256 of `sign::address_payload` under the approval key.
    pub sig: String,
}

/// The `remove-group` intent: take one body's domain down and close every
/// account in it. The console signs it, because the transition deletes accounts
/// and `intents/` is writable by the unprivileged handler.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupRemoveIntent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub filed_at: String,
    pub domain: String,
    /// The HMAC-SHA256 of `sign::group_remove_payload` under the approval key.
    pub sig: String,
}

/// The payment block `accounts/<username>/account.json` carries under
/// `payment`, named as the spec's State table names it. A paid approval writes
/// it, opens the window and draws the token; a credit sets `paid_until`, which
/// is what hides the token from both pages. `#[serde(default)]` so a block that
/// gains a field in a later release still reads here.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Payment {
    /// The payment token, present only on a paid approval. A bearer secret: it
    /// is never logged, and both pages show it only while `paid_until` is null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_issued_at: Option<String>,
    /// Null while the window runs, which is the state a paid approval opens in.
    pub paid_until: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<Window>,
    /// The rail the last credit arrived on, which stays visible on the account
    /// page after the token has gone. Absent until a credit sets it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rail: Option<String>,
    /// Money received beyond the yearly price, in pounds, spent by the next
    /// credit before it asks for more. Absent when nothing is held.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance_gbp: Option<String>,
    /// The card rail's own facts, attached by `checkout.session.completed` and
    /// reconciled by the subscription and invoice events. Absent until a card
    /// payment is heard, and absent from a prepaid or free account.
    #[serde(default)]
    pub stripe: StripeBilling,
}

/// What the card rail records on the account or group it belongs to. Nothing
/// here grants access: `paid_until` is the date, and this is the evidence of
/// which subscription sets it and what Stripe last said about it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StripeBilling {
    /// The subscription `checkout.session.completed` attached.
    pub subscription: Option<String>,
    /// The Customer Stripe made for the subscription.
    pub customer: Option<String>,
    /// The subscription's last reported status: `active`, `past_due`,
    /// `canceled`. Recorded and never the thing that revokes a paid date.
    pub status: Option<String>,
    /// Stripe's `current_period_end`, RFC 3339. `cancel_at_period_end` runs to
    /// this date and no further.
    pub current_period_end: Option<String>,
    /// The next retry a failed invoice named, RFC 3339.
    pub next_payment_attempt: Option<String>,
    /// How many payment attempts have failed since the last paid invoice.
    pub failed_attempts: u32,
    /// The invoice whose payment already extended `paid_until`, so a redelivery
    /// of that invoice settles nothing twice even if its event id is new.
    pub last_invoice: Option<String>,
}

/// The account's payment state, from the nested block or, for a record written
/// before that block existed, from the four flat fields the old shape carried.
/// The flat fields are read-only: the next write puts the block in their place.
impl Account {
    pub fn payment_state(&self) -> Option<Payment> {
        self.payment
            .clone()
            .or_else(|| self.legacy_payment.folded())
    }

    /// Approved without charge: no token, no window, nothing that lapses. A
    /// group mailbox carries the flag its group was approved with, but the
    /// group holds the payment, so the mailbox is not a free account itself.
    pub fn is_free(&self) -> bool {
        self.no_charge && self.group.is_none()
    }
}

/// The count of free accounts, for the console. One read per account. A store
/// that cannot be listed is an error rather than an empty one, and an account
/// that cannot be read is named on stderr and left out, so the number the
/// operator sees is never quietly wrong.
pub async fn free_account_count(store: &Store) -> Result<usize, String> {
    let names = store.list("accounts").await?;
    let mut free = 0;
    for username in names {
        let Some(text) = store
            .read_record(&format!("accounts/{username}"), "account.json")
            .await
        else {
            eprintln!(
                "kyriakon-onboard: accounts/{username}/account.json is unreadable, not counted"
            );
            continue;
        };
        let account: Account = match serde_json::from_str(&text) {
            Ok(account) => account,
            Err(e) => {
                eprintln!(
                    "kyriakon-onboard: accounts/{username}/account.json does not parse, not counted: {e}"
                );
                continue;
            }
        };
        if account.is_free() {
            free += 1;
        }
    }
    Ok(free)
}

/// The flat payment fields of an account written before the block existed.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct FlatPayment {
    pub token_ref: Option<String>,
    pub token_issued_at: Option<String>,
    pub paid_until: Option<String>,
    pub window: Option<Window>,
}

impl FlatPayment {
    /// The block the flat fields describe, or `None` when the record carried no
    /// payment state at all, which is the free account and the group mailbox.
    fn folded(&self) -> Option<Payment> {
        if self.token_ref.is_none()
            && self.token_issued_at.is_none()
            && self.paid_until.is_none()
            && self.window.is_none()
        {
            return None;
        }
        Some(Payment {
            token_ref: self.token_ref.clone(),
            token_issued_at: self.token_issued_at.clone(),
            paid_until: self.paid_until.clone(),
            window: self.window.clone(),
            rail: None,
            balance_gbp: None,
            stripe: StripeBilling::default(),
        })
    }
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

/// What a credit computed before it wrote the account: the date it was going to
/// set (or, for a shortfall, the date it left alone), what it applied and what
/// it held. A pass that crashed between the account write and the ledger append
/// reads these back, so it can finish the ledger line without extending the
/// date twice. Present only on a credit's `applying` journal line.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreditProgress {
    pub paid: bool,
    pub paid_until_after: Option<String>,
    pub applied_gbp: String,
    pub balance_gbp: Option<String>,
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
    /// The values a credit computed before it wrote the account, so a crash
    /// between the write and the ledger append is recoverable. Absent on every
    /// other line and on a credit's own `applied` line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credit: Option<CreditProgress>,
}

/// One line of `ledger/unattributed.jsonl`: money that could not be joined to
/// an account, held with its rail, amount, date and note. It names no member;
/// `attributed_to` is a token, never a username, because the ledger outlives the
/// account and the join is the token's to keep. The completion fields are
/// absent on a held line and written once, under the queue's lock, by
/// `reconcile`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HeldItem {
    pub version: u32,
    pub id: String,
    /// `held`, so the line's own name for what it is is visible in the file.
    pub kind: String,
    /// `held`, `attributed` or `returned`.
    pub state: String,
    pub rail: String,
    pub amount_gbp: String,
    pub received_on: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_xmr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    /// The intent that held it, which is also its dedup key.
    pub intent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributed_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returned_at: Option<String>,
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
        assert_eq!(crockford128([0xffu8; 16]), format!("7{}", "z".repeat(25)));
    }

    /// The certificate lookup: an empty hash answers nothing, an account whose
    /// record cannot be read is skipped rather than failing the page, and a
    /// pinned hash finds its account.
    #[tokio::test]
    async fn a_pinned_certificate_is_found_and_a_broken_record_is_skipped() {
        let dir = std::env::temp_dir().join(format!("onboard-store-cert-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("accounts/broken")).unwrap();
        std::fs::create_dir_all(dir.join("accounts/alice")).unwrap();
        std::fs::write(dir.join("accounts/broken/account.json"), "not json").unwrap();
        let account = serde_json::json!({
            "version": 1,
            "username": "alice",
            "state": "active",
            "decision": "approve",
            "decided_at": "2026-10-01T09:00:00Z",
            "rail": "no_charge",
            "no_charge": true,
            "created_at": "2026-10-01T09:00:00Z",
            "certificates": [{ "hash": "SHA256:aa" }],
        });
        std::fs::write(
            dir.join("accounts/alice/account.json"),
            serde_json::to_vec(&account).unwrap(),
        )
        .unwrap();
        let store = Store::new(dir.to_str().unwrap());

        assert!(
            store.account_for_certificate("").await.is_none(),
            "an empty hash names no account"
        );
        assert_eq!(
            store
                .account_for_certificate("SHA256:aa")
                .await
                .expect("the pinned account")
                .username,
            "alice"
        );
        assert!(
            store.account_for_certificate("SHA256:bb").await.is_none(),
            "an unpinned hash answers nothing"
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
            store
                .read_record("applications", "tok.json")
                .await
                .as_deref(),
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
        assert!(store
            .read_record("applications", "nope.json")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn a_payment_token_is_kyr_and_twelve_crockford_characters() {
        let t = payment_token().await.unwrap();
        assert_eq!(t.len(), 18, "{t}");
        assert!(t.starts_with("KYR-"), "{t}");
        assert!(is_payment_token(&t), "{t}");
        assert!(!t.contains(['I', 'L', 'O', 'U']), "{t}");
        assert!(
            t[4..]
                .chars()
                .all(|c| c == '-' || c.is_ascii_uppercase() || c.is_ascii_digit()),
            "{t}"
        );
        assert_ne!(t, payment_token().await.unwrap());
    }

    /// The queue's handle is `UN-` and eight uppercase Crockford characters: no
    /// lowercase, and none of the letters Crockford leaves out.
    #[tokio::test]
    async fn an_unattributed_id_is_un_and_eight_crockford_characters() {
        let id = unattributed_id().await.unwrap();
        assert_eq!(id.len(), 11, "{id}");
        assert!(id.starts_with("UN-"), "{id}");
        assert!(is_unattributed_id(&id), "{id}");
        assert!(!id[3..].contains(['I', 'L', 'O', 'U']), "{id}");
        assert_ne!(id, unattributed_id().await.unwrap());
        for bad in [
            "UN-3K7QW2M",
            "UN-3K7QW2M9X",
            "un-3k7qw2m9",
            "UN3K7QW2M9",
            "UN-3K7QW2M-",
            "UN-3K7QW2MI",
        ] {
            assert!(!is_unattributed_id(bad), "{bad:?} should be refused");
        }
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

    /// A record written before the payment block existed keeps its token: the
    /// flat fields are folded into the block on read, and a free account, whose
    /// flat fields were all null, folds to nothing.
    #[test]
    fn an_account_written_before_the_payment_block_still_reads_its_token() {
        let old: Account = serde_json::from_str(
            r#"{"version": 1, "username": "alice", "state": "active",
                "decision": "approve", "decided_at": "2026-10-01T09:00:00Z",
                "rail": "cash", "no_charge": false,
                "created_at": "2026-10-01T09:00:00Z",
                "token_ref": "KYR-4F2M-9QH7-XT3B",
                "token_issued_at": "2026-10-01T09:00:00Z",
                "paid_until": null,
                "window": {"opened_at": "2026-10-01T09:00:00Z",
                           "closes_at": "2026-10-15T09:00:00Z",
                           "state": "open", "extensions": 0}}"#,
        )
        .unwrap();
        let payment = old.payment_state().expect("the old shape's block");
        assert_eq!(payment.token_ref.as_deref(), Some("KYR-4F2M-9QH7-XT3B"));
        assert_eq!(
            payment.window.as_ref().map(|w| w.closes_at.as_str()),
            Some("2026-10-15T09:00:00Z")
        );
        // The flat fields are read-only: a rewrite keeps the block alone.
        let written = serde_json::to_string(&old).unwrap();
        assert!(!written.contains("\"token_ref\""), "{written}");
        assert!(!written.contains("\"paid_until\""), "{written}");

        let free: Account = serde_json::from_str(
            r#"{"version": 1, "username": "alice", "state": "active",
                "decision": "provision", "decided_at": "2026-10-01T09:00:00Z",
                "rail": "no_charge", "no_charge": true,
                "created_at": "2026-10-01T09:00:00Z", "paid_until": null}"#,
        )
        .unwrap();
        assert!(free.payment_state().is_none());
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
        assert!(
            store.lines("journal.jsonl").await.is_empty(),
            "missing reads as empty"
        );
        store.append("journal.jsonl", b"{\"a\":1}").await.unwrap();
        store.append("journal.jsonl", b"{\"a\":2}\n").await.unwrap();
        assert_eq!(
            store.lines("journal.jsonl").await,
            vec!["{\"a\":1}", "{\"a\":2}"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
