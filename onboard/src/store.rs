//! The store: the two shared files read at the top, the records written under
//! the root, and the on-disk shapes the drain reads.
//!
//! Every record is written by rename, so a reader never sees half of one. The
//! handler writes `applications/<token>.json` (the record the status page
//! renders) and `intents/<id>.json` (the one filed application). It never writes
//! anything root-owned.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: &str) -> Store {
        Store {
            root: PathBuf::from(root),
        }
    }

    pub fn read_text(path: &str) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))
    }

    /// Read a record, `None` when it is not there. A missing record and an
    /// expired one are the same to the caller, which is what keeps the status
    /// path from being a token oracle.
    pub fn read_record(&self, dir: &str, name: &str) -> Option<String> {
        std::fs::read_to_string(self.root.join(dir).join(name)).ok()
    }

    /// Write one record by rename: a temporary file in the same directory, then
    /// the rename, so a reader never sees half of one and a crash leaves the
    /// temporary file rather than a truncated record.
    pub fn write_record(&self, dir: &str, name: &str, bytes: &[u8]) -> Result<(), String> {
        let d = self.root.join(dir);
        let tmp = d.join(format!(".{name}.tmp"));
        let target = d.join(name);
        let placed = std::fs::File::create(&tmp)
            .and_then(|mut f| f.write_all(bytes).and_then(|_| f.sync_all()))
            .and_then(|_| std::fs::rename(&tmp, &target));
        placed.map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("cannot place {}: {e}", target.display())
        })
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
    /// The fingerprint the walkthrough computed in the browser. It is stored and
    /// never recomputed here, and the next reader will want to know why: the
    /// handler holds no crypto and no hash, so recomputing an OpenPGP
    /// fingerprint would mean a second, divergent implementation of the check
    /// #185 already runs. The reviewer sees both the browser's number and the
    /// material it names, and the drain rechecks before anything is carried out.
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
    pub front_end: String,
    /// received | with the reviewer | decided. The handler writes `received`;
    /// only the drain moves it on.
    pub stage: String,
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
#[derive(Clone, Debug, Serialize)]
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

#[derive(Clone, Debug, Serialize)]
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
pub fn status_token() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_128_bit_token_is_26_crockford_characters() {
        let t = status_token().unwrap();
        assert_eq!(t.len(), 26, "{t}");
        assert!(t
            .bytes()
            .all(|b| b"0123456789abcdefghjkmnpqrstvwxyz".contains(&b)));
        // Crockford leaves out I, L, O and U, so no token can carry one.
        assert!(!t.contains(['i', 'l', 'o', 'u']));
        assert_ne!(t, status_token().unwrap());
    }

    #[test]
    fn crockford_pads_at_the_high_end_like_a_ulid() {
        assert_eq!(crockford128([0u8; 16]), "0".repeat(26));
        assert_eq!(
            crockford128([0xffu8; 16]),
            format!("7{}", "z".repeat(25))
        );
    }

    #[test]
    fn a_record_is_written_by_rename_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("onboard-store-test-{}", std::process::id()));
        let apps = dir.join("applications");
        std::fs::create_dir_all(&apps).unwrap();
        let store = Store::new(dir.to_str().unwrap());
        store.write_record("applications", "tok.json", b"{\"a\":1}").unwrap();
        assert_eq!(store.read_record("applications", "tok.json").as_deref(), Some("{\"a\":1}"));
        // No temporary file is left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&apps)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "left a temporary file");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_record_is_none_not_an_error() {
        let store = Store::new("/tmp");
        assert!(store.read_record("applications", "nope.json").is_none());
    }
}
