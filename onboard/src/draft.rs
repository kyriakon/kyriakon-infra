//! The capsule's draft: the answers so far and the page cursor.
//!
//! A draft is `drafts/<token>.json`, and the token is the same 128-bit
//! capability the status link carries. The capsule writes one answer per request
//! and redirects to the next page with the query dropped, so the record is the
//! only place an answer is kept: the URL the client follows holds none.
//!
//! The record is deliberately open to fields later tickets add, as the account
//! record is. The key fingerprints and verdicts arrive with the key page; the
//! mail route writes them here too, because a key mailed to `apply@` must reach
//! the same draft the applicant is walking.

use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;

use crate::store::{self, KeyRecord, Store};
use crate::util;

/// `drafts/<token>.json`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Draft {
    pub version: u32,
    /// The draft's own token, and the token the filed application will carry.
    pub token: String,
    /// Every answer given so far, keyed by the question list's ids.
    pub answers: BTreeMap<String, String>,
    /// The mail keys filed against this draft, pasted or mailed, one per
    /// mailbox. Empty for a person until their key page is answered; a body's
    /// holds one entry per account name.
    #[serde(default)]
    pub mail_keys: Vec<KeyRecord>,
    /// The next page to ask, as an index into the applicant's own path. Zero is
    /// the first question; a value equal to the path's length means every page
    /// has been answered.
    pub cursor: usize,
    pub created_at: String,
    pub updated_at: String,
}

impl Draft {
    /// A new draft at the first page. The caller has already drawn the token.
    pub fn new(token: String) -> Draft {
        let now = util::filed_at();
        Draft {
            version: 1,
            token,
            answers: BTreeMap::new(),
            mail_keys: Vec::new(),
            cursor: 0,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

/// Whether a path segment could name a draft. Checked before it is used as a
/// record name, so a token never becomes a path.
pub fn valid_token(token: &str) -> bool {
    store::is_status_token(token)
}

/// Read a draft, or `None` when the token names nothing that parses. A missing
/// draft and an expired one are the same to the caller, which is what keeps the
/// route from being a token oracle.
pub async fn load(store: &Store, token: &str) -> Result<Option<Draft>, String> {
    if !valid_token(token) {
        return Ok(None);
    }
    let Some(text) = store.read_record("drafts", &format!("{token}.json")).await else {
        return Ok(None);
    };
    let draft: Draft = serde_json::from_str(&text)
        .map_err(|e| format!("the draft {token} does not parse: {e}"))?;
    if draft.token != token {
        return Ok(None);
    }
    Ok(Some(draft))
}

/// Hold the drafts directory's lock for one read-modify-write. The handler and
/// the root drain both write a draft: the applicant advances the cursor while
/// the drain files a mailed key. Without one lock around the read and the write,
/// one of the two saves overwrites the other's answer.
///
/// The lock file is never removed. Removing it while another process holds it
/// would let a third create a new file and lock that instead, which is no lock
/// at all.
pub async fn lock(store: &Store) -> Result<tokio::fs::File, String> {
    let dir = store.path("drafts");
    if tokio::fs::metadata(&dir).await.is_err() {
        // scripts/onboard-store.sh lays this directory out on the box. A store
        // that has not been laid out yet still needs a lock file, and the
        // process that opens the first draft is the one that owns it.
        store.ensure_dir("drafts").await?;
    }
    let path = store.path("drafts/.lock");
    let mut opts = tokio::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).mode(0o600);
    let file = opts
        .open(&path)
        .await
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!(
            "cannot lock {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

/// Write the draft by rename, stamping `updated_at`. The directory is created
/// here so a first draft does not depend on the store script having run. The
/// file is handed to the directory's owner because the drain writes this record
/// too, as root: a root-owned 0600 draft would read as missing to the
/// unprivileged handler that is walking it.
///
/// A caller that reads and then writes must hold `lock` across both.
pub async fn save(store: &Store, draft: &mut Draft) -> Result<(), String> {
    draft.updated_at = util::filed_at();
    store.ensure_dir("drafts").await?;
    let bytes =
        serde_json::to_vec_pretty(draft).map_err(|e| format!("cannot encode the draft: {e}"))?;
    let owner = store.dir_owner("drafts");
    store
        .write_record_owned("drafts", &format!("{}.json", draft.token), &bytes, owner)
        .await
}

/// Remove a draft once it has become an application.
pub async fn remove(store: &Store, token: &str) -> Result<(), String> {
    store.remove("drafts", &format!("{token}.json")).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_draft_round_trips_and_another_token_does_not_read_it() {
        let dir = std::env::temp_dir().join(format!("onboard-draft-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.to_str().unwrap());
        let token = "abcdefghjkmnpqrstvwxyz0123".to_string();
        let mut draft = Draft::new(token.clone());
        draft.answers.insert("username".into(), "secretary".into());
        draft.cursor = 1;
        save(&store, &mut draft).await.unwrap();

        let read = load(&store, &token).await.unwrap().expect("the draft");
        assert_eq!(read.answers["username"], "secretary");
        assert_eq!(read.cursor, 1);
        assert!(load(&store, "0123456789abcdefghjkmnpqrs")
            .await
            .unwrap()
            .is_none());
        assert!(!valid_token("../escape"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
