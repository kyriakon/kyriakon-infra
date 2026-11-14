//! The store: the three shared files read at the top, the records written under
//! the root, and the on-disk shapes the drain reads.
//!
//! Two shapes, two APIs. A `.jsonl` file is a log: appended only, through
//! [`Store::log`], whose handle has no write at all, so the natural overwrite of
//! a log does not compile. Everything else is a record: replaced whole by
//! rename, so a reader never sees half of one. The handler writes
//! `applications/<token>.json` (the record the status page renders) and
//! `intents/<id>.json` (the one filed application). It never writes anything
//! root-owned.
//!
//! The boundary is a type plus a runtime check, not a type alone: a caller that
//! names a record as a path string can still pass a `.jsonl` name to
//! [`Store::write_record_mode`], which refuses it rather than writing it. Names
//! are built at runtime (`format!("{token}.json")`), so no signature can make
//! that a compile error. The only write that completes a recorded line is
//! [`Store::rewrite_log`], measured by the name and by `pub(crate)`.

pub mod draft;
pub mod error;
pub mod journal;

pub use error::{Action, Error};

use std::collections::BTreeMap;
use std::os::unix::fs::{fchown, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The queue money with no token is held in, append-only except for the one
/// line `reconcile` completes under its lock.
pub const UNATTRIBUTED: &str = "ledger/unattributed.jsonl";

pub struct Store {
    root: PathBuf,
    /// Whether `append` waits for the line to reach the disk. Production does;
    /// a test store does not, because the integration suite writes thousands of
    /// lines and APFS fsync is the dominant cost. The bytes and the append
    /// order are identical; only the durability barrier is skipped.
    sync: bool,
    /// Journals read, so a test can hold a pass to one read: the acceptance of
    /// #531 is that the count does not grow with the number of intents.
    reads: std::sync::atomic::AtomicUsize,
}

impl Store {
    pub fn new(root: &str) -> Store {
        Store {
            root: PathBuf::from(root),
            sync: true,
            reads: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// The same store without the per-line durability barrier. Tests only: no
    /// deployed process should skip the sync an append promises.
    pub fn new_for_test(root: &str) -> Store {
        Store {
            root: PathBuf::from(root),
            sync: false,
            reads: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// How many times a journal has been read through this store. Test builds
    /// only: the string compare below disappears with the field.
    pub fn journal_reads(&self) -> usize {
        self.reads.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The absolute path of one store path, for a caller that has to open the
    /// file itself: a webhook's raw body, the mail replies' record. A lock goes
    /// through [`Store::lock`], which opens and hands over the descriptor.
    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    pub async fn read_text(path: &str) -> Result<String, Error> {
        tokio::fs::read_to_string(path)
            .await
            .map_err(|source| Error::Io {
                action: Action::Read,
                path: path.into(),
                source,
            })
    }

    /// Read a record's bytes when a missing one and a damaged one mean the same
    /// thing: the status page's token oracle, which answers an unknown token and
    /// a corrupt record alike, and a console listing that is best effort. A
    /// caller that has to tell the two apart reads an account, group or
    /// application record through the typed accessors below.
    pub async fn read_record(&self, dir: &str, name: &str) -> Option<String> {
        tokio::fs::read_to_string(self.root.join(dir).join(name))
            .await
            .ok()
    }

    /// One record's bytes, `Ok(None)` only when the file is absent. An IO error
    /// other than not-found is an error naming the file.
    async fn record_text(&self, rel: &str) -> Result<Option<String>, Error> {
        match tokio::fs::read_to_string(self.root.join(rel)).await {
            Ok(text) => Ok(Some(text)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(Error::Io {
                action: Action::Read,
                path: rel.into(),
                source,
            }),
        }
    }

    /// Read one record as its own type. `Ok(None)` only when the file is not
    /// there: an IO error or a parse failure is an error naming the file. A
    /// caller that has to tell a record that has gone from one that is damaged
    /// reads through this, not [`Store::read_record`], where both are "not
    /// there".
    async fn typed_record<T: DeserializeOwned>(&self, rel: &str) -> Result<Option<T>, Error> {
        let Some(text) = self.record_text(rel).await? else {
            return Ok(None);
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|source| Error::Parse {
                path: rel.into(),
                source,
            })
    }

    /// One account record, `accounts/<username>/account.json`.
    pub async fn account(&self, username: &str) -> Result<Option<Account>, Error> {
        self.typed_record(&format!("accounts/{username}/account.json"))
            .await
    }

    /// The same record as written, for the export, which copies it as recorded
    /// rather than re-encoding the fields this build models.
    pub async fn account_text(&self, username: &str) -> Result<Option<String>, Error> {
        self.record_text(&format!("accounts/{username}/account.json"))
            .await
    }

    /// One group record, `groups/<domain>/group.json`.
    pub async fn group(&self, domain: &str) -> Result<Option<GroupRecord>, Error> {
        self.typed_record(&format!("groups/{domain}/group.json"))
            .await
    }

    /// One filed application, `applications/<token>.json`.
    pub async fn application(&self, token: &str) -> Result<Option<Record>, Error> {
        self.typed_record(&format!("applications/{token}.json"))
            .await
    }

    /// The filed application as written. Two callers edit one key and write it
    /// back, and the record carries fields this build does not model, so a
    /// round trip through [`Record`] would drop them.
    pub async fn filed_application_text(&self, token: &str) -> Result<Option<String>, Error> {
        self.record_text(&format!("applications/{token}.json"))
            .await
    }

    /// The application's retained copy inside an account directory, as written.
    /// Its callers parse a field or two and copy it whole for the export, so it
    /// is read as text; the miss-versus-damage split is the same as the typed
    /// reads'.
    pub async fn account_application_text(&self, username: &str) -> Result<Option<String>, Error> {
        self.record_text(&format!("accounts/{username}/application.json"))
            .await
    }

    /// One token index entry, `tokens/<reference>.json`. This is the only join
    /// between a payment and who it pays for, so a record that cannot be read is
    /// an error rather than a token that names nobody.
    pub async fn token(&self, reference: &str) -> Result<Option<TokenRecord>, Error> {
        self.typed_record(&format!("tokens/{reference}.json")).await
    }

    /// One username hold, `holds/<username>.json`, as written. The one field
    /// read today is `until`, and a damaged file is an error: treating it as no
    /// hold would release a name the platform is still holding.
    pub async fn hold(&self, username: &str) -> Result<Option<serde_json::Value>, Error> {
        self.typed_record(&format!("holds/{username}.json")).await
    }

    /// One webhook event id the drain proved on first sight,
    /// `verified/<event_id>.json`. The directory is root-owned, so the handler
    /// cannot plant or rewrite a record. A damaged file is an error: treating
    /// it as no record would re-judge a proven event against this pass's clock.
    pub async fn verified_webhook(&self, id: &str) -> Result<Option<serde_json::Value>, Error> {
        self.typed_record(&format!("verified/{id}.json")).await
    }

    /// One spent one-time password link, `spent/<token>.json`. The directory is
    /// root-owned, so the handler cannot plant or rewrite a marker. A damaged
    /// file is an error rather than no record: reading it as unspent would let a
    /// captured link be replayed, which is the fact the marker exists to keep.
    pub async fn spent_link(&self, token: &str) -> Result<Option<serde_json::Value>, Error> {
        self.typed_record(&format!("spent/{token}.json")).await
    }

    /// Write one record by rename: a temporary file in the same directory, then
    /// the rename, so a reader never sees half of one and a crash leaves the
    /// temporary file rather than a truncated record. The file is created 0600,
    /// so the umask cannot widen the applicant's own words, keys and outside
    /// address beyond the account that wrote them and root.
    pub async fn write_record(&self, dir: &str, name: &str, bytes: &[u8]) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
        self.write_record_mode(dir, name, bytes, owner, 0o600).await
    }

    /// Like `write_record_owned`, with the file's mode. An account or group
    /// record is written 0640, group `_onboard`: the handler renders the page
    /// from it and cannot be allowed to rewrite it, and a 0600 file is invisible
    /// to the process the page runs as.
    pub async fn write_record_mode(
        &self,
        dir: &str,
        name: &str,
        bytes: &[u8],
        owner: Option<(u32, u32)>,
        mode: u32,
    ) -> Result<(), Error> {
        check_name(name)?;
        // The handler renders account and group records and runs as `_onboard`,
        // so a root-only mode here is a page that reads as missing. Refuse it
        // rather than letting three call sites rediscover the rule.
        if matches!(name, "account.json" | "group.json") && mode & 0o040 == 0 {
            return Err(Error::Refused(format!(
                "{name} is read by the unprivileged handler; write it 0640 through \
                 write_account_record or write_group_state"
            )));
        }
        // An append-only record is not replaced whole. The type already refuses
        // it through `Store::log`; this is the same rule for a caller that names
        // the file as a path, and the error says the name of the write that is
        // allowed to.
        if name.ends_with(".jsonl") {
            return Err(Error::Refused(format!(
                "{name} is an append-only record; Store::rewrite_log is the one write \
                 that completes a line already recorded"
            )));
        }
        self.place_record(dir, name, bytes, owner, mode).await
    }

    /// The rename itself, for a caller that has already decided the write is
    /// allowed: the record writer, and [`Store::rewrite_log`].
    async fn place_record(
        &self,
        dir: &str,
        name: &str,
        bytes: &[u8],
        owner: Option<(u32, u32)>,
        mode: u32,
    ) -> Result<(), Error> {
        let d = self.root.join(dir);
        let tmp = d.join(format!(".{name}.tmp"));
        let target = d.join(name);
        // A stale temporary this code left is removed and rewritten. A symlink
        // at that name is not one this code left: the directories it writes into
        // are the handler's, and a path handed to `chown` there must never be
        // one the handler can redirect. Refuse it rather than unlink it.
        if let Ok(md) = tokio::fs::symlink_metadata(&tmp).await {
            if md.file_type().is_symlink() {
                return Err(Error::Refused(format!(
                    "a symlink is planted at {}; a record is not written through it",
                    tmp.display()
                )));
            }
            let _ = tokio::fs::remove_file(&tmp).await;
        }
        let placed = async {
            let mut opts = tokio::fs::OpenOptions::new();
            opts.write(true).create_new(true).mode(mode);
            opts.custom_flags(libc::O_NOFOLLOW);
            let mut f = opts.open(&tmp).await?;
            f.write_all(bytes).await?;
            // `write_all` on a `tokio::fs::File` returns once the write is
            // handed to the blocking pool: `poll_write` answers `Ready` straight
            // after `spawn_mandatory_blocking` and keeps its error for the next
            // operation. Without this, the rename can publish a record the
            // write never wrote, and the error is lost. `flush` waits for the
            // write that is running and returns its result; the durability
            // barrier below is a separate promise.
            f.flush().await?;
            if self.sync {
                f.sync_all().await?;
            }
            // chown needs root, and only root ever needs to hand the file to
            // another owner: a test runs as the directory's own owner already.
            //
            // The descriptor, not the path: the directory is the handler's, so
            // a name in it can be replaced between the write and a `chown`, and
            // root would then follow the replacement. `create_new`/O_NOFOLLOW
            // closed the open; this closes the window after it.
            if let Some((uid, gid)) = owner {
                if unsafe { libc::geteuid() } == 0 {
                    fchown(&f, Some(uid), Some(gid))?;
                }
            }
            tokio::fs::rename(&tmp, &target).await
        }
        .await;
        placed.map_err(|source| {
            let _ = std::fs::remove_file(&tmp);
            Error::Io {
                action: Action::Place,
                path: d,
                source,
            }
        })
    }

    /// The account a pinned client certificate belongs to, or `None` when no
    /// account carries the hash.
    ///
    /// The scan reads each `account.json` rather than an index beside the pins:
    /// an index would be a second list that can disagree with the account, and
    /// the account directory is small enough that one read answers it. A record
    /// that cannot be read is an error: skipping it would turn a pinned
    /// certificate into a stranger's session, and the caller renders the
    /// failure instead.
    pub async fn account_for_certificate(&self, hash: &str) -> Result<Option<Account>, Error> {
        if hash.is_empty() {
            return Ok(None);
        }
        for username in self.list("accounts").await? {
            let Some(account) = self.account(&username).await? else {
                continue;
            };
            if account.certificates.iter().any(|c| c.hash == hash) {
                return Ok(Some(account));
            }
        }
        Ok(None)
    }

    /// The account whose one-time password link carries this token, or `None`
    /// when no account does. A link's token is a path component the handler
    /// reads, and the account record is the one place the link's state lives, so
    /// this is the handler's lookup for a link a group approval or a reset
    /// issued. A damaged record is skipped, so one unreadable account cannot
    /// take every other mailbox's page down with it: the page answers as an
    /// unknown token rather than as an error a probe can read.
    pub async fn account_for_password_token(&self, token: &str) -> Result<Option<Account>, Error> {
        // The link's token is 26 lowercase Crockford characters, the same shape
        // as a status token. A probe of another shape is refused before any
        // record is read.
        if !is_status_token(token) {
            return Ok(None);
        }
        for username in self.list("accounts").await? {
            let account = match self.account(&username).await {
                Ok(Some(account)) => account,
                Ok(None) | Err(_) => continue,
            };
            if account
                .password_link
                .as_ref()
                .is_some_and(|link| link.token == token)
            {
                return Ok(Some(account));
            }
        }
        Ok(None)
    }

    /// The names in one directory, sorted. A missing directory reads as empty,
    /// which is what a first run against a fresh store is: no intents, no
    /// journal, no notices, and none of those is an error to a reader.
    pub async fn list(&self, dir: &str) -> Result<Vec<String>, Error> {
        let d = self.root.join(dir);
        let mut rd = match tokio::fs::read_dir(&d).await {
            Ok(rd) => rd,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(Error::Io {
                    action: Action::Read,
                    path: d.clone(),
                    source,
                })
            }
        };
        let mut out = Vec::new();
        while let Some(entry) = rd.next_entry().await.map_err(|source| Error::Io {
            action: Action::Read,
            path: d.clone(),
            source,
        })? {
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

    /// One append-only record: a `.jsonl` file, never rewritten. The type is
    /// what holds the rule: `Log` has the append, the readers and no write, so
    /// overwriting a log through it does not compile. [`Store::rewrite_log`] is
    /// the one named exception. Appends and rewrites both take the record's own
    /// lock, [`Log::lock`].
    pub fn log<'a>(&'a self, path: &'a str) -> Log<'a> {
        Log { store: self, path }
    }

    /// Append one line to a store file, creating it 0600 and its directory if
    /// needed. Reached through [`Store::log`], which is the only handle that
    /// appends.
    async fn append_mode(
        &self,
        path: &str,
        bytes: &[u8],
        owner: Option<(u32, u32)>,
        mode: u32,
    ) -> Result<(), Error> {
        // The account page lists every notice, so the handler reads this one
        // append file; a root-only line is a notice the member cannot see.
        if path.ends_with("notices.jsonl") && mode & 0o040 == 0 {
            return Err(Error::Refused(
                "notices.jsonl is read by the unprivileged handler; append it 0640".to_string(),
            ));
        }
        use std::os::unix::fs::PermissionsExt;
        let p = self.root.join(path);
        if let Some(parent) = p.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|source| Error::Io {
                    action: Action::Create,
                    path: parent.to_path_buf(),
                    source,
                })?;
        }
        let mut line = bytes.to_vec();
        if !line.ends_with(b"\n") {
            line.push(b'\n');
        }
        let sync = self.sync;
        // A symlink or a FIFO planted at the record's name is refused before
        // open: O_NOFOLLOW stops the link, and O_NONBLOCK stops a readerless
        // FIFO from hanging the pass while it holds the lock.
        if let Ok(meta) = tokio::fs::symlink_metadata(&p).await {
            if !meta.file_type().is_file() {
                return Err(Error::Refused(format!(
                    "a symlink is planted at {}; an append is not written through it",
                    p.display()
                )));
            }
        }
        let placed = async {
            let mut f = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(mode)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&p)
                .await?;
            // The path could change between the check and the open; the
            // descriptor is what is appended to.
            if !f.metadata().await?.is_file() {
                return Err(std::io::Error::other(format!(
                    "{} is not a regular file; it is not appended to",
                    p.display()
                )));
            }
            // The mode argument above applies only at creation, and an upgrade
            // finds the file already 0600; both are corrected here.
            f.set_permissions(std::fs::Permissions::from_mode(mode))
                .await?;
            if let Some((uid, gid)) = owner {
                if unsafe { libc::geteuid() } == 0 {
                    // The open descriptor, as `write_record_mode` does: the
                    // record is appended, never replaced, so the path and the
                    // file are the same thing only while nobody else can
                    // rename over it.
                    fchown(&f, Some(uid), Some(gid)).map_err(|e| {
                        std::io::Error::other(format!(
                            "cannot hand {} to its group: {e}",
                            p.display()
                        ))
                    })?;
                }
            }
            f.write_all(&line).await?;
            // See `place_record`: the write is still in the blocking pool when
            // `write_all` returns, so its error would surface on a later call,
            // or never on the test store's path.
            f.flush().await?;
            if sync {
                f.sync_all().await
            } else {
                Ok(())
            }
        }
        .await;
        placed.map_err(|source| {
            // O_NOFOLLOW answers ELOOP for a planted symlink; say which record
            // and why rather than reporting an append that failed for no reason.
            if source.raw_os_error() == Some(libc::ELOOP) {
                return Error::Refused(format!(
                    "a symlink is planted at {}; an append is not written through it",
                    p.display()
                ));
            }
            Error::Io {
                action: Action::Append,
                path: p,
                source,
            }
        })
    }

    /// Create a directory under the root with its parents, 0700. The mode is
    /// passed to `DirBuilder` rather than left to the umask, so the comment and
    /// the code cannot disagree; an existing directory keeps the mode
    /// `scripts/control-store.sh` gave it.
    pub async fn ensure_dir(&self, dir: &str) -> Result<(), Error> {
        let d = self.root.join(dir);
        let mut builder = tokio::fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder.create(&d).await.map_err(|source| Error::Io {
            action: Action::Create,
            path: d,
            source,
        })
    }

    /// Create a directory under the root at `mode`, handed to `owner` when
    /// running as root, and correct an existing one whose mode has drifted.
    ///
    /// `ensure_dir`'s 0700 is right for the handler's own working directories
    /// and for lock files, but an account or group record's directory is read
    /// by `_onboard`: a root-owned 0700 directory makes
    /// `accounts/<user>/account.json` unreadable however the file itself is
    /// written, and the page then behaves as though the record were missing.
    /// 0750 with the parent's group is what `control-store.sh` gives `accounts/`
    /// and `groups/`.
    pub async fn ensure_dir_owned(
        &self,
        dir: &str,
        mode: u32,
        owner: Option<(u32, u32)>,
    ) -> Result<(), Error> {
        let d = self.root.join(dir);
        let mut builder = tokio::fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(mode);
        builder.create(&d).await.map_err(|source| Error::Io {
            action: Action::Create,
            path: d.clone(),
            source,
        })?;
        // The descriptor, not the path: this is root handing a directory to
        // another account, and a name in the tree can be replaced. `accounts/`
        // and `groups/` are root-owned with no group write, so the handler
        // cannot plant one here, but the descriptor keeps the rule local.
        let f = tokio::fs::File::open(&d)
            .await
            .map_err(|source| Error::Io {
                action: Action::Open,
                path: d.clone(),
                source,
            })?;
        if unsafe { libc::geteuid() } == 0 {
            if let Some((uid, gid)) = owner {
                fchown(&f, Some(uid), Some(gid)).map_err(|source| Error::Io {
                    action: Action::Chown,
                    path: d.clone(),
                    source,
                })?;
            }
        }
        // A directory made by an earlier release is repaired rather than left
        // at the mode that hid it.
        f.set_permissions(std::fs::Permissions::from_mode(mode))
            .await
            .map_err(|source| Error::Io {
                action: Action::Chmod,
                path: d,
                source,
            })
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
    pub async fn remove(&self, dir: &str, name: &str) -> Result<(), Error> {
        check_name(name)?;
        let p = self.root.join(dir).join(name);
        match tokio::fs::remove_file(&p).await {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(Error::Io {
                action: Action::Remove,
                path: self.root.join(dir),
                source,
            }),
        }
    }

    /// An exclusive lock on a lock file of its own, held until the returned
    /// handle drops. Every writer that needs one takes it here.
    ///
    /// The lock lives in a file of its own rather than on the record, because a
    /// rewrite replaces the record by rename: a lock on the replaced inode would
    /// stop guarding the path the moment the rename landed. The caller holds it
    /// across the whole read and write, which is what keeps a line another
    /// process appended between them.
    ///
    /// A lock file is never removed. Removing one while another process holds
    /// it would let a third create a new file and lock that instead, which is
    /// no lock at all.
    ///
    /// The open refuses a symlink: most of these directories belong to the
    /// unprivileged handler, and a name in one can be planted. The descriptor is
    /// then handed to the directory's owner, because the drain takes some of
    /// these locks as root and a root-owned 0600 lock in the handler's directory
    /// is one the handler can no longer take.
    pub async fn lock(&self, rel: &str) -> Result<tokio::fs::File, Error> {
        let file = self.open_lock(rel).await?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(Error::Io {
                action: Action::Lock,
                path: self.root.join(rel),
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(file)
    }

    /// [`Store::lock`] without waiting: `None` when another process holds it.
    /// The drain's pass lock takes this, because an overlapping tick is one to
    /// skip rather than one to queue behind, and holds it for the process's
    /// life: the kernel releases it however the process exits.
    pub async fn try_lock(&self, rel: &str) -> Result<Option<tokio::fs::File>, Error> {
        let file = self.open_lock(rel).await?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Some(file));
        }
        let source = std::io::Error::last_os_error();
        if source.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Ok(None);
        }
        Err(Error::Io {
            action: Action::Lock,
            path: self.root.join(rel),
            source,
        })
    }

    /// Open the lock file both of the above take, its directory made if the
    /// store has not been laid out yet.
    async fn open_lock(&self, rel: &str) -> Result<tokio::fs::File, Error> {
        // The record's directory, or the store root for a record at the top: a
        // store not laid out yet still needs a lock file.
        let dir = rel.rsplit_once('/').map_or("", |(d, _)| d);
        self.ensure_dir(dir).await?;
        let path = self.root.join(rel);
        let mut opts = tokio::fs::OpenOptions::new();
        // O_NOFOLLOW: the handler owns most of these directories and could
        // plant the lock as a symlink. The lock file may already exist, so this
        // is `create`, not `create_new`.
        opts.read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        let file = opts.open(&path).await.map_err(|source| Error::Io {
            action: Action::Open,
            path: path.clone(),
            source,
        })?;
        // chown needs root, and only root ever hands a lock to another owner: a
        // test runs as the directory's own owner already.
        if unsafe { libc::geteuid() } == 0 {
            if let Some((uid, gid)) = self.dir_owner(dir) {
                // The descriptor, after the no-follow open: a `chown` of the
                // path would follow whatever the name points at by then.
                fchown(&file, Some(uid), Some(gid)).map_err(|source| Error::Io {
                    action: Action::Chown,
                    path: path.clone(),
                    source,
                })?;
            }
        }
        Ok(file)
    }

    /// The unattributed queue, one held payment per line. A missing file reads
    /// as empty; a read error or a line that does not parse is an error, because
    /// `reconcile list` must not report a clear queue it cannot read.
    pub async fn held(&self) -> Result<Vec<HeldItem>, Error> {
        self.log(UNATTRIBUTED).jsonl().await
    }

    /// The typed lines of an append-only record: a missing file is empty, but an
    /// unreadable file or a line that does not parse is an error rather than an
    /// empty result. A reader that reports "nothing" for a record it could not
    /// read is a check that cannot see what it is checking.
    async fn read_jsonl<T: DeserializeOwned>(&self, path: &str) -> Result<Vec<T>, Error> {
        let mut out = Vec::new();
        for (i, line) in self.read_lines(path).await?.iter().enumerate() {
            out.push(
                serde_json::from_str(line).map_err(|source| Error::ParseLine {
                    path: path.into(),
                    line: i + 1,
                    source,
                })?,
            );
        }
        Ok(out)
    }

    /// Walk a record's lines in order, parsing each and handing it to `walk`,
    /// which answers whether to go on. One line is parsed at a time, so a caller
    /// that stops early does not parse the rest of the record.
    async fn walk_jsonl<T: DeserializeOwned>(
        &self,
        path: &str,
        mut walk: impl FnMut(usize, &T) -> bool,
    ) -> Result<(), Error> {
        for (i, line) in self.read_lines(path).await?.iter().enumerate() {
            let value: T = serde_json::from_str(line).map_err(|source| Error::ParseLine {
                path: path.into(),
                line: i + 1,
                source,
            })?;
            if !walk(i, &value) {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Whether any line of a record satisfies `pred`, stopping at the first
    /// that does.
    async fn read_jsonl_any<T: DeserializeOwned>(
        &self,
        path: &str,
        mut pred: impl FnMut(&T) -> bool,
    ) -> Result<bool, Error> {
        let mut hit = false;
        self.walk_jsonl(path, |_, value: &T| {
            hit = pred(value);
            !hit
        })
        .await?;
        Ok(hit)
    }

    /// The non-empty lines of a store file, as recorded. A missing file reads as
    /// nothing; an unreadable one is an error.
    async fn read_lines(&self, path: &str) -> Result<Vec<String>, Error> {
        if path == "journal.jsonl" {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let abs = self.root.join(path);
        match tokio::fs::read_to_string(&abs).await {
            Ok(s) => Ok(s
                .lines()
                .map(|l| l.trim_end().to_string())
                .filter(|l| !l.is_empty())
                .collect()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(source) => Err(Error::Io {
                action: Action::Read,
                path: abs,
                source,
            }),
        }
    }

    /// Rewrite an append-only record whole, under a lock the caller holds.
    ///
    /// This is the one exception `CODING_STANDARDS.md` names: a recorded line
    /// that has to be completed later rather than appended again. The callers
    /// (`ledger::Ledger::settle_refund`, `rewrite_unattributed`,
    /// `requests::rewrite`, the drain's `holds_sweep`, which drops the lines of
    /// a released username, and the notice rollback that takes back a line whose
    /// enqueue failed) each hold [`Log::lock`] across the read and this write,
    /// and appends take the same lock, so a line another process appends in
    /// between is either seen by the read or lands after the rewrite. Nothing
    /// else may call this, and the name is the warning.
    pub async fn rewrite_log(&self, path: &str, bytes: &[u8]) -> Result<(), Error> {
        self.rewrite_log_mode(path, bytes, None, 0o600).await
    }

    /// [`Store::rewrite_log`] for a record the unprivileged handler reads:
    /// `notices.jsonl` is 0640 and handed to the accounts directory's group, as
    /// its appends are. The rollback of a notice whose enqueue failed needs the
    /// same mode, or the account page loses the notices it still lists.
    pub(crate) async fn rewrite_log_mode(
        &self,
        path: &str,
        bytes: &[u8],
        owner: Option<(u32, u32)>,
        mode: u32,
    ) -> Result<(), Error> {
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
        self.place_record(dir, name, bytes, owner, mode).await
    }
}

/// One append-only record: a `.jsonl` file, never rewritten except through
/// [`Store::rewrite_log`].
///
/// The type is the rule. It carries append and the readers and no write, and
/// `Store`'s own record writer refuses a name ending `.jsonl`, so the only way
/// to overwrite a line is to say so by name:
///
/// ```compile_fail,E0599
/// # async fn f(store: &kyriakon_control::store::Store) {
/// store.log("journal.jsonl").write(b"{}").await;
/// # }
/// ```
pub struct Log<'a> {
    store: &'a Store,
    path: &'a str,
}

impl Log<'_> {
    /// The record's own lock: `<path>.lock`, held until the handle drops.
    ///
    /// An append takes it, and a rewrite must hold it across its read and its
    /// write. A lock on the record itself would be no lock, because the rewrite
    /// replaces the record by rename; the lock is a file of its own.
    pub async fn lock(&self) -> Result<tokio::fs::File, Error> {
        self.store.lock(&format!("{}.lock", self.path)).await
    }

    /// Append one line, creating the file 0600 and its directory if needed. The
    /// append takes the record's own lock, so it cannot land between a rewrite's
    /// read and its rename.
    pub async fn append(&self, bytes: &[u8]) -> Result<(), Error> {
        let _guard = self.lock().await?;
        self.store.append_mode(self.path, bytes, None, 0o600).await
    }

    /// Append with the file's mode and owner set on every call, including one
    /// that finds the file already there. `notices.jsonl` is the one append file
    /// the handler must read: the account page lists every notice sent, so it is
    /// written 0640 with the accounts directory's group rather than the 0600
    /// root-only default. `journal.jsonl` and `requests.jsonl` stay root-only,
    /// because nothing outside the drain reads them. Takes the record's lock.
    pub async fn append_mode(
        &self,
        bytes: &[u8],
        owner: Option<(u32, u32)>,
        mode: u32,
    ) -> Result<(), Error> {
        let _guard = self.lock().await?;
        self.store.append_mode(self.path, bytes, owner, mode).await
    }

    /// Append under a lock the caller already holds, from [`Self::lock`]. The
    /// descriptor is required: without it, an append that reads before taking
    /// the lock does not compile.
    ///
    /// Two callers need it: `requests::record` refuses a request id it has
    /// already recorded, and `ledger::Ledger::append` numbers a line after the
    /// highest already written, so each does its read and its append as one step
    /// under one lock. Taking the lock twice on two descriptors would deadlock,
    /// so this exists for those shapes and nothing else; every other writer
    /// calls [`Self::append`].
    pub(crate) async fn append_while_locked(
        &self,
        _lock: &tokio::fs::File,
        bytes: &[u8],
    ) -> Result<(), Error> {
        self.store.append_mode(self.path, bytes, None, 0o600).await
    }

    /// The record's lines, typed: a missing record is empty, an unreadable one
    /// or a line that does not parse is an error.
    pub async fn jsonl<T: DeserializeOwned>(&self) -> Result<Vec<T>, Error> {
        self.store.read_jsonl(self.path).await
    }

    /// Whether any line satisfies `pred`, stopping at the first that does. For
    /// a question about one line in a journal, which [`Self::jsonl`] would
    /// answer only after parsing every line into a list.
    pub async fn jsonl_any<T: DeserializeOwned>(
        &self,
        pred: impl FnMut(&T) -> bool,
    ) -> Result<bool, Error> {
        self.store.read_jsonl_any(self.path, pred).await
    }

    /// Walk the record's lines in order, parsing one at a time, for a reader
    /// that accumulates over all of them. The `usize` is the line's index, which
    /// is what a reader comparing the order of two lines needs.
    pub async fn jsonl_each<T: DeserializeOwned>(
        &self,
        mut walk: impl FnMut(usize, &T),
    ) -> Result<(), Error> {
        self.store
            .walk_jsonl(self.path, |i, value: &T| {
                walk(i, value);
                true
            })
            .await
    }

    /// The record's lines as written. For the one reader that copies a record
    /// into an artefact verbatim — the export — rather than reading it.
    pub async fn raw_lines(&self) -> Result<Vec<String>, Error> {
        self.store.read_lines(self.path).await
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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

/// The subject a journal line names: the account, and the capability token or
/// group domain the intent carried, where it carried one. A page action names
/// neither, which is why both are optional: an absent field says so, where an
/// empty string or a domain in the token field used to lie about what it was.
///
/// Existing journal files wrote `status_token` as a string, sometimes a group
/// domain, so that shape is still read; only real tokens reach the index.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ApplicationRef {
    pub username: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "optional_string"
    )]
    pub status_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// An old journal line wrote `status_token` as a plain string, an empty string
/// included; both read as the option they always meant.
fn optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.filter(|s| !s.is_empty()))
}

impl ApplicationRef {
    /// The subject of an account with no capability token or domain.
    pub fn account(username: impl Into<String>) -> Self {
        ApplicationRef {
            username: username.into(),
            ..Default::default()
        }
    }

    /// The subject of an application, named by its token. An absent token is
    /// absent, never an empty string: the journal must not say a field is there
    /// when it holds nothing.
    pub fn application(username: impl Into<String>, token: impl Into<String>) -> Self {
        let token = token.into();
        ApplicationRef {
            username: username.into(),
            status_token: (!token.is_empty()).then_some(token),
            domain: None,
        }
    }

    /// The subject of a group, named by its domain.
    pub fn group(username: impl Into<String>, domain: impl Into<String>) -> Self {
        let domain = domain.into();
        ApplicationRef {
            username: username.into(),
            status_token: None,
            domain: (!domain.is_empty()).then_some(domain),
        }
    }
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
            application: ApplicationRef::application(
                self.username.clone(),
                self.status_token.clone(),
            ),
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
pub async fn status_token() -> Result<String, Error> {
    let mut bytes = [0u8; 16];
    let mut f = tokio::fs::File::open("/dev/urandom")
        .await
        .map_err(|source| Error::Io {
            action: Action::Open,
            path: "/dev/urandom".into(),
            source,
        })?;
    f.read_exact(&mut bytes).await.map_err(|source| Error::Io {
        action: Action::Read,
        path: "/dev/urandom".into(),
        source,
    })?;
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

/// A record name is one component inside its directory. A name carrying a
/// separator or a NUL, or one that names the directory itself, is refused
/// rather than joined: the drain turns fields from records the unprivileged
/// handler owns into names, and `../../x` would leave the store.
fn check_name(name: &str) -> Result<(), Error> {
    if name.contains(['/', '\0']) || name.starts_with('.') {
        return Err(Error::Refused(format!(
            "{name:?} is not a record name; it must be one component inside its directory"
        )));
    }
    Ok(())
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
pub async fn payment_token() -> Result<String, Error> {
    let mut bytes = [0u8; 8];
    let mut f = tokio::fs::File::open("/dev/urandom")
        .await
        .map_err(|source| Error::Io {
            action: Action::Open,
            path: "/dev/urandom".into(),
            source,
        })?;
    f.read_exact(&mut bytes).await.map_err(|source| Error::Io {
        action: Action::Read,
        path: "/dev/urandom".into(),
        source,
    })?;
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
pub async fn unattributed_id() -> Result<String, Error> {
    let mut bytes = [0u8; 8];
    let mut f = tokio::fs::File::open("/dev/urandom")
        .await
        .map_err(|source| Error::Io {
            action: Action::Open,
            path: "/dev/urandom".into(),
            source,
        })?;
    f.read_exact(&mut bytes).await.map_err(|source| Error::Io {
        action: Action::Read,
        path: "/dev/urandom".into(),
        source,
    })?;
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
    /// The upload key's fingerprint and the day it was added, one entry per key
    /// the account may use for sftp and git. The account page shows these so a
    /// member can tell a key they added from one they did not; the key material
    /// itself lives where `provision-member.sh` puts it, not here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upload_keys: Vec<UploadKey>,
    /// The fingerprint of the mail key delivery uses, as the drain wrote the
    /// keyring file. The page shows it, and a rotation signed by this key skips
    /// the pending window. Absent on a record written before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail_key: Option<String>,
    /// A mail-key replacement inside its 72-hour window: the material waits here
    /// until the window closes, and the page offers to cancel it until then.
    /// Absent when no replacement is pending, which is every account normally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<Rotation>,
    /// Why the account is suspended, in the words the suspension notice used.
    /// Present only while `state` is `suspended`, and the page stays open so the
    /// member can read it and answer it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspension_reason: Option<String>,
    /// The one-time link that sets this mailbox's mail password, and the day it
    /// stops working. Written for every mailbox an approval or an address change
    /// makes, and again by an operator reset; cleared when the link is used, so
    /// the state is the link's own and not the application's. The record is the
    /// authority even when the application record still carries the link for the
    /// status page to render.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_link: Option<PasswordLink>,
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
    /// The last day of the 40-day grace after a lapse, `YYYY-MM-DD`. Written
    /// when a payment window closes with nothing recorded, so the grace and
    /// deletion sweeps measure from one date rather than from the lapse notice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_until: Option<String>,
    /// Set when a permanent delivery failure leaves no address the lifecycle
    /// notices reached. While it is present the deletion sweep refuses to run,
    /// so a later notice that is also not delivered cannot restart the clock.
    /// `kyriakon-admin notice resend` clears it and restarts the grace; a
    /// payment or a resume clears it because that clock is gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice_stopped: Option<NoticeStop>,
}

/// The stop a hard bounce sets on an account's grace clock: the failed
/// recipient, the status the receiving host gave, and when it was read. The
/// notice line keeps the whole history; this is the one fact the sweep needs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoticeStop {
    pub address: String,
    pub status: String,
    pub at: String,
}

/// One upload key the account carries: its fingerprint and the day it was
/// added. The material is not kept here, because the page never shows it and a
/// second copy is a second thing to leak.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadKey {
    pub fingerprint: String,
    pub added_at: String,
}

/// A one-time password link's state: the token in the URL and the last day the
/// signature is accepted. No signature is stored, because the link is rebuilt
/// from these two fields and the key when it is mailed, and the drain verifies
/// the submitted signature against them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordLink {
    pub token: String,
    pub until: String,
}

impl PasswordLink {
    /// A new link: a fresh token and the seven-day window a mailed link needs to
    /// reach a member and be used. Nothing else mints one, so the window is
    /// written in one place.
    pub async fn fresh() -> Result<Self, Error> {
        Ok(Self {
            token: status_token().await?,
            until: crate::util::date_after_days(7),
        })
    }
}

/// A mail-key replacement waiting out its window. The material is a public key
/// and the intent that filed it carried the same bytes, so nothing here is a
/// secret; it is kept in the record because the intent file is deleted once the
/// request is accepted, and the window outlives it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rotation {
    pub fingerprint: String,
    pub material: String,
    /// RFC 3339, when the member asked, and the moment the key applies.
    pub requested_at: String,
    pub applies_at: String,
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
/// application chose, whether it was approved without charge, the one token a
/// prepaid renewal is keyed by, the one window the money must arrive in, the
/// date the group's single renewal sets, and the card rail's subscription once
/// one is attached. The group holds the payment for every mailbox in it, so one
/// renewal cannot leave several dates that drift.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GroupPayment {
    pub rail: String,
    pub no_charge: bool,
    /// The group's one payment token, drawn when a charged group is approved.
    /// Absent on a free group, which has nothing to pay and nothing to key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ref: Option<String>,
    /// The one window the prepaid rail's money must arrive in. Absent on a free
    /// group, and absent from a record written before the group held a window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<Window>,
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
    /// The group's own quota figure, the sum of its mailbox accounts' used
    /// bytes. The page shows it against the allowance of `5 GB × mailboxes`;
    /// the drain computes it in the same sweep that reads the filesystem quota,
    /// so it cannot drift from the accounts it sums. Absent on a record written
    /// before the sweep, which the page reads as not recorded yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_used: Option<u64>,
    /// The last day of the 40-day grace after the group lapses, `YYYY-MM-DD`.
    /// Written when the window sweep lapses the group, so a sweep that runs late
    /// cannot shorten the grace by measuring from the old close date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_until: Option<String>,
    /// When the record was made, RFC 3339. The deletion journal id carries it,
    /// so a domain that is removed and later re-added gets its own deletion
    /// rather than matching the first one. Absent from a record written before
    /// this field existed.
    #[serde(default)]
    pub created_at: String,
}

/// The `provision-group` intent: everything the drain needs to make one body's
/// domain live, filed by the approval and applied in one idempotent pass.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
    /// The HMAC-SHA256 of `sign::group_provision_payload` under the approval
    /// key. Filed by the approval and verified by the drain, because `intents/`
    /// and `applications/` are writable by the unprivileged handler and this
    /// intent makes system accounts as root.
    pub sig: String,
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
    /// The Monero rail's subaddress and the one quote the window is honoured
    /// at. Absent on an account that is not on the Monero rail, and absent from
    /// a Monero account whose window opened with no rate ever fetched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monero: Option<Monero>,
}

/// What the Monero rail records against an account. The subaddress is the
/// operator's own wallet's, one per account, permanent: nothing here rotates it,
/// and the console refuses a second, different one. The quote is computed once,
/// when the window opens, and honoured for its fourteen days, so `rate_at` is
/// when that rate was fetched rather than anything the page recomputes.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Monero {
    /// The member's subaddress, recorded by `kyriakon-admin monero address` after
    /// the operator's wallet makes it. `None` until that wallet pass, which is
    /// why the page says the address is not ready rather than showing an empty
    /// field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// `price ÷ rate`, rounded up to six decimal places, as the window's quote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_xmr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_gbp_per_xmr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_source: Option<String>,
    /// When the rate that produced the quote was fetched, RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_at: Option<String>,
    /// The quote was taken from a cache the source could not refresh: it is
    /// still what the member was shown, and the page does not show the block.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
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
    /// Whether the member has stopped the yearly renewal. The subscription runs
    /// to the period's end, and the paid-until date is what decides access, so
    /// this records the choice and never shortens anything by itself.
    #[serde(default)]
    pub cancel_at_period_end: bool,
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

impl StripeBilling {
    /// Whether the subscription still renews, which is the one condition a
    /// cancellation is sent for and the one the account page offers the control
    /// under. A terminal status or a flag already set means nothing to do.
    pub fn renews(&self) -> bool {
        self.subscription.is_some()
            && !self.cancel_at_period_end
            && self.status.as_deref() != Some("canceled")
    }

    /// Whether there is a subscription that has stopped renewing, either
    /// because the member asked or because Stripe reports it canceled.
    pub fn renewal_stopped(&self) -> bool {
        self.subscription.is_some()
            && (self.cancel_at_period_end || self.status.as_deref() == Some("canceled"))
    }
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

    /// The account's own platform address: its mailbox at its group's domain,
    /// or at `kyriakon.net` for a person's account. The outside contact address
    /// is a separate thing and is never this.
    pub fn platform_address(&self) -> String {
        match self.group.as_deref() {
            Some(domain) => format!("{}@{}", self.username, domain),
            None => format!("{}@kyriakon.net", self.username),
        }
    }

    /// Where a notice goes: the contact the member gave, when it validates as a
    /// mail header, and their platform mailbox otherwise. The contact is
    /// validated again because it becomes a mail header, and a record that
    /// reached it from outside the drain is not trusted.
    pub fn notice_address(&self) -> String {
        self.outside_address
            .as_deref()
            .filter(|addr| crate::flow::validate::address(addr).is_none())
            .map(str::to_string)
            .unwrap_or_else(|| self.platform_address())
    }

    /// Whether the site and the capsule are served. An unrecorded lane on a
    /// member with an upload key is on, because provision-member.sh wrote it;
    /// a member with no upload key has no lane at all, so neither is served.
    pub fn serving(&self) -> (bool, bool) {
        let written = !self.upload_keys.is_empty();
        (
            self.site_served.unwrap_or(written),
            self.capsule_served.unwrap_or(written),
        )
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
pub async fn free_account_count(store: &Store) -> Result<usize, Error> {
    let names = store.list("accounts").await?;
    let mut free = 0;
    for username in names {
        match store.account(&username).await {
            Ok(Some(account)) => {
                if account.is_free() {
                    free += 1;
                }
            }
            Ok(None) => Error::Refused("is missing, not counted".into())
                .report(&format!("accounts/{username}/account.json")),
            Err(e) => e.report("an account could not be read, not counted"),
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
            monero: None,
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

/// `tokens/<token>.json`, the join from a token to what it pays for. Created at
/// a paid approval and deleted with the account or group, which is what makes
/// the ledger's row unlinkable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRecord {
    pub token: String,
    /// The account the token pays for, or the group's site owner when the token
    /// is a group's.
    pub username: String,
    /// The domain, when this is the one token a body's group holds. The join is
    /// to the group rather than to one of its accounts, so one renewal writes
    /// one date on the group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
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
    /// Whether this credit carried the window's quote. Read back by the recovery
    /// pass after the account write has set `paid_until`, when the payment
    /// block can no longer tell a first credit from a renewal.
    #[serde(default)]
    pub quoted: bool,
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
    /// The fields `sign::decide_payload` covers, as the review mail described
    /// them, written on the `review-sent` line. `applications/<token>.json`
    /// belongs to the handler and can be rewritten after the mail, so the
    /// console signs only a record whose fields still match these. Absent on
    /// every other line, and on a line a release before this one wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<crate::account::sign::Reviewed>,
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
    /// The permanent failure a DSN reported for this message, when one did.
    /// Absent until the bounce arrives and on every notice that was delivered,
    /// which is the ordinary state: a DSN is the only report this platform
    /// gets, so no record means no report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<Delivery>,
}

/// A delivery-status report for one notice: the permanent SMTP status the
/// receiving host answered with, and when the DSN was read.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delivery {
    /// The DSN's `Status`, e.g. `5.1.1`. Only a permanent failure is recorded;
    /// a soft bounce stays in the sender's queue and is not a lost channel.
    pub status: String,
    pub at: String,
}

impl Delivery {
    /// Whether the status is a permanent failure: the DSN's 5.x.x class.
    pub fn permanent(&self) -> bool {
        self.status.starts_with('5')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An account or group record's directory is 0750, not the 0700 the plain
    /// `ensure_dir` makes: the handler reads the record as another account, and
    /// a directory it cannot enter reads as a record that is not there. A
    /// directory an earlier release left at 0700 is repaired by the next write.
    #[tokio::test]
    async fn an_owned_directory_is_group_readable_and_repaired() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("onboard-dirmode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("accounts")).unwrap();
        let store = Store::new(dir.to_str().unwrap());
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;

        store
            .ensure_dir_owned("accounts/alice", 0o750, None)
            .await
            .unwrap();
        assert_eq!(mode(&dir.join("accounts/alice")), 0o750);

        std::fs::set_permissions(
            dir.join("accounts/alice"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        store
            .ensure_dir_owned("accounts/alice", 0o750, None)
            .await
            .unwrap();
        assert_eq!(
            mode(&dir.join("accounts/alice")),
            0o750,
            "an existing 0700 directory is repaired"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

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

    /// The one "still renewing" rule: a subscription attached, not set to stop
    /// at the period's end, and not canceled. The drain cancels under it and
    /// the account page offers the control under it.
    #[test]
    fn a_subscription_renews_only_while_it_is_attached_and_unstopped() {
        let cases = [
            (StripeBilling::default(), false, false),
            (
                StripeBilling {
                    subscription: Some("sub_example".to_string()),
                    status: Some("active".to_string()),
                    ..Default::default()
                },
                true,
                false,
            ),
            (
                StripeBilling {
                    subscription: Some("sub_example".to_string()),
                    cancel_at_period_end: true,
                    ..Default::default()
                },
                false,
                true,
            ),
            (
                StripeBilling {
                    subscription: Some("sub_example".to_string()),
                    status: Some("canceled".to_string()),
                    ..Default::default()
                },
                false,
                true,
            ),
        ];
        for (stripe, renews, stopped) in cases {
            assert_eq!(stripe.renews(), renews, "{stripe:?}");
            assert_eq!(stripe.renewal_stopped(), stopped, "{stripe:?}");
        }
    }

    /// A subject writes only the fields it has, and an old line's plain string
    /// token (a group domain included, an empty string included) still reads.
    #[test]
    fn a_subject_writes_only_the_fields_it_has() {
        let line = JournalLine {
            version: 1,
            at: "2026-11-04T00:00:00Z".to_string(),
            intent: "01H".to_string(),
            kind: "set-password".to_string(),
            release: "test".to_string(),
            application: ApplicationRef::application("secretary", ""),
            outcome: "refused".to_string(),
            note: None,
            review: None,
            credit: None,
        };
        let text = serde_json::to_string(&line).unwrap();
        assert!(!text.contains("status_token"), "{text}");

        let old: JournalLine = serde_json::from_str(
            r#"{"version":1,"at":"2026-11-04T00:00:00Z","intent":"01H","kind":"provision-group","release":"old","application":{"username":"warden","status_token":"parish.example"},"outcome":"applied"}"#,
        )
        .unwrap();
        assert_eq!(
            old.application.status_token.as_deref(),
            Some("parish.example"),
            "an old line's string token no longer reads"
        );

        let blank: JournalLine = serde_json::from_str(
            r#"{"version":1,"at":"2026-11-04T00:00:00Z","intent":"01H","kind":"set-password","release":"old","application":{"username":"secretary","status_token":""},"outcome":"refused"}"#,
        )
        .unwrap();
        assert!(
            blank.application.status_token.is_none(),
            "an old blank token reads as absent, not as a value"
        );
    }

    #[test]
    fn crockford_pads_at_the_high_end_like_a_ulid() {
        assert_eq!(crockford128([0u8; 16]), "0".repeat(26));
        assert_eq!(crockford128([0xffu8; 16]), format!("7{}", "z".repeat(25)));
    }

    /// The certificate lookup: an empty hash answers nothing, a pinned hash
    /// finds its account, and a record that cannot be read is an error rather
    /// than a stranger's session.
    #[tokio::test]
    async fn a_pinned_certificate_is_found_and_a_broken_record_fails_the_lookup() {
        let dir = std::env::temp_dir().join(format!("control-store-cert-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("accounts/alice")).unwrap();
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
            store.account_for_certificate("").await.unwrap().is_none(),
            "an empty hash names no account"
        );
        assert_eq!(
            store
                .account_for_certificate("SHA256:aa")
                .await
                .unwrap()
                .expect("the pinned account")
                .username,
            "alice"
        );
        assert!(
            store
                .account_for_certificate("SHA256:bb")
                .await
                .unwrap()
                .is_none(),
            "an unpinned hash answers nothing"
        );
        // A record the scan has to read before it can answer is damage, not a
        // pin that was never made.
        std::fs::create_dir_all(dir.join("accounts/broken")).unwrap();
        std::fs::write(dir.join("accounts/broken/account.json"), "not json").unwrap();
        let err = store
            .account_for_certificate("SHA256:bb")
            .await
            .expect_err("a corrupt record fails the scan");
        assert!(
            matches!(&err, Error::Parse { path, .. } if path.ends_with("accounts/broken/account.json")),
            "{err}"
        );
    }

    /// The password-link lookup answers for the mailbox holding that token even
    /// when a damaged record sorts ahead of it in the walk: one unreadable
    /// account must not make every link's page answer as an error.
    #[tokio::test]
    async fn a_password_link_is_found_past_a_damaged_record() {
        let dir = std::env::temp_dir().join(format!("control-store-pwlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let token = "0123456789abcdefghjkmnpqrs";
        std::fs::create_dir_all(dir.join("accounts/live")).unwrap();
        let account = serde_json::json!({
            "version": 1,
            "username": "live",
            "state": "active",
            "decision": "approve",
            "decided_at": "2026-10-01T09:00:00Z",
            "rail": "no_charge",
            "no_charge": true,
            "created_at": "2026-10-01T09:00:00Z",
            "password_link": { "token": token, "until": "2026-11-20" },
        });
        std::fs::write(
            dir.join("accounts/live/account.json"),
            serde_json::to_vec(&account).unwrap(),
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("accounts/broken")).unwrap();
        std::fs::write(dir.join("accounts/broken/account.json"), "not json").unwrap();
        let store = Store::new(dir.to_str().unwrap());

        assert_eq!(
            store
                .account_for_password_token(token)
                .await
                .unwrap()
                .expect("the mailbox whose link this is")
                .username,
            "live"
        );
        assert!(
            store
                .account_for_password_token("0123456789abcdefghjkmnpqrt")
                .await
                .unwrap()
                .is_none(),
            "a well-formed token no account holds names nobody"
        );
    }

    /// The typed reads split three ways: an absent file is `Ok(None)`, a
    /// damaged one is an `Err` naming it, and a valid one is `Ok(Some)`.
    #[tokio::test]
    async fn a_typed_record_read_separates_missing_damaged_and_valid() {
        let dir = std::env::temp_dir().join(format!("control-store-typed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.to_str().unwrap());

        for (what, result) in [
            (
                "account",
                store.account("alice").await.is_ok_and(|a| a.is_none()),
            ),
            (
                "group",
                store
                    .group("parish.example")
                    .await
                    .is_ok_and(|g| g.is_none()),
            ),
            (
                "application",
                store.application("tok").await.is_ok_and(|r| r.is_none()),
            ),
        ] {
            assert!(result, "a missing {what} is not Ok(None)");
        }

        std::fs::create_dir_all(dir.join("accounts/alice")).unwrap();
        std::fs::write(
            dir.join("accounts/alice/account.json"),
            serde_json::json!({
                "version": 1, "username": "alice", "state": "active",
                "decision": "approve", "decided_at": "2026-10-01T09:00:00Z",
                "rail": "no_charge", "no_charge": true,
                "created_at": "2026-10-01T09:00:00Z"
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            store.account("alice").await.unwrap().unwrap().username,
            "alice"
        );

        std::fs::create_dir_all(dir.join("groups/parish.example")).unwrap();
        std::fs::write(
            dir.join("groups/parish.example/group.json"),
            serde_json::json!({
                "version": 1, "domain": "parish.example", "name": "Parish",
                "kind": "parish",
                "payment": {"rail": "no_charge", "no_charge": true, "paid_until": null},
                "accounts": ["alice"], "site_owner": "alice"
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            store.group("parish.example").await.unwrap().unwrap().domain,
            "parish.example"
        );

        std::fs::create_dir_all(dir.join("applications")).unwrap();
        std::fs::write(
            dir.join("applications/tok.json"),
            serde_json::json!({
                "username": "alice", "status_token": "tok",
                "filed_at": "2026-10-01T09:00:00Z", "front_end": "web",
                "stage": "received", "answers": {}, "mail_keys": [],
                "rail": "no_charge", "no_charge": true, "acceptances": [],
                "question_list": "2026-10-01 abc1234"
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            store.application("tok").await.unwrap().unwrap().username,
            "alice"
        );

        // Damage in each file is named, not read as absence.
        std::fs::write(dir.join("accounts/alice/account.json"), b"{not json").unwrap();
        let err = store.account("alice").await.unwrap_err();
        assert!(
            matches!(&err, Error::Parse { path, .. } if path.ends_with("accounts/alice/account.json")),
            "{err}"
        );

        std::fs::write(dir.join("groups/parish.example/group.json"), b"{not json").unwrap();
        let err = store.group("parish.example").await.unwrap_err();
        assert!(
            matches!(&err, Error::Parse { path, .. } if path.ends_with("groups/parish.example/group.json")),
            "{err}"
        );

        std::fs::write(dir.join("applications/tok.json"), b"{not json").unwrap();
        let err = store.application("tok").await.unwrap_err();
        assert!(
            matches!(&err, Error::Parse { path, .. } if path.ends_with("applications/tok.json")),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record the handler renders cannot be written root-only. The three
    /// helpers that write it in production pass 0640; this is the guard for the
    /// next branch that calls the root-only one.
    #[tokio::test]
    async fn a_handler_read_record_refuses_a_root_only_mode() {
        let dir =
            std::env::temp_dir().join(format!("control-store-readable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("accounts/alice")).unwrap();
        std::fs::create_dir_all(dir.join("groups/example")).unwrap();
        let store = Store::new(dir.to_str().unwrap());

        let err = store
            .write_record("accounts/alice", "account.json", b"{}")
            .await
            .expect_err("a root-only account record must be refused");
        assert!(
            matches!(&err, Error::Refused(message) if message.contains("0640")),
            "{err}"
        );
        assert!(store
            .write_record_mode("accounts/alice", "account.json", b"{}", None, 0o600)
            .await
            .is_err());
        store
            .write_record_mode("accounts/alice", "account.json", b"{}", None, 0o640)
            .await
            .unwrap();
        assert!(store
            .write_record("groups/example", "group.json", b"{}")
            .await
            .is_err());
        assert!(store
            .log("accounts/alice/notices.jsonl")
            .append(b"{}")
            .await
            .is_err());
        store
            .log("accounts/alice/notices.jsonl")
            .append_mode(b"{}", None, 0o640)
            .await
            .unwrap();
        assert_eq!(
            store
                .read_record("accounts/alice", "account.json")
                .await
                .as_deref(),
            Some("{}")
        );
    }

    #[tokio::test]
    async fn a_record_is_written_by_rename_at_0600_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("control-store-test-{}", std::process::id()));
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

    /// A symlink planted at the temporary's name is refused, and the file it
    /// points at keeps its owner, mode and bytes. `write_record_mode` used to
    /// chown the path after dropping the handle, which is the window this covers.
    #[tokio::test]
    async fn a_symlink_at_the_temporary_name_is_refused_and_its_target_untouched() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        let dir =
            std::env::temp_dir().join(format!("control-store-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let apps = dir.join("applications");
        std::fs::create_dir_all(&apps).unwrap();
        let target = dir.join("master.passwd");
        let body = b"root:*:0:0::0:0:Charlie Root:/root:/bin/ksh\n";
        std::fs::write(&target, body).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = std::fs::metadata(&target).unwrap();
        symlink(&target, apps.join(".tok.json.tmp")).unwrap();

        let store = Store::new(dir.to_str().unwrap());
        store
            .write_record_owned(
                "applications",
                "tok.json",
                b"{\"a\":1}",
                Some((before.uid(), before.gid())),
            )
            .await
            .expect_err("a planted symlink must be refused");
        let after = std::fs::metadata(&target).unwrap();
        assert_eq!(
            (after.uid(), after.gid(), after.mode() & 0o777),
            (before.uid(), before.gid(), 0o600)
        );
        assert_eq!(std::fs::read(&target).unwrap(), body);
        assert!(!apps.join("tok.json").exists(), "a record was placed");

        // A normal write still lands under the directory's owner, with its mode.
        std::fs::remove_file(apps.join(".tok.json.tmp")).unwrap();
        let owner = std::fs::metadata(&apps).unwrap();
        store
            .write_record_owned(
                "applications",
                "tok.json",
                b"{\"a\":1}",
                Some((owner.uid(), owner.gid())),
            )
            .await
            .unwrap();
        let written = std::fs::metadata(apps.join("tok.json")).unwrap();
        assert_eq!(
            (written.uid(), written.gid(), written.mode() & 0o777),
            (owner.uid(), owner.gid(), 0o600)
        );
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

    /// A notice goes to the validated contact and otherwise to the member's own
    /// platform mailbox: a group mailbox's is its mailbox on the group's domain,
    /// and an outside address that is not a mail header is not used.
    #[test]
    fn a_notice_address_is_the_validated_contact_or_the_platform_mailbox() {
        let parse = |extra: &str| -> Account {
            serde_json::from_str(&format!(
                r#"{{"version": 1, "username": "secretary", "state": "active",
                    "decision": "approve", "decided_at": "2026-10-01T09:00:00Z",
                    "rail": "no_charge", "no_charge": true,
                    "created_at": "2026-10-01T09:00:00Z"{extra}}}"#
            ))
            .unwrap()
        };
        assert_eq!(parse("").notice_address(), "secretary@kyriakon.net");
        assert_eq!(
            parse(r#", "outside_address": "secretary@example.invalid""#).notice_address(),
            "secretary@example.invalid"
        );
        assert_eq!(
            parse(r#", "outside_address": "warden at example.invalid""#).notice_address(),
            "secretary@kyriakon.net"
        );
        assert_eq!(
            parse(r#", "group": "parish.example""#).notice_address(),
            "secretary@parish.example"
        );
    }

    #[tokio::test]
    async fn a_store_file_appends_and_reads_back_line_by_line() {
        let dir = std::env::temp_dir().join(format!("onboard-append-lines-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.to_str().unwrap());
        let log = store.log("journal.jsonl");
        assert!(
            log.raw_lines().await.unwrap().is_empty(),
            "missing reads as empty"
        );
        assert!(log.jsonl::<serde_json::Value>().await.unwrap().is_empty());
        log.append(b"{\"a\":1}").await.unwrap();
        log.append(b"{\"a\":2}\n").await.unwrap();
        assert_eq!(
            log.raw_lines().await.unwrap(),
            vec!["{\"a\":1}", "{\"a\":2}"]
        );
        assert_eq!(
            log.jsonl::<serde_json::Value>().await.unwrap(),
            vec![serde_json::json!({"a": 1}), serde_json::json!({"a": 2})]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A missing record is empty to both readers; a record that cannot be read
    /// is an error, never an empty one.
    #[tokio::test]
    async fn an_unreadable_record_is_an_error_not_an_empty_read() {
        let dir = std::env::temp_dir().join(format!("onboard-lines-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // A directory where the record belongs: the path exists and cannot be read.
        std::fs::create_dir_all(dir.join("journal.jsonl")).unwrap();
        let store = Store::new(dir.to_str().unwrap());
        assert!(store.log("journal.jsonl").raw_lines().await.is_err());
        assert!(store
            .log("journal.jsonl")
            .jsonl::<serde_json::Value>()
            .await
            .is_err());

        // A line that does not parse names itself, rather than reading as a
        // record with one line fewer.
        std::fs::remove_dir_all(dir.join("journal.jsonl")).unwrap();
        store
            .log("journal.jsonl")
            .append(b"{\"a\":1}")
            .await
            .unwrap();
        store
            .log("journal.jsonl")
            .append(b"not json")
            .await
            .unwrap();
        let err = store
            .log("journal.jsonl")
            .jsonl::<serde_json::Value>()
            .await
            .expect_err("a line that does not parse is an error");
        assert!(matches!(&err, Error::ParseLine { line: 2, .. }), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An append-only record is not replaced whole: the `Log` type has no write,
    /// and the record writer refuses the name. The one write that completes a
    /// recorded line is `rewrite_log`, and it says so.
    #[tokio::test]
    async fn an_append_only_record_is_not_written_as_a_record() {
        let dir = std::env::temp_dir().join(format!("onboard-rewrite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.to_str().unwrap());
        store.ensure_dir("ledger").await.unwrap();
        let err = store
            .write_record("ledger", "payments.jsonl", b"{}\n")
            .await
            .expect_err("an append-only record must be refused");
        assert!(
            matches!(&err, Error::Refused(message) if message.contains("rewrite_log")),
            "{err}"
        );
        assert!(!store.path("ledger/payments.jsonl").exists());

        store
            .rewrite_log(
                "ledger/payments.jsonl",
                b"{\"settled_on\":\"2026-11-03\"}\n",
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .log("ledger/payments.jsonl")
                .raw_lines()
                .await
                .unwrap(),
            vec!["{\"settled_on\":\"2026-11-03\"}"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The lock is opened without following a symlink, and the descriptor rather
    /// than the path is handed to the directory's owner: a symlink the
    /// unprivileged handler plants is refused and its target untouched.
    #[tokio::test]
    async fn a_lock_refuses_a_planted_symlink_and_leaves_its_target_alone() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("onboard-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("applications")).unwrap();
        let store = Store::new(dir.to_str().unwrap());
        let target = dir.join("master.passwd");
        let body = b"root:*:0:0::0:0:Charlie Root:/root:/bin/ksh\n";
        std::fs::write(&target, body).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = std::fs::metadata(&target).unwrap();
        let lock_path = dir.join("applications/.confirmation.lock");
        symlink(&target, &lock_path).unwrap();

        store
            .lock("applications/.confirmation.lock")
            .await
            .expect_err("a planted symlink must be refused");
        let after = std::fs::metadata(&target).unwrap();
        assert_eq!(
            (after.uid(), after.gid(), after.mode() & 0o777),
            (before.uid(), before.gid(), 0o600)
        );
        assert_eq!(std::fs::read(&target).unwrap(), body);

        // A real lock is made under the directory's owner, 0600, in a directory
        // the store has not laid out yet.
        std::fs::remove_file(&lock_path).unwrap();
        let _lock = store.lock("applications/.confirmation.lock").await.unwrap();
        let lock = std::fs::metadata(&lock_path).unwrap();
        let apps = std::fs::metadata(dir.join("applications")).unwrap();
        assert_eq!(
            (lock.uid(), lock.gid(), lock.mode() & 0o777),
            (apps.uid(), apps.gid(), 0o600)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An append opens the record without following a symlink: a `.jsonl` name
    /// the unprivileged handler plants as a link to a file outside the store is
    /// refused, and neither the target's bytes nor its mode move.
    #[tokio::test]
    async fn an_append_refuses_a_planted_symlink_and_leaves_its_target_alone() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        let dir =
            std::env::temp_dir().join(format!("onboard-append-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ledger")).unwrap();
        let store = Store::new(dir.to_str().unwrap());
        let target = dir.join("shadow");
        let body = b"root:*:0:0::0:0:Charlie Root:/root:/bin/ksh\n";
        std::fs::write(&target, body).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = std::fs::metadata(&target).unwrap();
        symlink(&target, dir.join("ledger/payments.jsonl")).unwrap();

        let err = store
            .log("ledger/payments.jsonl")
            .append(b"{\"amount_gbp\":\"20.00\"}\n")
            .await
            .expect_err("a planted symlink must be refused");
        assert!(
            matches!(&err, Error::Refused(message) if message.contains("ledger/payments.jsonl")),
            "{err}"
        );
        let after = std::fs::metadata(&target).unwrap();
        assert_eq!(
            (after.uid(), after.gid(), after.mode() & 0o777),
            (before.uid(), before.gid(), 0o600)
        );
        assert_eq!(std::fs::read(&target).unwrap(), body);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A record name is one component inside its directory: a name that walks
    /// out of it is refused by both the writer and the removal.
    #[tokio::test]
    async fn a_record_name_that_leaves_its_directory_is_refused() {
        let dir = std::env::temp_dir().join(format!("onboard-name-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("accounts")).unwrap();
        let store = Store::new(dir.to_str().unwrap());

        let err = store
            .write_record("accounts", "../x.json", b"{}")
            .await
            .expect_err("a name that leaves its directory must be refused");
        assert!(matches!(&err, Error::Refused(_)), "{err}");
        let err = store
            .remove("accounts", "../x.json")
            .await
            .expect_err("a removal that leaves its directory must be refused");
        assert!(matches!(&err, Error::Refused(_)), "{err}");
        assert!(!dir.join("x.json").exists(), "the escape wrote a file");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An append takes the record's own lock, `<path>.lock`: the same one a
    /// rewrite holds across its read and its rename. Held, the append waits and
    /// the record stays as it was; released, it lands and lets the lock go.
    ///
    /// The second append runs on its own thread with its own runtime, because
    /// `flock` blocks the thread that calls it and a current-thread runtime
    /// cannot time out or drop a future that is parked inside a blocking call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_append_takes_the_records_own_lock() {
        let dir = std::env::temp_dir().join(format!("onboard-log-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.to_str().unwrap());
        let log = store.log("ledger/payments.jsonl");
        let held = log.lock().await.unwrap();
        // The append is the same lock: a second holder cannot take it.
        assert!(store
            .try_lock("ledger/payments.jsonl.lock")
            .await
            .unwrap()
            .is_none());

        let root = dir.to_str().unwrap().to_string();
        let append = std::thread::spawn(move || {
            let store = Store::new(&root);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(store.log("ledger/payments.jsonl").append(b"{}\n"))
        });
        // Long enough for the thread to reach the lock. If appends did not take
        // it, the line would be on disk by now.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            log.raw_lines().await.unwrap().is_empty(),
            "the append wrote without the record's lock"
        );
        drop(held);
        append.join().unwrap().unwrap();
        assert_eq!(log.raw_lines().await.unwrap(), vec!["{}"]);
        assert!(
            store
                .try_lock("ledger/payments.jsonl.lock")
                .await
                .unwrap()
                .is_some(),
            "the append left the record's lock held"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// One lock at a time, and the non-blocking form reports the holder rather
    /// than waiting: that is what the drain's pass lock is.
    #[tokio::test]
    async fn a_second_try_on_a_held_lock_is_none_and_a_freed_one_is_some() {
        let dir = std::env::temp_dir().join(format!("onboard-lock-try-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.to_str().unwrap());
        let held = store
            .try_lock("ledger/payments.jsonl.lock")
            .await
            .unwrap()
            .expect("the first takes the lock and makes the directory");
        assert!(store
            .try_lock("ledger/payments.jsonl.lock")
            .await
            .unwrap()
            .is_none());
        drop(held);
        assert!(store
            .try_lock("ledger/payments.jsonl.lock")
            .await
            .unwrap()
            .is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
