//! The one writer of the `/etc/mail` tables.
//!
//! `virtuals`, `mail_domains`, `mail_from`, `dkim_domains` and
//! `spamd_alloweddomains` are read whole by smtpd or by a filter, so a write
//! that leaves half a line behind takes addresses offline. Every mutation in
//! this module holds a kernel `flock(2)` on `<table>.lock`, writes a sibling
//! candidate, syncs it, and renames it over the table. There is no pid file to
//! reap and no directory to leave behind: the kernel releases the lock when the
//! holder exits.
//!
//! The same module backs the drain's transitions and the `mail-table` command
//! of `kyriakon-control-drain` that the shell scripts run, so a script and a
//! transition cannot disagree about the lock, the canonical form or the order of
//! the lines.
//!
//! Keys are lowercased everywhere. Addresses are lowercased too; a local
//! delivery target such as `oliver+Admin` is not an address and keeps its case,
//! because the detail part names a folder.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::Error;

/// Which table a path is, from its file name. The five are the only files this
/// module writes; the shapes below differ enough that guessing would be worse
/// than refusing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Virtuals,
    MailDomains,
    MailFrom,
    DkimDomains,
    SpamdAllowedDomains,
}

impl Kind {
    pub fn of(path: &Path) -> Result<Kind, Error> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        match name {
            "virtuals" => Ok(Kind::Virtuals),
            "mail_domains" => Ok(Kind::MailDomains),
            "mail_from" => Ok(Kind::MailFrom),
            "dkim_domains" => Ok(Kind::DkimDomains),
            "spamd.alloweddomains" => Ok(Kind::SpamdAllowedDomains),
            other => Err(Error::UnknownTable {
                name: other.to_string(),
            }),
        }
    }
}

/// How a drop matches a line's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropMode {
    Exact,
    Prefix,
    Suffix,
    /// Drop every address ending with the text from every mapping value, and a
    /// line left with no address. For `mail_from`.
    ValueSuffix,
}

impl DropMode {
    pub fn parse(how: &str) -> Result<DropMode, Error> {
        match how {
            "exact" => Ok(DropMode::Exact),
            "prefix" => Ok(DropMode::Prefix),
            "suffix" => Ok(DropMode::Suffix),
            "value-suffix" => Ok(DropMode::ValueSuffix),
            other => Err(Error::UnknownDropMode {
                mode: other.to_string(),
            }),
        }
    }
}

/// Whether a write changed the table, and whether it appended a line rather
/// than rewriting one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Change {
    pub changed: bool,
    pub added: bool,
}

impl Change {
    fn none() -> Change {
        Change {
            changed: false,
            added: false,
        }
    }
}

/// Where a wanted line stands in the table, from the writer's own parse. A
/// line written in the space form counts as present, unlike a colon-only read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    Absent,
    Same,
    /// The key is there and maps elsewhere; the line's value is carried so a
    /// caller can say where.
    Different(String),
}

/// One table file.
#[derive(Clone, Debug)]
pub struct Table {
    path: PathBuf,
    kind: Kind,
}

impl Table {
    pub fn at(path: &str) -> Result<Table, Error> {
        let path = PathBuf::from(path);
        let kind = Kind::of(&path)?;
        Ok(Table { path, kind })
    }

    /// Ensure one line is present. A bare line (`None`) is a domain or an
    /// allow-list entry; a mapping wins only when it agrees with what is there,
    /// because silently repointing an address is how mail goes elsewhere.
    pub fn ensure(&self, name: &str, value: Option<&str>) -> Result<Change, Error> {
        let entry = self.entry(name, value)?;
        self.mutate(|doc| {
            for line in doc.lines.iter_mut() {
                let Some(existing) = line.entry() else {
                    continue;
                };
                if !same(&existing.key, &entry.key) {
                    continue;
                }
                match (&existing.value, &entry.value) {
                    (None, None) => return Ok(Change::none()),
                    (Some(have), Some(want)) if same_value(have.trim(), want.trim()) => {
                        return Ok(Change::none())
                    }
                    (Some(have), Some(want)) => {
                        return Err(Error::AlreadyMapped {
                            path: self.path.clone(),
                            key: entry.key.clone(),
                            have: have.clone(),
                            want: want.clone(),
                        })
                    }
                    _ => {
                        return Err(Error::OtherShape {
                            path: self.path.clone(),
                            key: entry.key.clone(),
                        })
                    }
                }
            }
            doc.lines.push(entry_line(entry));
            Ok(Change {
                changed: true,
                added: true,
            })
        })
    }

    /// Replace the line whose key the argument names, or append it. This is the
    /// explicit repoint: the caller supplies the whole line and has decided.
    pub fn set(&self, line: &str) -> Result<Change, Error> {
        let entry = self.parse_entry(line)?;
        self.mutate(|doc| {
            for line in doc.lines.iter_mut() {
                let Some(existing) = line.entry() else {
                    continue;
                };
                if same(&existing.key, &entry.key) {
                    if line_matches(existing, &entry) {
                        return Ok(Change::none());
                    }
                    *line = entry_line(entry);
                    return Ok(Change {
                        changed: true,
                        added: false,
                    });
                }
            }
            doc.lines.push(entry_line(entry));
            Ok(Change {
                changed: true,
                added: true,
            })
        })
    }

    /// Drop every line whose key matches, or every address ending with the text
    /// from every mapping value.
    pub fn drop(&self, how: DropMode, text: &str) -> Result<Change, Error> {
        let text = text.trim();
        if text.is_empty() {
            return Err(Error::EmptyDropText);
        }
        let text = lower(text);
        self.mutate(|doc| {
            let mut changed = false;
            let mut kept = Vec::with_capacity(doc.lines.len());
            for mut line in std::mem::take(&mut doc.lines) {
                match how {
                    DropMode::ValueSuffix => {
                        let Some(entry) = line.entry_mut() else {
                            kept.push(line);
                            continue;
                        };
                        let Some(values) = entry.value.as_mut() else {
                            kept.push(line);
                            continue;
                        };
                        let before = values.clone();
                        let parts = split_values(values)
                            .into_iter()
                            .filter(|value| !lower(value).ends_with(&text))
                            .collect::<Vec<_>>();
                        if parts.len() != split_values(&before).len() {
                            changed = true;
                        }
                        if parts.is_empty() {
                            continue;
                        }
                        *values = parts.join(",");
                        kept.push(line);
                    }
                    _ => {
                        let Some(entry) = line.entry() else {
                            kept.push(line);
                            continue;
                        };
                        let key = lower(&entry.key);
                        let matched = match how {
                            DropMode::Exact => key == text,
                            DropMode::Prefix => key.starts_with(&text),
                            DropMode::Suffix => key.ends_with(&text),
                            DropMode::ValueSuffix => unreachable!(),
                        };
                        if matched {
                            changed = true;
                        } else {
                            kept.push(line);
                        }
                    }
                }
            }
            doc.lines = kept;
            Ok(Change {
                changed,
                added: false,
            })
        })
    }

    /// Add `value` to the comma-separated list of the line keyed `key`, creating
    /// the line when it is absent.
    pub fn map_add(&self, key: &str, value: &str) -> Result<Change, Error> {
        let key = self.key(key)?;
        let value = self.canonical_value(value)?;
        self.mutate_map(&key, &value)
    }

    /// Give `address` to `keep`'s line and take it off every other account's.
    pub fn map_move(&self, address: &str, keep: &str) -> Result<Change, Error> {
        let address = self.canonical_value(address)?;
        let keep = self.key(keep)?;
        self.mutate(|doc| {
            let mut changed = false;
            let mut has_keep = false;
            for line in doc.lines.iter_mut() {
                let Some(entry) = line.entry_mut() else {
                    continue;
                };
                let Some(values) = entry.value.as_mut() else {
                    continue;
                };
                let keep_line = same(&entry.key, &keep);
                has_keep |= keep_line;
                let mut parts = split_values(values);
                let had = parts.iter().any(|have| same_value(have, &address));
                if keep_line {
                    if !had {
                        parts.push(address.clone());
                        *values = parts.join(",");
                        changed = true;
                    }
                } else if had {
                    parts.retain(|have| !same_value(have, &address));
                    *values = parts.join(",");
                    changed = true;
                }
            }
            if !has_keep {
                doc.lines.push(entry_line(Entry {
                    key: keep.clone(),
                    value: Some(address.clone()),
                }));
                changed = true;
            }
            let mut kept = Vec::with_capacity(doc.lines.len());
            for line in std::mem::take(&mut doc.lines) {
                if line.entry().is_some_and(|entry| {
                    entry
                        .value
                        .as_deref()
                        .is_some_and(|value| value.trim().is_empty())
                }) {
                    changed = true;
                    continue;
                }
                kept.push(line);
            }
            doc.lines = kept;
            Ok(Change {
                changed,
                added: false,
            })
        })
    }

    /// Drop every line whose key ends with `key_suffix` and delivers into
    /// `value`: a mailbox's own addresses and the aliases that point at it.
    pub fn drop_delivering(&self, key_suffix: &str, value: &str) -> Result<Change, Error> {
        let suffix = lower(key_suffix);
        let value = value.trim().to_string();
        self.mutate(|doc| {
            let mut changed = false;
            let mut kept = Vec::with_capacity(doc.lines.len());
            for line in std::mem::take(&mut doc.lines) {
                let deliver = line.entry().is_some_and(|entry| {
                    lower(&entry.key).ends_with(&suffix)
                        && entry
                            .value
                            .as_deref()
                            .is_some_and(|have| same_value(have.trim(), &value))
                });
                if deliver {
                    changed = true;
                } else {
                    kept.push(line);
                }
            }
            doc.lines = kept;
            Ok(Change {
                changed,
                added: false,
            })
        })
    }

    /// Drop every address ending with `suffix` from `account`'s sender list,
    /// dropping the line when no address is left. Other accounts are untouched.
    pub fn drop_sender_suffix(&self, account: &str, suffix: &str) -> Result<Change, Error> {
        let account = lower(account.trim());
        let suffix = lower(suffix);
        self.mutate(|doc| {
            let mut changed = false;
            let mut kept = Vec::with_capacity(doc.lines.len());
            for mut line in std::mem::take(&mut doc.lines) {
                let Some(entry) = line.entry_mut() else {
                    kept.push(line);
                    continue;
                };
                if !same(&entry.key, &account) {
                    kept.push(line);
                    continue;
                }
                let Some(values) = entry.value.as_mut() else {
                    kept.push(line);
                    continue;
                };
                let parts = split_values(values);
                let before = parts.len();
                let parts: Vec<String> = parts
                    .into_iter()
                    .filter(|value| !lower(value).ends_with(&suffix))
                    .collect();
                if parts.len() == before {
                    kept.push(line);
                    continue;
                }
                changed = true;
                if parts.is_empty() {
                    continue;
                }
                *values = parts.join(",");
                kept.push(line);
            }
            doc.lines = kept;
            Ok(Change {
                changed,
                added: false,
            })
        })
    }

    /// Regenerate the sender mapping from `/etc/passwd` and the virtual table,
    /// under this table's lock. The deploy used to generate the file in awk and
    /// take the lock only around the rename, so a drain append that landed after
    /// the virtuals read and before the rename was dropped. Reading both sources
    /// inside the lock closes that window. The virtual table is read as a file,
    /// not through its own lock: its writes already rename atomically, and the
    /// drain never holds both locks, so a read sees the old or the whole new
    /// table.
    pub fn regenerate_senders(
        &self,
        passwd: &Path,
        virtuals: &Path,
        platform_domain: &str,
    ) -> Result<Change, Error> {
        if let Some(source) = crate::flow::validate::domain(platform_domain) {
            return Err(Error::PlatformDomain { source });
        }
        let domain = lower(platform_domain);
        let _lock = self.lock()?;
        let passwd_text = std::fs::read_to_string(passwd).map_err(|source| Error::ReadPasswd {
            path: passwd.to_path_buf(),
            source,
        })?;
        let virtuals_text =
            std::fs::read_to_string(virtuals).map_err(|source| Error::ReadVirtuals {
                path: virtuals.to_path_buf(),
                source,
            })?;
        let source = Table {
            path: virtuals.to_path_buf(),
            kind: Kind::Virtuals,
        };
        let doc = Document::parse(&source, &virtuals_text)?;

        let mut accounts = Vec::new();
        let mut own = std::collections::BTreeMap::new();
        for line in passwd_text.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 6 && fields[5].starts_with("/home/") && !fields[0].is_empty() {
                accounts.push(fields[0].to_string());
                own.insert(fields[0].to_string(), format!("{}@{domain}", fields[0]));
            }
        }
        let mut seen: std::collections::BTreeSet<String> = own.values().cloned().collect();
        let mut extra: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for entry in doc.lines.iter().filter_map(|line| line.entry()) {
            let Some(value) = entry.value.as_deref() else {
                continue;
            };
            if !entry.key.contains('@') {
                continue;
            }
            let target = value.trim().split('+').next().unwrap_or_default();
            if !own.contains_key(target) || seen.contains(&entry.key) {
                continue;
            }
            seen.insert(entry.key.clone());
            extra
                .entry(target.to_string())
                .or_default()
                .push(entry.key.clone());
        }
        let mut out = String::new();
        for account in accounts {
            let mut list = vec![own[&account].clone()];
            list.extend(extra.get(&account).cloned().unwrap_or_default());
            out.push_str(&format!("{account}: {}\n", list.join(",")));
        }
        let before = std::fs::read_to_string(&self.path).unwrap_or_default();
        if before == out {
            return Ok(Change::none());
        }
        self.write(out.as_bytes())?;
        Ok(Change {
            changed: true,
            added: false,
        })
    }

    /// The value a mapping line gives `name`, or `None`. Read under the same
    /// lock, so a caller never sees a half-written table.
    pub fn lookup(&self, name: &str) -> Result<Option<String>, Error> {
        let _lock = self.lock()?;
        let text = self.read()?;
        let doc = Document::parse(self, &text)?;
        Ok(doc
            .lines
            .iter()
            .filter_map(|line| line.entry())
            .find(|entry| same(&entry.key, name))
            .and_then(|entry| entry.value.clone()))
    }

    /// How a wanted line stands, with the same parse and comparison `set` uses:
    /// so a space-form line is present, and `Same` is exactly the no-op `set`
    /// would report. Read under the same lock as a write.
    pub fn check(&self, line: &str) -> Result<Lookup, Error> {
        let entry = self.parse_entry(line)?;
        let _lock = self.lock()?;
        let text = self.read()?;
        let doc = Document::parse(self, &text)?;
        for existing in doc.lines.iter().filter_map(|line| line.entry()) {
            if !same(&existing.key, &entry.key) {
                continue;
            }
            return Ok(if line_matches(existing, &entry) {
                Lookup::Same
            } else {
                Lookup::Different(existing.value.clone().unwrap_or_default())
            });
        }
        Ok(Lookup::Absent)
    }

    /// How many lines key a name on `suffix`: `@domain` counts every address on
    /// the domain, which is the ten-address cap's count. Read under the lock, so
    /// a concurrent append is either seen or not, never half.
    pub fn count_suffix(&self, suffix: &str) -> Result<usize, Error> {
        let _lock = self.lock()?;
        let suffix = lower(suffix);
        let text = self.read()?;
        let doc = Document::parse(self, &text)?;
        Ok(doc
            .lines
            .iter()
            .filter_map(|line| line.entry())
            .filter(|entry| lower(&entry.key).ends_with(&suffix))
            .count())
    }

    fn read(&self) -> Result<String, Error> {
        std::fs::read_to_string(&self.path).map_err(|source| Error::ReadTable {
            path: self.path.clone(),
            source,
        })
    }

    /// Read, apply, and atomically replace when the closure changed something.
    /// The lock file is opened once for the whole call and dropped at the end;
    /// the kernel releases the lock when the process exits, however it exits.
    fn mutate(
        &self,
        apply: impl FnOnce(&mut Document) -> Result<Change, Error>,
    ) -> Result<Change, Error> {
        let _lock = self.lock()?;
        let text = self.read()?;
        let mut doc = Document::parse(self, &text)?;
        let change = apply(&mut doc)?;
        if change.changed {
            self.write(doc.render().as_bytes())?;
        }
        Ok(change)
    }

    fn mutate_map(&self, key: &str, value: &str) -> Result<Change, Error> {
        self.mutate(|doc| {
            if let Some(entry) = doc
                .lines
                .iter_mut()
                .filter_map(|line| line.entry_mut())
                .find(|entry| same(&entry.key, key))
            {
                let mut values = entry.value.as_deref().map(split_values).unwrap_or_default();
                if values.iter().any(|have| same_value(have, value)) {
                    return Ok(Change::none());
                }
                values.push(value.to_string());
                entry.value = Some(values.join(","));
                return Ok(Change {
                    changed: true,
                    added: false,
                });
            }
            doc.lines.push(entry_line(Entry {
                key: key.to_string(),
                value: Some(value.to_string()),
            }));
            Ok(Change {
                changed: true,
                added: true,
            })
        })
    }

    fn lock(&self) -> Result<File, Error> {
        let path = lock_path(&self.path);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|source| Error::OpenLock {
                path: path.clone(),
                source,
            })?;
        file.lock().map_err(|source| Error::LockTable {
            path: path.clone(),
            source,
        })?;
        Ok(file)
    }

    fn write(&self, bytes: &[u8]) -> Result<(), Error> {
        let dir = self.path.parent().ok_or_else(|| Error::TableNoDirectory {
            path: self.path.clone(),
        })?;
        let candidate = dir.join(format!(
            ".{}.onboard.{}.{}",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("table"),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o644)
                .open(&candidate)
                .map_err(|source| Error::CreateCandidate {
                    path: candidate.clone(),
                    source,
                })?;
            file.write_all(bytes)
                .map_err(|source| Error::WriteCandidate {
                    path: candidate.clone(),
                    source,
                })?;
            // `.mode` at creation is masked by the process umask; the tables are
            // read by smtpd and its filters, so the mode is set, not inherited.
            std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o644)).map_err(
                |source| Error::ModeCandidate {
                    path: candidate.clone(),
                    source,
                },
            )?;
            file.sync_all().map_err(|source| Error::SyncCandidate {
                path: candidate.clone(),
                source,
            })?;
            std::fs::rename(&candidate, &self.path).map_err(|source| Error::ReplaceTable {
                path: self.path.clone(),
                source,
            })?;
            // The rename is durable only after the directory is synced.
            if let Ok(dir) = File::open(dir) {
                let _ = dir.sync_all();
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&candidate);
        }
        result
    }

    fn entry(&self, name: &str, value: Option<&str>) -> Result<Entry, Error> {
        let key = self.key(name)?;
        let value = match value {
            Some(value) => Some(self.canonical_value(value)?),
            None => None,
        };
        Ok(Entry { key, value })
    }

    fn parse_entry(&self, line: &str) -> Result<Entry, Error> {
        let (key, value) = split_line(line);
        self.entry(key, value)
    }

    /// Canonicalise and validate a key for this table.
    fn key(&self, key: &str) -> Result<String, Error> {
        let key = key.trim();
        if key.is_empty()
            || key
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == ':')
        {
            return Err(Error::NotTableKey {
                key: key.to_string(),
            });
        }
        match self.kind {
            Kind::MailFrom if key.contains('@') => Err(Error::AddressAsSenderKey {
                key: key.to_string(),
            }),
            Kind::MailDomains | Kind::DkimDomains if key.contains('@') => {
                Err(Error::NotBareDomain {
                    key: key.to_string(),
                })
            }
            Kind::SpamdAllowedDomains if !key.starts_with('@') || key.len() == 1 => {
                Err(Error::NotAllowListEntry {
                    key: key.to_string(),
                })
            }
            Kind::SpamdAllowedDomains if key.contains('@') && key[1..].contains('@') => {
                Err(Error::NotOneDomain {
                    key: key.to_string(),
                })
            }
            _ => Ok(lower(key)),
        }
    }

    /// Canonicalise and validate a value for this table. A local delivery target
    /// keeps its case; an address does not.
    fn canonical_value(&self, value: &str) -> Result<String, Error> {
        let value = value.trim();
        if value.is_empty() {
            return Err(Error::EmptyTableValue);
        }
        match self.kind {
            Kind::Virtuals if value.contains('@') => Err(Error::NotDeliveryAccount {
                value: value.to_string(),
            }),
            Kind::Virtuals if value.chars().any(|c| c.is_whitespace() || c.is_control()) => {
                Err(Error::ValueWhitespace {
                    value: value.to_string(),
                })
            }
            Kind::MailFrom => {
                let values = split_values(value);
                if values.is_empty() {
                    return Err(Error::EmptySenderList);
                }
                if let Some(not_address) = values.iter().find(|v| {
                    !v.contains('@') || v.chars().any(|c| c.is_whitespace() || c.is_control())
                }) {
                    return Err(Error::NotAddress {
                        value: not_address.clone(),
                    });
                }
                Ok(values
                    .iter()
                    .map(|v| lower(v))
                    .collect::<Vec<_>>()
                    .join(","))
            }
            _ if value.chars().any(|c| c.is_whitespace() || c.is_control()) => {
                Err(Error::ValueWhitespace {
                    value: value.to_string(),
                })
            }
            _ if value.contains('@') => Ok(lower(value)),
            _ => Ok(value.to_string()),
        }
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    PathBuf::from(lock)
}

fn lower(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn same(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

fn split_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

/// A table line into its key and optional value. `table(5)` allows a colon or
/// whitespace between the columns, and a hand edit may carry a `#` comment after
/// either. The key is never split on whitespace alone, because a bare domain has
/// none.
fn split_line(line: &str) -> (&str, Option<&str>) {
    let line = match line.split_once('#') {
        Some((head, _)) => head.trim(),
        None => line.trim(),
    };
    if let Some((key, value)) = line.split_once(':') {
        return (key.trim(), Some(value.trim()));
    }
    match line.split_once(char::is_whitespace) {
        Some((key, value)) => (key.trim(), Some(value.trim())),
        None => (line, None),
    }
}

fn same_value(left: &str, right: &str) -> bool {
    left.trim() == right.trim()
}

#[derive(Clone, Debug)]
struct Entry {
    key: String,
    value: Option<String>,
}

#[derive(Clone, Debug)]
enum Line {
    Entry(Entry),
    Raw(String),
}

impl Line {
    fn entry(&self) -> Option<&Entry> {
        match self {
            Line::Entry(entry) => Some(entry),
            Line::Raw(_) => None,
        }
    }

    fn entry_mut(&mut self) -> Option<&mut Entry> {
        match self {
            Line::Entry(entry) => Some(entry),
            Line::Raw(_) => None,
        }
    }
}

fn entry_line(entry: Entry) -> Line {
    Line::Entry(entry)
}

fn line_matches(existing: &Entry, wanted: &Entry) -> bool {
    match (&existing.value, &wanted.value) {
        (None, None) => true,
        (Some(have), Some(want)) => same_value(have, want),
        _ => false,
    }
}

#[derive(Debug)]
struct Document {
    lines: Vec<Line>,
}

impl Document {
    fn parse(table: &Table, text: &str) -> Result<Document, Error> {
        let mut lines = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                lines.push(Line::Raw(line.to_string()));
                continue;
            }
            let (key, value) = split_line(trimmed);
            let key = table.key(key)?;
            let value = match value {
                Some(value) => Some(table.canonical_value(value)?),
                None => None,
            };
            lines.push(Line::Entry(Entry { key, value }));
        }
        Ok(Document { lines })
    }

    fn render(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            match line {
                Line::Raw(raw) => out.push_str(raw),
                Line::Entry(entry) => match &entry.value {
                    Some(value) => out.push_str(&format!("{}: {value}", entry.key)),
                    None => out.push_str(&entry.key),
                },
            }
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Fixture {
            let dir = std::env::temp_dir().join(format!(
                "mail-table-{name}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Fixture { dir }
        }

        fn path(&self, name: &str) -> String {
            self.dir.join(name).to_str().unwrap().to_string()
        }

        fn write(&self, name: &str, text: &str) -> String {
            let path = self.path(name);
            std::fs::write(&path, text).unwrap();
            path
        }

        fn read(&self, name: &str) -> String {
            std::fs::read_to_string(self.path(name)).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn an_ensure_canonicalises_and_refuses_a_different_value() {
        let fix = Fixture::new("ensure");
        let path = fix.write("virtuals", "Alice@Kyriakon.NET: alice\n");
        let table = Table::at(&path).unwrap();
        assert_eq!(
            table.ensure("alice@kyriakon.net", Some("alice")).unwrap(),
            Change::none()
        );
        let change = table
            .ensure("bob@kyriakon.net", Some("bob"))
            .expect("a fresh line");
        assert!(change.changed && change.added);
        assert_eq!(
            fix.read("virtuals"),
            "alice@kyriakon.net: alice\nbob@kyriakon.net: bob\n"
        );
        let err = table
            .ensure("alice@kyriakon.net", Some("somebody-else"))
            .unwrap_err();
        assert!(matches!(
            err,
            Error::AlreadyMapped { key, have, want, .. }
                if key == "alice@kyriakon.net" && have == "alice" && want == "somebody-else"
        ));
    }

    #[test]
    fn a_set_repoints_and_an_absent_key_is_appended() {
        let fix = Fixture::new("set");
        let path = fix.write("virtuals", "alice@kyriakon.net: alice\n");
        let table = Table::at(&path).unwrap();
        let change = table.set("alice@kyriakon.net: dave").unwrap();
        assert_eq!(
            change,
            Change {
                changed: true,
                added: false
            }
        );
        assert_eq!(fix.read("virtuals"), "alice@kyriakon.net: dave\n");
        assert!(table.set("bob@kyriakon.net: bob").unwrap().added);
    }

    #[test]
    fn drops_match_literally_and_value_suffix_keeps_the_rest() {
        let fix = Fixture::new("drop");
        let path = fix.write(
            "virtuals",
            "alice@kyriakon.net: alice\nbob@parish.example: bob\n",
        );
        let table = Table::at(&path).unwrap();
        assert!(
            table
                .drop(DropMode::Exact, "alice@kyriakon.net")
                .unwrap()
                .changed
        );
        assert!(
            !table
                .drop(DropMode::Exact, "alice@kyriakon.net")
                .unwrap()
                .changed
        );
        assert!(
            table
                .drop(DropMode::Suffix, "@parish.example")
                .unwrap()
                .changed
        );
        assert_eq!(fix.read("virtuals"), "");

        let path = fix.write(
            "mail_from",
            "alice: alice@kyriakon.net,secretary@parish.example\noliver: oliver@kyriakon.net\n",
        );
        let table = Table::at(&path).unwrap();
        assert!(
            table
                .drop(DropMode::ValueSuffix, "@parish.example")
                .unwrap()
                .changed
        );
        assert_eq!(
            fix.read("mail_from"),
            "alice: alice@kyriakon.net\noliver: oliver@kyriakon.net\n"
        );
    }

    #[test]
    fn a_map_add_and_move_keep_one_address_on_one_line() {
        let fix = Fixture::new("map");
        let path = fix.write("mail_from", "alice: alice@kyriakon.net\n");
        let table = Table::at(&path).unwrap();
        assert!(
            table
                .map_add("alice", "secretary@parish.example")
                .unwrap()
                .changed
        );
        assert!(
            !table
                .map_add("alice", "secretary@parish.example")
                .unwrap()
                .changed
        );
        assert_eq!(
            fix.read("mail_from"),
            "alice: alice@kyriakon.net,secretary@parish.example\n"
        );
        // A move creates the destination line and drops an emptied source.
        assert!(
            table
                .map_move("alice@kyriakon.net", "dave")
                .unwrap()
                .changed
        );
        let text = fix.read("mail_from");
        assert!(!text.contains("alice: alice@kyriakon.net"), "{text}");
        assert!(text.contains("dave: alice@kyriakon.net"), "{text}");
    }

    #[test]
    fn delivering_addresses_and_one_domains_senders_are_dropped() {
        let fix = Fixture::new("deliver");
        let path = fix.write(
            "virtuals",
            "alice@kyriakon.net: alice\nsecretary@parish.example: alice\nalice@parish.example: parish-secretary\n",
        );
        let table = Table::at(&path).unwrap();
        assert!(
            table
                .drop_delivering("@kyriakon.net", "alice")
                .unwrap()
                .changed
        );
        let text = fix.read("virtuals");
        assert!(!text.contains("alice@kyriakon.net"), "{text}");
        assert!(text.contains("secretary@parish.example: alice"), "{text}");

        let path = fix.write(
            "mail_from",
            "alice: alice@kyriakon.net,secretary@parish.example\noliver: oliver@kyriakon.net\n",
        );
        let table = Table::at(&path).unwrap();
        assert!(
            table
                .drop_sender_suffix("alice", "@parish.example")
                .unwrap()
                .changed
        );
        assert_eq!(
            fix.read("mail_from"),
            "alice: alice@kyriakon.net\noliver: oliver@kyriakon.net\n"
        );
    }

    #[test]
    fn hand_edited_shapes_are_read_without_wedging_writes() {
        let fix = Fixture::new("hand");
        let path = fix.write(
            "virtuals",
            "alice@kyriakon.net alice\nbob@kyriakon.net: bob # note\ncarol: carol\n",
        );
        let table = Table::at(&path).unwrap();
        assert_eq!(
            table.lookup("alice@kyriakon.net").unwrap().as_deref(),
            Some("alice")
        );
        assert!(
            table
                .ensure("dave@kyriakon.net", Some("dave"))
                .unwrap()
                .changed
        );
        let text = fix.read("virtuals");
        assert!(text.contains("alice@kyriakon.net: alice"), "{text}");
        assert!(text.contains("bob@kyriakon.net: bob"), "{text}");
        assert!(text.contains("dave@kyriakon.net: dave"), "{text}");
    }

    #[test]
    fn a_check_reads_a_space_form_line_like_the_set_that_rewrites_it() {
        let fix = Fixture::new("check");
        let path = fix.write(
            "virtuals",
            "alice@kyriakon.net bob\nbob@kyriakon.net: dave\ncarol@kyriakon.net: carol\n",
        );
        let table = Table::at(&path).unwrap();
        // The space form is present, and the wanted line the scripts pass is
        // exactly what set would make of it: a forward is Different, a line
        // already mapping the account is Same.
        assert_eq!(
            table.check("alice@kyriakon.net: alice").unwrap(),
            Lookup::Different("bob".to_string())
        );
        assert_eq!(
            table.check("alice@kyriakon.net: bob").unwrap(),
            Lookup::Same
        );
        assert_eq!(table.check("bob@kyriakon.net: dave").unwrap(), Lookup::Same);
        assert_eq!(
            table.check("bob@kyriakon.net: alice").unwrap(),
            Lookup::Different("dave".to_string())
        );
        assert_eq!(
            table.check("carol@kyriakon.net: carol").unwrap(),
            Lookup::Same
        );
        assert_eq!(
            table.check("dave@kyriakon.net: dave").unwrap(),
            Lookup::Absent
        );
    }

    #[test]
    fn a_local_target_keeps_its_case_and_an_address_does_not() {
        let fix = Fixture::new("case");
        let path = fix.write("virtuals", "admin: oliver+Admin\n");
        let table = Table::at(&path).unwrap();
        assert_eq!(
            table.lookup("admin").unwrap().as_deref(),
            Some("oliver+Admin")
        );
        assert!(!table.set("admin: oliver+Admin").unwrap().changed);
        assert!(table.set("admin: oliver+private").unwrap().changed);

        let path = fix.write("mail_from", "admin: ADMIN@Kyriakon.NET\n");
        let table = Table::at(&path).unwrap();
        assert_eq!(
            table.lookup("admin").unwrap().as_deref(),
            Some("admin@kyriakon.net")
        );
        assert!(!table.set("admin: admin@kyriakon.net").unwrap().changed);
    }

    #[test]
    fn a_sender_map_is_regenerated_under_the_lock() {
        let fix = Fixture::new("regenerate");
        let path = fix.write("mail_from", "stale: stale@kyriakon.net\n");
        let passwd = fix.write(
            "passwd",
            "oliver:x:1000:1000::/home/oliver:/bin/ksh\n\
             alice:x:1001:1001::/home/alice:/bin/ksh\n\
             _onboard:x:800:800::/var/db/onboard:/sbin/nologin\n",
        );
        let virtuals = fix.write(
            "virtuals",
            "oliver@kyriakon.net: oliver\n\
             secretary@parish.example: alice\n\
             admin@kyriakon.net: alice+Admin\n\
             hello: alice\n\
             apply@kyriakon.net: _onboard\n",
        );
        let table = Table::at(&path).unwrap();
        assert!(
            table
                .regenerate_senders(Path::new(&passwd), Path::new(&virtuals), "kyriakon.net")
                .unwrap()
                .changed
        );
        assert_eq!(
            fix.read("mail_from"),
            "oliver: oliver@kyriakon.net\n\
             alice: alice@kyriakon.net,secretary@parish.example,admin@kyriakon.net\n"
        );
        assert!(
            !table
                .regenerate_senders(Path::new(&passwd), Path::new(&virtuals), "kyriakon.net")
                .unwrap()
                .changed
        );
    }

    #[test]
    fn twenty_writers_lose_no_line() {
        let fix = Fixture::new("concurrent");
        let path = fix.write("virtuals", "");
        let mut handles = Vec::new();
        for index in 0..20 {
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                Table::at(&path)
                    .unwrap()
                    .ensure(
                        &format!("user{index}@kyriakon.net"),
                        Some(&format!("user{index}")),
                    )
                    .unwrap();
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        let text = fix.read("virtuals");
        assert_eq!(text.lines().count(), 20, "{text}");
        for index in 0..20 {
            assert!(
                text.contains(&format!("user{index}@kyriakon.net: user{index}")),
                "{text}"
            );
        }

        // Ten removes and ten adds at once: the same lock covers both, and what
        // is left is the ten survivors and the ten new lines, nothing else.
        let mut handles = Vec::new();
        for index in 0..20 {
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                let table = Table::at(&path).unwrap();
                if index % 2 == 0 {
                    table
                        .drop(DropMode::Exact, &format!("user{index}@kyriakon.net"))
                        .unwrap();
                } else {
                    table
                        .ensure(
                            &format!("new{index}@kyriakon.net"),
                            Some(&format!("new{index}")),
                        )
                        .unwrap();
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        let text = fix.read("virtuals");
        assert_eq!(
            text.lines().count(),
            20,
            "ten survivors plus ten additions: {text}"
        );
        for index in (1..20).step_by(2) {
            assert!(
                text.contains(&format!("user{index}@kyriakon.net: user{index}")),
                "{text}"
            );
            assert!(
                text.contains(&format!("new{index}@kyriakon.net: new{index}")),
                "{text}"
            );
        }
        for index in (0..20).step_by(2) {
            assert!(
                !text.contains(&format!("user{index}@kyriakon.net")),
                "{text}"
            );
        }
    }

    #[test]
    fn a_missing_table_is_reported_as_unreadable() {
        let fix = Fixture::new("missing");
        let table = Table::at(&fix.path("virtuals")).unwrap();
        let err = table
            .ensure("alice@kyriakon.net", Some("alice"))
            .unwrap_err();
        assert!(matches!(err, Error::ReadTable { .. }));
    }
}
