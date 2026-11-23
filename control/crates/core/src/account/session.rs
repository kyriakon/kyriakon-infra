//! The account page's login and its server-side session.
//!
//! Login is by the mail password alone, and the platform holds no second copy
//! of it: the check is `doveadm auth test`, run as root through the one fixed
//! `doas` rule the deploy documents, by a fixed-argument checker the handler
//! cannot turn into an arbitrary `doveadm` subcommand. A page session is one
//! file per account under `sessions/`, named by a derivation of the username,
//! and the cookie carries that name and an HMAC of it under a secret stored in
//! the same file. Neither key is a credential: the mail key protects mail, the
//! upload key protects sftp and git, and nothing here reads either.
//!
//! The signature is over the id with a per-session secret rather than a
//! long-lived service key, so the handler still holds no key of its own and a
//! second process with the store cannot mint a cookie from a username.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::account::sign;
use crate::store::Store;
use crate::Error;

/// The cookie's name. The `__Host-` prefix is enforced by the browser: only a
/// host-only cookie with `Secure` and `Path=/` and no `Domain` may carry it, so
/// a member's `*.kyriakon.net` page cannot set a domain-wide cookie that the
/// handler would read ahead of its own.
pub const COOKIE: &str = "__Host-kyriakon_session";

/// How long a session lasts, server-side and in the cookie. The login check's
/// proof lives for the same span, so a session cannot outlive the login that
/// made it.
pub const TTL_HOURS: i64 = 12;

/// The checker the one `doas` rule authorises. The path is fixed, because
/// `doas.conf` matches the command path literally: a configurable one would be
/// a login that fails whenever it differed from the rule.
pub const AUTHCHECK: &str = "/usr/local/libexec/kyriakon-authcheck";

/// The `doas` the box installs.
pub const DOAS: &str = "/usr/bin/doas";

/// The command that verifies a mail password: `doas` in production, and the
/// checker directly in a test, where a root rule cannot exist.
#[derive(Clone, Debug)]
pub struct Authenticator {
    pub program: PathBuf,
    pub args: Vec<String>,
}

impl Default for Authenticator {
    fn default() -> Authenticator {
        Authenticator {
            program: PathBuf::from(DOAS),
            args: vec![AUTHCHECK.to_string()],
        }
    }
}

impl Authenticator {
    /// The proof a correct mail password earns, or `None`. The password goes on
    /// the checker's stdin and never on its command line, where `ps` would show
    /// it to every local user. The checker mints a proof in `proof_dir` and
    /// prints its token; the handler stores the token and cannot make one. Any
    /// failure of the check itself is a refusal: a box whose `doas` or checker
    /// is missing must not admit anyone.
    ///
    /// `source` is the client as the rate counters key it, and the checker keys
    /// the failed-attempt record on it: ten wrong passwords then refuse that
    /// pair rather than the member's name, which anyone who reads `keys/` knows.
    /// It is an argument rather than the environment because the checker is run
    /// through `doas`, which scrubs the environment.
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        proof_dir: &Path,
        source: &str,
    ) -> Option<String> {
        let mut child = match Command::new(&self.program)
            .args(&self.args)
            .arg(username)
            .arg(proof_dir)
            .arg(source)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(source) => {
                Error::Io {
                    what: "run the login check",
                    path: Some(self.program.clone()),
                    source,
                }
                .report("the login check");
                return None;
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            let mut line = password.as_bytes().to_vec();
            line.push(b'\n');
            if stdin.write_all(&line).await.is_err() {
                // `doas` can exit before the pipe is drained, which is EPIPE.
                // The child is still this process's to reap, or a refusal that
                // the handler answers hundreds of times a day leaves zombies in
                // a process that never exits.
                let _ = child.wait().await;
                return None;
            }
            let _ = stdin.shutdown().await;
        }
        let output = child.wait_with_output().await.ok()?;
        if !output.status.success() {
            return None;
        }
        let token = String::from_utf8(output.stdout).ok()?.trim().to_string();
        (!token.is_empty()).then_some(token)
    }
}

/// `sessions/<id>.json`: the server-side half. The secret is what signs the
/// cookie, and the file lives 0600 under the handler's own store directory, so
/// only the handler and root can read it. `proof` names the root-written file
/// that is the login's actual evidence; it is the handler's copy of a token it
/// cannot mint.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Record {
    version: u32,
    username: String,
    created_at: String,
    expires_at: String,
    secret: String,
    #[serde(default)]
    proof: String,
}

/// One root-written login proof, as `scripts/kyriakon-authcheck.sh` writes it.
#[derive(Deserialize)]
struct Proof {
    username: String,
    /// Unix seconds, when the login that made it stops counting.
    expires: i64,
}

/// Whether `token` is the shape the login check mints: 32 random bytes as 64
/// lowercase hex characters. A name of any other shape is not a file this code
/// wrote, and a handler-authored record cannot make one into a path.
fn is_proof_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Read one proof, `None` when it is missing or is not the shape the script
/// writes. A proof that cannot be read proves nothing.
async fn read_proof(dir: &Path, token: &str) -> Option<Proof> {
    let text = tokio::fs::read_to_string(dir.join(token)).await.ok()?;
    serde_json::from_str(&text).ok()
}

/// The root-written proof behind a session, checked without trusting the
/// record the handler can rewrite: the file's own username and expiry decide.
/// A token of another shape, a missing file and a file naming another account
/// are all refusals.
pub async fn verify_proof(
    dir: &Path,
    token: &str,
    username: &str,
    now: OffsetDateTime,
) -> Result<(), Error> {
    if !is_proof_token(token) {
        return Err(Error::Failed(
            "the session carries no proof this box minted".to_string(),
        ));
    }
    let Some(proof) = read_proof(dir, token).await else {
        return Err(Error::Failed(
            "the session's proof is not one this box minted".to_string(),
        ));
    };
    if proof.username != username {
        return Err(Error::Failed(format!(
            "the session belongs to {:?}, not {username:?}",
            proof.username
        )));
    }
    if now.unix_timestamp() >= proof.expires {
        return Err(Error::Failed(
            "the session named by the intent has expired".to_string(),
        ));
    }
    Ok(())
}

/// Remove the proofs whose expiry has passed. The drain runs it as root on each
/// pass, because the directory is root's 0700 and the handler cannot read it. A
/// file this code did not write is left alone: only the checker puts anything
/// there.
pub async fn prune_proofs(dir: &Path, now: OffsetDateTime) {
    let Ok(mut rd) = tokio::fs::read_dir(dir).await else {
        return;
    };
    loop {
        let Ok(entry) = rd.next_entry().await else {
            return;
        };
        let Some(entry) = entry else {
            return;
        };
        let name = entry.file_name();
        let Some(token) = name.to_str() else {
            continue;
        };
        if !is_proof_token(token) {
            continue;
        }
        let Some(proof) = read_proof(dir, token).await else {
            continue;
        };
        if now.unix_timestamp() >= proof.expires {
            let _ = tokio::fs::remove_file(entry.path()).await;
        }
    }
}

/// An admitted session, as the account route reads it.
pub struct Session {
    pub username: String,
}

/// The one record an account may hold: `sessions/<id>.json`, where the id is
/// derived from the username so a second login replaces the first's file. The
/// derivation is an HMAC under a fixed, published key: the id is a filename,
/// not a capability (the record's own secret signs the cookie), so a guessable
/// id grants nothing. Its 104 bits put an accidental collision between two
/// accounts out of reach, and its lowercase-hex alphabet is a subset of the
/// status-token alphabet the drain checks.
fn session_id(username: &str) -> Result<String, Error> {
    let hex = sign::sign(b"kyriakon account page session id", username)?;
    Ok(hex[..26].to_string())
}

/// The lock over one account's record, taken by the login that writes it and
/// by the pass that removes it. A hidden name, so `Store::list` (which drops
/// dotfiles) never reads it as a session. It is never removed: unlinking a lock
/// another writer holds would let a third make a second lock file for the same
/// record.
fn lock_path(id: &str) -> String {
    format!("sessions/.{id}.lock")
}

/// Open a session for `username` and return the cookie's value: the id, a dot,
/// and the HMAC of the id under the session's own secret. `proof` is the token
/// the root-side login check printed, which the drain reads back from its own
/// proof directory; the handler stores it and cannot mint one.
///
/// An account has one live session: the record's name comes from the username,
/// so this overwrites the previous login's record instead of adding a file, and
/// never lists the directory. A failed login writes nothing, so a member who
/// mistypes a password keeps the session they already had.
///
/// The record's lock serialises two logins for one account. `write_record`
/// stages through a fixed `.tmp` name, so without it a double submit could
/// unlink the other's temporary or publish a record whose secret the cookie it
/// returned does not carry.
pub async fn open(
    store: &Store,
    username: &str,
    proof: &str,
    now: OffsetDateTime,
) -> Result<String, Error> {
    let id = session_id(username)?;
    let _lock = store.lock(&lock_path(&id)).await?;
    let secret = crate::store::status_token().await?;
    let expires = (now + Duration::hours(TTL_HOURS))
        .replace_nanosecond(0)
        .unwrap_or(now + Duration::hours(TTL_HOURS));
    let record = Record {
        version: 1,
        username: username.to_string(),
        created_at: now
            .replace_nanosecond(0)
            .unwrap_or(now)
            .format(&Rfc3339)
            .map_err(|e| Error::context("cannot stamp the session", e))?,
        expires_at: expires
            .format(&Rfc3339)
            .map_err(|e| Error::context("cannot stamp the session", e))?,
        secret: secret.clone(),
        proof: proof.to_string(),
    };
    let bytes = serde_json::to_vec_pretty(&record)
        .map_err(|e| Error::context("cannot encode the session", e))?;
    store.ensure_dir("sessions").await?;
    store
        .write_record("sessions", &format!("{id}.json"), &bytes)
        .await?;
    let sig = sign::sign(secret.as_bytes(), &id)?;
    Ok(format!("{id}.{sig}"))
}

/// The session a cookie names, when it is live and its signature is the one the
/// record's own secret makes. An expired session answers nothing; the drain's
/// scheduled [`prune`] removes its file. A cookie naming no record answers
/// nothing.
pub async fn lookup(store: &Store, cookie: &str, now: OffsetDateTime) -> Option<Session> {
    let (id, sig) = cookie.split_once('.')?;
    // The id is a store token: 26 lowercase Crockford characters. A cookie of
    // another shape names no file this code wrote, and is not a path.
    if !crate::store::is_status_token(id) {
        return None;
    }
    let text = store.session_text(id).await.ok()??;
    let record: Record = serde_json::from_str(&text).ok()?;
    if !sign::verify(record.secret.as_bytes(), id, sig) {
        return None;
    }
    let expires = OffsetDateTime::parse(&record.expires_at, &Rfc3339).ok()?;
    if now >= expires {
        return None;
    }
    Some(Session {
        username: record.username,
    })
}

/// Remove every session that belongs to `username`. A password change runs
/// this: the record is the whole of what a cookie proves, so deleting it is what
/// ends the authority a copied cookie still names. A session for another
/// account, and a record that does not parse, are left to `prune`; a store that
/// cannot be listed is an error rather than a silent pass, because a password
/// that changed with a live session left behind is the bug this prevents.
pub async fn close_all(store: &Store, username: &str) -> Result<(), Error> {
    for name in store.list("sessions").await? {
        if !name.ends_with(".json") {
            continue;
        }
        let Some(text) = store.session_text(name.trim_end_matches(".json")).await? else {
            continue;
        };
        let belongs =
            serde_json::from_str::<Record>(&text).is_ok_and(|record| record.username == username);
        if belongs {
            store.remove("sessions", &name).await?;
        }
    }
    Ok(())
}

/// Remove the session records whose expiry has passed. The drain runs it on
/// every pass, because the handler no longer walks the directory on login: a
/// login touches only its own account's record. One unreadable file is skipped
/// rather than failing every pass: the directory holds only what this module
/// wrote, and a partial record is not a session either.
pub async fn prune(store: &Store, now: OffsetDateTime) {
    let Ok(names) = store.list("sessions").await else {
        return;
    };
    for name in names {
        if !name.ends_with(".json") {
            continue;
        }
        let id = name.trim_end_matches(".json");
        // The login that rewrites this record takes the same lock. Without it,
        // a fresh record written between this read and the removal would be
        // deleted, and the cookie the login just returned would name nothing.
        let Ok(_lock) = store.lock(&lock_path(id)).await else {
            continue;
        };
        let Ok(Some(text)) = store.session_text(id).await else {
            continue;
        };
        let expired = serde_json::from_str::<Record>(&text)
            .ok()
            .and_then(|record| OffsetDateTime::parse(&record.expires_at, &Rfc3339).ok())
            .is_none_or(|expires| now >= expires);
        if expired {
            let _ = store.remove("sessions", &name).await;
        }
    }
}

/// The session id inside a cookie, without verifying it. A caller that needs
/// the id the drain will check (the export intent) reads it here; the record
/// behind it is what proves the session, and the drain verifies that.
pub fn id(cookie: &str) -> Option<&str> {
    let (id, _) = cookie.split_once('.')?;
    crate::store::is_status_token(id).then_some(id)
}

/// Remove the session a cookie names, when its signature is the one the
/// record's own secret makes. A cookie that names nothing, or names a record
/// without carrying that record's signature, is a no-op: logging out twice is
/// not an error, and an id is not the authority the signature exists to prove.
/// The record's lock covers the second read and the removal, so a login racing
/// this logout either lands first (its new secret fails the check, and the new
/// session survives) or lands after (the logout removed only its own record).
/// The first read answers a cookie with no authority before the lock exists,
/// so an unauthenticated logout cannot litter the directory with lock files.
pub async fn close(store: &Store, cookie: &str) {
    let Some((id, sig)) = cookie.split_once('.') else {
        return;
    };
    if !crate::store::is_status_token(id) {
        return;
    }
    let Ok(Some(text)) = store.session_text(id).await else {
        return;
    };
    let Ok(record) = serde_json::from_str::<Record>(&text) else {
        return;
    };
    if !sign::verify(record.secret.as_bytes(), id, sig) {
        return;
    }
    let Ok(_lock) = store.lock(&lock_path(id)).await else {
        return;
    };
    // The record can be replaced while this waits for the lock, and the cookie
    // signs only the record it was issued for.
    let Ok(Some(text)) = store.session_text(id).await else {
        return;
    };
    let Ok(current) = serde_json::from_str::<Record>(&text) else {
        return;
    };
    if !sign::verify(current.secret.as_bytes(), id, sig) {
        return;
    }
    let _ = store.remove("sessions", &format!("{id}.json")).await;
}

/// The `Set-Cookie` value for a live session. `Secure` because the form is
/// served over TLS only; `HttpOnly` so a script cannot read it; `SameSite=Lax`
/// so a cross-site post does not carry it, while a link into the page still
/// opens with the session.
pub fn cookie(value: &str) -> String {
    format!(
        "{COOKIE}={value}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Lax",
        TTL_HOURS * 3600
    )
}

/// The `Set-Cookie` value that removes the cookie at the client.
pub fn clear_cookie() -> String {
    format!("{COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

/// One named cookie from a `Cookie` header. A malformed pair is skipped rather
/// than failing the whole header: another application's cookie is not this
/// service's to judge.
pub fn from_header(header: &str, name: &str) -> Option<String> {
    header.split(';').find_map(|pair| {
        let (key, value) = pair.trim().split_once('=')?;
        (key.trim() == name && !value.trim().is_empty()).then(|| value.trim().to_string())
    })
}

/// The stub checker the tests share: one password, read from stdin like the
/// real checker, and no `doas`, which a test cannot have. On success it prints
/// a proof token as the real one does; it writes no proof file, so a test that
/// needs the drain to accept the session mints its own.
#[cfg(test)]
pub(crate) mod stub {
    use std::path::PathBuf;

    pub(crate) fn checker(name: &str, password: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("onboard-auth-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kyriakon-authcheck");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nread -r given\n[ \"$given\" = '{password}' ] || exit 1\n\
                 printf '%s\\n' '{}'\n",
                "ab".repeat(32)
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(name: &str) -> Store {
        let dir =
            std::env::temp_dir().join(format!("onboard-session-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sessions")).unwrap();
        std::fs::create_dir_all(dir.join("proofs")).unwrap();
        Store::new_for_test(dir.to_str().unwrap())
    }

    /// The proof directory beside a test store.
    fn proofs(store: &Store) -> PathBuf {
        store.path("proofs")
    }

    /// One root-written proof, in the shape `kyriakon-authcheck` writes.
    fn mint(store: &Store, username: &str, expires: i64) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let token = format!("{:064x}", NEXT.fetch_add(1, Ordering::Relaxed));
        std::fs::write(
            proofs(store).join(&token),
            format!("{{\"username\":\"{username}\",\"expires\":{expires}}}\n"),
        )
        .unwrap();
        token
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-10-31T09:00:00Z", &Rfc3339).unwrap()
    }

    /// The source the tests pass to the checker: the address the rate counters
    /// key on, so both counters name the same client.
    const SOURCE: &str = "203.0.113.10";

    /// The throttle is the checker's, and it is keyed on the pair. A handler that
    /// did not pass the source would leave the checker one field and every
    /// failure under the same key, which is the lockout this fixes.
    #[tokio::test]
    async fn the_checker_is_given_the_source_after_the_proof_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("onboard-auth-args-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kyriakon-authcheck");
        // Reads the password as the real checker does, then answers with its
        // third argument as the "proof", so the value the test reads back is the
        // one the handler passed rather than one the stub made up.
        std::fs::write(&path, "#!/bin/sh\nread -r given\nprintf '%s\\n' \"$3\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let auth = Authenticator {
            program: path,
            args: Vec::new(),
        };
        let proof_dir = std::path::Path::new("/var/db/kyriakon/logins");
        assert_eq!(
            auth.authenticate("alice", "right horse battery", proof_dir, "2001:db8::/64")
                .await
                .as_deref(),
            Some("2001:db8::/64")
        );
    }

    #[tokio::test]
    async fn a_correct_password_admits_and_a_wrong_one_does_not() {
        let store = store("admits");
        let auth = Authenticator {
            program: stub::checker("admits", "right horse battery"),
            args: Vec::new(),
        };
        assert!(auth
            .authenticate("alice", "right horse battery", &proofs(&store), SOURCE)
            .await
            .is_some());
        assert!(auth
            .authenticate("alice", "wrong horse battery", &proofs(&store), SOURCE)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn a_missing_checker_admits_nobody() {
        let store = store("missing-checker");
        let auth = Authenticator {
            program: PathBuf::from("/nonexistent/kyriakon-authcheck"),
            args: Vec::new(),
        };
        assert!(auth
            .authenticate("alice", "right horse battery", &proofs(&store), SOURCE)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn a_session_lives_for_twelve_hours_and_its_cookie_is_signed() {
        let store = store("live");
        let proof = mint(&store, "alice", now().unix_timestamp() + 3600);
        let cookie = open(&store, "alice", &proof, now()).await.unwrap();
        assert_eq!(cookie.split('.').count(), 2, "{cookie}");
        let live = lookup(&store, &cookie, now() + Duration::hours(11))
            .await
            .expect("a live session");
        assert_eq!(live.username, "alice");
        // At the twelfth hour it is spent.
        assert!(lookup(&store, &cookie, now() + Duration::hours(12))
            .await
            .is_none());
    }

    /// The record the handler writes is not the evidence: the proof the root
    /// checker wrote is. A token of the right shape with no file behind it, and
    /// a proof naming another account, are both refused.
    #[tokio::test]
    async fn a_session_is_proved_by_the_root_written_file_not_the_record() {
        let store = store("proof");
        let proof = mint(&store, "alice", now().unix_timestamp() + 3600);
        assert!(verify_proof(&proofs(&store), &proof, "alice", now())
            .await
            .is_ok());
        // A made-up token of the right shape: no file, so no proof.
        let made_up = "0".repeat(64);
        assert!(verify_proof(&proofs(&store), &made_up, "alice", now())
            .await
            .is_err());
        // A shape that is not a filename this code would build.
        assert!(
            verify_proof(&proofs(&store), "../sessions/x", "alice", now())
                .await
                .is_err()
        );
        // The file's own username, not the record's.
        let err = verify_proof(&proofs(&store), &proof, "bob", now())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Failed(message) if message.contains("belongs to")),
            "{err}"
        );
        // The file's own expiry.
        let stale = mint(&store, "alice", now().unix_timestamp() - 1);
        let err = verify_proof(&proofs(&store), &stale, "alice", now())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Failed(message) if message.contains("expired")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_cookie_with_the_wrong_signature_or_another_shape_is_refused() {
        let store = store("forged");
        let proof = mint(&store, "alice", now().unix_timestamp() + 3600);
        let cookie = open(&store, "alice", &proof, now()).await.unwrap();
        let (id, sig) = cookie.split_once('.').unwrap();
        let forged = format!("{id}.{}", "0".repeat(sig.len()));
        assert!(lookup(&store, &forged, now()).await.is_none());
        assert!(lookup(&store, "../account", now()).await.is_none());
        assert!(lookup(&store, "", now()).await.is_none());
        // Closing removes the record, so the cookie answers nothing afterwards.
        close(&store, &cookie).await;
        assert!(lookup(&store, &cookie, now()).await.is_none());
    }

    /// A logout is authority to remove the record only when the cookie carries
    /// the signature that record's secret makes. A real id with a wrong one
    /// deletes nothing; the valid cookie still closes the session.
    #[tokio::test]
    async fn a_forged_logout_signature_deletes_nothing() {
        let store = store("logout-forged");
        let proof = mint(&store, "alice", now().unix_timestamp() + 3600);
        let cookie = open(&store, "alice", &proof, now()).await.unwrap();
        let (id, sig) = cookie.split_once('.').unwrap();
        let forged = format!("{id}.{}", "0".repeat(sig.len()));
        close(&store, &forged).await;
        assert!(
            lookup(&store, &cookie, now()).await.is_some(),
            "a forged signature deleted the session"
        );
        close(&store, &cookie).await;
        assert!(lookup(&store, &cookie, now()).await.is_none());
    }

    /// A password change closes every session the account holds and leaves
    /// another account's alone. A login after the change is a fresh record, so
    /// the new cookie is what the member uses, not the one that was revoked.
    #[tokio::test]
    async fn closing_an_accounts_sessions_leaves_anothers_and_a_new_login() {
        let store = store("close-all");
        let alice_proof = mint(&store, "alice", now().unix_timestamp() + 3600);
        let first = open(&store, "alice", &alice_proof, now()).await.unwrap();
        let second = open(&store, "alice", &alice_proof, now()).await.unwrap();
        let bob_proof = mint(&store, "bob", now().unix_timestamp() + 3600);
        let bob = open(&store, "bob", &bob_proof, now()).await.unwrap();

        close_all(&store, "alice").await.unwrap();
        assert!(lookup(&store, &first, now()).await.is_none());
        assert!(lookup(&store, &second, now()).await.is_none());
        assert!(
            lookup(&store, &bob, now()).await.is_some(),
            "another account's session was closed"
        );
        let fresh = open(&store, "alice", &alice_proof, now()).await.unwrap();
        assert!(
            lookup(&store, &fresh, now()).await.is_some(),
            "a login after the change still works"
        );
    }

    #[test]
    fn the_cookie_is_http_only_same_site_and_expires_with_the_session() {
        let cookie = cookie("abc.def");
        for flag in [
            "__Host-kyriakon_session=abc.def;",
            "HttpOnly",
            "Secure",
            "SameSite=Lax",
            "Max-Age=43200",
            "Path=/",
        ] {
            assert!(cookie.contains(flag), "{cookie} misses {flag}");
        }
        // `__Host-` is only valid host-only, so the cookie must carry no Domain.
        assert!(!cookie.contains("Domain"), "{cookie}");
        assert!(clear_cookie().contains("Max-Age=0"));
        assert!(!clear_cookie().contains("Domain"), "{}", clear_cookie());
    }

    #[test]
    fn one_named_cookie_is_read_from_a_header_with_others() {
        let header = "other=1; __Host-kyriakon_session=abc.def; trailing=2";
        assert_eq!(from_header(header, COOKIE).as_deref(), Some("abc.def"));
        assert_eq!(from_header("other=1", COOKIE), None);
    }

    #[test]
    fn the_unprefixed_cookie_a_subdomain_can_set_is_ignored() {
        // A member's page can set `kyriakon_session` with `Domain=kyriakon.net`;
        // the handler reads only the host-only, browser-guarded name.
        assert_eq!(from_header("kyriakon_session=forged", COOKIE), None);
        assert_eq!(
            from_header(
                "kyriakon_session=forged; __Host-kyriakon_session=abc.def",
                COOKIE
            )
            .as_deref(),
            Some("abc.def")
        );
    }

    /// One account holds one session: a second login replaces the first's
    /// record rather than adding another, the first cookie stops answering, and
    /// the id keeps the status-token shape the drain's `verify_session` checks.
    #[tokio::test]
    async fn a_second_login_replaces_the_first_and_keeps_one_file() {
        let store = store("cap");
        let proof = mint(&store, "alice", now().unix_timestamp() + 3600);
        let first = open(&store, "alice", &proof, now()).await.unwrap();
        let id = first.split_once('.').unwrap().0;
        assert!(crate::store::is_status_token(id), "{id}");
        let second = open(&store, "alice", &proof, now() + Duration::seconds(1))
            .await
            .unwrap();
        assert_eq!(
            second.split_once('.').unwrap().0,
            id,
            "a login no longer draws a new name"
        );
        assert!(lookup(&store, &first, now()).await.is_none());
        assert!(lookup(&store, &second, now()).await.is_some());
        assert_eq!(
            store.list("sessions").await.unwrap(),
            vec![format!("{id}.json")],
            "a repeated login left a second record"
        );
    }

    /// A login touches one record and neither lists nor prunes the directory,
    /// so its cost does not grow with the sessions other accounts hold. The
    /// drain's scheduled pass is what clears a spent record; a login leaves it.
    #[tokio::test]
    async fn a_login_leaves_the_other_sessions_alone_and_prune_clears_them() {
        let store = store("no-walk");
        let abandoned = store.path("sessions").join("abandoned.json");
        std::fs::write(&abandoned, b"{\"not\":\"a session\"}").unwrap();
        let proof = mint(&store, "alice", now().unix_timestamp() + 3600);
        open(&store, "alice", &proof, now()).await.unwrap();
        assert!(
            abandoned.exists(),
            "the login walked and pruned the directory"
        );
        prune(&store, now()).await;
        assert!(!abandoned.exists(), "the scheduled prune left it behind");
    }

    /// The prune compares the record's own expiry: a live one stays and a
    /// spent one goes, so an inverted comparison cannot pass this.
    #[tokio::test]
    async fn prune_keeps_a_live_record_and_removes_a_spent_one() {
        let store = store("prune-clock");
        let proof = mint(&store, "alice", now().unix_timestamp() + 3600);
        let cookie = open(&store, "alice", &proof, now()).await.unwrap();
        let id = cookie.split_once('.').unwrap().0;
        let path = store.path("sessions").join(format!("{id}.json"));
        prune(&store, now() + Duration::hours(11)).await;
        assert!(path.exists(), "a live record was pruned");
        prune(&store, now() + Duration::hours(13)).await;
        assert!(!path.exists(), "a spent record survived the prune");
    }

    /// The drain prunes the proofs, because the handler cannot read the root
    /// directory: the expired file goes and the live one stays.
    #[tokio::test]
    async fn an_expired_proof_is_pruned_and_a_live_one_is_kept() {
        let store = store("prune-proofs");
        let stale = mint(&store, "alice", now().unix_timestamp() - 1);
        let live = mint(&store, "alice", now().unix_timestamp() + 3600);
        prune_proofs(&proofs(&store), now()).await;
        assert!(!proofs(&store).join(&stale).exists(), "a spent proof goes");
        assert!(proofs(&store).join(&live).exists(), "a live proof stays");
    }

    #[tokio::test]
    async fn a_checker_that_exits_before_reading_admits_nobody() {
        // The write fails with EPIPE once the child has gone. The check still
        // answers nothing, and the child is reaped rather than left a zombie.
        let store = store("exits");
        let auth = Authenticator {
            program: stub::checker("exits", "unused"),
            args: Vec::new(),
        };
        assert!(auth
            .authenticate("alice", &"x".repeat(256 * 1024), &proofs(&store), SOURCE)
            .await
            .is_none());
    }
}
