//! The account page's login and its server-side session.
//!
//! Login is by the mail password alone, and the platform holds no second copy
//! of it: the check is `doveadm auth test`, run as root through the one fixed
//! `doas` rule the deploy documents, by a fixed-argument checker the handler
//! cannot turn into an arbitrary `doveadm` subcommand. A page session is a file
//! under `sessions/` named by 128 random bits, and the cookie carries that name
//! and an HMAC of it under a secret stored in the same file. Neither key is a
//! credential: the mail key protects mail, the upload key protects sftp and git,
//! and nothing here reads either.
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
const DOAS: &str = "/usr/bin/doas";

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
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        proof_dir: &Path,
    ) -> Option<String> {
        let mut child = match Command::new(&self.program)
            .args(&self.args)
            .arg(username)
            .arg(proof_dir)
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

/// Open a session for `username` and return the cookie's value: the id, a dot,
/// and the HMAC of the id under the session's own secret. `proof` is the token
/// the root-side login check printed, which the drain reads back from its own
/// proof directory; the handler stores it and cannot mint one.
pub async fn open(
    store: &Store,
    username: &str,
    proof: &str,
    now: OffsetDateTime,
) -> Result<String, Error> {
    // A new login is where the old sessions are cleared. Nothing else walks the
    // directory, and an id is random, so an expired file would never be reused.
    // The proofs are pruned by the drain instead: that directory is root's, and
    // the handler cannot read it.
    prune(store, now).await;
    let id = crate::store::status_token().await?;
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
/// record's own secret makes. An expired session answers nothing; its file is
/// removed by the next `open`, which is the only walk of the directory. A cookie
/// naming no record answers nothing.
pub async fn lookup(store: &Store, cookie: &str, now: OffsetDateTime) -> Option<Session> {
    let (id, sig) = cookie.split_once('.')?;
    // The id is a store token: 26 lowercase Crockford characters. A cookie of
    // another shape names no file this code wrote, and is not a path.
    if !crate::store::is_status_token(id) {
        return None;
    }
    let text = store.read_record("sessions", &format!("{id}.json")).await?;
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

/// Remove the session records whose expiry has passed. One unreadable file is
/// skipped rather than failing every login: the directory holds only what this
/// module wrote, and a partial record is not a session either.
pub async fn prune(store: &Store, now: OffsetDateTime) {
    let Ok(names) = store.list("sessions").await else {
        return;
    };
    for name in names {
        if !name.ends_with(".json") {
            continue;
        }
        let Some(text) = store.read_record("sessions", &name).await else {
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

/// Remove the session a cookie names. A cookie that names nothing is a no-op:
/// logging out twice is not an error.
pub async fn close(store: &Store, cookie: &str) {
    let Some((id, _)) = cookie.split_once('.') else {
        return;
    };
    if !crate::store::is_status_token(id) {
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

    #[tokio::test]
    async fn a_correct_password_admits_and_a_wrong_one_does_not() {
        let store = store("admits");
        let auth = Authenticator {
            program: stub::checker("admits", "right horse battery"),
            args: Vec::new(),
        };
        assert!(auth
            .authenticate("alice", "right horse battery", &proofs(&store))
            .await
            .is_some());
        assert!(auth
            .authenticate("alice", "wrong horse battery", &proofs(&store))
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
            .authenticate("alice", "right horse battery", &proofs(&store))
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

    #[tokio::test]
    async fn the_next_login_removes_an_expired_session_and_keeps_a_live_one() {
        let store = store("prune");
        let stale_proof = mint(&store, "alice", now().unix_timestamp() - 1);
        let stale = open(&store, "alice", &stale_proof, now() - Duration::hours(24))
            .await
            .unwrap();
        let live_proof = mint(
            &store,
            "bob",
            (now() + Duration::hours(TTL_HOURS)).unix_timestamp(),
        );
        let live = open(&store, "bob", &live_proof, now()).await.unwrap();
        assert!(lookup(&store, &stale, now()).await.is_none());
        assert!(lookup(&store, &live, now()).await.is_some());
        assert_eq!(
            store.list("sessions").await.unwrap().len(),
            1,
            "only the live session file remains"
        );
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
            .authenticate("alice", &"x".repeat(256 * 1024), &proofs(&store))
            .await
            .is_none());
    }
}
