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

use std::path::PathBuf;
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::sign;
use crate::store::Store;

/// The cookie's name.
pub const COOKIE: &str = "kyriakon_session";

/// How long a session lasts, server-side and in the cookie.
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
    /// Whether the mail password admits `username`. The password goes on the
    /// checker's stdin and never on its command line, where `ps` would show it
    /// to every local user. Any failure of the check itself is a refusal: a box
    /// whose `doas` or checker is missing must not admit anyone.
    pub async fn admits(&self, username: &str, password: &str) -> bool {
        let mut child = match Command::new(&self.program)
            .args(&self.args)
            .arg(username)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                eprintln!(
                    "kyriakon-onboard: cannot run the login check {}: {e}",
                    self.program.display()
                );
                return false;
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
                return false;
            }
            let _ = stdin.shutdown().await;
        }
        matches!(child.wait().await, Ok(status) if status.success())
    }
}

/// `sessions/<id>.json`: the server-side half. The secret is what signs the
/// cookie, and the file lives 0600 under the handler's own store directory, so
/// only the handler and root can read it.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Record {
    version: u32,
    username: String,
    created_at: String,
    expires_at: String,
    secret: String,
}

/// An admitted session, as the account route reads it.
pub struct Session {
    pub username: String,
}

/// Open a session for `username` and return the cookie's value: the id, a dot,
/// and the HMAC of the id under the session's own secret.
pub async fn open(store: &Store, username: &str, now: OffsetDateTime) -> Result<String, String> {
    // A new login is where the old sessions are cleared. Nothing else walks the
    // directory, and an id is random, so an expired file would never be reused.
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
            .map_err(|e| format!("cannot stamp the session: {e}"))?,
        expires_at: expires
            .format(&Rfc3339)
            .map_err(|e| format!("cannot stamp the session: {e}"))?,
        secret: secret.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&record)
        .map_err(|e| format!("cannot encode the session: {e}"))?;
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
/// real checker, and no `doas`, which a test cannot have.
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
            format!("#!/bin/sh\nread -r given\n[ \"$given\" = '{password}' ]\n"),
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
        Store::new_for_test(dir.to_str().unwrap())
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-10-31T09:00:00Z", &Rfc3339).unwrap()
    }

    #[tokio::test]
    async fn a_correct_password_admits_and_a_wrong_one_does_not() {
        let auth = Authenticator {
            program: stub::checker("admits", "right horse battery"),
            args: Vec::new(),
        };
        assert!(auth.admits("alice", "right horse battery").await);
        assert!(!auth.admits("alice", "wrong horse battery").await);
    }

    #[tokio::test]
    async fn a_missing_checker_admits_nobody() {
        let auth = Authenticator {
            program: PathBuf::from("/nonexistent/kyriakon-authcheck"),
            args: Vec::new(),
        };
        assert!(!auth.admits("alice", "right horse battery").await);
    }

    #[tokio::test]
    async fn a_session_lives_for_twelve_hours_and_its_cookie_is_signed() {
        let store = store("live");
        let cookie = open(&store, "alice", now()).await.unwrap();
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

    #[tokio::test]
    async fn a_cookie_with_the_wrong_signature_or_another_shape_is_refused() {
        let store = store("forged");
        let cookie = open(&store, "alice", now()).await.unwrap();
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
            "HttpOnly",
            "Secure",
            "SameSite=Lax",
            "Max-Age=43200",
            "Path=/",
        ] {
            assert!(cookie.contains(flag), "{cookie} misses {flag}");
        }
        assert!(clear_cookie().contains("Max-Age=0"));
    }

    #[test]
    fn one_named_cookie_is_read_from_a_header_with_others() {
        let header = "other=1; kyriakon_session=abc.def; trailing=2";
        assert_eq!(from_header(header, COOKIE).as_deref(), Some("abc.def"));
        assert_eq!(from_header("other=1", COOKIE), None);
    }

    #[tokio::test]
    async fn the_next_login_removes_an_expired_session_and_keeps_a_live_one() {
        let store = store("prune");
        let stale = open(&store, "alice", now() - Duration::hours(24))
            .await
            .unwrap();
        let live = open(&store, "bob", now()).await.unwrap();
        assert!(lookup(&store, &stale, now()).await.is_none());
        assert!(lookup(&store, &live, now()).await.is_some());
        assert_eq!(
            store.list("sessions").await.unwrap().len(),
            1,
            "only the live session file remains"
        );
    }

    #[tokio::test]
    async fn a_checker_that_exits_before_reading_admits_nobody() {
        // The write fails with EPIPE once the child has gone. The check still
        // answers false, and the child is reaped rather than left a zombie.
        let auth = Authenticator {
            program: stub::checker("exits", "unused"),
            args: Vec::new(),
        };
        assert!(!auth.admits("alice", &"x".repeat(256 * 1024)).await);
    }
}
