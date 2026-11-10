//! The box's plumbing: run the repository's privileged scripts, write the mail
//! and upload keys those scripts read, and choose the address an account's
//! notices go to.
//!
//! The job modules that provision accounts, publish keys or run a box script
//! call these. A script is run by argv only, with the PATH the box's packages
//! live on.

use crate::config::DrainConfig;
use crate::flow::validate;
use crate::store::{KeyRecord, Record, Store};
use std::os::unix::fs::PermissionsExt;
use tokio::process::Command;

/// Run one of the repository's privileged scripts by its configured path and
/// hand back what it wrote. It is called with argv only: there is no shell
/// anywhere in the drain, and every value that reaches it was validated first.
pub(super) async fn spawn_script(
    cfg: &DrainConfig,
    name: &str,
    args: &[&str],
) -> Result<std::process::Output, String> {
    let path = format!("{}/{}", cfg.scripts.trim_end_matches('/'), name);
    // The drain runs from root cron, whose PATH is /usr/bin:/bin, and the scripts
    // it runs reach the packages in /usr/local: without this, a provision's
    // reload call cannot find gmid, refuses, and fails the whole approval.
    Command::new(&path)
        .args(args)
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin",
        )
        .output()
        .await
        .map_err(|e| format!("cannot run {path}: {e}"))
}

/// Run a script and refuse a non-zero exit, naming what it said.
pub(super) async fn run_script(cfg: &DrainConfig, name: &str, args: &[&str]) -> Result<(), String> {
    let out = spawn_script(cfg, name, args).await?;
    if !out.status.success() {
        return Err(script_error(cfg, name, &out));
    }
    Ok(())
}

/// Run a script and tolerate one known refusal, named by the message it prints.
/// `add-user.sh` exits non-zero when the account already exists, which is the
/// state a run that died after it leaves and the state a retry has to get past.
pub(super) async fn run_script_tolerating(
    cfg: &DrainConfig,
    name: &str,
    args: &[&str],
    tolerate: &str,
) -> Result<(), String> {
    let out = spawn_script(cfg, name, args).await?;
    if out.status.success() || String::from_utf8_lossy(&out.stderr).contains(tolerate) {
        return Ok(());
    }
    Err(script_error(cfg, name, &out))
}

pub(super) fn script_error(cfg: &DrainConfig, name: &str, out: &std::process::Output) -> String {
    let path = format!("{}/{}", cfg.scripts.trim_end_matches('/'), name);
    format!(
        "{path} exited {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    )
}

/// Write the member's upload key where `provision-member.sh` reads it, in the
/// store's own `keys/` directory, root-owned like the rest of the drain's half.
pub(super) async fn write_public_key(
    store: &Store,
    username: &str,
    material: &str,
) -> Result<(), String> {
    let body = material.trim();
    if body.is_empty() {
        return Err("the upload key material is empty".to_string());
    }
    store.ensure_dir("keys").await?;
    let mut bytes = body.as_bytes().to_vec();
    bytes.push(b'\n');
    store
        .write_record("keys", &format!("{username}.pub"), &bytes)
        .await
}

/// The localpart a mail key is published and served under: the mailbox when the
/// application named one, and the account's own name otherwise. The keyring file,
/// the published file and the branch the change is opened on all take it.
fn mail_key_localpart<'a>(username: &'a str, key: &'a KeyRecord) -> &'a str {
    if key.mailbox.is_empty() {
        username
    } else {
        key.mailbox.as_str()
    }
}

/// Publish the member's mail keys into the box keyring the encrypting LMTP reads,
/// one `<localpart>.asc` each, before any path can deliver to the account. The
/// file is created once and then left alone, so the drift check's age for it is
/// the moment this service first wrote it. Delivery fails closed without the key,
/// so an application that carries none is refused rather than made into an
/// account whose mail bounces.
pub(super) async fn publish_mail_keys(
    cfg: &DrainConfig,
    username: &str,
    keys: &[KeyRecord],
) -> Result<(), String> {
    if keys.is_empty() {
        return Err(
            "the application carries no mail key, so the account could not receive mail"
                .to_string(),
        );
    }
    let dir = std::path::Path::new(&cfg.keyring_dir);
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    for key in keys {
        let localpart = mail_key_localpart(username, key);
        if let Some(why) = validate::username_shape(localpart) {
            return Err(format!("the mail key's mailbox {localpart:?}: {why}"));
        }
        let body = key.material.trim();
        if body.is_empty() {
            return Err(format!("the mail key for {localpart} is empty"));
        }
        let path = crate::mail::keycheck::keyring_file(&cfg.keyring_dir, localpart);
        let mut bytes = body.as_bytes().to_vec();
        bytes.push(b'\n');
        // Written only when the bytes differ. The drift check's seven days for an
        // unpublished key are the age of this file, and the publish runs after
        // this in the same transition, so a retry whose publish failed must leave
        // the file, and its mtime, exactly as they are. Rewriting an identical
        // file would restart that window on every retry and it would never close.
        let same = std::fs::read(&path)
            .map(|have| have == bytes)
            .unwrap_or(false);
        if !same {
            std::fs::write(&path, &bytes)
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        }
        // deploy-mail installs the tracked keys 0644, and the drift check and the
        // encrypting daemon both read them as they find them.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("cannot set the mode on {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Offer the member's mail keys to the published set, one `keys/<localpart>.asc`
/// each, by opening a change against the public repository through
/// scripts/publish-mail-key.sh, which holds the mechanism and the token.
///
/// This runs after the keyring write and after the member is built, and before
/// the account record and the notice. Nothing about the publish may stand between
/// the member and their mail: the box keyring is what delivers, so a failed
/// publish costs the member nothing, while its failure is loud and its retry
/// leaves the keyring file, and the drift check's seven days, untouched. The
/// window in check-keyring-drift.sh is the backstop for one that never succeeds.
pub(super) async fn publish_mail_keys_publicly(
    cfg: &DrainConfig,
    username: &str,
    keys: &[KeyRecord],
) -> Result<(), String> {
    let dir = cfg.keyring_dir.trim_end_matches('/');
    for key in keys {
        let localpart = mail_key_localpart(username, key);
        let path = crate::mail::keycheck::keyring_file(dir, localpart)
            .display()
            .to_string();
        run_script(
            cfg,
            "publish-mail-key.sh",
            &[localpart, path.as_str(), cfg.keyring_publish_token.as_str()],
        )
        .await?;
    }
    Ok(())
}

/// The address the applicant gave outside the platform, revalidated here because
/// it was written by the unprivileged half and is about to become a mail header.
/// `None` when none was given.
pub(super) fn outside_address(record: &Record) -> Result<Option<String>, String> {
    match record.outside_address.as_deref() {
        Some(addr) => {
            if let Some(why) = validate::address(addr) {
                return Err(format!("the address outside the platform {addr:?}: {why}"));
            }
            Ok(Some(addr.to_string()))
        }
        None => Ok(None),
    }
}

/// The address an approval notice goes to: the applicant's own outside address,
/// or the mailbox the approval just created.
pub(super) fn recipient(record: &Record, username: &str) -> Result<String, String> {
    Ok(outside_address(record)?.unwrap_or_else(|| format!("{username}@kyriakon.net")))
}
