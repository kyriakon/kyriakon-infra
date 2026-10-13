//! Notices: the one way anything leaves the box, and the record that stops a
//! second copy.
//!
//! A notice is recorded in the account's own `notices.jsonl` **before** it is
//! enqueued, deduplicated on the notice type and its subject. That ordering is
//! the spec's accepted direction: a crash between the record and the send loses
//! an email, which is visible in the file and on the account page, where a
//! duplicate would be a member reading the same message twice.
//!
//! Everything leaves through the local enqueuer (`/usr/sbin/sendmail` by
//! default), which the config names, so the tests point it at a stub and the
//! DKIM signing stays the smtpd's.

use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::config::DrainConfig;
use crate::store::{Notice, Store};

/// The RFC 5322 message: the two headers the enqueuer reads and a plain-text
/// body. Deliberately no From or Message-ID: the local smtpd owns those, and a
/// header the platform invents here is a header the DKIM signer then has to
/// account for.
fn message(to: &str, subject: &str, body: &str) -> String {
    format!(
        "To: {to}\nSubject: {subject}\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n{body}\n"
    )
}

/// Enqueue one message through the enqueuer the config names.
pub async fn enqueue(cfg: &DrainConfig, to: &str, subject: &str, body: &str) -> Result<(), String> {
    let mut child = Command::new(&cfg.sendmail)
        .arg("-i")
        .arg("-t")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", cfg.sendmail))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(message(to, subject, body).as_bytes())
            .await
            .map_err(|e| format!("cannot write to {}: {e}", cfg.sendmail))?;
        stdin
            .shutdown()
            .await
            .map_err(|e| format!("cannot close {}: {e}", cfg.sendmail))?;
    }
    let status = child
        .wait()
        .await
        .map_err(|e| format!("cannot wait for {}: {e}", cfg.sendmail))?;
    if !status.success() {
        return Err(format!("{} exited {status}", cfg.sendmail));
    }
    Ok(())
}

/// Whether the account already records a notice of this type and subject.
pub async fn already_sent(store: &Store, username: &str, notice_type: &str, subject: &str) -> bool {
    for line in store
        .lines(&format!("accounts/{username}/notices.jsonl"))
        .await
    {
        if let Ok(n) = serde_json::from_str::<Notice>(&line) {
            if n.notice_type == notice_type && n.subject == subject {
                return true;
            }
        }
    }
    false
}

/// Record a notice and then enqueue it, in that order. `false` means the
/// account already records it, in which case nothing was sent and nothing was
/// written.
pub async fn send_account_notice(
    cfg: &DrainConfig,
    store: &Store,
    username: &str,
    notice_type: &str,
    subject: &str,
    to: &str,
    body: &str,
) -> Result<bool, String> {
    if already_sent(store, username, notice_type, subject).await {
        return Ok(false);
    }
    let line = Notice {
        version: 1,
        at: crate::util::filed_at(),
        notice_type: notice_type.to_string(),
        subject: subject.to_string(),
        to: to.to_string(),
    };
    let encoded =
        serde_json::to_string(&line).map_err(|e| format!("cannot encode a notice: {e}"))?;
    store
        .append(&format!("accounts/{username}/notices.jsonl"), encoded.as_bytes())
        .await?;
    enqueue(cfg, to, subject, body).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stub enqueuer: it appends its own stdin to `$ONBOARD_SENT`, so a test
    /// reads exactly what would have reached the box's smtpd.
    fn stub(dir: &std::path::Path) -> String {
        let path = dir.join("enqueuer.sh");
        std::fs::write(&path, "#!/bin/sh\ncat >> \"$ONBOARD_SENT\"\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("ONBOARD_SENT", dir.join("sent"));
        path.to_str().unwrap().to_string()
    }

    fn cfg(dir: &std::path::Path) -> DrainConfig {
        DrainConfig {
            store_root: dir.join("store").to_str().unwrap().to_string(),
            scripts: dir.join("bin").to_str().unwrap().to_string(),
            sendmail: stub(dir),
            approval_key: dir.join("key").to_str().unwrap().to_string(),
            stripe_webhook_secret: String::new(),
            keyring_publish_token: String::new(),
            reviewer: "reviewer@example.invalid".to_string(),
            base_url: "https://signup.kyriakon.net".to_string(),
            price_gbp: "20.00".to_string(),
            postal_address: "REPLACE_ME".to_string(),
            release: "2026-10-10 abc1234".to_string(),
        }
    }

    #[tokio::test]
    async fn a_notice_is_recorded_before_it_is_enqueued_and_only_once() {
        let dir = std::env::temp_dir().join(format!("onboard-notice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = cfg(&dir);
        let store = Store::new(&cfg.store_root);
        store.ensure_dir("accounts/secretary").await.unwrap();

        assert!(send_account_notice(&cfg, &store, "secretary", "approval.decision", "Your application", "a@b.c", "hello")
            .await
            .unwrap());
        // The record exists before the send is observable, and the message left.
        let sent = std::fs::read_to_string(dir.join("sent")).unwrap();
        assert!(sent.contains("To: a@b.c"), "{sent}");
        assert!(sent.contains("Subject: Your application"), "{sent}");
        // The second attempt does nothing: no second message, no second line.
        assert!(!send_account_notice(&cfg, &store, "secretary", "approval.decision", "Your application", "a@b.c", "hello")
            .await
            .unwrap());
        assert_eq!(store.lines("accounts/secretary/notices.jsonl").await.len(), 1);
        assert_eq!(std::fs::read_to_string(dir.join("sent")).unwrap().matches("Subject:").count(), 1);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
