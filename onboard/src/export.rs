//! The data-subject export: the written part of the platform's record of one
//! account, written into the member's sftp chroot, or mailed encrypted to the
//! key they already hold.
//!
//! The spec is `docs/planning/specs/data-subject-requests.md`, "What an export
//! contains". The bundle is built from one account directory and the token that
//! account references; nothing is selected that is not reached from either, so
//! one member's export cannot hold another member's record. The member's tree,
//! the Maildir, the repositories and the published roots, is named in the
//! manifest as paths they pull, and copied nowhere: the mail is ciphertext to a
//! key the platform does not hold, so a copy would change nothing.
//!
//! The destination is `<public_root>/<username>.kyriakon.net/export/<stamp>/`,
//! inside the chroot their sftp session is already confined to, and the whole
//! tree is handed to the account that owns it.

use std::path::Path;
use std::process::Stdio;

use time::format_description::well_known::Rfc3339;
use time::{Date, Duration, OffsetDateTime};

use crate::config::DrainConfig;
use crate::notice;
use crate::store::{Account, JournalLine, Store};
use crate::util;

/// The window ADR 0005 gives the application answers: ninety days from the day
/// they were filed, after which the purge deletes them.
const APPLICATION_PURGE_DAYS: i64 = 90;

/// The written answer, the part of the bundle a member reads first. It names
/// the three exclusions the spec states, because a bundle that stays silent
/// about them reads as an exhaustive record.
fn answer(username: &str, stamp: &str, purge_note: &str, mailed: bool) -> String {
    let where_it_is = if mailed {
        format!(
            "The attached file, export-{stamp}.txt.asc, is that written record,\n\
             encrypted to your public key: {purge_note}\n\
             \n\
             Open it in your own client with the private key you hold. Pull your own\n\
             tree yourself when your login is back:\n"
        )
    } else {
        format!(
            "This directory, export/{stamp}/, is that written record: {purge_note}\n\
             \n\
             It is inside the sftp space you already have. Pull your own tree yourself:\n"
        )
    };
    format!(
        "kyriakon.net data export for {username}\n\
         ====================================\n\
         \n\
         You asked for a copy of what this platform holds about your account.\n\
         {where_it_is}\n\
         The manifest names every path and copies none of it, because your mail, your\n\
         repositories and your published sites belong to you and are reached by the\n\
         protocol that owns each one.\n\
         \n\
         Three things are not in this bundle.\n\
         \n\
         1. The operator's own mailbox. The application email you sent, and your own\n\
            words in it, is the operator's correspondence and not part of this export.\n\
            ADR 0005's 90-day application purge is what bounds the text in it.\n\
         2. The platform's per-user log records. The smtpd envelope line, the Dovecot\n\
            authentication line, sshd and nsd are kept for seven days and then rotated\n\
            away; a request inside those seven days does not turn a log into a records\n\
            store, and this bundle does not reconstruct them.\n\
         3. Nothing about another member. Every file here is reached from this\n\
            account's directory or from this account's token, and the boundary is the\n\
            account.\n\
         \n\
         Your mail is not redacted: it is ciphertext to your key, in the form the\n\
         platform stores it, and you open it with the private key you already hold.\n\
         \n\
         If you cannot log in\n\
         --------------------\n\
         If you still hold your mail key, the operator can send this written part to\n\
         you encrypted to that public key, and you open it in your own client.\n\
         If you hold neither your key nor your password, the platform holds no key\n\
         that would open your mail, so what is still reachable is the written record\n\
         in this bundle and the login, restored through the password path in the\n\
         runbook. Your mail is unreadable to the platform, and to you without the\n\
         private key; the answer says that rather than promising the whole.\n"
    )
}

/// What the manifest says about the member's tree. The paths are the ones
/// `scripts/provision-member.sh` and `add-user.sh` build; the published roots
/// follow the configured public root so a test tree reads truly.
fn tree_paths(public_root: &str, username: &str) -> Vec<String> {
    let site = Path::new(public_root).join(format!("{username}.kyriakon.net"));
    vec![
        format!(
            "- Maildir: /home/{username}/Maildir. Your mail is ciphertext to your key; \
             collect it with the IMAP client you already read it with."
        ),
        format!("- Git repositories: /home/{username}/repos. Collect each one with `git clone`."),
        format!(
            "- Published web tree: {}. Collect it over sftp.",
            site.join("www").display()
        ),
        format!(
            "- Published gemini tree: {}. Collect it over sftp.",
            site.join("gemini").display()
        ),
    ]
}

fn manifest(
    public_root: &str,
    username: &str,
    stamp: &str,
    files: &[String],
    purge_note: &str,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "kyriakon.net data export manifest\n\
         ================================\n\
         account: {username}\n\
         generated: {stamp}\n\
         \n\
         This directory holds the platform's written record of the account. Each\n\
         file is named below.\n\
         \n"
    ));
    for file in files {
        out.push_str(&format!("- {file}\n"));
    }
    out.push_str(&format!("\napplication.json: {purge_note}\n\n"));
    out.push_str(
        "The member's tree, which this export does not copy\n\
         -------------------------------------------------\n\
         Nothing below is in this bundle. Each path is yours and is reached by the\n\
         protocol that owns it:\n\n",
    );
    for line in tree_paths(public_root, username) {
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str(
        "\nOne Maildir, one set of repositories and one pair of site roots belong to\n\
         one account, and the boundary is the account.\n",
    );
    out
}

/// `YYYY-MM-DDTHHMMSSZ`: the directory name, sortable by age like the store's
/// other timestamps.
fn stamp(now: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// Whether an application filed on `filed` is still inside ADR 0005's window on
/// `today`. The boundary is inclusive: the last held day is the ninetieth.
fn within_purge(filed: Date, today: Date) -> bool {
    filed + Duration::days(APPLICATION_PURGE_DAYS) >= today
}

/// The day an application record was filed, from the RFC 3339 `filed_at` the
/// record carries.
fn filed_day(text: &str) -> Option<Date> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let filed_at = value.get("filed_at")?.as_str()?;
    OffsetDateTime::parse(filed_at, &Rfc3339)
        .ok()
        .map(|t| t.date())
}

/// The account's uid and gid, from the box's passwd file. The bundle is handed
/// to the account that owns it, so a member who is not in the file is a
/// refusal rather than a root-owned directory they can no longer read.
fn member_owner(passwd: &str, username: &str) -> Result<(u32, u32), String> {
    let text = std::fs::read_to_string(passwd)
        .map_err(|e| format!("cannot read the account list {passwd}: {e}"))?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 4 && fields[0] == username {
            let uid = fields[2]
                .parse()
                .map_err(|_| format!("the uid for {username} in {passwd} is not a number"))?;
            let gid = fields[3]
                .parse()
                .map_err(|_| format!("the gid for {username} in {passwd} is not a number"))?;
            return Ok((uid, gid));
        }
    }
    Err(format!(
        "{username} is not in {passwd}, so the export has no owner to hand the bundle to"
    ))
}

fn join_lines(lines: Vec<String>) -> Vec<u8> {
    let mut out = String::new();
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }
    out.into_bytes()
}

/// One account's written part: the documents and the manifest, built from the
/// account directory and the token the account references.
async fn written(
    cfg: &DrainConfig,
    store: &Store,
    username: &str,
    now: OffsetDateTime,
    mailed: bool,
) -> Result<(Account, String, Vec<(String, Vec<u8>)>), String> {
    let account_text = store
        .read_record(&format!("accounts/{username}"), "account.json")
        .await
        .ok_or_else(|| format!("no account for {username}"))?;
    let account: Account = serde_json::from_str(&account_text)
        .map_err(|e| format!("the account record does not parse: {e}"))?;

    let mut docs: Vec<(String, Vec<u8>)> = Vec::new();
    docs.push(("account.json".to_string(), account_text.into_bytes()));
    docs.push((
        "notices.jsonl".to_string(),
        join_lines(
            store
                .lines(&format!("accounts/{username}/notices.jsonl"))
                .await,
        ),
    ));

    let purged = |day: Date| {
        format!(
            "purged after ADR 0005's 90-day window ended on {}; the platform no longer holds the answers.",
            util::date_string(day + Duration::days(APPLICATION_PURGE_DAYS))
        )
    };
    let purge_note = match store
        .read_record(&format!("accounts/{username}"), "application.json")
        .await
    {
        Some(text) => match filed_day(&text) {
            Some(filed) if within_purge(filed, now.date()) => {
                let until = util::date_string(filed + Duration::days(APPLICATION_PURGE_DAYS));
                docs.push(("application.json".to_string(), text.into_bytes()));
                format!("included; the answers are held until {until} under ADR 0005's 90-day purge")
            }
            Some(filed) => purged(filed),
            // A record with no readable filing date is still the member's own
            // words inside the store: it is included rather than lost.
            None => {
                docs.push(("application.json".to_string(), text.into_bytes()));
                "included; the record carries no filing date, so the purge boundary cannot be computed from it".to_string()
            }
        },
        None => "purged; the platform no longer holds the application answers (ADR 0005's 90-day purge has run)".to_string(),
    };

    let mut journal = Vec::new();
    for line in store.lines("journal.jsonl").await {
        if let Ok(entry) = serde_json::from_str::<JournalLine>(&line) {
            if entry.application.username == username {
                journal.push(line);
            }
        }
    }
    docs.push(("journal.jsonl".to_string(), join_lines(journal)));
    docs.push((
        "requests.jsonl".to_string(),
        join_lines(
            store
                .lines(&format!("accounts/{username}/requests.jsonl"))
                .await,
        ),
    ));

    let key_path = Path::new(&cfg.keyring_dir).join(format!("{username}.asc"));
    let key = std::fs::read(&key_path).map_err(|e| {
        format!(
            "no mail key for {username} at {}: {e}; the account's own key belongs in the export",
            key_path.display()
        )
    })?;
    docs.push((format!("keys/{username}.asc"), key));

    let token = account
        .payment_state()
        .and_then(|payment| payment.token_ref);
    let mut ledger = Vec::new();
    if let Some(token) = token.as_deref() {
        for line in store.lines("ledger/payments.jsonl").await {
            if serde_json::from_str::<serde_json::Value>(&line)
                .ok()
                .and_then(|value| {
                    value
                        .get("token")
                        .and_then(|t| t.as_str())
                        .map(str::to_string)
                })
                .as_deref()
                == Some(token)
            {
                ledger.push(line);
            }
        }
    }
    docs.push(("ledger/payments.jsonl".to_string(), join_lines(ledger)));

    let stamp = stamp(now);
    let mut files: Vec<String> = docs.iter().map(|(name, _)| name.clone()).collect();
    files.push("MANIFEST.txt".to_string());
    files.push("answer.txt".to_string());
    let manifest = manifest(&cfg.public_root, username, &stamp, &files, &purge_note);
    let answer = answer(username, &stamp, &purge_note, mailed);
    docs.push(("MANIFEST.txt".to_string(), manifest.into_bytes()));
    docs.push(("answer.txt".to_string(), answer.clone().into_bytes()));
    Ok((account, answer, docs))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("cannot set the mode on {}: {e}", path.display()))
}

/// Hand every file and directory under `root` to the member. The caller is
/// root on the box; a test runs as the tree's own owner and skips it, which is
/// the same rule `store::write_record_owned` applies.
fn hand_over(root: &Path, (uid, gid): (u32, u32)) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    std::os::unix::fs::chown(root, Some(uid), Some(gid))
        .map_err(|e| format!("cannot hand {} to {uid}:{gid}: {e}", root.display()))?;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for entry in entries {
            let path = entry
                .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
                .path();
            std::os::unix::fs::chown(&path, Some(uid), Some(gid))
                .map_err(|e| format!("cannot hand {} to {uid}:{gid}: {e}", path.display()))?;
            if path.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

fn write_tree(dir: &Path, docs: &[(String, Vec<u8>)], owner: (u32, u32)) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    use std::os::unix::fs::PermissionsExt;
    for (name, bytes) in docs {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("cannot set the mode on {}: {e}", parent.display()))?;
        }
        write_file(&path, bytes)?;
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("cannot set the mode on {}: {e}", dir.display()))?;
    let export = dir.parent().unwrap_or(dir);
    hand_over(export, owner)
}

/// The address the ready notice goes to: the contact the member gave, and the
/// mailbox on the platform otherwise.
fn member_address(account: &Account, username: &str) -> String {
    account
        .outside_address
        .clone()
        .unwrap_or_else(|| format!("{username}@kyriakon.net"))
}

/// Write the written part into the member's sftp chroot and append the ready
/// notice. Returns the bundle's path relative to the chroot, which is the shape
/// the request record's `bundle` field carries.
pub async fn deliver(cfg: &DrainConfig, store: &Store, username: &str) -> Result<String, String> {
    if let Some(why) = crate::validate::username_shape(username) {
        return Err(format!("the username {username:?}: {why}"));
    }
    let now = OffsetDateTime::now_utc();
    let (account, answer, docs) = written(cfg, store, username, now, false).await?;
    let chroot = Path::new(&cfg.public_root).join(format!("{username}.kyriakon.net"));
    if !chroot.is_dir() {
        return Err(format!(
            "the member's tree {} is not there, so there is no chroot to write the export into",
            chroot.display()
        ));
    }
    let owner = member_owner(&cfg.passwd, username)?;
    let dir = chroot.join("export").join(stamp(now));
    write_tree(&dir, &docs, owner)?;
    let to = member_address(&account, username);
    notice::send_again(
        cfg,
        store,
        username,
        "export.ready",
        "Your kyriakon.net data export is ready",
        &to,
        &answer,
    )
    .await?;
    Ok(format!("export/{}/", stamp(now)))
}

/// The bundle as one text file, for the mailed path: the same documents, each
/// under its own heading, so the written part arrives whole without a copy of
/// the tree.
fn bundle_text(docs: &[(String, Vec<u8>)]) -> String {
    let mut out = String::new();
    for (name, bytes) in docs {
        out.push_str(&format!("===== {name} =====\n"));
        out.push_str(&String::from_utf8_lossy(bytes));
        out.push('\n');
    }
    out
}

/// The one explanation a member with neither the key nor the password is owed.
fn reachable() -> String {
    "What is still reachable is the written part of the export and the login: the\n\
     login through the password path in the runbook, and the written part by post or\n\
     in person from the operator. The mail is ciphertext to a key the platform does\n\
     not hold, and with no private key it is unreadable to the member too; the answer\n\
     says which parts are reachable rather than promising the whole."
        .to_string()
}

/// Encrypt the written part to the member's public key with the same gpg
/// invocation `kyriakon-encrypt` uses for their mail: `--recipient-file` reads
/// the armored cert directly, and a scratch homedir keeps gpg's own files out
/// of the keyring.
async fn encrypt(key: &Path, plain: &[u8]) -> Result<Vec<u8>, String> {
    use tokio::io::AsyncWriteExt;
    let home = std::env::temp_dir().join(format!("kyriakon-export-gpg-{}", ulid::Ulid::new()));
    tokio::fs::create_dir_all(&home)
        .await
        .map_err(|e| format!("cannot create {}: {e}", home.display()))?;
    let run = async {
        let mut child = tokio::process::Command::new("gpg")
            .args([
                "--batch",
                "--no-tty",
                "--no-options",
                "--encrypt",
                "--armor",
                "--no-encrypt-to",
                "--recipient-file",
            ])
            .arg(key)
            .arg("--homedir")
            .arg(&home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot spawn gpg: {e}"))?;
        let mut stdin = child.stdin.take().ok_or("gpg has no stdin")?;
        stdin
            .write_all(plain)
            .await
            .map_err(|e| format!("cannot write to gpg: {e}"))?;
        stdin
            .shutdown()
            .await
            .map_err(|e| format!("cannot close gpg's stdin: {e}"))?;
        // The pipe has to be closed before the wait, or gpg never sees EOF.
        drop(stdin);
        child
            .wait_with_output()
            .await
            .map_err(|e| format!("cannot wait for gpg: {e}"))
    }
    .await;
    let _ = tokio::fs::remove_dir_all(&home).await;
    let out = run?;
    if !out.status.success() {
        return Err(format!(
            "gpg refused to encrypt to {}: {}",
            key.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// Mail the written part as an attachment encrypted to the member's public key.
/// This is the path for a member who cannot log in but still holds their key;
/// a member who holds neither is told what is reachable, and nothing is sent.
pub async fn deliver_by_mail(
    cfg: &DrainConfig,
    store: &Store,
    username: &str,
) -> Result<String, String> {
    if let Some(why) = crate::validate::username_shape(username) {
        return Err(format!("the username {username:?}: {why}"));
    }
    let key = Path::new(&cfg.keyring_dir).join(format!("{username}.asc"));
    if !key.is_file() {
        return Err(format!(
            "no public key for {username} at {}, so the written part cannot be sent encrypted.\n\n{}",
            key.display(),
            reachable()
        ));
    }
    let now = OffsetDateTime::now_utc();
    let (account, answer, docs) = written(cfg, store, username, now, true).await?;
    let armored = encrypt(&key, bundle_text(&docs).as_bytes()).await?;
    let filename = format!("export-{}.txt.asc", stamp(now));
    let to = member_address(&account, username);
    notice::send_account_notice_attachment(
        cfg,
        store,
        username,
        "export.ready",
        "Your kyriakon.net data export is ready",
        &to,
        &answer,
        &filename,
        &armored,
    )
    .await?;
    Ok(format!("mailed encrypted to the key in {}", key.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Month;

    fn day(year: i32, month: Month, day: u8) -> Date {
        Date::from_calendar_date(year, month, day).unwrap()
    }

    #[test]
    fn the_purge_boundary_is_the_ninetieth_day() {
        let filed = day(2026, Month::July, 1);
        // 89 days later is inside, the 90th day is still inside, the 91st is out.
        assert!(within_purge(filed, filed + Duration::days(89)));
        assert!(within_purge(filed, filed + Duration::days(90)));
        assert!(!within_purge(filed, filed + Duration::days(91)));
    }

    #[test]
    fn the_written_answer_names_the_three_exclusions() {
        let text = answer("secretary", "2026-10-31T120000Z", "included", false);
        assert!(text.contains("The operator's own mailbox"), "{text}");
        assert!(text.contains("log records"), "{text}");
        assert!(text.contains("Nothing about another member"), "{text}");
        assert!(text.contains("If you cannot log in"), "{text}");

        // The mailed answer points at the attachment instead of a directory,
        // and keeps the same three exclusions.
        let mailed = answer("secretary", "2026-10-31T120000Z", "included", true);
        assert!(mailed.contains("The attached file"), "{mailed}");
        assert!(mailed.contains("The operator's own mailbox"), "{mailed}");
        assert!(mailed.contains("log records"), "{mailed}");
        assert!(mailed.contains("Nothing about another member"), "{mailed}");
    }

    #[test]
    fn the_manifest_names_the_tree_as_paths_and_copies_none() {
        let text = manifest(
            "/home/www",
            "secretary",
            "2026-10-31T120000Z",
            &["account.json".to_string()],
            "purged: ADR 0005's 90-day window ended on 2026-10-01",
        );
        assert!(text.contains("/home/secretary/Maildir"), "{text}");
        assert!(text.contains("/home/secretary/repos"), "{text}");
        assert!(
            text.contains("/home/www/secretary.kyriakon.net/www"),
            "{text}"
        );
        assert!(
            text.contains("/home/www/secretary.kyriakon.net/gemini"),
            "{text}"
        );
        assert!(text.contains("does not copy"), "{text}");
        assert!(text.contains("purged"), "{text}");
    }

    #[test]
    fn the_owner_comes_from_the_account_list_and_a_stranger_is_refused() {
        let passwd = "/tmp/kyriakon-export-passwd-test";
        std::fs::write(
            passwd,
            "root:*:0:0::/root:/bin/ksh\nsecretary:*:1001:1002::/home/secretary:/sbin/nologin\n",
        )
        .unwrap();
        assert_eq!(member_owner(passwd, "secretary").unwrap(), (1001, 1002));
        assert!(member_owner(passwd, "treasurer").is_err());
        let _ = std::fs::remove_file(passwd);
    }
}
