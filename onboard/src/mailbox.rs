//! The `apply@kyriakon.net` spool: the fallback route for a key that will not
//! fit a status 10 answer.
//!
//! `smtpd` delivers this address to a plaintext Maildir rather than the LMTP
//! path, because the drain has to read the key to file it and zero-access mail
//! is exactly what it cannot read. Each pass reads `mail/new`, files whatever
//! key the message carries against the draft named in its subject, and deletes
//! the message. A message that carries no key block is not answered; one whose
//! token no longer resolves gets one reply with a fresh link, rate-limited per
//! sender so the address cannot become a backscatter source.
//!
//! The parser is deliberately small: headers, multipart, and the two transfer
//! encodings a mail client uses for an armoured block. Anything it cannot read
//! has no key block, and is dropped rather than answered.

use std::collections::BTreeMap;

use time::OffsetDateTime;

use crate::config::DrainConfig;
use crate::draft::{self, Draft};
use crate::keycheck;
use crate::notice;
use crate::responder::HOST;
use crate::store::Store;

const BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const END: &str = "-----END PGP PUBLIC KEY BLOCK-----";
/// One reply per sender per day. The spec's requirement is that the address is
/// not a backscatter source; a day is long enough that a second mail from the
/// same applicant is not answered twice and short enough that a genuine retry
/// the next day is.
const REPLY_INTERVAL_SECONDS: i64 = 24 * 60 * 60;
const REPLY_SUBJECT: &str = "Your Kyriakon application key";

/// Read the spool and act on every message in it. A failure on one message is
/// reported and the rest still run; the message that failed is left for the next
/// pass, so a transient store error loses nothing.
pub async fn run(cfg: &DrainConfig, store: &Store) -> Result<(), String> {
    let dir = std::path::Path::new(&cfg.mail_dir);
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("cannot read {}: {e}", dir.display())),
    };
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
    {
        let path = entry.path();
        if !entry.file_type().await.is_ok_and(|t| t.is_file()) {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        let text = match tokio::fs::read(&path).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => {
                crate::transitions::report_failure(
                    cfg,
                    store,
                    name.as_ref(),
                    "mail",
                    &format!("cannot read {}: {e}", path.display()),
                )
                .await;
                continue;
            }
        };
        if let Err(e) = one(cfg, store, &text).await {
            crate::transitions::report_failure(cfg, store, name.as_ref(), "mail", &e).await;
            continue;
        }
        if let Err(e) = tokio::fs::remove_file(&path).await {
            crate::transitions::report_failure(
                cfg,
                store,
                name.as_ref(),
                "mail",
                &format!("cannot remove {}: {e}", path.display()),
            )
            .await;
        }
    }
    Ok(())
}

/// Act on one message. `Ok` means it has been dealt with and may be deleted,
/// whether that was files, refuse or ignore. The reply address is read only on
/// the paths that answer: a live token files the key even when From is empty.
async fn one(cfg: &DrainConfig, store: &Store, raw: &str) -> Result<(), String> {
    let message = Message::parse(raw);
    let blocks = labelled_blocks(&message.body);
    if blocks.is_empty() {
        return Ok(());
    }
    let Some(token) = token_in_subject(&message.subject) else {
        return reply_or_drop(cfg, store, &message, &restart_body()).await;
    };
    let lock = draft::lock(store).await?;
    let Some(mut draft) = draft::load(store, &token).await? else {
        drop(lock);
        return reply_or_drop(cfg, store, &message, &restart_body()).await;
    };
    let keys = match assign(&blocks, &draft) {
        Ok(keys) => keys,
        Err(missing) => {
            drop(lock);
            return reply_or_drop(cfg, store, &message, &missing_body(&missing)).await;
        }
    };
    for (mailbox, material) in keys {
        draft.mail_keys.retain(|k| k.mailbox != mailbox);
        draft.mail_keys.push(keycheck::mail_key(mailbox, &material));
    }
    let saved = draft::save(store, &mut draft).await;
    drop(lock);
    saved
}

/// Answer the sender when there is one to answer. A message with no usable From
/// still gets its key filed, but there is nowhere to send a refusal.
async fn reply_or_drop(
    cfg: &DrainConfig,
    store: &Store,
    message: &Message,
    body: &str,
) -> Result<(), String> {
    match message.reply_address() {
        Some(from) => reply(cfg, store, &from, body).await,
        None => Ok(()),
    }
}

/// One message: the headers it needs, and the decoded body.
pub struct Message {
    pub from: String,
    pub subject: String,
    pub body: String,
}

impl Message {
    /// Parse a raw message. A message with no blank line has an empty body,
    /// which carries no key and is therefore ignored rather than an error.
    pub fn parse(raw: &str) -> Message {
        let raw = raw.replace("\r\n", "\n");
        let (headers, body) = match raw.split_once("\n\n") {
            Some((h, b)) => (h, b),
            None => (raw.as_str(), ""),
        };
        Message {
            from: header(headers, "from").unwrap_or_default(),
            subject: header(headers, "subject").unwrap_or_default(),
            body: decode_body(headers, body),
        }
    }

    /// The address a reply may go to, or `None` when the From header holds
    /// nothing that parses. Never reply to something that is not an address:
    /// the alternative is a bounce loop.
    pub fn reply_address(&self) -> Option<String> {
        if let (Some(open), Some(close)) = (self.from.find('<'), self.from.find('>')) {
            if open < close {
                let inner = self.from[open + 1..close].trim();
                if is_address(inner) {
                    return Some(inner.to_string());
                }
            }
        }
        self.from
            .split(|c: char| {
                c.is_whitespace() || matches!(c, '<' | '>' | ',' | ';' | ':' | '"' | '(' | ')')
            })
            .find(|token| is_address(token))
            .map(str::to_string)
    }
}

fn is_address(value: &str) -> bool {
    let mut parts = value.split('@');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(local), Some(domain), None) => {
            !local.is_empty()
                && !domain.is_empty()
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && domain.contains('.')
                && value
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && !b"<>\"(),;:".contains(&b))
        }
        _ => false,
    }
}

/// The first status token in a subject, matched case-insensitively. A token is
/// 26 characters from one alphabet, so the first run that validates is it.
pub fn token_in_subject(subject: &str) -> Option<String> {
    let lower = subject.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    for start in 0..bytes.len() {
        if start + 26 > bytes.len() {
            break;
        }
        if !lower.is_char_boundary(start) || !lower.is_char_boundary(start + 26) {
            continue;
        }
        let candidate = &lower[start..start + 26];
        if crate::store::is_status_token(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

/// Armoured blocks with the line above each, which is where the applicant names
/// the mailbox. A block's label is the nearest non-empty line before its BEGIN.
pub fn labelled_blocks(text: &str) -> Vec<(Option<String>, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !lines[i].trim().starts_with(BEGIN) {
            i += 1;
            continue;
        }
        let label = lines[..i]
            .iter()
            .rev()
            .map(|l| l.trim())
            .find(|l| !l.is_empty())
            .map(str::to_string);
        let mut block = String::new();
        while i < lines.len() {
            block.push_str(lines[i].trim_end());
            block.push('\n');
            let done = lines[i].trim().starts_with(END);
            i += 1;
            if done {
                break;
            }
        }
        out.push((label, block.trim().to_string()));
    }
    out
}

/// Pair each block with the draft's mailbox. A body with more than one mailbox
/// needs a label above each block; a person's single key does not. `Err` names
/// the mailboxes the message failed to label, which is what the reply says.
fn assign(
    blocks: &[(Option<String>, String)],
    draft: &Draft,
) -> Result<Vec<(String, String)>, Vec<String>> {
    let body = draft.answers.get("whose").map(String::as_str) == Some("body");
    let domain = draft
        .answers
        .get("body_domain")
        .cloned()
        .unwrap_or_default();
    let names: Vec<String> = if body {
        crate::questions::account_names(&draft.answers)
    } else {
        draft
            .answers
            .get("username")
            .filter(|n| !n.is_empty())
            .cloned()
            .into_iter()
            .collect()
    };
    if names.is_empty() {
        return Ok(Vec::new());
    }
    // One mailbox takes the first block, labelled or not. The spec says the
    // drain takes the first block from the message body; a second block is not
    // something a single-mailbox applicant needs to label.
    if names.len() == 1 {
        return Ok(vec![(names[0].clone(), blocks[0].1.clone())]);
    }

    let mut assigned: Vec<(String, String)> = Vec::new();
    let mut covered = vec![false; names.len()];
    for (label, block) in blocks {
        let Some(label) = label.as_deref() else {
            continue;
        };
        let index = names
            .iter()
            .enumerate()
            .find(|(index, name)| !covered[*index] && name_in_label(label, name, &domain))
            .map(|(index, _)| index);
        if let Some(index) = index {
            covered[index] = true;
            assigned.push((names[index].clone(), block.clone()));
        }
    }
    if assigned.len() != blocks.len() {
        let missing: Vec<String> = names
            .into_iter()
            .zip(covered)
            .filter_map(|(name, seen)| (!seen).then_some(name))
            .collect();
        return Err(missing);
    }
    Ok(assigned)
}

fn name_in_label(label: &str, name: &str, domain: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    if !domain.is_empty() && lower.contains(&format!("{name}@{}", domain.to_ascii_lowercase())) {
        return true;
    }
    lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-'))
        .any(|token| token == name)
}

/// Send one reply unless this sender already had one today. The timestamp is
/// written before the enqueuer runs, so a crash or a failed send cannot produce
/// a second reply on the next pass.
async fn reply(cfg: &DrainConfig, store: &Store, sender: &str, body: &str) -> Result<(), String> {
    let path = store.path("mail/replies.json");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut sent: BTreeMap<String, i64> = store
        .read_record("mail", "replies.json")
        .await
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    sent.retain(|_, at| now.saturating_sub(*at) < REPLY_INTERVAL_SECONDS);
    if sent.contains_key(sender) {
        return Ok(());
    }
    sent.insert(sender.to_string(), now);
    let bytes = serde_json::to_vec_pretty(&sent)
        .map_err(|e| format!("cannot encode the reply log: {e}"))?;
    let owner = store.dir_owner("mail");
    store
        .write_record_owned("mail", "replies.json", &bytes, owner)
        .await
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    notice::enqueue(cfg, sender, REPLY_SUBJECT, body).await
}

fn restart_body() -> String {
    format!(
        "The application this key belongs to has closed, or the subject carried no \
         application token, so the key was not filed.\n\n\
         Start again here, and keep the new link:\n\n\
         gemini://{HOST}/apply\n"
    )
}

fn missing_body(missing: &[String]) -> String {
    if missing.is_empty() {
        return format!(
            "The key was not filed: the message carries more key blocks than \
             mailboxes. Mail one key for one mailbox, or start again here:\n\n\
             gemini://{HOST}/apply\n"
        );
    }
    format!(
        "The key was not filed. These mailboxes have no key labelled with their \
         name: {}.\n\n\
         Put the mailbox address on the line above each key block and mail it \
         again, or start again here:\n\n\
         gemini://{HOST}/apply\n",
        missing.join(", "),
    )
}

/// How deep a MIME tree may nest before it is treated as carrying no text. A
/// message is unauthenticated input from a stranger; without a bound, a message
/// built from a few hundred bytes of boundaries recurses until the worker's
/// stack overflows and takes the drain down with it.
const MAX_MIME_DEPTH: usize = 8;

/// The message body with its transfer encoding undone and the text part chosen
/// from a multipart. Unknown encodings are read as they are, which loses no key
/// block that was sent as text.
fn decode_body(headers: &str, body: &str) -> String {
    decode_body_at(headers, body, 0)
}

fn decode_body_at(headers: &str, body: &str, depth: usize) -> String {
    if depth > MAX_MIME_DEPTH {
        return String::new();
    }
    let content_type = header(headers, "content-type").unwrap_or_default();
    let lower = content_type.to_ascii_lowercase();
    if lower.starts_with("multipart/") {
        let Some(boundary) = parameter(&content_type, "boundary") else {
            return String::new();
        };
        let marker = format!("--{boundary}");
        let mut fallback = None;
        for part in body.split(&marker) {
            let part = part.trim_start_matches('\n');
            if part.starts_with("--") {
                continue;
            }
            let Some((part_headers, part_body)) = part.split_once("\n\n") else {
                continue;
            };
            let part_type = header(part_headers, "content-type")
                .unwrap_or_default()
                .to_ascii_lowercase();
            let decoded = decode_body_at(part_headers, part_body, depth + 1);
            if part_type.starts_with("text/plain") {
                return decoded;
            }
            // A nested multipart can hold the text/plain; keep what it found
            // rather than discarding it because its own type is not text/*.
            if fallback.is_none()
                && !decoded.is_empty()
                && (part_type.starts_with("text/") || part_type.starts_with("multipart/"))
            {
                fallback = Some(decoded);
            }
        }
        return fallback.unwrap_or_default();
    }

    match header(headers, "content-transfer-encoding")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "base64" => keycheck::base64_decode(body)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default(),
        "quoted-printable" => quoted_printable(body),
        _ => body.to_string(),
    }
}

fn quoted_printable(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'=' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        if bytes.get(i + 1) == Some(&b'\n') {
            i += 2;
            continue;
        }
        if bytes.get(i + 1) == Some(&b'\r') && bytes.get(i + 2) == Some(&b'\n') {
            i += 3;
            continue;
        }
        match (
            bytes.get(i + 1).and_then(|b| hex(*b)),
            bytes.get(i + 2).and_then(|b| hex(*b)),
        ) {
            (Some(high), Some(low)) => {
                out.push(high * 16 + low);
                i += 3;
            }
            _ => {
                out.push(b'=');
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// A header's value, folded lines joined, matched case-insensitively.
fn header(headers: &str, name: &str) -> Option<String> {
    let mut unfolded: Vec<String> = Vec::new();
    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = unfolded.last_mut() {
                last.push(' ');
                last.push_str(line.trim());
            }
        } else {
            unfolded.push(line.to_string());
        }
    }
    unfolded.iter().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

/// A `; name=value` parameter, quoted or bare.
fn parameter(value: &str, name: &str) -> Option<String> {
    value.split(';').skip(1).find_map(|part| {
        let (key, value) = part.split_once('=')?;
        if !key.trim().eq_ignore_ascii_case(name) {
            return None;
        }
        let value = value.trim().trim_matches('"');
        (!value.is_empty()).then(|| value.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
mAYEAAAAABK4BgQAAAAAEg==\n-----END PGP PUBLIC KEY BLOCK-----\n";

    #[test]
    fn a_plain_message_carries_its_headers_and_key() {
        let raw = format!(
            "From: Applicant <applicant@example.invalid>\nSubject: 0123456789abcdefghjkmnpqrs\n\n{KEY}"
        );
        let message = Message::parse(&raw);
        assert_eq!(
            message.reply_address().as_deref(),
            Some("applicant@example.invalid")
        );
        assert_eq!(
            token_in_subject(&message.subject).as_deref(),
            Some("0123456789abcdefghjkmnpqrs")
        );
        let blocks = labelled_blocks(&message.body);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].1.contains(BEGIN));
    }

    #[test]
    fn a_folded_subject_and_an_upper_case_token_are_read() {
        let raw =
            "From: applicant@example.invalid\nSubject: Re:\n 0123456789ABCDEFGHJKMNPQRS\n\nhello\n";
        let message = Message::parse(raw);
        assert_eq!(message.subject, "Re: 0123456789ABCDEFGHJKMNPQRS");
        assert_eq!(
            token_in_subject(&message.subject).as_deref(),
            Some("0123456789abcdefghjkmnpqrs")
        );
    }

    #[test]
    fn a_quoted_printable_block_is_decoded() {
        let raw = "From: a@example.invalid\nSubject: x\n\
Content-Type: text/plain\nContent-Transfer-Encoding: quoted-printable\n\n\
-----BEGIN PGP PUBLIC KEY BLOCK-----=0A=0A\
mAYEAAAAABK4BgQAAAAAEg=3D=3D=0A\
-----END PGP PUBLIC KEY BLOCK-----=0A";
        let message = Message::parse(raw);
        assert!(message
            .body
            .contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(message.body.contains("mAYEAAAAABK4BgQAAAAAEg=="));
    }

    #[test]
    fn a_multipart_uses_the_text_plain_part() {
        let raw = "From: a@example.invalid\nSubject: x\n\
MIME-Version: 1.0\n\
Content-Type: multipart/alternative; boundary=\"line\"\n\n\
--line\nContent-Type: text/html\n\n<p>not this</p>\n\
--line\nContent-Type: text/plain\nContent-Transfer-Encoding: base64\n\n\
aGVsbG8=\n--line--\n";
        let message = Message::parse(raw);
        assert_eq!(message.body.trim(), "hello");
    }

    #[test]
    fn a_label_names_the_mailbox_above_its_block() {
        let text = format!("secretary@parish.example\n{KEY}\nhall@parish.example\n{KEY}");
        let blocks = labelled_blocks(&text);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].0.as_deref(), Some("secretary@parish.example"));
        assert_eq!(blocks[1].0.as_deref(), Some("hall@parish.example"));
    }

    #[test]
    fn an_unlabelled_block_or_one_for_another_mailbox_names_what_is_missing() {
        let mut draft = Draft::new("0123456789abcdefghjkmnpqrs".to_string());
        draft.answers.insert("whose".into(), "body".into());
        draft
            .answers
            .insert("body_domain".into(), "parish.example".into());
        draft
            .answers
            .insert("body_account_names".into(), "secretary\nhall".into());
        let blocks = labelled_blocks(KEY);
        assert_eq!(
            assign(&blocks, &draft).unwrap_err(),
            vec!["secretary".to_string(), "hall".to_string()]
        );
        let blocks = labelled_blocks(&format!("secretary@parish.example\n{KEY}"));
        let assigned = assign(&blocks, &draft).unwrap();
        assert_eq!(assigned[0].0, "secretary");
    }

    #[test]
    fn a_person_key_needs_no_label() {
        let mut draft = Draft::new("0123456789abcdefghjkmnpqrs".to_string());
        draft.answers.insert("username".into(), "secretary".into());
        let blocks = labelled_blocks(KEY);
        let assigned = assign(&blocks, &draft).unwrap();
        assert_eq!(assigned[0].0, "secretary");
    }

    #[test]
    fn a_single_mailbox_takes_the_first_block_when_two_arrive() {
        let mut draft = Draft::new("0123456789abcdefghjkmnpqrs".to_string());
        draft.answers.insert("username".into(), "secretary".into());
        let blocks = labelled_blocks(&format!("{KEY}\n{KEY}"));
        let assigned = assign(&blocks, &draft).unwrap();
        assert_eq!(assigned.len(), 1, "one mailbox, one key");
        assert_eq!(assigned[0].0, "secretary");
    }

    #[test]
    fn a_nested_multipart_keeps_the_text_plain_it_finds() {
        let raw = format!(
            "From: a@example.invalid\nSubject: x\nMIME-Version: 1.0\n\
             Content-Type: multipart/mixed; boundary=\"outer\"\n\n\
             --outer\nContent-Type: multipart/alternative; boundary=\"inner\"\n\n\
             --inner\nContent-Type: text/plain\n\n{KEY}\n--inner--\n--outer--\n"
        );
        let message = Message::parse(&raw);
        assert!(message.body.contains(BEGIN), "{}", message.body);
    }

    #[test]
    fn a_message_nested_past_the_limit_has_no_body() {
        let mut part = format!("Content-Type: text/plain\n\n{KEY}\n");
        for i in 0..20 {
            let boundary = format!("b{i}");
            part = format!(
                "Content-Type: multipart/mixed; boundary=\"{boundary}\"\n\n\
                 --{boundary}\n{part}\n--{boundary}--\n"
            );
        }
        let raw = format!("From: a@example.invalid\nSubject: x\n{part}");
        let message = Message::parse(&raw);
        assert!(
            !message.body.contains(BEGIN),
            "the depth limit stops the recursion: {}",
            message.body
        );
    }
}
