//! The OpenSMTPD From-header filter: its policy and its protocol state.
//!
//! `senders <mail_from>` binds the SMTP envelope; `filter-dkimsign` signs the
//! domain the message's `From:` header names. So the header is a separate
//! decision, and this crate makes it on every message: an authenticated session
//! may only name addresses mapped to its account, the local enqueuer may only
//! name this platform's domains, and inbound mail is not ours to police.
//!
//! The header is read with `kyriakon-mailparse`, the same strict RFC 5322
//! grammar the signer follows, so the three #923 bypasses and an oversized
//! folded header (#894) are refused rather than read differently by each half.
//! The header block is capped in memory as it arrives and every data line is
//! echoed unchanged, because the filter's contract is passthrough plus one
//! verdict at commit.

use std::collections::{HashMap, HashSet};

use kyriakon_mailparse::{headers, parse_address_list};

/// The most header bytes one transaction may buffer. A legitimate header block
/// is a few KiB; the cap is what keeps a folded `From:` from growing without
/// bound before the policy is asked (#894).
const MAX_HEADER_BLOCK: usize = 256 * 1024;

/// The account-to-addresses mapping (`/etc/mail/mail_from`) and the domains the
/// local enqueuer may originate.
pub struct Policy {
    allowed: HashMap<String, HashSet<String>>,
    domains: HashSet<String>,
}

impl Policy {
    /// Read the table `scripts/lib.sh` writes: `account: address,address` one
    /// account per line. A malformed line is skipped, as the table is generated
    /// on the box rather than parsed as untrusted input.
    pub fn parse(table: &[u8], domains: &[String]) -> Self {
        let mut allowed: HashMap<String, HashSet<String>> = HashMap::new();
        for line in table.split(|byte| *byte == b'\n') {
            let line = trim_ascii(line);
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            let Some(colon) = line.iter().position(|byte| *byte == b':') else {
                continue;
            };
            let account = String::from_utf8_lossy(trim_ascii(&line[..colon])).to_ascii_lowercase();
            if account.is_empty() {
                continue;
            }
            let addresses = allowed.entry(account).or_default();
            for address in line[colon + 1..].split(|byte| *byte == b',') {
                let address = trim_ascii(address);
                if !address.is_empty() {
                    addresses.insert(String::from_utf8_lossy(address).to_ascii_lowercase());
                }
            }
        }
        let domains = domains
            .iter()
            .map(|domain| domain.trim().to_ascii_lowercase())
            .filter(|domain| !domain.is_empty())
            .collect();
        Self { allowed, domains }
    }
}

#[derive(Default)]
struct Session {
    /// The account from `link-auth pass`, empty for an unauthenticated session.
    user: Option<Vec<u8>>,
    /// A `link-connect` whose source was the local enqueuer.
    local: bool,
    transaction: Transaction,
}

#[derive(Default)]
struct Transaction {
    in_headers: bool,
    block: Vec<u8>,
    overflow: bool,
}

impl Transaction {
    fn new() -> Self {
        Self {
            in_headers: true,
            block: Vec::new(),
            overflow: false,
        }
    }

    fn data_line(&mut self, line: &[u8]) {
        if !self.in_headers {
            return;
        }
        if line.is_empty() {
            self.in_headers = false;
            return;
        }
        if self.overflow {
            return;
        }
        if self.block.len() + line.len() + 1 > MAX_HEADER_BLOCK {
            // Reject at commit; the bytes already held are not needed to say so.
            self.overflow = true;
            self.block = Vec::new();
            return;
        }
        self.block.extend_from_slice(line);
        self.block.push(b'\n');
    }
}

enum Verdict {
    Proceed,
    Reject(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Authenticated,
    Local,
}

/// The smtpd filter state: one entry per session, from `link-connect` to
/// `link-disconnect`.
pub struct Filter {
    policy: Policy,
    sessions: HashMap<Vec<u8>, Session>,
}

impl Filter {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            sessions: HashMap::new(),
        }
    }

    /// Feed one protocol line and return the bytes to write back (empty when
    /// the line needs no answer). Data lines are echoed with their own token.
    pub fn handle(&mut self, line: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if line == b"config|ready" {
            out.extend_from_slice(
                b"register|report|smtp-in|link-connect\n\
                  register|report|smtp-in|link-auth\n\
                  register|report|smtp-in|link-disconnect\n\
                  register|filter|smtp-in|data-line\n\
                  register|filter|smtp-in|commit\n\
                  register|ready\n",
            );
            return out;
        }
        let mut fields = line.splitn(8, |byte| *byte == b'|');
        match fields.next() {
            Some(b"report") => {
                // `report` has six fixed fields; its params are one field that
                // may itself contain '|'. Splitting on the filter's limit would
                // cut the params short.
                let mut fields = line.splitn(7, |byte| *byte == b'|');
                let _kind = fields.next();
                let _version = fields.next();
                let _timestamp = fields.next();
                let _subsystem = fields.next();
                let Some(event) = fields.next() else {
                    return out;
                };
                let Some(session) = fields.next() else {
                    return out;
                };
                let rest = fields.next().unwrap_or(b"");
                if !session.is_empty() {
                    self.report(event, session, rest);
                }
            }
            Some(b"filter") => {
                let _version = fields.next();
                let _timestamp = fields.next();
                let _subsystem = fields.next();
                let Some(phase) = fields.next() else {
                    return out;
                };
                let Some(session) = fields.next() else {
                    return out;
                };
                let Some(token) = fields.next() else {
                    return out;
                };
                let param = fields.next().unwrap_or(b"");
                if !session.is_empty() && !token.is_empty() {
                    self.filter_line(phase, session, token, param, &mut out);
                }
            }
            _ => {}
        }
        out
    }

    fn report(&mut self, event: &[u8], session: &[u8], rest: &[u8]) {
        match event {
            b"link-connect" => {
                let mut params = rest.splitn(4, |byte| *byte == b'|');
                let _rdns = params.next();
                let _auth = params.next();
                let source = params.next().unwrap_or(b"");
                let local = source == b"local" || source.starts_with(b"unix:");
                self.sessions.insert(
                    session.to_vec(),
                    Session {
                        transaction: Transaction::new(),
                        local,
                        ..Session::default()
                    },
                );
            }
            b"link-auth" => {
                let mut params = rest.splitn(2, |byte| *byte == b'|');
                let result = params.next().unwrap_or(b"");
                let user = params.next().unwrap_or(b"");
                let entry = self
                    .sessions
                    .entry(session.to_vec())
                    .or_insert_with(|| Session {
                        transaction: Transaction::new(),
                        ..Session::default()
                    });
                entry.user = (result == b"pass" && !user.is_empty()).then(|| user.to_vec());
            }
            b"link-disconnect" => {
                self.sessions.remove(session);
            }
            _ => {}
        }
    }

    fn filter_line(
        &mut self,
        phase: &[u8],
        session: &[u8],
        token: &[u8],
        param: &[u8],
        out: &mut Vec<u8>,
    ) {
        match phase {
            b"data-line" => {
                out.extend_from_slice(b"filter-dataline|");
                out.extend_from_slice(session);
                out.push(b'|');
                out.extend_from_slice(token);
                out.push(b'|');
                out.extend_from_slice(param);
                out.push(b'\n');
                if let Some(entry) = self.sessions.get_mut(session) {
                    entry.transaction.data_line(param);
                }
            }
            b"commit" => {
                let verdict = match self.sessions.get(session) {
                    Some(entry) => self.decide(entry),
                    None => Verdict::Proceed,
                };
                out.extend_from_slice(b"filter-result|");
                out.extend_from_slice(session);
                out.push(b'|');
                out.extend_from_slice(token);
                out.push(b'|');
                match verdict {
                    Verdict::Proceed => out.extend_from_slice(b"proceed\n"),
                    Verdict::Reject(reason) => {
                        out.extend_from_slice(b"reject|550 5.7.1 ");
                        out.extend_from_slice(reason.as_bytes());
                        out.push(b'\n');
                    }
                }
                if let Some(entry) = self.sessions.get_mut(session) {
                    entry.transaction = Transaction::new();
                }
            }
            _ => {}
        }
    }

    fn decide(&self, session: &Session) -> Verdict {
        let mode = match session.user.as_ref() {
            Some(user) if !user.is_empty() => Mode::Authenticated,
            _ if session.local => Mode::Local,
            // Inbound mail's From is the correspondent's, not ours to police.
            _ => return Verdict::Proceed,
        };
        let transaction = &session.transaction;
        if transaction.overflow {
            return Verdict::Reject("the message headers are too large".into());
        }
        let block = &transaction.block;
        let mut from_values = Vec::new();
        for header in headers(block) {
            if header.is("from") {
                from_values.push(header.value(block));
            }
        }
        if from_values.len() > 1 {
            return Verdict::Reject("the message has more than one From header".into());
        }
        let Some(value) = from_values.first().copied() else {
            return match mode {
                Mode::Authenticated => Verdict::Reject("the message has no From header".into()),
                Mode::Local => Verdict::Proceed,
            };
        };
        if value.is_empty() {
            return match mode {
                Mode::Authenticated => Verdict::Reject("the From header names no address".into()),
                Mode::Local => Verdict::Proceed,
            };
        }
        // cron(8) and mail(1) write a bare localpart. It has no domain to
        // police, so the local policy accepts it, but only when the header
        // holds no address outside comments and quoted strings; anything the
        // scanner cannot read is refused.
        if mode == Mode::Local {
            match has_at_outside_cfws(value) {
                AtScan::None => return Verdict::Proceed,
                AtScan::Unbalanced => {
                    return Verdict::Reject("the From header is not a valid address list".into())
                }
                AtScan::Has => {}
            }
        }
        let mailboxes = match parse_address_list(value) {
            Ok(mailboxes) => mailboxes,
            Err(_) => return Verdict::Reject("the From header is not a valid address list".into()),
        };
        match mode {
            Mode::Authenticated => {
                if mailboxes.is_empty() {
                    return Verdict::Reject("the From header names no address".into());
                }
                let user = String::from_utf8_lossy(session.user.as_deref().unwrap_or(b""))
                    .to_ascii_lowercase();
                let none = HashSet::new();
                let allowed = self.policy.allowed.get(&user).unwrap_or(&none);
                for mailbox in mailboxes {
                    if !allowed.contains(&mailbox.address.to_ascii_lowercase()) {
                        return Verdict::Reject(format!(
                            "{} is not an address this account may send as",
                            sanitize(&mailbox.address)
                        ));
                    }
                }
            }
            Mode::Local => {
                for mailbox in mailboxes {
                    if !self
                        .policy
                        .domains
                        .contains(&mailbox.domain.to_ascii_lowercase())
                    {
                        return Verdict::Reject(format!(
                            "{} is not a domain this platform originates",
                            sanitize(&mailbox.address)
                        ));
                    }
                }
            }
        }
        Verdict::Proceed
    }
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while matches!(bytes.first(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        bytes = &bytes[1..];
    }
    while matches!(bytes.last(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

/// Whether an `@` sits outside comments and quoted strings. A bare localpart
/// has none; a header the scanner cannot finish is refused instead of guessed.
enum AtScan {
    None,
    Has,
    Unbalanced,
}

fn has_at_outside_cfws(value: &[u8]) -> AtScan {
    let mut index = 0;
    let mut quoted = false;
    let mut depth = 0usize;
    while index < value.len() {
        let byte = value[index];
        if byte == b'\\' && (quoted || depth > 0) {
            index += 2;
            if index > value.len() {
                return AtScan::Unbalanced;
            }
            continue;
        }
        if depth > 0 {
            match byte {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            index += 1;
            continue;
        }
        if quoted {
            if byte == b'"' {
                quoted = false;
            }
            index += 1;
            continue;
        }
        match byte {
            b'(' => depth = 1,
            b'"' => quoted = true,
            b'@' => return AtScan::Has,
            _ => {}
        }
        index += 1;
    }
    if quoted || depth > 0 {
        AtScan::Unbalanced
    } else {
        AtScan::None
    }
}

/// The address goes into the SMTP reply, so a control byte in a quoted local
/// part must not become a second protocol line.
fn sanitize(address: &str) -> String {
    address
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const SID: &str = "a000000000000001";

    fn filter() -> Filter {
        Filter::new(Policy::parse(
            b"alice: alice@kyriakon.net,secretary@parish.example\n",
            &["kyriakon.net".into(), "mail.kyriakon.net".into()],
        ))
    }

    fn data(token: &str, text: &str) -> String {
        format!("filter|0.7|2.1|smtp-in|data-line|{SID}|{token}|{text}")
    }

    fn commit() -> String {
        format!("filter|0.7|9.0|smtp-in|commit|{SID}|t9")
    }

    fn remote() -> Vec<String> {
        vec![
            format!(
                "report|0.7|1.1|smtp-in|link-connect|{SID}|mail.example|pass|192.0.2.5:41000|192.0.2.1:465"
            ),
            format!("report|0.7|1.2|smtp-in|link-auth|{SID}|pass|alice"),
        ]
    }

    fn local() -> Vec<String> {
        vec![format!(
            "report|0.7|1.1|smtp-in|link-connect|{SID}|localhost|pass|unix:/var/run/smtpd.sock|unix:/var/run/smtpd.sock"
        )]
    }

    /// The verdict line the last commit produced, or an empty string.
    fn run(lines: &[String]) -> String {
        let mut filter = filter();
        let mut result = String::new();
        for line in lines {
            let out = filter.handle(line.as_bytes());
            for line in String::from_utf8_lossy(&out).lines() {
                if line.starts_with("filter-result|") {
                    result = line.to_string();
                }
            }
        }
        result
    }

    fn message(prefix: Vec<String>, from: &str, extra: &[&str]) -> Vec<String> {
        let mut lines = prefix;
        lines.push(data("t0", "Received: from client"));
        lines.push(data("t1", &format!("From: {from}")));
        for (index, line) in extra.iter().enumerate() {
            lines.push(data(&format!("x{index}"), line));
        }
        lines.push(data("t2", "Subject: hi"));
        lines.push(data("t3", ""));
        lines.push(data("t4", "body"));
        lines.push(data("t5", "."));
        lines.push(commit());
        lines
    }

    fn auth(from: &str) -> String {
        run(&message(remote(), from, &[]))
    }

    fn enqueued(from: &str) -> String {
        run(&message(local(), from, &[]))
    }

    #[test]
    fn a_member_may_send_as_their_own_address() {
        assert!(auth("Alice <alice@kyriakon.net>").ends_with("|proceed"));
        assert!(auth("ALICE@Kyriakon.Net").ends_with("|proceed"));
        assert!(auth("alice@kyriakon.net, secretary@parish.example").ends_with("|proceed"));
    }

    #[test]
    fn a_member_may_not_send_as_another_address() {
        let answer = auth("hello@kyriakon.net");
        assert!(answer.contains("|reject|550 5.7.1 hello@kyriakon.net"));
        let answer = auth("a@kyriakon.net, alice@kyriakon.net");
        assert!(answer.contains("550 5.7.1 a@kyriakon.net"));
        // A bare localpart is not an authenticated identity.
        assert!(auth("alice").contains("|reject|"));
    }

    #[test]
    fn quoted_names_and_comments_do_not_change_the_address() {
        assert!(auth("\"A, Inc.\" <alice@kyriakon.net>").ends_with("|proceed"));
        assert!(
            auth("\"Alice \\\"Q\\\" Public, Inc.\" <alice@kyriakon.net>").ends_with("|proceed")
        );
        assert!(auth("\"Alice\" (the platform) <alice@kyriakon.net>").ends_with("|proceed"));
        let answer = auth("hello@kyriakon.net (x <alice@kyriakon.net>)");
        assert!(answer.contains("550 5.7.1 hello@kyriakon.net"));
    }

    #[test]
    fn the_three_spoofing_bypasses_are_refused() {
        // #923 bypass one: an obsolete `From :` is a second From the signer
        // reads and this filter must count.
        let lines = message(
            remote(),
            "alice@kyriakon.net",
            &["From : secretary@otherparish.org"],
        );
        assert!(run(&lines).contains("more than one From header"));

        // #923 bypass two: a paren inside a quoted display name does not hide
        // the first mailbox the signer reads.
        assert!(
            auth("\"x(\" <secretary@otherparish.org>, \"y)\" <alice@kyriakon.net>")
                .contains("550 5.7.1 secretary@otherparish.org")
        );

        // #923 bypass three: a backslash escapes the `)` in a comment.
        assert!(
            auth("(\\)\" )\"<alice@kyriakon.net>(\" <secretary@otherparish.org> (\\))")
                .contains("550 5.7.1 secretary@otherparish.org")
        );
    }

    #[test]
    fn a_folded_header_is_unfolded_and_a_huge_one_is_refused() {
        let lines = message(remote(), "Alice", &[" <alice@kyriakon.net>"]);
        assert!(run(&lines).ends_with("|proceed"));

        let mut folded = remote();
        folded.push(data("t0", "From: Alice"));
        for index in 0..60_000 {
            folded.push(data(&format!("c{index}"), "\t(comment)"));
        }
        folded.push(data("last", "\t <alice@kyriakon.net>"));
        folded.push(data("blank", ""));
        folded.push(commit());
        let started = Instant::now();
        let answer = run(&folded);
        assert!(
            answer.contains("the message headers are too large"),
            "{answer}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the folded header parse must stay linear"
        );
    }

    #[test]
    fn a_header_the_parser_cannot_read_is_refused() {
        assert!(auth("\" <hello@kyriakon.net>").contains("not a valid address list"));
        assert!(auth("<hello@kyriakon.net").contains("not a valid address list"));
        assert!(auth("\"hello@kyriakon.net\"").contains("not a valid address list"));
        let no_from = {
            let mut lines = remote();
            lines.push(data("t0", "Received: from client"));
            lines.push(data("t1", "Subject: hi"));
            lines.push(data("t2", ""));
            lines.push(data("t3", "body"));
            lines.push(data("t4", "."));
            lines.push(commit());
            lines
        };
        assert!(run(&no_from).contains("no From header"));
    }

    #[test]
    fn a_body_from_is_not_a_header() {
        let mut lines = remote();
        lines.push(data("t0", "From: alice@kyriakon.net"));
        lines.push(data("t1", ""));
        lines.push(data("t2", "From: anyone@evil.example"));
        lines.push(commit());
        assert!(run(&lines).ends_with("|proceed"));
    }

    #[test]
    fn the_local_enqueuer_is_bound_to_the_platform_domains() {
        assert!(enqueued("kyriakon <hello@kyriakon.net>").ends_with("|proceed"));
        assert!(enqueued("root (Cron Daemon)").ends_with("|proceed"));
        assert!(enqueued("root").ends_with("|proceed"));
        assert!(enqueued("root@mail.kyriakon.net").ends_with("|proceed"));
        assert!(enqueued("secretary@parish.example").contains("550 5.7.1 secretary@parish.example"));
        assert!(enqueued("x@evil.example (x <hello@kyriakon.net>)")
            .contains("550 5.7.1 x@evil.example"));
        assert!(enqueued("hello@kyriakon.net, <anything@evil.example>")
            .contains("550 5.7.1 anything@evil.example"));
    }

    #[test]
    fn inbound_mail_is_not_looked_at() {
        let mut lines = vec![format!(
            "report|0.7|1.1|smtp-in|link-connect|{SID}|mail.example|pass|192.0.2.5:41000|192.0.2.1:25"
        )];
        lines.extend(message(Vec::new(), "anyone@example.org", &[]));
        assert!(run(&lines).ends_with("|proceed"));
    }

    #[test]
    fn the_account_outlives_a_commit_and_a_reconnect_starts_clean() {
        let mut lines = remote();
        lines.extend(message(Vec::new(), "alice@kyriakon.net", &[]));
        lines.extend(message(Vec::new(), "hello@kyriakon.net", &[]));
        let answer = run(&lines);
        assert!(answer.contains("550 5.7.1 hello@kyriakon.net"), "{answer}");

        let mut reconnected = remote();
        reconnected.extend(message(Vec::new(), "alice@kyriakon.net", &[]));
        reconnected.push(format!("report|0.7|4.0|smtp-in|link-disconnect|{SID}"));
        reconnected.push(format!(
            "report|0.7|5.0|smtp-in|link-connect|{SID}|mail.example|pass|192.0.2.5:41001|192.0.2.1:25"
        ));
        reconnected.extend(message(Vec::new(), "anyone@example.org", &[]));
        assert!(run(&reconnected).ends_with("|proceed"));
    }

    #[test]
    fn every_data_line_is_echoed_with_its_own_token() {
        let mut filter = filter();
        let lines = message(remote(), "Alice <alice@kyriakon.net>", &[]);
        let mut echoed = 0;
        for line in &lines {
            let out = filter.handle(line.as_bytes());
            for field in String::from_utf8_lossy(&out).lines() {
                if field.starts_with(&format!("filter-dataline|{SID}|t")) {
                    echoed += 1;
                }
            }
        }
        // Received, From, Subject, the blank line, body and the terminating dot.
        assert_eq!(echoed, 6);
    }

    #[test]
    fn the_handshake_registers_the_reports_before_the_requests() {
        let out = filter().handle(b"config|ready");
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("register|report|smtp-in|link-connect\n"));
        assert!(text.ends_with("register|ready\n"));
        assert!(text.contains("register|filter|smtp-in|commit\n"));
    }

    #[test]
    fn arbitrary_protocol_lines_do_not_panic() {
        let mut filter = filter();
        for line in [
            b"".as_slice(),
            b"|",
            b"filter|",
            b"filter||||||",
            b"report|1|2|3",
            b"report|0.7|1|smtp-in|link-connect|",
            b"filter|0.7|1|smtp-in|data-line|||",
            b"filter|0.7|1|smtp-in|commit|x|\xff",
            b"config|ready",
        ] {
            let _ = filter.handle(line);
        }
    }
}
