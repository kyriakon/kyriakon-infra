//! Field validation. Every refusal names its reason, and existence is never
//! checked: the username rule is format and the reserved set only, so the form
//! cannot be used to ask whether a name is taken.

use std::collections::HashSet;

use crate::flow::questions::{self, Kind, Question, Rule};
use crate::flow::Reason;
use crate::mail::{keycheck, pgp};
use crate::util;

/// The reserved set, one name per line, `#` comments and blank lines skipped so
/// the file can explain itself.
pub fn reserved(text: &str) -> HashSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_ascii_lowercase())
        .collect()
}

/// The longest a single-line answer may be. A body's name is a name, not a
/// paragraph, and without a bound a megabyte answer is stored and printed.
const SINGLE_LINE_MAX: usize = 200;

/// The refusal for one answer, or `None` when it is acceptable. `required` is
/// passed in rather than read from the question, because the monastic blessing
/// is required only on the monastic path.
pub fn reason(
    q: &Question,
    value: &str,
    reserved: &HashSet<String>,
    required: bool,
) -> Option<Reason> {
    let v = value.trim();
    if v.is_empty() {
        if !required {
            return None;
        }
        return Some(if q.rule == Rule::Username {
            Reason::UsernameRequired
        } else {
            Reason::Required
        });
    }
    // The answer's type is a rule of its own, and the one the form offers: a
    // yes/no page offers two answers, and an acceptance tick offers one. An
    // empty answer is settled above, so only a non-empty one is shape-checked
    // here; the web form and the capsule both read this, so neither can file a
    // value the other refuses.
    if let Some(why) = match q.kind {
        Kind::YesNo => (!matches!(v, "yes" | "no")).then_some(Reason::YesNo),
        // An optional acceptance is unticked by leaving it empty; a value the
        // page never offers is still refused, and says what the page does offer.
        Kind::Acceptance => (v != "yes").then_some(if required {
            Reason::AcceptanceRequired
        } else {
            Reason::AcceptanceOptional
        }),
        _ => None,
    } {
        return Some(why);
    }
    match &q.rule {
        Rule::None => free_text(q.kind, value),
        Rule::Username => username(v, reserved),
        Rule::Usernames => usernames(v, reserved),
        Rule::Address => address(v),
        Rule::Domain => domain(v),
        // A key that cannot deliver is refused at the form, not carried to the
        // review email: AEAD, an expiry, a revoked key or no encryption subkey
        // all stop delivery, and the applicant is the one who can still change
        // the key. The one advisory that proceeds is the parser-gap warning,
        // where `inspected` is false and a person checks the key instead.
        Rule::MailKey => match pgp::public_key(v) {
            Err(source) => Some(Reason::KeyUnusable {
                source: Box::new(source),
            }),
            Ok(checked) => checked.refusal().map(|verdict| Reason::KeyRefused {
                verdict: verdict.to_string(),
            }),
        },
        Rule::UploadKey => {
            keycheck::openssh_public_key(v)
                .err()
                .map(|source| Reason::KeyUnusable {
                    source: Box::new(source),
                })
        }
        Rule::Choice(opts) => choice(opts, v),
        Rule::MaxLen(limit) => {
            (v.chars().count() > *limit).then_some(Reason::MaxLength { limit: *limit })
        }
        // The raw value, not the trimmed one: a trailing newline would be cut
        // by `trim` and land on the record anyway. The capsule prints this
        // answer as gemtext, where a line break starts a line of its own. The
        // caller prefixes the question's own prompt, so this fragment does not
        // repeat it.
        Rule::SingleLine => {
            if !printable(value) {
                Some(Reason::SingleLineControl)
            } else {
                (value.chars().count() > SINGLE_LINE_MAX).then_some(Reason::MaxLength {
                    limit: SINGLE_LINE_MAX,
                })
            }
        }
    }
}

/// Whether every character in `text` may reach a terminal unchanged.
fn printable(text: &str) -> bool {
    text.chars().all(util::terminal_safe)
}

/// A free-text answer may not carry a control or invisible formatter onto a
/// terminal, where it would repaint the screen or reorder a name. A list's
/// line breaks are the shape it was asked for: a lone newline, as the portal
/// and the terminal read one, or the CRLF pair a browser posts for a textarea.
/// A tab survives too, because an address line may separate `alias` from its
/// target with one and [`util::clean_body`] keeps it. Every other character has
/// to survive [`util::clean`] unchanged.
fn free_text(kind: Kind, value: &str) -> Option<Reason> {
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if kind.is_list()
            && (matches!(c, '\n' | '\t') || (c == '\r' && chars.peek() == Some(&'\n')))
        {
            continue;
        }
        if !util::terminal_safe(c) {
            return Some(Reason::FreeTextControl);
        }
    }
    None
}

/// The username rule: the single DNS label `scripts/add-user.sh` enforces, 1-31
/// characters of lowercase letters, digits and interior hyphens, and not a
/// reserved name. Never whether it exists.
pub fn username(value: &str, reserved: &HashSet<String>) -> Option<Reason> {
    if let Some(why) = username_shape(value) {
        return Some(why);
    }
    reserved.contains(value).then_some(Reason::UsernameHeld)
}

/// The charset and length a username must fit, without the reserved set. The
/// body's own addresses live on its own domain, so the platform's reserved
/// names do not apply to them, but the shape does.
pub fn username_shape(value: &str) -> Option<Reason> {
    if value.is_empty() {
        return Some(Reason::UsernameRequired);
    }
    if value.chars().count() > 31 {
        return Some(Reason::UsernameTooLong { limit: 31 });
    }
    let bytes = value.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !alnum(bytes[0]) {
        return Some(Reason::UsernameFirst);
    }
    if !bytes.iter().all(|&b| alnum(b) || b == b'-') {
        return Some(Reason::UsernameCharset);
    }
    if !alnum(bytes[bytes.len() - 1]) {
        return Some(Reason::UsernameLast);
    }
    None
}

/// Every non-empty line is checked exactly as the single username is, reserved
/// set included, and the refusal names the offending line: these lines become OS
/// account names, created as root by the drain.
pub fn usernames(value: &str, reserved: &HashSet<String>) -> Option<Reason> {
    let mut seen = HashSet::new();
    for line in value.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if !seen.insert(line) {
            return Some(Reason::UsernameTwice {
                name: line.to_string(),
            });
        }
        if let Some(source) = username(line, reserved) {
            return Some(Reason::UsernameNamed {
                name: line.to_string(),
                source: Box::new(source),
            });
        }
    }
    None
}

/// A dotted hostname: lowercase letters, digits and hyphens, each label at most
/// 63 characters and not beginning or ending with a hyphen, at least two labels,
/// and a last label that is two or more letters. This value is the group key the
/// drain writes under and the DNS and certificate material, so a traversal or a
/// space must not reach it.
///
/// The last-label rule is `scripts/lib.sh`'s `dkim_domains_args`, which renders
/// every line of `/etc/mail/dkim_domains` into smtpd's filter arguments. The
/// drain writes this rule's answers into that table, so the two must accept the
/// same names: a name accepted here and refused there fails the render and every
/// later transition that reloads smtpd.
pub fn domain(value: &str) -> Option<Reason> {
    if value.len() > 253 {
        return Some(Reason::DomainTooLong { limit: 253 });
    }
    for label in value.split('.') {
        if label.is_empty() {
            return Some(Reason::DomainEmptyLabel);
        }
        if label.len() > 63 {
            return Some(Reason::DomainLabelTooLong { limit: 63 });
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Some(Reason::DomainLabelCharset {
                label: label.to_string(),
            });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Some(Reason::DomainLabelHyphen {
                label: label.to_string(),
            });
        }
    }
    if value.split('.').count() < 2 {
        return Some(Reason::DomainTooFewLabels);
    }
    // A numeric or hyphenated top-level label is a real DNS name but not a
    // registrable domain, and the DKIM list will not take it.
    let tld = value.rsplit('.').next().unwrap_or_default();
    if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_lowercase()) {
        return Some(Reason::DomainLastLabel {
            label: tld.to_string(),
        });
    }
    None
}

/// The localpart of an own-domain address, the key written before `@` in the
/// virtual table. It is not an account name, a keyring filename or a DNS label,
/// so it keeps the wider address charset and the 32 character bound.
pub fn address_localpart_shape(value: &str) -> Option<Reason> {
    if value.is_empty() {
        return Some(Reason::LocalpartRequired);
    }
    if value.chars().count() > 32 {
        return Some(Reason::LocalpartTooLong { limit: 32 });
    }
    let first = value.as_bytes()[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Some(Reason::LocalpartFirst);
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Some(Reason::LocalpartCharset);
    }
    None
}

/// The body's addresses, one per line, each `localpart: own` or
/// `localpart: alias localpart`, at most ten. The localpart is an address on the
/// body's own domain, not an account name, so dots and underscores stay legal.
pub fn address_lines(value: &str) -> Option<Reason> {
    let lines: Vec<&str> = value
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.len() > 10 {
        return Some(Reason::AddressLinesTooMany { count: lines.len() });
    }
    for line in lines {
        if let Some(why) = address_line(line) {
            return Some(why);
        }
    }
    None
}

/// The target of an address line's rest when it is exactly `alias <target>`.
/// The form and the drain both read a line here, so a tab cannot pass one and
/// fail the other.
pub fn alias_target(rest: &str) -> Option<&str> {
    let mut words = rest.split_whitespace();
    match (words.next(), words.next(), words.next()) {
        (Some("alias"), Some(target), None) => Some(target),
        _ => None,
    }
}

fn address_line(line: &str) -> Option<Reason> {
    let malformed = || Reason::AddressLineMalformed {
        line: line.to_string(),
    };
    let (local, rest) = match line.split_once(':') {
        Some(parts) => parts,
        None => return Some(malformed()),
    };
    let (local, rest) = (local.trim(), rest.trim());
    if let Some(source) = address_localpart_shape(local) {
        return Some(Reason::AddressLineNamed {
            line: line.to_string(),
            source: Box::new(source),
        });
    }
    if rest == "own" {
        return None;
    }
    match alias_target(rest) {
        Some(target) => address_localpart_shape(target).map(|source| Reason::AddressLineTarget {
            line: line.to_string(),
            target: target.to_string(),
            source: Box::new(source),
        }),
        None => Some(malformed()),
    }
}

/// The address outside the platform: exactly one `local@domain`, and nothing in
/// it that could become a second recipient or a header line when the value is
/// later written into a `To:` header. The drain revalidates the stored field for
/// that reason, so the rule lives here once instead of twice: whitespace, a
/// control character, a comma and the address-list punctuation are refused, in
/// the local part as much as the domain.
pub fn address(v: &str) -> Option<Reason> {
    let mut parts = v.split('@');
    let (local, domain) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let punctuation = |c: char| {
        c.is_whitespace() || c.is_control() || matches!(c, ',' | ';' | '<' | '>' | '"' | '(' | ')')
    };
    let acceptable = !local.is_empty()
        && !domain.is_empty()
        && parts.next().is_none()
        && domain.contains('.')
        && !v.chars().any(punctuation);
    (!acceptable).then_some(Reason::OutsideAddress)
}

fn choice(opts: &[questions::Choice], v: &str) -> Option<Reason> {
    if opts.iter().any(|o| o.value == v) {
        None
    } else {
        Some(Reason::ChoiceNotOffered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::questions::{Branch, Choice, Kind, Question, Rule};
    use crate::mail::keycheck::fixtures::{AEAD, CLEAN, EXPIRED_SUBKEY, NO_ENCRYPTION};

    fn name() -> HashSet<String> {
        reserved("# comment\n\nmail\nwww\nsignup\n")
    }

    #[test]
    fn reserved_skips_comments_and_blank_lines() {
        let r = name();
        assert_eq!(r.len(), 3);
        assert!(r.contains("mail"));
        assert!(!r.contains("# comment"));
    }

    #[test]
    fn a_username_outside_the_charset_is_refused_with_its_reason() {
        let r = name();
        assert!(matches!(username("Upper", &r), Some(Reason::UsernameFirst)));
        assert!(matches!(
            username("bad_name!", &r),
            Some(Reason::UsernameCharset)
        ));
        assert!(matches!(
            username("bad.name", &r),
            Some(Reason::UsernameCharset)
        ));
        assert!(matches!(username("bad-", &r), Some(Reason::UsernameLast)));
    }

    #[test]
    fn a_username_is_a_single_dns_label_of_at_most_31_characters() {
        // Mirrors `scripts/lib.sh --self-test` and `scripts/acme-queue.sh
        // --self-test`, which prove the same boundary names against
        // `valid_localpart` and `name_ok` as `<username>.kyriakon.net`.
        let r = name();
        let thirty_one = "a".repeat(31);
        let thirty_two = "a".repeat(32);
        for value in ["a", "7", "a-b", "a1-2b", thirty_one.as_str()] {
            assert!(username(value, &r).is_none(), "{value}");
        }
        for value in ["", "a.b", "a_b", "a-", "-a", thirty_two.as_str()] {
            assert!(username(value, &r).is_some(), "{value}");
        }
        assert!(matches!(
            username(&thirty_two, &r),
            Some(Reason::UsernameTooLong { limit: 31 })
        ));
        assert!(username(&thirty_one, &r).is_none());
    }

    #[test]
    fn a_reserved_username_is_refused_with_its_reason() {
        assert!(matches!(
            username("mail", &name()),
            Some(Reason::UsernameHeld)
        ));
        assert!(username("theophilus", &name()).is_none());
    }

    #[test]
    fn existence_is_not_the_question() {
        // "taken" is a perfectly good name as far as this rule is concerned:
        // nothing here reads the account store.
        assert!(username("taken", &name()).is_none());
    }

    #[test]
    fn an_empty_optional_answer_is_not_a_refusal() {
        let q = Question {
            id: "diocese".into(),
            prompt: "Diocese".into(),
            kind: Kind::Text,
            branch: Branch::All,
            required: false,
            rule: Rule::None,
        };
        assert!(reason(&q, "", &name(), false).is_none());
    }

    #[test]
    fn an_empty_required_answer_is_refused() {
        let q = Question {
            id: "mail_key".into(),
            prompt: "Your public key".into(),
            kind: Kind::Key,
            branch: Branch::Person,
            required: true,
            rule: Rule::MailKey,
        };
        assert!(reason(&q, "", &name(), true).is_some());
    }

    /// A one-line answer cannot carry a line break or an escape sequence onto
    /// the record, because the capsule prints it into gemtext unchanged, and
    /// it is a name rather than a paragraph, so it has a bound.
    #[test]
    fn a_single_line_answer_refuses_a_control_character_or_an_over_long_value() {
        let q = Question {
            id: "body_name".into(),
            prompt: "The body's name".into(),
            kind: Kind::Text,
            branch: Branch::Body,
            required: true,
            rule: Rule::SingleLine,
        };
        assert!(reason(&q, "Parish of Example", &name(), true).is_none());
        let why = reason(&q, "Parish\n=> https://evil.example/", &name(), true)
            .expect("a newline is refused");
        assert!(matches!(why, Reason::SingleLineControl));
        for hostile in [
            "Parish\rX",
            "Parish\u{1b}X",
            "Parish\tX",
            "Parish\u{7}X",
            "Parish\u{202e}X",
            "Parish\u{200f}X",
        ] {
            assert!(reason(&q, hostile, &name(), true).is_some(), "{hostile:?}");
        }

        // The bound is the last character accepted and one more refused.
        let at_bound = "a".repeat(SINGLE_LINE_MAX);
        assert!(reason(&q, &at_bound, &name(), true).is_none());
        let over = "a".repeat(SINGLE_LINE_MAX + 1);
        let why = reason(&q, &over, &name(), true).expect("one over the bound is refused");
        assert!(matches!(
            why,
            Reason::MaxLength {
                limit: SINGLE_LINE_MAX
            }
        ));
    }

    /// A free-text rule is not a hole in the escaping rules: an escape, a
    /// carriage return or an invisible formatter is refused, while a multiline
    /// answer keeps the newlines it was asked for.
    #[test]
    fn a_free_text_answer_refuses_an_escape_and_a_multiline_keeps_its_newlines() {
        let text = Question {
            id: "vat".into(),
            prompt: "VAT number".into(),
            kind: Kind::Text,
            branch: Branch::Body,
            required: false,
            rule: Rule::None,
        };
        assert!(reason(&text, "GB 123 4567 89", &name(), false).is_none());
        // A text answer is one line however it arrived, so a newline and a tab
        // are refused with the rest of the control characters.
        for hostile in [
            "a\rb",
            "a\nb",
            "a\tb",
            "a\u{1b}[2Jb",
            "a\u{7f}b",
            "a\u{9b}b",
            "a\u{202e}b",
            "a\u{200f}b",
            "a\u{2028}b",
        ] {
            assert!(
                reason(&text, hostile, &name(), false).is_some(),
                "{hostile:?}"
            );
        }

        let multiline = Question {
            kind: Kind::Multiline,
            ..text.clone()
        };
        // The terminal reads LF. A browser posts a textarea's line break as
        // CRLF, and a tab is the shape an answer may carry.
        for accepted in [
            "first\nsecond",
            "first\r\nsecond",
            "first\r\nsecond\nthird",
            "first\tsecond",
        ] {
            assert!(
                reason(&multiline, accepted, &name(), false).is_none(),
                "{accepted:?}"
            );
        }
        for hostile in ["first\rsecond", "first\u{1b}second", "first\u{202e}second"] {
            assert!(
                reason(&multiline, hostile, &name(), false).is_some(),
                "{hostile:?}"
            );
        }

        // The address list is the other list kind, and its own rule reads a tab
        // between `alias` and its target as a space: the check before it must
        // let the line through.
        let addresses = Question {
            kind: Kind::Addresses,
            ..multiline
        };
        assert!(reason(
            &addresses,
            "secretary: own\noffice: alias\tsecretary",
            &name(),
            false
        )
        .is_none());
    }

    #[test]
    fn a_mail_key_that_cannot_deliver_is_refused_at_submission() {
        let q = Question {
            id: "mail_key".into(),
            prompt: "Your public key".into(),
            kind: Kind::Key,
            branch: Branch::Person,
            required: true,
            rule: Rule::MailKey,
        };
        assert!(reason(&q, CLEAN, &name(), true).is_none());
        assert!(matches!(
            reason(&q, AEAD, &name(), true),
            Some(Reason::KeyRefused { verdict }) if verdict.contains("AEAD")
        ));
        assert!(reason(&q, EXPIRED_SUBKEY, &name(), true).is_some());
        assert!(matches!(
            reason(&q, NO_ENCRYPTION, &name(), true),
            Some(Reason::KeyRefused { verdict }) if verdict.contains("encryption-capable")
        ));
    }

    #[test]
    fn a_choice_outside_the_offered_answers_is_refused() {
        let q = Question {
            id: "rail".into(),
            prompt: "How you will pay".into(),
            kind: Kind::Choice,
            branch: Branch::All,
            required: true,
            rule: Rule::Choice(vec![Choice {
                value: "card".into(),
                label: "Card".into(),
            }]),
        };
        assert!(reason(&q, "card", &name(), true).is_none());
        assert!(reason(&q, "bitcoin", &name(), true).is_some());
    }

    #[test]
    fn an_answer_the_question_type_does_not_offer_is_refused() {
        let yesno = Question {
            id: "body_records".into(),
            prompt: "The records".into(),
            kind: Kind::YesNo,
            branch: Branch::Body,
            required: true,
            rule: Rule::None,
        };
        assert!(reason(&yesno, "yes", &name(), true).is_none());
        assert!(reason(&yesno, "no", &name(), true).is_none());
        assert!(matches!(
            reason(&yesno, "maybe", &name(), true),
            Some(Reason::YesNo)
        ));
        // An empty value is the `required` question's, not the type's.
        assert!(reason(&yesno, "", &name(), false).is_none());

        let acceptance = Question {
            id: "accept_terms".into(),
            prompt: "I accept".into(),
            kind: Kind::Acceptance,
            branch: Branch::All,
            required: true,
            rule: Rule::None,
        };
        assert!(reason(&acceptance, "yes", &name(), true).is_none());
        assert!(matches!(
            reason(&acceptance, "no", &name(), true),
            Some(Reason::AcceptanceRequired)
        ));
    }

    #[test]
    fn an_address_outside_the_platform_is_one_address() {
        assert!(address("someone@example.invalid").is_none());
        assert!(address("not an address").is_some());
        assert!(address("two@at@example.invalid").is_some());
        assert!(address("no@domain").is_some());
        // The forms that would add a second recipient or a header line if the
        // value were written into a `To:` header, which the drain guards against
        // by revalidating this same rule.
        assert!(address("x,attacker@evil.example").is_some());
        assert!(address("x\nBcc: attacker@evil.example").is_some());
        assert!(address("x y@example.invalid").is_some());
        assert!(address("<x@example.invalid>").is_some());
    }

    #[test]
    fn a_domain_is_a_dotted_hostname_and_each_refusal_names_its_reason() {
        assert!(domain("theirparish.example").is_none());
        assert!(domain("a-b.c-d.example").is_none());
        assert!(matches!(domain("foo"), Some(Reason::DomainTooFewLabels)));
        assert!(matches!(
            domain("Foo.example"),
            Some(Reason::DomainLabelCharset { .. })
        ));
        assert!(matches!(
            domain("-foo.example"),
            Some(Reason::DomainLabelHyphen { .. })
        ));
        assert!(matches!(
            domain("foo-.example"),
            Some(Reason::DomainLabelHyphen { .. })
        ));
        assert!(matches!(domain("a..b"), Some(Reason::DomainEmptyLabel)));
        let long = format!("{}.example", "a".repeat(64));
        assert!(matches!(
            domain(&long),
            Some(Reason::DomainLabelTooLong { limit: 63 })
        ));
        // The traversal a group key must never take.
        assert!(domain("../../../etc/cron.d/evil").is_some());
    }

    #[test]
    fn the_last_label_is_the_tld_the_smtpd_render_accepts() {
        // scripts/lib.sh's dkim_domains_args takes `(label.)+[A-Za-z]{2,}` and
        // is what renders /etc/mail/dkim_domains into smtpd's filter arguments.
        // scripts/deploy-mail.sh --self-test feeds this same list to it; a name
        // accepted here and refused there wedges every later smtpd reload.
        for good in [
            "theirparish.example",
            "sub.parish.example",
            "parish-12.example",
            "a.bb",
            "parish.example",
        ] {
            assert!(domain(good).is_none(), "{good}: {:?}", domain(good));
        }
        for bad in ["parish.12", "parish.ab-c", "parish.ex4mple", "parish.x"] {
            assert!(
                matches!(domain(bad), Some(Reason::DomainLastLabel { .. })),
                "{bad}: {:?}",
                domain(bad)
            );
        }
    }

    #[test]
    fn a_domain_is_at_most_253_characters() {
        // Four valid labels and three dots: exactly DNS's limit, still accepted.
        let longest = [
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(61),
        ]
        .join(".");
        assert_eq!(longest.len(), 253);
        assert!(domain(&longest).is_none());
        // One over the limit: 254 bytes. The cap is exact, not "long".
        let too_long = [
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(3),
        ]
        .join(".");
        assert_eq!(too_long.len(), 259);
        assert!(matches!(
            domain(&too_long),
            Some(Reason::DomainTooLong { limit: 253 })
        ));
        let one_over = [
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(62),
        ]
        .join(".");
        assert_eq!(one_over.len(), 254);
        assert!(matches!(
            domain(&one_over),
            Some(Reason::DomainTooLong { limit: 253 })
        ));
    }

    #[test]
    fn every_line_of_a_username_list_is_checked_and_the_line_is_named() {
        let r = name();
        assert!(usernames("secretary\nhall\n", &r).is_none());
        assert!(matches!(
            usernames("secretary\nBad_Name", &r),
            Some(Reason::UsernameNamed { name, source })
                if name == "Bad_Name" && matches!(*source, Reason::UsernameFirst)
        ));
        assert!(matches!(
            usernames("mail", &r),
            Some(Reason::UsernameNamed { name, source })
                if name == "mail" && matches!(*source, Reason::UsernameHeld)
        ));
    }

    #[test]
    fn a_duplicate_account_name_is_refused_and_the_name_is_in_the_refusal() {
        assert!(matches!(
            usernames("secretary\nhall\nhall", &name()),
            Some(Reason::UsernameTwice { name }) if name == "hall"
        ));
    }

    #[test]
    fn a_tab_after_alias_is_the_same_line_as_a_space() {
        assert!(address_lines("secretary: own\noffice: alias\tsecretary").is_none());
        assert!(address_lines("secretary: own\noffice: alias secretary").is_none());
    }

    #[test]
    fn the_body_addresses_are_checked_line_by_line() {
        assert!(address_lines("secretary: own\nhall: alias secretary").is_none());
        assert!(address_lines("first.last: own\nhall: alias first.last").is_none());
        assert!(address_lines("first_last: own").is_none());
        assert!(address_lines("secretary: own").is_none());
        assert!(matches!(
            address_lines("secretary"),
            Some(Reason::AddressLineMalformed { .. })
        ));
        assert!(matches!(
            address_lines("Bad_Name: own"),
            Some(Reason::AddressLineNamed { line, .. }) if line == "Bad_Name: own"
        ));
        assert!(matches!(
            address_lines("hall: alias Bad Target"),
            Some(Reason::AddressLineMalformed { line }) if line == "hall: alias Bad Target"
        ));
        assert!(matches!(
            address_lines("hall: alias Bad_Name"),
            Some(Reason::AddressLineTarget { target, .. }) if target == "Bad_Name"
        ));
        assert!(matches!(
            address_lines("hall: alias"),
            Some(Reason::AddressLineMalformed { .. })
        ));
        assert!(matches!(
            address_lines("hall: shared secretary"),
            Some(Reason::AddressLineMalformed { .. })
        ));
        let eleven: Vec<String> = (0..11).map(|i| format!("a{i}: own")).collect();
        assert!(matches!(
            address_lines(&eleven.join("\n")),
            Some(Reason::AddressLinesTooMany { count: 11 })
        ));
    }
}
