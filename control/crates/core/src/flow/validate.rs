//! Field validation. Every refusal names its reason, and existence is never
//! checked: the username rule is format and the reserved set only, so the form
//! cannot be used to ask whether a name is taken.

use std::collections::HashSet;

use crate::flow::questions::{self, Kind, Question, Rule};
use crate::mail::keycheck;

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
) -> Option<String> {
    let v = value.trim();
    if v.is_empty() {
        if !required {
            return None;
        }
        return Some(if q.rule == Rule::Username {
            "a username is needed".to_string()
        } else {
            "this is needed".to_string()
        });
    }
    // The answer's type is a rule of its own, and the one the form offers: a
    // yes/no page offers two answers, and an acceptance tick offers one. An
    // empty answer is settled above, so only a non-empty one is shape-checked
    // here; the web form and the capsule both read this, so neither can file a
    // value the other refuses.
    if let Some(why) = match q.kind {
        Kind::YesNo => (!matches!(v, "yes" | "no")).then(|| "answer yes or no".to_string()),
        Kind::Acceptance => (v != "yes").then(|| "this has to be accepted".to_string()),
        _ => None,
    } {
        return Some(why);
    }
    match &q.rule {
        Rule::None => None,
        Rule::Username => username(v, reserved),
        Rule::Usernames => usernames(v, reserved),
        Rule::Address => address(v),
        Rule::Domain => domain(v),
        // A key that cannot deliver is refused at the form, not carried to the
        // review email: AEAD, an expiry, a revoked key or no encryption subkey
        // all stop delivery, and the applicant is the one who can still change
        // the key. The one advisory that proceeds is the parser-gap warning,
        // where `inspected` is false and a person checks the key instead.
        Rule::MailKey => match keycheck::pgp_public_key(v) {
            Err(e) => Some(e.to_string()),
            Ok(checked) => checked.refusal().map(str::to_string),
        },
        Rule::UploadKey => keycheck::openssh_public_key(v).err().map(|e| e.to_string()),
        Rule::Choice(opts) => choice(opts, v),
        Rule::MaxLen(n) => (v.chars().count() > *n).then(|| format!("at most {n} characters")),
        // The raw value, not the trimmed one: a trailing newline would be cut
        // by `trim` and land on the record anyway. The capsule prints this
        // answer as gemtext, where a line break starts a line of its own. The
        // caller prefixes the question's own prompt, so this fragment does not
        // repeat it.
        Rule::SingleLine => {
            if value.chars().any(char::is_control) {
                Some("one line, without control characters".to_string())
            } else {
                (value.chars().count() > SINGLE_LINE_MAX)
                    .then(|| format!("at most {SINGLE_LINE_MAX} characters"))
            }
        }
    }
}

/// The username rule: the single DNS label `scripts/add-user.sh` enforces, 1-31
/// characters of lowercase letters, digits and interior hyphens, and not a
/// reserved name. Never whether it exists.
pub fn username(value: &str, reserved: &HashSet<String>) -> Option<String> {
    if let Some(why) = username_shape(value) {
        return Some(why);
    }
    reserved
        .contains(value)
        .then(|| "that name is held back by the platform".to_string())
}

/// The charset and length a username must fit, without the reserved set. The
/// body's own addresses live on its own domain, so the platform's reserved
/// names do not apply to them, but the shape does.
pub fn username_shape(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("a username is needed".to_string());
    }
    if value.chars().count() > 31 {
        return Some("a username is at most 31 characters".to_string());
    }
    let bytes = value.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !alnum(bytes[0]) {
        return Some("a username starts with a lowercase letter or a digit".to_string());
    }
    if !bytes.iter().all(|&b| alnum(b) || b == b'-') {
        return Some("a username is lowercase letters, digits and hyphen".to_string());
    }
    if !alnum(bytes[bytes.len() - 1]) {
        return Some("a username ends with a lowercase letter or a digit".to_string());
    }
    None
}

/// Every non-empty line is checked exactly as the single username is, reserved
/// set included, and the refusal names the offending line: these lines become OS
/// account names, created as root by the drain.
pub fn usernames(value: &str, reserved: &HashSet<String>) -> Option<String> {
    for line in value.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(why) = username(line, reserved) {
            return Some(format!("the name {line:?}: {why}"));
        }
    }
    None
}

/// A dotted hostname: lowercase letters, digits and hyphens, each label at most
/// 63 characters and not beginning or ending with a hyphen, at least two labels.
/// This value is the group key the drain writes under and the DNS and
/// certificate material, so a traversal or a space must not reach it.
pub fn domain(value: &str) -> Option<String> {
    if value.len() > 253 {
        return Some("a domain is at most 253 characters".to_string());
    }
    for label in value.split('.') {
        if label.is_empty() {
            return Some("a domain has no empty labels".to_string());
        }
        if label.len() > 63 {
            return Some("a domain label is at most 63 characters".to_string());
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Some(format!(
                "the domain label {label:?} is not lowercase letters, digits and hyphen"
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Some(format!(
                "the domain label {label:?} begins or ends with a hyphen"
            ));
        }
    }
    (value.split('.').count() < 2)
        .then(|| "a domain has at least two labels, like theirparish.example".to_string())
}

/// The localpart of an own-domain address, the key written before `@` in the
/// virtual table. It is not an account name, a keyring filename or a DNS label,
/// so it keeps the wider address charset and the 32 character bound.
pub fn address_localpart_shape(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("an address localpart is needed".to_string());
    }
    if value.chars().count() > 32 {
        return Some("an address localpart is at most 32 characters".to_string());
    }
    let first = value.as_bytes()[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Some("an address localpart starts with a lowercase letter or a digit".to_string());
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Some(
            "an address localpart is lowercase letters, digits, dot, underscore and hyphen"
                .to_string(),
        );
    }
    None
}

/// The body's addresses, one per line, each `localpart: own` or
/// `localpart: alias localpart`, at most ten. The localpart is an address on the
/// body's own domain, not an account name, so dots and underscores stay legal.
pub fn address_lines(value: &str) -> Option<String> {
    let lines: Vec<&str> = value
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.len() > 10 {
        return Some(format!("up to ten addresses, {} given", lines.len()));
    }
    for line in lines {
        if let Some(why) = address_line(line) {
            return Some(why);
        }
    }
    None
}

fn address_line(line: &str) -> Option<String> {
    let malformed =
        || format!("the address line {line:?} is not localpart: own or localpart: alias localpart");
    let (local, rest) = match line.split_once(':') {
        Some(parts) => parts,
        None => return Some(malformed()),
    };
    let (local, rest) = (local.trim(), rest.trim());
    if let Some(why) = address_localpart_shape(local) {
        return Some(format!("the address line {line:?}: {why}"));
    }
    let mut words = rest.split_whitespace();
    match (words.next(), words.next(), words.next()) {
        (Some("own"), None, None) => None,
        (Some("alias"), Some(target), None) => address_localpart_shape(target)
            .map(|why| format!("the address line {line:?}: the alias target {target:?} {why}")),
        _ => Some(malformed()),
    }
}

/// The address outside the platform: exactly one `local@domain`, and nothing in
/// it that could become a second recipient or a header line when the value is
/// later written into a `To:` header. The drain revalidates the stored field for
/// that reason, so the rule lives here once instead of twice: whitespace, a
/// control character, a comma and the address-list punctuation are refused, in
/// the local part as much as the domain.
pub fn address(v: &str) -> Option<String> {
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
    (!acceptable).then(|| {
        "an address outside this platform is one, like someone@example.invalid".to_string()
    })
}

fn choice(opts: &[questions::Choice], v: &str) -> Option<String> {
    if opts.iter().any(|o| o.value == v) {
        None
    } else {
        Some("choose one of the answers offered".to_string())
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
        assert!(username("Upper", &r).unwrap().contains("starts with"));
        assert!(username("bad_name!", &r)
            .unwrap()
            .contains("digits and hyphen"));
        assert!(username("bad.name", &r)
            .unwrap()
            .contains("digits and hyphen"));
        assert!(username("bad-", &r).unwrap().contains("ends with"));
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
        assert!(username(&thirty_two, &r).unwrap().contains("at most 31"));
        assert!(username(&thirty_one, &r).is_none());
    }

    #[test]
    fn a_reserved_username_is_refused_with_its_reason() {
        assert!(username("mail", &name()).unwrap().contains("held back"));
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
        assert_eq!(why, "one line, without control characters");
        for hostile in ["Parish\rX", "Parish\u{1b}X", "Parish\tX", "Parish\u{7}X"] {
            assert!(reason(&q, hostile, &name(), true).is_some(), "{hostile:?}");
        }

        // The bound is the last character accepted and one more refused.
        let at_bound = "a".repeat(SINGLE_LINE_MAX);
        assert!(reason(&q, &at_bound, &name(), true).is_none());
        let over = "a".repeat(SINGLE_LINE_MAX + 1);
        let why = reason(&q, &over, &name(), true).expect("one over the bound is refused");
        assert!(
            why.contains(&format!("at most {SINGLE_LINE_MAX} characters")),
            "{why}"
        );
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
        assert!(reason(&q, AEAD, &name(), true).unwrap().contains("AEAD"));
        assert!(reason(&q, EXPIRED_SUBKEY, &name(), true).is_some());
        assert!(reason(&q, NO_ENCRYPTION, &name(), true)
            .unwrap()
            .contains("encryption-capable"));
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
        assert!(reason(&yesno, "maybe", &name(), true)
            .unwrap()
            .contains("answer yes or no"));
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
        assert!(reason(&acceptance, "no", &name(), true)
            .unwrap()
            .contains("this has to be accepted"));
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
        assert!(domain("foo").unwrap().contains("at least two labels"));
        assert!(domain("Foo.example").unwrap().contains("not lowercase"));
        assert!(domain("-foo.example").unwrap().contains("begins or ends"));
        assert!(domain("foo-.example").unwrap().contains("begins or ends"));
        assert!(domain("a..b").unwrap().contains("empty labels"));
        let long = format!("{}.example", "a".repeat(64));
        assert!(domain(&long).unwrap().contains("at most 63"));
        // The traversal a group key must never take.
        assert!(domain("../../../etc/cron.d/evil").is_some());
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
        assert!(domain(&too_long).unwrap().contains("at most 253"));
        let one_over = [
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(62),
        ]
        .join(".");
        assert_eq!(one_over.len(), 254);
        assert!(domain(&one_over).unwrap().contains("at most 253"));
    }

    #[test]
    fn every_line_of_a_username_list_is_checked_and_the_line_is_named() {
        let r = name();
        assert!(usernames("secretary\nhall\n", &r).is_none());
        let why = usernames("secretary\nBad_Name", &r).unwrap();
        assert!(why.contains("Bad_Name"), "{why}");
        assert!(why.contains("starts with"), "{why}");
        let why = usernames("mail", &r).unwrap();
        assert!(why.contains("held back"), "{why}");
    }

    #[test]
    fn the_body_addresses_are_checked_line_by_line() {
        assert!(address_lines("secretary: own\nhall: alias secretary").is_none());
        assert!(address_lines("first.last: own\nhall: alias first.last").is_none());
        assert!(address_lines("first_last: own").is_none());
        assert!(address_lines("secretary: own").is_none());
        assert!(address_lines("secretary")
            .unwrap()
            .contains("not localpart: own"));
        assert!(address_lines("Bad_Name: own").unwrap().contains("Bad_Name"));
        assert!(address_lines("hall: alias Bad Target")
            .unwrap()
            .contains("Bad Target"));
        assert!(address_lines("hall: alias")
            .unwrap()
            .contains("not localpart: own"));
        assert!(address_lines("hall: shared secretary")
            .unwrap()
            .contains("not localpart: own"));
        let eleven: Vec<String> = (0..11).map(|i| format!("a{i}: own")).collect();
        assert!(address_lines(&eleven.join("\n"))
            .unwrap()
            .contains("up to ten"));
    }
}
