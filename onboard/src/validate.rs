//! Field validation. Every refusal names its reason, and existence is never
//! checked: the username rule is format and the reserved set only, so the form
//! cannot be used to ask whether a name is taken.

use std::collections::HashSet;

use crate::keycheck;
use crate::questions::{self, Question, Rule};

/// The reserved set, one name per line, `#` comments and blank lines skipped so
/// the file can explain itself.
pub fn reserved(text: &str) -> HashSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_ascii_lowercase())
        .collect()
}

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
    match &q.rule {
        Rule::None => None,
        Rule::Username => username(&v, reserved),
        Rule::Usernames => usernames(&v, reserved),
        Rule::Address => address(&v),
        Rule::Domain => domain(&v),
        Rule::MailKey => keycheck::pgp_public_key(&v).err(),
        Rule::UploadKey => keycheck::openssh_public_key(&v).err(),
        Rule::Choice(opts) => choice(opts, &v),
        Rule::MaxLen(n) => (v.chars().count() > *n).then(|| format!("at most {n} characters")),
    }
}

/// The username rule: the charset `scripts/add-user.sh` enforces, no longer than
/// 32 characters, and not a reserved name. Never whether it exists.
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
    if value.chars().count() > 32 {
        return Some("a username is at most 32 characters".to_string());
    }
    let first = value.as_bytes()[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Some("a username starts with a lowercase letter or a digit".to_string());
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Some("a username is lowercase letters, digits, dot, underscore and hyphen".to_string());
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

/// The body's addresses, one per line, each `localpart: own` or
/// `localpart: alias localpart`, at most ten. The localpart is the shape a
/// username has, without the reserved set: it names an address on the body's own
/// domain, not a name in the platform's namespace.
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
    if let Some(why) = username_shape(local) {
        return Some(format!("the address line {line:?}: {why}"));
    }
    let mut words = rest.split_whitespace();
    match (words.next(), words.next(), words.next()) {
        (Some("own"), None, None) => None,
        (Some("alias"), Some(target), None) => match username_shape(target) {
            None => None,
            Some(why) => Some(format!("the address line {line:?}: the alias target {target:?} {why}")),
        },
        _ => Some(malformed()),
    }
}

fn address(v: &str) -> Option<String> {
    let mut parts = v.split('@');
    let (local, domain) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let acceptable = !local.is_empty()
        && !domain.is_empty()
        && parts.next().is_none()
        && !domain.contains(char::is_whitespace)
        && domain.contains('.');
    (!acceptable)
        .then(|| "an address outside this platform is one, like someone@example.invalid".to_string())
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
    use crate::questions::{Branch, Choice, Kind, Question, Rule};

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
        assert!(username("bad_name!", &r).unwrap().contains("dot, underscore and hyphen"));
    }

    #[test]
    fn a_username_past_32_characters_is_refused_with_its_reason() {
        let long = "a".repeat(33);
        assert!(username(&long, &name()).unwrap().contains("at most 32"));
        assert!(username(&"a".repeat(32), &name()).is_none());
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
    fn an_address_outside_the_platform_is_one_address() {
        assert!(address("someone@example.invalid").is_none());
        assert!(address("not an address").is_some());
        assert!(address("two@at@example.invalid").is_some());
        assert!(address("no@domain").is_some());
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
        assert!(address_lines("secretary: own").is_none());
        assert!(address_lines("secretary").unwrap().contains("not localpart: own"));
        assert!(address_lines("Bad_Name: own").unwrap().contains("Bad_Name"));
        assert!(address_lines("hall: alias Bad Target").unwrap().contains("Bad Target"));
        assert!(address_lines("hall: alias").unwrap().contains("not localpart: own"));
        assert!(address_lines("hall: shared secretary").unwrap().contains("not localpart: own"));
        let eleven: Vec<String> = (0..11).map(|i| format!("a{i}: own")).collect();
        assert!(address_lines(&eleven.join("\n")).unwrap().contains("up to ten"));
    }
}
