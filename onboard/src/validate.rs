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
        Rule::Address => address(&v),
        Rule::MailKey => keycheck::pgp_public_key(&v).err(),
        Rule::UploadKey => keycheck::openssh_public_key(&v).err(),
        Rule::Choice(opts) => choice(opts, &v),
        Rule::MaxLen(n) => (v.chars().count() > *n).then(|| format!("at most {n} characters")),
    }
}

/// The username rule: the charset `scripts/add-user.sh` enforces, no longer than
/// 32 characters, and not a reserved name. Never whether it exists.
pub fn username(value: &str, reserved: &HashSet<String>) -> Option<String> {
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
    if reserved.contains(value) {
        return Some("that name is held back by the platform".to_string());
    }
    None
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
}
