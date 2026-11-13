//! The applicant flow shared by the web form, the capsule and the terminal:
//! the page path, the answer rules, the cross-checks and the front-end label.
//!
//! The handler keeps the askama rendering and the route that starts the flow;
//! everything here is data and rules and depends on no front end.

use std::collections::{BTreeMap, HashSet};

use crate::flow::questions::{self, Branch, Kind, Question, Rule};
use crate::flow::validate;
use crate::mail::keycheck;
use crate::store::draft;
use crate::Error;

/// One page of the applicant's path. A mail key is one page per mailbox, with
/// the mailbox in the prompt: a body's key page would otherwise ask for every
/// key at once, and a status 10 answer cannot say which block is whose.
pub struct Page<'a> {
    pub q: &'a Question,
    /// Set on a key page, which is generated per mailbox rather than read from
    /// the question list.
    pub mailbox: Option<Mailbox>,
}

pub struct Mailbox {
    /// The account name the key is filed under, empty for a person.
    pub name: String,
    /// The address the page names.
    pub address: String,
}

/// The pages this applicant's path will ask, in file order: the branch the
/// `whose` answer selects, the blessing only once `orders` says monastic, and
/// one mail-key page per mailbox. The capsule and the terminal both walk it, so
/// the counter and the branches cannot disagree between the two.
pub fn flow_path<'a>(list: &'a [Question], answers: &BTreeMap<String, String>) -> Vec<Page<'a>> {
    let body = answers.get("whose").map(String::as_str) == Some("body");
    let monastic = questions::is_monastic(answers.get("orders").map(String::as_str));
    let mut out = Vec::new();
    for q in questions::shown(list, !body) {
        if q.branch == Branch::Monastic && !monastic {
            continue;
        }
        if q.id == "mail_key" && !body {
            let name = answers.get("username").cloned().unwrap_or_default();
            let address = if name.is_empty() {
                "your address".to_string()
            } else {
                format!("{name}@kyriakon.net")
            };
            out.push(Page {
                q,
                mailbox: Some(Mailbox { name, address }),
            });
        } else if q.id == "body_mail_key" && body {
            let domain = answers.get("body_domain").cloned().unwrap_or_default();
            for name in questions::account_names(answers) {
                let address = if domain.is_empty() {
                    name.clone()
                } else {
                    format!("{name}@{domain}")
                };
                out.push(Page {
                    q,
                    mailbox: Some(Mailbox { name, address }),
                });
            }
        } else {
            out.push(Page { q, mailbox: None });
        }
    }
    out
}

/// Why one page's answer cannot advance the flow, or `None`. The rules are the
/// web form's, `validate::reason` included, so the capsule refuses what the form
/// refuses; a key's per-mailbox checks and an address list's shape are added
/// here because `reason` proves one block and no list.
pub fn flow_problem(
    page: &Page,
    value: &str,
    reserved: &HashSet<String>,
    required: bool,
    answers: &BTreeMap<String, String>,
) -> Option<String> {
    let q = page.q;
    if page.mailbox.is_some() {
        if value.trim().is_empty() {
            return Some("a public key is needed".to_string());
        }
        let blocks = keycheck::blocks(value);
        if blocks.len() != 1 {
            return Some("one key for one mailbox".to_string());
        }
        return key_error(&blocks[0]);
    }
    if let Some(why) = validate::reason(q, value, reserved, required) {
        return Some(why);
    }
    // The shared key check is the web form's, because `validate::reason` only
    // proves the first block parses; it does not count blocks or compare them
    // with the body's account names.
    if q.rule == Rule::MailKey && !value.is_empty() {
        if let Some(why) = mail_key_errors(q, value, answers).into_iter().next() {
            return Some(why);
        }
    }
    if q.kind == Kind::Addresses {
        return validate::address_lines(value);
    }
    None
}

/// The draft's answers with the key answer rebuilt from the keys the draft
/// holds, pasted and mailed alike. `build_record` pairs one block per mailbox in
/// account order, so a key the mail route filed and one pasted on the next page
/// cannot disagree about which mailbox they serve.
pub fn flow_answers(record: &draft::Draft, body: bool) -> BTreeMap<String, String> {
    let mut answers = record.answers.clone();
    let (id, mailboxes) = if body {
        ("body_mail_key", questions::account_names(&record.answers))
    } else {
        (
            "mail_key",
            vec![record.answers.get("username").cloned().unwrap_or_default()],
        )
    };
    let mut materials = Vec::new();
    for mailbox in &mailboxes {
        match record.mail_keys.iter().find(|k| k.mailbox == *mailbox) {
            Some(key) => materials.push(key.material.clone()),
            None => return answers,
        }
    }
    if !materials.is_empty() {
        answers.insert(id.to_string(), materials.join("\n\n"));
    }
    answers
}

/// What a submission is read against.
pub struct Reading {
    /// Whether it is read as a body's, which decides which questions exist.
    pub body: bool,
    /// Whether the applicant has already been shown that branch's questions. False
    /// when the answer names a branch the page did not carry, which is a question
    /// the page had not opened and therefore answers it never showed.
    pub shown: bool,
}

/// The branch a submission is read against, and whether its own answers are the
/// page it was shown. The branch question's answer settles this, from the same
/// field whichever front-end filed the submission: the web form posts its select,
/// and the terminal and the capsule post the same answer.
pub fn reading(form: &BTreeMap<String, String>) -> Reading {
    let body = form.get("whose").map(String::as_str) == Some("body");
    let shown = match form.get("branch") {
        // The web form posts the branch its page was rendered for. An answer
        // naming the other one means the applicant changed the select without
        // opening the block it asks for, so the page they were shown is not the
        // page their answer asks for.
        Some(page) => (page == "body") == body,
        // No page: a front-end that renders its own has already shown whatever its
        // answer asks for, so its answer is the page.
        None => true,
    };
    Reading { body, shown }
}

/// The front end that filed a submission: `web`, `tui` or `capsule`, and the web
/// form when the field is not sent at all, since the browser form does not carry
/// one. It is a label and nothing more, so nothing reads it but the reviewer and
/// the intent: that is also why an unknown value is refused rather than recorded,
/// because a value no reader recognises is a value that cannot be read at all.
pub fn label(form: &BTreeMap<String, String>) -> Result<&'static str, Error> {
    match form.get("front_end").map(String::as_str) {
        None | Some("web") => Ok("web"),
        Some("tui") => Ok("tui"),
        Some("capsule") => Ok("capsule"),
        Some(other) => Err(Error::Failed(format!("unknown front_end {other:?}"))),
    }
}

/// The body's addresses against its account names: the same number of lines, at
/// most ten, and each address line `localpart: own` or `localpart: alias
/// localpart`, which is the form the spec's community-block table gives.
pub fn body_cross_checks(form: &BTreeMap<String, String>, errors: &mut Vec<String>) {
    let addresses = form.get("body_addresses").map(String::as_str).unwrap_or("");
    let a = addresses.lines().filter(|l| !l.trim().is_empty()).count();
    let n = questions::account_names(form).len();
    if a != n {
        errors.push(format!(
            "The addresses, one per line: {a} addresses and {n} account names; there is one account name per address"
        ));
    }
    if let Some(why) = validate::address_lines(addresses) {
        errors.push(format!("The addresses, one per line: {why}"));
    }
}

/// The refusals for a mail-key answer. A person's key is one block; a body's is
/// one block per mailbox, paired with the account names in the order given.
pub fn mail_key_errors(q: &Question, value: &str, form: &BTreeMap<String, String>) -> Vec<String> {
    let blocks = keycheck::blocks(value);
    if blocks.is_empty() {
        return vec!["a public key is needed".to_string()];
    }
    if q.id == "body_mail_key" {
        let mailboxes = questions::account_names(form).len();
        if blocks.len() != mailboxes {
            return vec![format!(
                "one key per mailbox: {mailboxes} mailboxes and {} keys",
                blocks.len()
            )];
        }
        blocks.iter().filter_map(|b| key_error(b)).collect()
    } else if blocks.len() > 1 {
        vec!["one key for one address".to_string()]
    } else {
        key_error(&blocks[0]).into_iter().collect()
    }
}

/// The refusal a submitted block has earned, or `None` when it can deliver.
/// An inspected finding (AEAD, expiry, revocation, no encryption subkey) is a
/// refusal at the form; the parser-gap advisory proceeds, because a key the
/// platform cannot inspect is not a key it can prove bad.
pub fn key_error(block: &str) -> Option<String> {
    match keycheck::pgp_public_key(block) {
        Err(e) => Some(e.to_string()),
        Ok(checked) => checked.refusal().map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::questions::{Branch, Kind, Question, Rule};
    use crate::mail::keycheck::fixtures::{AEAD, CLEAN, EXPIRED_SUBKEY};

    fn mail_key_question() -> Question {
        Question {
            id: "mail_key".into(),
            prompt: "Your public key".into(),
            kind: Kind::Key,
            branch: Branch::Person,
            required: true,
            rule: Rule::MailKey,
        }
    }

    #[test]
    fn a_mail_key_that_cannot_deliver_is_refused() {
        let q = mail_key_question();
        let form = BTreeMap::new();
        assert!(mail_key_errors(&q, CLEAN, &form).is_empty());
        assert!(mail_key_errors(&q, AEAD, &form)
            .iter()
            .any(|why| why.contains("AEAD")));
        assert!(!mail_key_errors(&q, EXPIRED_SUBKEY, &form).is_empty());
    }
}
