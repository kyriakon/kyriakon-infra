//! The pages the handler renders, and the copy that is not in the shared
//! question list.
//!
//! The applicant page is one page of four sections, the prototype's order, with
//! the community block open only for a body. It is inside the first section, so
//! the section count is four on both paths. The labels are the shared list's
//! prompts, rendered from `questions.tsv`; the hints below are page copy and the
//! prototype is their source.

use std::collections::BTreeMap;

use askama::Template;

use crate::questions::{self, Kind, Question, Rule};

#[derive(Template)]
#[template(path = "applicant.html")]
pub struct ApplicantPage {
    pub errors: Vec<String>,
    pub community: Vec<Rq>,
    pub you: Vec<Rq>,
    pub mailkey: Vec<Rq>,
    pub pay: Vec<Rq>,
    pub about: Vec<Rq>,
    pub acceptance: Vec<Rq>,
    pub doc_version: String,
}

#[derive(Template)]
#[template(path = "received.html")]
pub struct ReceivedPage {
    pub status_url: String,
}

#[derive(Template)]
#[template(path = "status.html")]
pub struct StatusPage {
    pub stage: String,
    pub filed_at: String,
    pub notice: String,
    /// The one-time password link the drain wrote onto the record, absent when
    /// the record carries none. The handler never signs one: it renders what it
    /// finds or nothing at all.
    pub password_link: Option<String>,
}

#[derive(Template)]
#[template(path = "notice.html")]
pub struct NoticePage {
    pub title: String,
    pub message: String,
}

/// A question as the template renders it.
pub struct Rq {
    pub id: String,
    pub prompt: String,
    pub kind: &'static str,
    /// The parenthetical after the prompt, e.g. "required" or "required for
    /// monastics", empty when the question is optional.
    pub note: String,
    pub value: String,
    pub checked: bool,
    pub options: Vec<Opt>,
    /// The hidden field the browser walkthrough fills with the fingerprint it
    /// computed, carried beside the material and never recomputed here.
    pub fingerprint_id: String,
    pub fingerprint: String,
    pub hint: String,
}

pub struct Opt {
    pub value: String,
    pub label: String,
    pub selected: bool,
}

enum Section {
    You,
    Community,
    MailKey,
    Pay,
    About,
    Acceptance,
}

/// Which of the four sections, or the community block, a question belongs to.
/// The grouping is presentation: the capsule and the TUI ask the same questions
/// in the file's order and ignore it.
fn section(id: &str) -> Section {
    match id {
        "username" | "whose" | "vat" | "address_outside" | "address_ack" => Section::You,
        "body_name" | "body_kind" | "body_domain" | "body_records" | "body_addresses"
        | "body_account_names" | "body_dns_contact" => Section::Community,
        "mail_key" | "upload_key" | "body_mail_key" | "body_upload_key" => Section::MailKey,
        "rail" => Section::Pay,
        "accept_terms" => Section::Acceptance,
        _ => Section::About,
    }
}

/// Build the page for one branch. `answers` is the last submission when one was
/// refused, so the applicant does not lose what they typed.
pub fn applicant(
    list: &[Question],
    body: bool,
    answers: &BTreeMap<String, String>,
    doc_version: &str,
) -> ApplicantPage {
    let mut page = ApplicantPage {
        errors: Vec::new(),
        community: Vec::new(),
        you: Vec::new(),
        mailkey: Vec::new(),
        pay: Vec::new(),
        about: Vec::new(),
        acceptance: Vec::new(),
        doc_version: doc_version.to_string(),
    };
    for q in questions::shown(list, !body) {
        let rq = render(q, answers);
        match section(&q.id) {
            Section::You => page.you.push(rq),
            Section::Community => page.community.push(rq),
            Section::MailKey => page.mailkey.push(rq),
            Section::Pay => page.pay.push(rq),
            Section::About => page.about.push(rq),
            Section::Acceptance => page.acceptance.push(rq),
        }
    }
    page
}

fn render(q: &Question, answers: &BTreeMap<String, String>) -> Rq {
    let value = answers.get(&q.id).cloned().unwrap_or_default();
    let fingerprint_id = format!("{}_fingerprint", q.id);
    let fingerprint = answers.get(&fingerprint_id).cloned().unwrap_or_default();
    let options = match &q.rule {
        Rule::Choice(choices) => choices
            .iter()
            .map(|c| Opt {
                value: c.value.clone(),
                label: c.label.clone(),
                selected: value == c.value,
            })
            .collect(),
        _ => Vec::new(),
    };
    Rq {
        id: q.id.clone(),
        prompt: q.prompt.clone(),
        kind: q.kind.token(),
        // The blessing is required only on the monastic path, which the page
        // cannot know until the orders answer arrives, so its marker says so and
        // the rule is applied when the form is submitted.
        note: if q.id == "blessing" {
            "required for monastics".to_string()
        } else if q.required {
            "required".to_string()
        } else {
            String::new()
        },
        checked: q.kind == Kind::YesNo && !value.is_empty() && value != "no",
        value,
        options,
        fingerprint_id,
        fingerprint,
        hint: hint(&q.id).to_string(),
    }
}

/// The page copy attached to a question. The prototype's hints, verbatim where
/// it has them; the community block's line format has to be stated somewhere, so
/// it is here.
fn hint(id: &str) -> &'static str {
    match id {
        "username" => "Lowercase letters, digits, dot, underscore and hyphen, up to 32. This becomes your address, <span class=\"mono\">theophilus@kyriakon.net</span>, and your site, <span class=\"mono\">theophilus.kyriakon.net</span>. The names the platform uses itself are held back, so <span class=\"mono\">mail</span>, <span class=\"mono\">www</span>, <span class=\"mono\">kleio</span>, <span class=\"mono\">press</span> and <span class=\"mono\">signup</span> are not available, and a web address in this namespace is a username in it too.",
        "whose" => "A body is a parish, a monastery, a school or a small Orthodox business. Answering for one opens the community block: the body's name and kind, its domain, its addresses and a mail key for each mailbox, and it pays £40 a year rather than £20. Whoever applies stays one person either way, and is who we reach, who accepts the terms and who pays.",
        "vat" => "Optional. A body in business in the Union supplies a reverse-charge supply, which is why the number is asked for.",
        "address_outside" => "We write here as well as to your new address, including if the account is ever in trouble, and if this address bounces we hold on longer before doing anything final. It is used for notices only, it is never shared, and we never use it to look you up anywhere else. <strong>If you leave it empty,</strong> we can only reach you inside this account: if you lose your key or your mail client you will not hear from us, and an unpaid account will still lapse and in time be deleted, with the mail. Nothing else changes.",
        "mail_key" => "The walkthrough makes a key in your browser and gives you a recovery phrase to write down: <a href=\"/keys\">the key walkthrough</a>. Paste the public block here; only the public half is ever sent.",
        "upload_key" => "Needed for a website or repositories. An OpenSSH public key, the line starting <span class=\"mono\">ssh-ed25519</span> or <span class=\"mono\">ssh-rsa</span>.",
        "rail" => "Clergy, monastics, and anyone without the means to pay are not charged. There is nothing to prove and no means test: say so below and the same person who reviews the application decides it.",
        "body_records" => "The platform asks for the domain's A and AAAA, MX, SPF, DKIM and DMARC records.",
        "body_addresses" => "One address per line, each as <span class=\"mono\">localpart: own</span> for a mailbox of its own, or <span class=\"mono\">localpart: alias localpart</span> for one that shares another's mailbox and key. Up to ten.",
        "body_account_names" => "One account name per mailbox, one per line, in the order of the addresses above.",
        "body_mail_key" => "One public key block per mailbox, in the order above. An alias shares the mailbox and the key of the address it points at.",
        "body_upload_key" => "Needed for the domain's website. An OpenSSH public key.",
        "body_dns_contact" => "Who we write to about the domain's records, if it is not you.",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::questions::{Branch, Choice};

    fn q(id: &str, branch: Branch, kind: Kind, required: bool, rule: Rule) -> Question {
        Question {
            id: id.into(),
            prompt: id.into(),
            kind,
            branch,
            required,
            rule,
        }
    }

    fn choices(pairs: &[(&str, &str)]) -> Rule {
        Rule::Choice(
            pairs
                .iter()
                .map(|(v, l)| Choice {
                    value: (*v).into(),
                    label: (*l).into(),
                })
                .collect(),
        )
    }

    fn list() -> Vec<Question> {
        vec![
            q("username", Branch::All, Kind::Text, true, Rule::Username),
            q(
                "whose",
                Branch::All,
                Kind::Choice,
                true,
                choices(&[("person", "Just me"), ("body", "A body")]),
            ),
            q("vat", Branch::Body, Kind::Text, false, Rule::None),
            q("body_name", Branch::Body, Kind::Text, true, Rule::None),
            q("address_outside", Branch::All, Kind::Text, false, Rule::Address),
            q("mail_key", Branch::Person, Kind::Key, true, Rule::MailKey),
            q("body_mail_key", Branch::Body, Kind::Key, true, Rule::MailKey),
            q(
                "rail",
                Branch::All,
                Kind::Choice,
                true,
                choices(&[("card", "Card"), ("no_charge", "No charge")]),
            ),
            q("blessing", Branch::Monastic, Kind::Multiline, true, Rule::None),
            q("accept_terms", Branch::All, Kind::Acceptance, true, Rule::None),
        ]
    }

    #[test]
    fn a_person_has_four_sections_and_no_community_block() {
        let p = applicant(&list(), false, &BTreeMap::new(), "r");
        assert!(p.community.is_empty());
        let ids = |v: &[Rq]| v.iter().map(|q| q.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&p.you), ["username", "whose", "address_outside"]);
        assert_eq!(ids(&p.mailkey), ["mail_key"]);
        assert_eq!(ids(&p.pay), ["rail"]);
        assert_eq!(ids(&p.about), ["blessing"]);
        assert_eq!(ids(&p.acceptance), ["accept_terms"]);
    }

    #[test]
    fn a_body_has_the_community_block_and_its_own_keys() {
        let p = applicant(&list(), true, &BTreeMap::new(), "r");
        let ids = |v: &[Rq]| v.iter().map(|q| q.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&p.community), ["body_name"]);
        assert_eq!(ids(&p.you), ["username", "whose", "vat", "address_outside"]);
        assert_eq!(ids(&p.mailkey), ["body_mail_key"]);
    }

    #[test]
    fn a_selected_answer_is_still_selected_after_a_refusal() {
        let mut answers = BTreeMap::new();
        answers.insert("whose".to_string(), "body".to_string());
        let p = applicant(&list(), true, &answers, "r");
        let whose = p.you.iter().find(|q| q.id == "whose").unwrap();
        assert!(whose.options.iter().any(|o| o.value == "body" && o.selected));
        assert!(whose.options.iter().any(|o| o.value == "person" && !o.selected));
    }
}
