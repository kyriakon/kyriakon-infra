//! The pages the handler renders, and the copy that is not in the shared
//! question list.
//!
//! The applicant page is one page of four sections, the prototype's order, with
//! the community block open only for a body. It is inside the first section, so
//! the section count is four on both paths. The labels are the shared list's
//! prompts, rendered from `questions.toml`; the hints below are page copy and the
//! prototype is their source.

use std::collections::BTreeMap;

use askama::Template;

use crate::catalogue::{self, Protocol, Row, Service};
use crate::questions::{self, Kind, Question, Rule};

#[derive(Template)]
#[template(path = "applicant.html")]
pub struct ApplicantPage {
    pub errors: Vec<String>,
    /// The branch the page was rendered for, `person` or `body`. The form posts
    /// it back in a hidden field, so a submission is read against the page the
    /// applicant was shown rather than against whatever the select says now.
    pub branch: &'static str,
    pub community: Vec<Rq>,
    pub you: Vec<Rq>,
    pub mailkey: Vec<Rq>,
    pub pay: Vec<Rq>,
    pub about: Vec<Rq>,
    pub acceptance: Vec<Rq>,
    pub doc_version: String,
    /// What the platform offers, one row per catalogue entry. The applicant is
    /// nobody yet, so no host is rendered from a member.
    pub services: Vec<Row>,
}

/// The member's own page. Its list of what the platform offers is the same
/// catalogue the application page's cards come from; the rest of the page, and
/// the session that identifies a member, are the account page's own ticket.
#[derive(Template)]
#[template(path = "account.html")]
pub struct AccountPage {
    pub services: Vec<Row>,
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

/// The page a decision link opens. It names what the link would do and carries
/// the signature in the form, because the link itself acts on nothing: a GET
/// that decided would let anything that fetches a URL decide for the operator.
#[derive(Template)]
#[template(path = "decide.html")]
pub struct DecidePage {
    /// The decision in words, as the review email lists it.
    pub label: String,
    pub username: String,
    pub token: String,
    pub action: String,
    pub sig: String,
}

/// The page a one-time password link opens. It shows the form; the hash it
/// submits is checked against the link's signature by the drain, which holds the
/// key, so this page proves nothing and cannot know the link is spent.
#[derive(Template)]
#[template(path = "password.html")]
pub struct PasswordPage {
    pub username: String,
    pub token: String,
    /// The signed expiry, passed through so the drain checks the same value the
    /// link carried.
    pub until: String,
    pub sig: String,
    /// Set when the submission was refused, so the form comes back with the
    /// reason on it rather than a bare page.
    pub error: Option<String>,
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

/// The catalogue as the web page shows it, one row per entry. Both the
/// application page's cards and the account page's list format these, and the
/// rows are what the check compares: a list held in the template would not be
/// these rows.
pub fn services(list: &[Service], member: Option<&str>) -> Vec<Row> {
    list.iter()
        .map(|s| catalogue::row(s, Protocol::Web, member))
        .collect()
}

/// The member's page. `member` is the session's member where there is one, which
/// a host carrying `<name>` is rendered from.
pub fn account(list: &[Service], member: Option<&str>) -> AccountPage {
    AccountPage {
        services: services(list, member),
    }
}

/// Build the page for one branch. `answers` is the last submission when one was
/// refused, so the applicant does not lose what they typed.
pub fn applicant(
    list: &[Question],
    catalogue: &[Service],
    body: bool,
    answers: &BTreeMap<String, String>,
    doc_version: &str,
) -> ApplicantPage {
    let mut page = ApplicantPage {
        errors: Vec::new(),
        branch: if body { "body" } else { "person" },
        community: Vec::new(),
        you: Vec::new(),
        mailkey: Vec::new(),
        pay: Vec::new(),
        about: Vec::new(),
        acceptance: Vec::new(),
        doc_version: doc_version.to_string(),
        // An applicant is not a member, so a host carrying `<name>` is the
        // pattern itself here.
        services: services(catalogue, None),
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
    let options = match &q.rule {
        Rule::Choice(choices) => {
            // An optional choice opens on a blank answer rather than on its
            // first one: the orders question is optional, so an applicant who
            // ignores it must declare nothing rather than be recorded as a
            // priest. A required choice has no blank, because there is no
            // answer to leave it on.
            let mut opts: Vec<Opt> = Vec::new();
            if !q.required {
                opts.push(Opt {
                    value: String::new(),
                    label: String::new(),
                    selected: value.is_empty(),
                });
            }
            opts.extend(choices.iter().map(|c| Opt {
                value: c.value.clone(),
                label: c.label.clone(),
                selected: value == c.value,
            }));
            opts
        }
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
        // Both kinds are drawn as a checkbox by the field macro, and for both the
        // box is the only place the answer is carried. An acceptance answer is
        // "yes" or nothing, so it is restored the same way a yes/no answer is: a
        // page rebuilt from a submission that dropped this came back with the
        // terms unticked and refused the applicant for an answer they had given.
        checked: matches!(q.kind, Kind::YesNo | Kind::Acceptance)
            && !value.is_empty()
            && value != "no",
        value,
        options,
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
        "mail_key" => "The walkthrough makes a key in your browser and gives you a recovery phrase to write down: the key walkthrough. Paste the public block here; only the public half is ever sent.",
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

    /// A catalogue for the page tests. The services themselves are the
    /// catalogue module's own subject; what these tests carry is that the page
    /// renders the file it was given.
    fn catalogue() -> Vec<Service> {
        crate::catalogue::parse(
            "[[service]]\n\
             id = \"mail\"\n\
             name = \"Mail\"\n\
             summary = \"zero-access mail\"\n\
             state = \"live\"\n\
             host = \"mail.example.invalid\"\n\
             action = \"read\"\n",
        )
        .expect("a catalogue the file could hold")
    }

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
            q(
                "address_outside",
                Branch::All,
                Kind::Text,
                false,
                Rule::Address,
            ),
            q("mail_key", Branch::Person, Kind::Key, true, Rule::MailKey),
            q(
                "body_mail_key",
                Branch::Body,
                Kind::Key,
                true,
                Rule::MailKey,
            ),
            q(
                "rail",
                Branch::All,
                Kind::Choice,
                true,
                choices(&[("card", "Card"), ("no_charge", "No charge")]),
            ),
            q(
                "blessing",
                Branch::Monastic,
                Kind::Multiline,
                true,
                Rule::None,
            ),
            q(
                "accept_terms",
                Branch::All,
                Kind::Acceptance,
                true,
                Rule::None,
            ),
        ]
    }

    #[test]
    fn a_person_has_four_sections_and_no_community_block() {
        let p = applicant(&list(), &catalogue(), false, &BTreeMap::new(), "r");
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
        let p = applicant(&list(), &catalogue(), true, &BTreeMap::new(), "r");
        let ids = |v: &[Rq]| v.iter().map(|q| q.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&p.community), ["body_name"]);
        assert_eq!(ids(&p.you), ["username", "whose", "vat", "address_outside"]);
        assert_eq!(ids(&p.mailkey), ["body_mail_key"]);
    }

    #[test]
    fn a_selected_answer_is_still_selected_after_a_refusal() {
        let mut answers = BTreeMap::new();
        answers.insert("whose".to_string(), "body".to_string());
        let p = applicant(&list(), &catalogue(), true, &answers, "r");
        let whose = p.you.iter().find(|q| q.id == "whose").unwrap();
        assert!(whose
            .options
            .iter()
            .any(|o| o.value == "body" && o.selected));
        assert!(whose
            .options
            .iter()
            .any(|o| o.value == "person" && !o.selected));
    }

    #[test]
    fn an_optional_choice_declares_nothing_until_it_is_answered() {
        // The orders question is optional and its first answer is Priest, so a
        // select that opens on the first answer records priesthood for an
        // applicant who ignores the question.
        let mut list = list();
        list.push(q(
            "orders",
            Branch::All,
            Kind::Choice,
            false,
            choices(&[("priest", "Priest"), ("nun", "Nun")]),
        ));
        let untouched_page = applicant(&list, &catalogue(), false, &BTreeMap::new(), "r");
        let untouched = &untouched_page
            .about
            .iter()
            .find(|q| q.id == "orders")
            .unwrap()
            .options;
        assert_eq!(untouched.first().map(|o| o.value.as_str()), Some(""));
        assert!(
            untouched[0].selected,
            "the blank answer is the one declared"
        );
        assert!(untouched[1..].iter().all(|o| !o.selected));

        // Answered, it opens on the answer, blank answer included: an applicant
        // who changes their mind can go back to declaring nothing.
        let mut answers = BTreeMap::new();
        answers.insert("orders".to_string(), "nun".to_string());
        let answered_page = applicant(&list, &catalogue(), false, &answers, "r");
        let answered = &answered_page
            .about
            .iter()
            .find(|q| q.id == "orders")
            .unwrap()
            .options;
        assert!(!answered[0].selected && answered[0].value.is_empty());
        assert!(answered.iter().any(|o| o.value == "nun" && o.selected));

        // A required choice has no blank answer: there would be nothing to
        // leave it on.
        let p = applicant(&list, &catalogue(), false, &BTreeMap::new(), "r");
        let rail = p.pay.iter().find(|q| q.id == "rail").unwrap();
        assert!(rail.options.iter().all(|o| !o.value.is_empty()));
    }

    /// The two web renderings format the catalogue they were handed: the cards
    /// come from the rows, so the template cannot carry a list of its own, and
    /// the account page's list is the same file.
    #[test]
    fn the_catalogue_is_a_card_per_entry_and_a_list_on_the_account_page() {
        let p = applicant(&list(), &catalogue(), false, &BTreeMap::new(), "r");
        assert_eq!(p.services.len(), 1);

        let html = p.render().unwrap();
        assert!(html.contains("<div class=\"service\">"), "{html}");
        assert!(html.contains("Mail"), "{html}");
        assert!(html.contains("zero-access mail"), "{html}");
        assert!(html.contains("https://mail.example.invalid/"), "{html}");
        assert!(html.contains("<span class=\"tag\">live</span>"), "{html}");

        let listed = account(&catalogue(), None).render().unwrap();
        assert!(listed.contains("zero-access mail"), "{listed}");
        assert!(listed.contains("https://mail.example.invalid/"), "{listed}");

        // No member to render a host from, so the pattern itself is what shows,
        // HTML-escaped in the markup as `<name>.example.invalid`.
        let pattern = crate::catalogue::parse(
            "[[service]]\n\
             id = \"web\"\n\
             name = \"A website\"\n\
             summary = \"static pages\"\n\
             state = \"live\"\n\
             host = \"<name>.example.invalid\"\n\
             action = \"read\"\n",
        )
        .unwrap();
        assert!(account(&pattern, None)
            .render()
            .unwrap()
            .contains("&#60;name&#62;.example.invalid"));
        assert!(account(&pattern, Some("theophilus"))
            .render()
            .unwrap()
            .contains("https://theophilus.example.invalid/"));
    }
}
