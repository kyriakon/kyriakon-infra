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
use time::OffsetDateTime;

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
    /// The account the session signed in as.
    pub username: String,
    /// The address outside the platform, absent when the member gave none. The
    /// page says plainly that an empty one is the whole recovery path.
    pub outside_address: Option<String>,
    /// The space used, formatted, and whether the drain has recorded one.
    pub space_used: Option<String>,
    pub space_soft: &'static str,
    pub space_hard: &'static str,
    /// The upload key fingerprints and the day each was added.
    pub upload_keys: Vec<UploadKeyView>,
    /// Every notice sent, newest last, each with the address it went to.
    pub notices: Vec<NoticeView>,
    /// The group a mailbox belongs to, with the billing and state the group
    /// holds. Absent for a person's account.
    pub group: Option<GroupView>,
    /// The reason a suspended account gives, and the day a closing one ends.
    pub suspended: Option<String>,
    pub closing_until: Option<String>,
    /// Whether the page offers the close form. False on the login page, which
    /// is not an account page at all.
    pub can_close: bool,
    /// The group's DNS recipe, present only for a mailbox whose account names a
    /// group. It is the same [`crate::dns::Recipe`] the approval email renders, so
    /// the values cannot disagree.
    pub dns: Option<crate::dns::Recipe>,
    /// The payment block, absent for a free account and for one whose approval
    /// has not happened yet.
    pub payment: Option<PaymentView>,
    /// Approved without charge: no payment block, nothing due, never lapses.
    /// The page says so in one line rather than leaving the absence to be read
    /// as an unpaid account whose block failed to render.
    pub free: bool,
}

/// One upload key, as the page shows it.
pub struct UploadKeyView {
    pub fingerprint: String,
    pub added_at: String,
}

/// One notice, as the page shows it.
pub struct NoticeView {
    pub at: String,
    pub subject: String,
    pub to: String,
}

/// A group mailbox's body, as the group record holds it. The billing lives on
/// the group so one renewal writes one date, and the page shows the date rather
/// than a copy of it.
pub struct GroupView {
    pub domain: String,
    pub name: String,
    pub kind: String,
    pub rail: String,
    pub no_charge: bool,
    pub paid_until: Option<String>,
    /// `free`, `active` or `payment due`, from the group's own payment block.
    pub state: String,
    /// The group's one payment reference while money is still due, in full so
    /// any mailbox holder can pay it. Absent once the date is set, when the
    /// token goes back to being a secret, and on a free group.
    pub token: Option<String>,
    /// The day the group's one window closes, while it runs.
    pub window_closes: Option<String>,
    pub accounts: Vec<String>,
    /// The space its mailboxes use together, and the allowance they add up to.
    /// The quota lives on the group record, summed by the drain from the same
    /// per-account figures the page shows each mailbox.
    pub space_used: Option<String>,
    pub allowance: String,
}

impl GroupView {
    pub fn from_record(group: &crate::store::GroupRecord) -> GroupView {
        let payment = &group.payment;
        let state = if payment.no_charge {
            "free"
        } else if payment.paid_until.is_some() {
            "active"
        } else {
            "payment due"
        };
        let unpaid = !payment.no_charge && payment.paid_until.is_none();
        GroupView {
            domain: group.domain.clone(),
            name: group.name.clone(),
            kind: group.kind.clone(),
            rail: payment.rail.clone(),
            no_charge: payment.no_charge,
            paid_until: payment.paid_until.clone(),
            state: state.to_string(),
            token: payment.token_ref.clone().filter(|_| unpaid),
            window_closes: payment
                .window
                .as_ref()
                .filter(|_| unpaid)
                .map(|w| w.closes_at[..10.min(w.closes_at.len())].to_string()),
            accounts: group.accounts.clone(),
            space_used: group.space_used.map(space),
            allowance: format!(
                "{} mailbox{}, {} soft and {} hard each",
                group.accounts.len(),
                if group.accounts.len() == 1 { "" } else { "es" },
                QUOTA_SOFT,
                QUOTA_HARD
            ),
        }
    }
}

/// The login page: the only thing a request with no session is shown.
#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginPage {
    /// Set when a submission was refused, so the form comes back with the
    /// reason on it rather than a bare page.
    pub error: Option<String>,
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
    /// The payment block, present for a decided paid application whose account
    /// still owes for the year.
    pub payment: Option<PaymentView>,
}

/// The lapse's own words, shared by the page, the capsule and the notice: mail
/// stays readable and published work stays up; sending, uploading and pushing
/// stop; nothing is deleted at that point.
pub const LAPSE_NOTE: &str = "Mail keeps arriving and stays readable, and everything you \
published stays up. Sending, uploading and pushing have stopped. Nothing is deleted at \
this point. If you have posted the money, write to admin@kyriakon.net.";

/// The payment block, built once from the account and rendered by the web page,
/// the capsule and the status page, so the three cannot disagree about what a
/// member owes. The token is in it only while the account is unpaid: a credit
/// sets `paid_until` and the token goes back to being a secret.
#[derive(Clone)]
pub struct PaymentView {
    /// The account's state, which is the drain's word and not this page's.
    pub state: String,
    pub rail: String,
    /// The amount owed for the year, in pounds. While the account is unpaid and
    /// a balance is held, this is what remains rather than the full price.
    pub amount: String,
    /// Money received towards the year but not yet applied, in pounds.
    pub balance: Option<String>,
    /// The token in full, while the account is unpaid.
    pub token: Option<String>,
    /// The date a credit set. Present instead of the token once money arrived.
    pub paid_until: Option<String>,
    /// The date the window closed with nothing recorded, while the account is
    /// lapsed. Present instead of the window countdown.
    pub lapsed: Option<String>,
    /// What still works and what stopped once the account has lapsed, in the
    /// lapse notice's words.
    pub lapsed_note: Option<String>,
    /// The window's close date and the days left, while one runs.
    pub window: Option<String>,
    /// The rail's own instructions, one line each.
    pub instructions: Vec<String>,
    /// What happens if nothing arrives before the window closes.
    pub deadline: Option<String>,
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
        "accept_terms" | "accept_supply" => Section::Acceptance,
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

/// The quota the platform publishes, as the page shows it: 5 GB soft and 5.5 GB
/// hard, across mail, the site and the repositories together.
pub const QUOTA_SOFT: &str = "5 GB";
pub const QUOTA_HARD: &str = "5.5 GB";

/// The signed-in member's page, built from the account record the drain wrote
/// and the notices it recorded. `group` is the group the mailbox belongs to,
/// read from the group's own record rather than copied per account, and `dns`
/// is that group's recipe.
pub fn member_page(
    list: &[Service],
    account: &crate::store::Account,
    notices: &[crate::store::Notice],
    group: Option<GroupView>,
    dns: Option<crate::dns::Recipe>,
    payment: Option<PaymentView>,
) -> AccountPage {
    AccountPage {
        services: services(list, Some(&account.username)),
        username: account.username.clone(),
        outside_address: account.outside_address.clone(),
        space_used: account.space_used.map(space),
        space_soft: QUOTA_SOFT,
        space_hard: QUOTA_HARD,
        upload_keys: account
            .upload_keys
            .iter()
            .map(|key| UploadKeyView {
                fingerprint: key.fingerprint.clone(),
                added_at: key.added_at.get(..10).unwrap_or(&key.added_at).to_string(),
            })
            .collect(),
        notices: notices
            .iter()
            .map(|notice| NoticeView {
                at: notice.at.get(..10).unwrap_or(&notice.at).to_string(),
                subject: notice.subject.clone(),
                to: notice.to.clone(),
            })
            .collect(),
        group,
        suspended: account
            .suspension_reason
            .clone()
            .filter(|_| account.state == "suspended"),
        closing_until: account.closing_until.clone(),
        can_close: true,
        dns,
        payment,
        free: account.is_free(),
    }
}

/// The space used under the allowance, in the units the quota is set in. Binary
/// multiples, because 5 GB here is five gibibytes.
fn space(bytes: u64) -> String {
    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    if bytes >= GIB {
        format!("{:.1} GB", bytes as f64 / GIB as f64)
    } else {
        format!("{} MB", bytes / MIB)
    }
}

/// The payment block for one account. Its three states are the spec's: a window
/// still running names the rail, the days left, the close date, the amount, the
/// token and the rail's instructions; a window that closed with nothing
/// recorded reads `Lapsed`, repeats the close date, states what still works and
/// what stopped, and shows the token again; a credit sets `paid_until` and the
/// date replaces the token. A free account has no block at all, which is why
/// the caller passes one only when the record carries a `Payment`.
pub fn payment(
    state: &str,
    rail: &str,
    payment: &crate::store::Payment,
    price_gbp: &str,
    postal_address: &str,
    card_link: Option<&str>,
    now: OffsetDateTime,
) -> PaymentView {
    let unpaid = payment.paid_until.is_none();
    let window = payment.window.as_ref().filter(|_| unpaid);
    let closes_on = window.map(|w| w.closes_at.get(..10).unwrap_or(&w.closes_at).to_string());
    // A window whose state is still `open` after its close date has not been
    // swept yet, and the member reads the same `Lapsed` the sweep will write:
    // the date, not the sweep's own progress, is what the page is about.
    let running = window.is_some_and(|w| {
        w.state == "open" && crate::util::days_left(&w.closes_at, now).is_some_and(|days| days > 0)
    });
    let window_line = if running {
        closes_on.as_ref().map(|date| {
            let days = window
                .and_then(|w| crate::util::days_left(&w.closes_at, now))
                .unwrap_or(0)
                .max(0);
            format!("closes on {date}: {days} days left")
        })
    } else {
        None
    };
    // A held balance re-quotes the remainder: the member has already sent part
    // of the price, so the page asks for what is still owed and never less than
    // nothing.
    let amount = if unpaid {
        match (
            crate::util::pence(price_gbp),
            payment.balance_gbp.as_deref(),
        ) {
            (Ok(price), Some(balance)) => match crate::util::pence(balance) {
                Ok(balance) => crate::util::gbp((price - balance).max(0)),
                Err(_) => price_gbp.to_string(),
            },
            _ => price_gbp.to_string(),
        }
    } else {
        price_gbp.to_string()
    };
    // A window that is closed, or open past its date and not yet swept, is the
    // lapse; a credit leaves the window paid and the date is what the page
    // shows instead.
    let lapsed = if unpaid && !running {
        closes_on.clone()
    } else {
        None
    };
    let lapsed_closed = lapsed.is_some();
    let deadline = window_line.as_ref().map(|_| {
        format!(
            "The money must arrive before {}, or the account lapses: mail keeps \
             arriving and everything published stays up, and sending, uploading and \
             pushing stop. Nothing is deleted at that point.",
            closes_on.as_deref().unwrap_or("the close date")
        )
    });
    // A running window carries the rail's instructions. A lapsed one shows the
    // token again but no instructions: the window it would have paid is gone.
    let instructions = if running {
        crate::transitions::rail_instructions(
            rail,
            postal_address,
            card_link,
            payment.monero.as_ref(),
            &amount,
        )
    } else {
        Vec::new()
    };
    PaymentView {
        state: if lapsed_closed {
            "lapsed".to_string()
        } else {
            state.to_string()
        },
        rail: rail.to_string(),
        amount,
        balance: payment.balance_gbp.clone(),
        token: if unpaid {
            payment.token_ref.clone()
        } else {
            None
        },
        paid_until: payment.paid_until.clone(),
        lapsed_note: lapsed.as_ref().map(|_| LAPSE_NOTE.to_string()),
        lapsed,
        window: window_line,
        instructions,
        deadline,
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

    /// A member's record, in the shape the store holds one: enough for the
    /// renderer to read the username and the free flag, with everything else
    /// absent. The page's own facts are the account's, so a test builds the
    /// record rather than a page-only shape.
    fn member(username: &str, free: bool) -> crate::store::Account {
        serde_json::from_value(serde_json::json!({
            "version": 1, "username": username, "state": "active",
            "decision": "approve", "decided_at": "2026-10-01T09:00:00Z",
            "rail": if free { "no_charge" } else { "cash" },
            "no_charge": free, "created_at": "2026-10-01T09:00:00Z"
        }))
        .expect("a record the store could hold")
    }

    #[test]
    fn the_status_page_links_the_password_page() {
        // The link is what a member clicks to set the only password they will
        // ever have. Rendered as text it cannot be clicked, which is how it
        // reached the first real member.
        let page = StatusPage {
            stage: "approved: an account was made".into(),
            filed_at: "2026-10-22T10:53:46Z".into(),
            notice: String::new(),
            password_link: Some(
                "https://signup.kyriakon.net/password/x?until=2026-10-29&sig=abc".into(),
            ),
            payment: None,
        };
        let html = page.render().expect("the page renders");
        assert!(
            html.contains(
                "<a href=\"https://signup.kyriakon.net/password/x?until=2026-10-29&#38;sig=abc\">Set your mail password</a>"
            ),
            "{html}"
        );
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
            q(
                "accept_supply",
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
        assert_eq!(ids(&p.acceptance), ["accept_terms", "accept_supply"]);
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

        let listed = member_page(&catalogue(), &member("alice", false), &[], None, None, None)
            .render()
            .unwrap();
        assert!(listed.contains("zero-access mail"), "{listed}");
        assert!(listed.contains("https://mail.example.invalid/"), "{listed}");

        // The row's host is the pattern itself when no member is given; the
        // page is never rendered for an applicant, so this is the row's own
        // behaviour rather than a second page constructor.
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
        assert_eq!(
            services(&pattern, None)[0].href,
            "https://<name>.example.invalid/"
        );
        assert_eq!(
            services(&pattern, Some("theophilus"))[0].href,
            "https://theophilus.example.invalid/"
        );
    }

    /// A group's recipe is on the page, from the same generator the approval
    /// email uses, and an account with no group carries none.
    #[test]
    fn the_account_page_renders_a_groups_recipe_and_nothing_for_a_person() {
        let values = crate::dns::Values {
            mail_host: "mail.kyriakon.net".into(),
            ipv4: "192.0.2.10".into(),
            ipv6: "2001:db8::10".into(),
            dkim_selector: "mail".into(),
            dkim_public_key: "v=DKIM1; k=rsa; p=example".into(),
            dmarc_rua: "mailto:dmarc@kyriakon.net".into(),
        };
        let recipe = crate::dns::recipe("parish.example", &values);
        let html = member_page(
            &catalogue(),
            &member("parish-secretary", false),
            &[],
            None,
            Some(recipe),
            None,
        )
        .render()
        .unwrap();
        assert!(html.contains("DNS records"), "{html}");
        assert!(html.contains("10 mail.kyriakon.net."), "{html}");
        assert!(html.contains("192.0.2.10"), "{html}");
        assert!(html.contains("2001:db8::10"), "{html}");
        assert!(html.contains("v=spf1 mx ip6:2001:db8::10 -all"), "{html}");
        assert!(html.contains("mail._domainkey"), "{html}");
        assert!(html.contains("v=DMARC1; p=none"), "{html}");
        assert!(html.contains("does not host your zone"), "{html}");
        assert!(html.contains("cannot set a reverse DNS record"), "{html}");

        let none = member_page(&catalogue(), &member("alice", false), &[], None, None, None)
            .render()
            .unwrap();
        assert!(!none.contains("DNS records"), "{none}");
    }

    /// One payment block, across each of its three states. The running window
    /// names the token and the whole rail's instructions; the lapsed one repeats
    /// the close date, says what still works and what stopped, and shows the
    /// token again; the paid one shows the date and no token.
    #[test]
    fn the_payment_block_reads_running_lapsed_and_paid() {
        use crate::store::{Payment, Window};
        let now = OffsetDateTime::parse(
            "2026-10-31T09:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let mut block = Payment {
            token_ref: Some("KYR-4F2M-9QH7-XT3B".into()),
            window: Some(Window {
                opened_at: "2026-10-20T09:00:00Z".into(),
                closes_at: "2026-11-03T09:00:00Z".into(),
                state: "open".into(),
                extensions: 0,
            }),
            ..Payment::default()
        };
        let view = payment(
            "active",
            "cash",
            &block,
            "20.00",
            "1 Example Street",
            None,
            now,
        );
        assert!(view.lapsed.is_none());
        assert_eq!(view.token.as_deref(), Some("KYR-4F2M-9QH7-XT3B"));
        assert!(view
            .window
            .as_deref()
            .unwrap()
            .contains("closes on 2026-11-03"));
        assert!(!view.instructions.is_empty());
        let html = member_page(
            &catalogue(),
            &member("alice", false),
            &[],
            None,
            None,
            Some(view),
        )
        .render()
        .unwrap();
        assert!(html.contains("KYR-4F2M-9QH7-XT3B"), "{html}");
        assert!(html.contains("1 Example Street"), "{html}");

        // The same window, a day after it closed: the sweep may not have run,
        // and the page still reads Lapsed.
        block.window.as_mut().unwrap().state = "closed".into();
        let lapsed = payment(
            "lapsed",
            "cash",
            &block,
            "20.00",
            "1 Example Street",
            None,
            now + time::Duration::days(10),
        );
        assert_eq!(lapsed.lapsed.as_deref(), Some("2026-11-03"));
        assert_eq!(lapsed.token.as_deref(), Some("KYR-4F2M-9QH7-XT3B"));
        assert!(lapsed.instructions.is_empty());
        let html = member_page(
            &catalogue(),
            &member("alice", false),
            &[],
            None,
            None,
            Some(lapsed),
        )
        .render()
        .unwrap();
        assert!(html.contains("Lapsed"), "{html}");
        assert!(html.contains("closed on 2026-11-03"), "{html}");
        assert!(html.contains("admin@kyriakon.net"), "{html}");

        // A credit sets the date, which replaces the token.
        block.paid_until = Some("2027-10-04".into());
        let paid = payment(
            "active",
            "cash",
            &block,
            "20.00",
            "1 Example Street",
            None,
            now,
        );
        assert!(paid.lapsed.is_none());
        assert_eq!(paid.token, None);
        assert_eq!(paid.paid_until.as_deref(), Some("2027-10-04"));
        let html = member_page(
            &catalogue(),
            &member("alice", false),
            &[],
            None,
            None,
            Some(paid),
        )
        .render()
        .unwrap();
        assert!(html.contains("Paid until 2027-10-04"), "{html}");
        assert!(!html.contains("KYR-4F2M-9QH7-XT3B"), "{html}");
    }
}
