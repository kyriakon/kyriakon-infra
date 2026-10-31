//! The capsule's pages as gemtext: the catalogue and its links, the mirrored
//! documents the deploy stages, the acceptances page, the status page, and the
//! member's reading half.
//!
//! A page is plain text and link lines. A claim that needs its limit stated
//! carries that sentence in the body, because a link label has no room for it.
//! The account page is a read and nothing else; a certificate that matched no
//! pin gets the same page as a stranger, carrying only its own fingerprint.

use crate::catalogue::{self, Protocol, Row, Service};
use crate::page::{PaymentView, StatusPage};
use crate::questions::{Kind, Question};
use crate::responder::HOST;
use crate::store::{Account, Certificate, Notice};

/// The mirrored pages the deploy stages as gemtext, as the route name, the file
/// `scripts/render-docs.sh --gemini` writes, and the link label the front page
/// gives it. One table because the route, the file and the label must name the
/// same page: adding one here is what makes the renderer stage it and the front
/// page link it.
pub const PAGES: &[(&str, &str, &str)] = &[
    ("terms", "terms.gmi", "Terms of service"),
    ("aup", "aup.gmi", "Acceptable use policy"),
    ("privacy", "privacy.gmi", "Privacy notice"),
    ("keys", "key-walkthrough.gmi", "Making a key"),
];

/// The route the acceptances page answers on. It is not a staged file: the page
/// is generated from the question list and the release the handler carries.
pub const ACCEPTANCES: &str = "acceptances";

/// The three documents the one acceptance question covers, in the order the
/// record stores them. One checkbox, three acceptances: each document is
/// accepted in its own name, and the page says so rather than carrying one
/// sentence that names all three and no separate acceptance of each.
pub const ACCEPTED: [(&str, &str); 3] = [
    ("terms", "the terms of service"),
    ("aup", "the acceptable use policy"),
    ("privacy", "the privacy notice"),
];

/// The entries as rows, one per service. Here as well as in the gemtext page so
/// the check can compare what this front-end shows before it is formatted, which
/// is what "compared as rows rather than as strings" means.
pub fn entries(list: &[Service], member: Option<&str>) -> Vec<Row> {
    list.iter()
        .map(|s| catalogue::row(s, Protocol::Gemini, member))
        .collect()
}

/// The catalogue as `text/gemini`: `=> <scheme>://<host>/ <name>: <summary>`,
/// because the link label is the only place a gemtext link carries text, so the
/// name and the clause travel in it.
///
/// An entry whose job the capsule cannot finish links over https and carries the
/// hand-off sentence under it: a gemtext link opens in the reader's browser, and
/// the sentence is the one table's, so the reader learns where they are going
/// rather than being handed an address to transcribe.
pub fn gemtext(list: &[Service], member: Option<&str>) -> String {
    let mut out = String::new();
    for row in entries(list, member) {
        out.push_str(&format!("=> {} {}: {}\n", row.href, row.name, row.summary));
        if let Some(sentence) = row.handoff {
            out.push_str(sentence);
            out.push('\n');
        }
    }
    out
}

/// The capsule's front page: what this is, the catalogue it lists, and the
/// documents and keys it carries. It names the web form as the other way in,
/// because a gemini client cannot open the form, and says where the two pages
/// the capsule does not mirror stay, so a reader is not left thinking the
/// refusal list and the threat model are missing rather than published
/// elsewhere.
pub fn front_page(list: &[Service], member: Option<&str>) -> String {
    let mut out = String::from(
        "# Kyriakon\n\n\
         This capsule is one of the ways in. The web form at https://signup.kyriakon.net/ \
         is the other way in today if you would rather use a browser, and an ssh terminal \
         follows.\n\n\
         The refusal list and the threat model stay published over HTTPS, because they are \
         pages for a browser:\n\n",
    );
    out.push_str(
        "=> https://signup.kyriakon.net/ The web form\n\
         => https://kyriakon.net/ The main site, where both are published\n\n\
         ## What the platform offers\n\n",
    );
    out.push_str(&gemtext(list, member));
    // The catalogue summary claims zero-access, so the limit travels with it
    // here, the way the terms and privacy notice state it: a reader who takes
    // only this page must not read the claim without it.
    out.push_str(
        "\nThat zero-access covers the content of your mail, not the addressing \
         information it needs to move: sender, recipient, timestamp and size \
         appear in the server's logs and in the outer message wrapper.\n",
    );
    out.push_str("\n## The documents and the keys\n\n");
    for (route, _, label) in PAGES {
        out.push_str(&format!("=> gemini://{HOST}/{route} {label}\n"));
    }
    out.push_str(&format!(
        "=> gemini://{HOST}/{ACCEPTANCES} What you accept\n"
    ));
    out
}

/// The acceptances page: the three documents and the release they were
/// generated from. The acceptance wording comes from the question list, so the
/// page and the form ask the same question, and the three documents are listed
/// in the order the application record stores them.
pub fn acceptances(list: &[Question], release: &str) -> String {
    let mut out = String::from("# What you accept\n\n");
    out.push_str(
        "When you apply, you accept three documents on one checkbox. A person reads every \
         application, and the version of each document you accepted is recorded by date and \
         short commit.\n\n",
    );
    for q in list.iter().filter(|q| q.kind == Kind::Acceptance) {
        out.push_str(&q.prompt);
        out.push('\n');
    }
    out.push('\n');
    for (_, label) in ACCEPTED {
        out.push_str(&format!("* I accept {label}.\n"));
    }
    out.push_str(&format!("\nVersion: {release}\n\n"));
    for (route, _) in ACCEPTED {
        let (_, _, label) = PAGES
            .iter()
            .find(|(r, _, _)| *r == route)
            .unwrap_or_else(|| panic!("{route} is accepted but not a staged page"));
        out.push_str(&format!("=> gemini://{HOST}/{route} {label}\n"));
    }
    out
}

/// The status page as `text/gemini`, from the same record the web page renders:
/// the stage a filed application has reached, or the one notice that covers a
/// token that is unknown, expired or spent alike. The two reads are the web
/// page's own words, in a page with no table to put them in and no hint below
/// them, because a hint about links and referrers is chrome the web page carries
/// and the capsule has no need of.
///
/// The stage is the whole of what this page says about a live application: it
/// never repeats an answer, the contact address or a key, and a token that
/// resolves to nothing reads exactly as one that has expired.
pub fn status(page: &StatusPage) -> String {
    let mut out = String::from("# Where your application has got to\n\n");
    if !page.notice.is_empty() {
        out.push_str(&page.notice);
        out.push('\n');
        return out;
    }
    out.push_str(&format!(
        "Received: {}. A person reads every application. Nothing is charged yet.\n",
        page.filed_at
    ));
    out.push_str(&format!("Stage: {}\n", page.stage));
    if let Some(payment) = &page.payment {
        out.push_str("\n## Paying\n\n");
        match (&payment.paid_until, &payment.token) {
            (Some(until), _) => out.push_str(&format!("Paid until {until}.\n")),
            (None, token) => {
                if let Some(token) = token {
                    out.push_str(&format!("Your payment reference is {token}.\n"));
                }
                out.push_str(&format!("Amount: GBP {}.\n", payment.amount));
                if let Some(window) = &payment.window {
                    out.push_str(&format!("The payment window {window}.\n"));
                }
            }
        }
    }
    if let Some(link) = &page.password_link {
        out.push_str("\n## Setting your mail password\n\n");
        // A gemtext link is a `=>` line; a bare URL is text to every client, the
        // same defect the web page had on its other front end.
        out.push_str(&format!("=> {link} Set your mail password\n"));
    }
    out
}

/// The page a completed draft answers with: the status link, so the applicant
/// leaves the flow with the one capability the application is identified by.
pub fn filed(link: &str) -> String {
    format!(
        "# Application filed\n\nKeep this link. It is the only thing that identifies your application:\n\n=> {link} Application status\n"
    )
}

/// The member's reading half: the payment block, the account's state, whether
/// the site and the capsule are served, the space used and the notices sent. It
/// is a read and nothing else, so the page carries no prompt, no form and no
/// link that files anything; changing an account is handed off to the two
/// front-ends that can.
///
/// `payment` is the same block the web page renders, built from the account by
/// one function, so the two cannot disagree about what is owed. It is `None` for
/// a free account, which has no window, no token and no payment block.
///
/// The words for the serving facts are the capsule's own chrome. A fact the
/// drain has not recorded yet reads as that rather than as a false "no".
pub fn account(
    account: &Account,
    notices: &[Notice],
    dns: Option<&crate::dns::Recipe>,
    payment: Option<&PaymentView>,
) -> String {
    let mut out = String::from("# Your account\n\n");
    if account.is_free() {
        out.push_str("This account is free: nothing is due, and it does not lapse.\n\n");
    }
    if let Some(p) = payment {
        out.push_str("## Payment\n\n");
        out.push_str(&format!("Rail: {}.\n", p.rail));
        if let Some(until) = &p.paid_until {
            out.push_str(&format!("Paid until {until}.\n"));
        } else {
            if let Some(window) = &p.window {
                out.push_str(&format!("The payment window {window}.\n"));
            }
            out.push_str(&format!("Amount: GBP {}.\n", p.amount));
            if let Some(token) = &p.token {
                out.push_str(&format!("Your payment reference is {token}.\n"));
            }
            for line in &p.instructions {
                out.push_str(&format!("{line}\n"));
            }
            if let Some(deadline) = &p.deadline {
                out.push_str(&format!("{deadline}\n"));
            }
        }
        out.push('\n');
    }
    out.push_str(&format!("State: {}\n", account.state));
    out.push_str(&format!("Site: {}\n", served(account.site_served)));
    out.push_str(&format!("Capsule: {}\n", served(account.capsule_served)));
    out.push_str(&format!("Space used: {}\n", space(account.space_used)));
    out.push_str(&format!(
        "\nNothing here changes anything. The account page at https://{HOST}/account \
         and the terminal are where settings will change; both are read-only until \
         their own tickets land.\n"
    ));
    out.push_str("\n## Notices\n\n");
    if notices.is_empty() {
        out.push_str("Nothing has been sent yet.\n");
    }
    for notice in notices {
        out.push_str(&format!(
            "{}: {} (to {})\n",
            date(&notice.at),
            notice.subject,
            notice.to
        ));
    }
    if let Some(recipe) = dns {
        out.push_str("\n## Your domain's DNS records\n\n");
        out.push_str(&recipe.text());
    }
    out
}

/// The account page for a visit no pin matched. It says what the page is for
/// and, when the client presented a certificate, how to register it. It never
/// says whether the certificate is known, because a page that said "unknown"
/// would answer the question a stranger is asking one hash at a time.
pub fn account_stranger(certificate: Option<&Certificate>) -> String {
    let mut out = String::from(
        "# Your account\n\n\
         Your account is read here when a client presents a certificate the\n\
         account has pinned, one per device. Nothing is changed from the capsule.\n",
    );
    if let Some(certificate) = certificate.filter(|c| !c.hash.is_empty()) {
        out.push('\n');
        out.push_str(&registration(certificate));
    }
    out
}

/// The line a presented certificate earns: its own fingerprint, so a member can
/// pin the device in their hand without copying anything out of a client's
/// settings, and where registering it happens.
pub fn registration(certificate: &Certificate) -> String {
    format!(
        "This client presented the certificate below. Registering it is not \
         available yet; it will be from https://{HOST}/account or from the terminal.\n\n\
         {}\n",
        short_hash(&certificate.hash)
    )
}

/// The first bytes of a certificate's fingerprint: the algorithm gmid names and
/// the first eight hexadecimal characters of the digest, which is enough to
/// tell two devices apart by eye.
fn short_hash(hash: &str) -> String {
    match hash.split_once(':') {
        Some((algorithm, digest)) => {
            format!("{algorithm}:{}", digest.chars().take(8).collect::<String>())
        }
        None => hash.chars().take(8).collect(),
    }
}

/// Whether a protocol is being served, as the drain recorded it.
fn served(flag: Option<bool>) -> &'static str {
    match flag {
        Some(true) => "serving",
        Some(false) => "not serving",
        None => "not recorded yet",
    }
}

/// The space used under the quota, in the units the platform publishes. Binary
/// multiples, because the quota itself is five gibibytes.
fn space(bytes: Option<u64>) -> String {
    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    match bytes {
        Some(bytes) if bytes >= GIB => format!("{:.1} GB", bytes as f64 / GIB as f64),
        Some(bytes) => format!("{} MB", bytes / MIB),
        None => "not recorded yet".to_string(),
    }
}

/// A notice's date, which is the RFC 3339 timestamp's own date part.
fn date(at: &str) -> &str {
    at.get(..10).unwrap_or(at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::StatusPage;

    #[test]
    fn the_front_page_names_the_web_form_and_the_pages_that_stay_https() {
        let list = catalogue::parse(include_str!("../../openbsd/etc/onboard/catalogue.toml"))
            .expect("the tracked catalogue parses");
        let text = front_page(&list, None);
        assert!(
            text.contains("The web form at https://signup.kyriakon.net/ is the other way in"),
            "{text}"
        );
        assert!(
            text.contains("The refusal list and the threat model stay published over HTTPS"),
            "{text}"
        );
        assert!(
            text.contains("not the addressing information it needs to move"),
            "the front page states the zero-access limit beside the catalogue's claim: {text}"
        );
        for route in ["terms", "aup", "privacy", "keys", ACCEPTANCES] {
            assert!(
                text.contains(&format!("=> gemini://{HOST}/{route} ")),
                "{route} is linked from the front page: {text}"
            );
        }
        assert!(
            text.contains("=> gemini://mail.kyriakon.net/ Mail:"),
            "{text}"
        );
    }

    /// The one table links every staged page and stages every accepted
    /// document, so a page added there cannot ship without a link, and an
    /// acceptance cannot name a page that is not served.
    #[test]
    fn every_staged_page_is_linked_and_every_accepted_document_is_staged() {
        let list = catalogue::parse(include_str!("../../openbsd/etc/onboard/catalogue.toml"))
            .expect("the tracked catalogue parses");
        let front = front_page(&list, None);
        for (route, _, label) in PAGES {
            assert!(
                front.contains(&format!("=> gemini://{HOST}/{route} {label}")),
                "{route} is linked from the front page as {label}: {front}"
            );
        }
        let mine = crate::questions::shipped().expect("the shipped question list parses");
        let accepted = acceptances(&mine, "2026-10-13 test");
        for (route, _) in ACCEPTED {
            assert!(
                PAGES.iter().any(|(r, _, _)| *r == route),
                "{route} is accepted but not a staged page"
            );
            assert!(
                accepted.contains(&format!("=> gemini://{HOST}/{route} ")),
                "{route} is linked from the acceptances page"
            );
        }
    }

    #[test]
    fn the_acceptances_page_carries_three_documents_and_the_release() {
        let list = crate::questions::shipped().expect("the shipped question list parses");
        let text = acceptances(&list, "2026-10-13 test");
        for label in [
            "the terms of service",
            "the acceptable use policy",
            "the privacy notice",
        ] {
            assert!(
                text.contains(&format!("* I accept {label}.")),
                "{label} is accepted in its own name: {text}"
            );
        }
        assert_eq!(text.matches("* I accept ").count(), 3, "{text}");
        assert!(text.contains("Version: 2026-10-13 test"), "{text}");
    }

    /// The mirror may not carry a claim the resistance decision refuses. The
    /// sources are read from the tracked files, so a sentence added to one of
    /// them is caught here rather than only by a reader.
    #[test]
    fn the_mirrored_sources_make_no_refused_claim() {
        let sources = [
            ("terms", include_str!("../../docs/terms.md")),
            ("aup", include_str!("../../docs/aup.md")),
            ("privacy", include_str!("../../docs/privacy.md")),
            (
                "key walkthrough",
                include_str!("../../docs/key-walkthrough.md"),
            ),
        ];
        for (name, text) in sources {
            let lower = text.to_lowercase();
            for claim in [
                "encrypted at rest",
                "end-to-end",
                "forward secrecy",
                "no logs",
                "warrant canary",
            ] {
                assert!(!lower.contains(claim), "{name} claims {claim}");
            }
        }
    }

    /// Where a source claims zero-access mail, it states the metadata limit in
    /// the same document. Every mirrored document is in this list, so the one
    /// mirror CI runs cannot carry the claim alone.
    #[test]
    fn every_zero_access_claim_states_the_metadata_limit() {
        let sources = [
            ("terms", include_str!("../../docs/terms.md")),
            ("aup", include_str!("../../docs/aup.md")),
            ("privacy", include_str!("../../docs/privacy.md")),
            (
                "key walkthrough",
                include_str!("../../docs/key-walkthrough.md"),
            ),
        ];
        for (name, text) in sources {
            let lower = text.to_lowercase();
            if lower.contains("zero-access") {
                assert!(
                    lower.contains("metadata") || lower.contains("addressing information"),
                    "{name} claims zero-access without the metadata limit"
                );
            }
        }
    }

    #[test]
    fn the_capsule_filed_page_links_the_status() {
        let link = "gemini://signup.kyriakon.net/status/abcdefghjkmnpqrstvwxyz0123";
        let text = filed(link);
        assert!(text.contains("# Application filed"), "{text}");
        assert!(
            text.contains(&format!("=> {link} Application status")),
            "{text}"
        );
    }

    fn member() -> Account {
        serde_json::from_str(
            r#"{"version": 1, "username": "alice", "state": "active",
                "decision": "approve", "decided_at": "2026-09-30T09:00:00Z",
                "rail": "no_charge", "no_charge": true,
                "created_at": "2026-09-30T09:00:00Z", "paid_until": null,
                "site_served": true, "capsule_served": false,
                "space_used": 432013312}"#,
        )
        .unwrap()
    }

    #[test]
    fn the_capsule_account_reads_the_four_facts_and_the_notices() {
        let notices: Vec<Notice> = vec![Notice {
            version: 1,
            at: "2026-09-30T09:00:00Z".into(),
            notice_type: "approval.free".into(),
            subject: "Application approved, account opened.".into(),
            to: "alice@kyriakon.net".into(),
        }];
        let text = account(&member(), &notices, None, None);
        assert!(text.contains("State: active"), "{text}");
        assert!(text.contains("Site: serving"), "{text}");
        assert!(text.contains("Capsule: not serving"), "{text}");
        assert!(text.contains("Space used: 412 MB"), "{text}");
        assert!(
            text.contains(
                "2026-09-30: Application approved, account opened. (to alice@kyriakon.net)"
            ),
            "{text}"
        );
        assert!(text.contains("Nothing here changes anything"), "{text}");
    }

    #[test]
    fn an_unrecorded_fact_is_not_a_false_no() {
        let mut record = member();
        record.site_served = None;
        record.space_used = None;
        let text = account(&record, &[], None, None);
        assert!(text.contains("Site: not recorded yet"), "{text}");
        assert!(text.contains("Space used: not recorded yet"), "{text}");
        assert!(text.contains("Nothing has been sent yet."), "{text}");
    }

    #[test]
    fn a_stranger_sees_the_fingerprint_and_never_the_word_unknown() {
        let certificate = Certificate {
            hash: "SHA256:0123456789abcdef".into(),
            ..Certificate::default()
        };
        let text = account_stranger(Some(&certificate));
        assert!(text.contains("SHA256:01234567"), "{text}");
        assert!(
            text.contains("https://signup.kyriakon.net/account"),
            "{text}"
        );
        assert!(text.contains("terminal"), "{text}");
        assert!(!text.to_lowercase().contains("unknown"), "{text}");

        // No certificate is no fingerprint, and the page is still a page.
        let text = account_stranger(None);
        assert!(!text.contains("SHA256:"), "{text}");
    }

    #[test]
    fn the_space_and_the_hash_shorten_for_the_page() {
        assert_eq!(space(Some(1 << 30)), "1.0 GB");
        assert_eq!(space(Some(432013312)), "412 MB");
        assert_eq!(space(None), "not recorded yet");
        assert_eq!(short_hash("SHA256:0123456789abcdef"), "SHA256:01234567");
        assert_eq!(short_hash("0123456789"), "01234567");
    }

    #[test]
    fn the_capsule_status_page_links_the_password_page() {
        let page = StatusPage {
            stage: "approved: an account was made".into(),
            filed_at: "2026-10-22T10:53:46Z".into(),
            notice: String::new(),
            password_link: Some(
                "https://signup.kyriakon.net/password/x?until=2026-10-29&sig=abc".into(),
            ),
            payment: None,
        };
        let text = status(&page);
        assert!(
            text.contains(
                "=> https://signup.kyriakon.net/password/x?until=2026-10-29&sig=abc Set your mail password\n"
            ),
            "{text}"
        );
    }
}
