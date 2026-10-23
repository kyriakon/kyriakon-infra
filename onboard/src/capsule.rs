//! The capsule's rendering of the shared catalogue.
//!
//! The capsule front-end itself is a later ticket: this is the one page it
//! renders from the catalogue file today, which is the page its spec fixes, one
//! line per entry with the name and the clause in the link label.

use crate::catalogue::{self, Protocol, Row, Service};
use crate::page::StatusPage;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::StatusPage;

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

    #[test]
    fn the_capsule_status_page_links_the_password_page() {
        let page = StatusPage {
            stage: "approved: an account was made".into(),
            filed_at: "2026-10-22T10:53:46Z".into(),
            notice: String::new(),
            password_link: Some(
                "https://signup.kyriakon.net/password/x?until=2026-10-29&sig=abc".into(),
            ),
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
