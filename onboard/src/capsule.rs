//! The capsule's rendering of the shared catalogue.
//!
//! The capsule front-end itself is a later ticket: this is the one page it
//! renders from the catalogue file today, which is the page its spec fixes, one
//! line per entry with the name and the clause in the link label.

use crate::catalogue::{self, Protocol, Row, Service};

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
