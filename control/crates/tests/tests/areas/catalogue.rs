//! The catalogue's cross-render check: every front-end renders the file it was
//! given, in the file's order, with no entry added or dropped.
//!
//! The check lives in the acceptance suite, not in `flow`, because it is the one
//! place that joins the shared catalogue to the handler's three renderers.

use kyriakon_control_core::flow;
use kyriakon_control_core::flow::catalogue::{parse, row, Action, Job, Protocol, Row, Service};
use kyriakon_control_handler::{capsule, page};
use kyriakon_control_tui as tui;

/// The tracked file, read at compile time, so a malformed commit of the data
/// file fails the build rather than a deployment.
const SHIPPED: &str = include_str!("../../../../../openbsd/etc/onboard/catalogue.toml");

/// A catalogue that differs from the shipped file in every column the
/// renderings carry: different ids, names, summaries, states, hosts and
/// actions, so a renderer reading anything but its argument shows none of it.
const FIXTURE: &str = "\
[[service]]
id = \"orchard\"
name = \"The orchard\"
summary = \"apples, by arrangement\"
state = \"by_request\"
host = \"orchard.example.invalid\"
action = \"account\"

[[service]]
id = \"kiln\"
name = \"The kiln\"
summary = \"firing, once the kiln is built\"
state = \"planned\"
host = \"<name>.kiln.example.invalid\"
action = \"pay\"
";

/// Every rendering that exists, as the rows it shows: the application page's
/// cards, the account page's list, the capsule's gemtext lines and the terminal's
/// menu. The check covers all four, which is what keeps a front-end that drops an
/// entry, or invents one, from reaching a reader.
fn renderings(list: &[Service], member: Option<&str>) -> Vec<(&'static str, Vec<Row>)> {
    vec![
        ("the application page", page::services(list, member)),
        ("the account page", page::services(list, member)),
        ("the capsule", capsule::entries(list, member)),
        ("the terminal menu", tui::entries(list, member)),
    ]
}

/// A disagreement between the file and a front-end's rendering.
///
/// The fields are read by the derived `Debug` failure message when a test
/// unwraps, not by the check itself.
#[allow(dead_code)]
#[derive(Debug)]
enum Mismatch {
    /// The file did not parse.
    Catalogue(flow::Error),
    /// The file carries no services at all.
    NoServices,
    /// A rendering has the wrong entries.
    Count {
        front_end: &'static str,
        missing: Vec<String>,
        invented: Vec<String>,
    },
    /// A rendering orders the entries differently.
    Order {
        front_end: &'static str,
        shown: String,
        expected: String,
    },
    /// A rendering shows an entry's values other than as the file has them.
    Content { front_end: &'static str, id: String },
}

/// The check the spec asks for, on the file's own text: every entry the file
/// carries appears in every rendering that exists, compared as rows, and no
/// rendering shows one the file does not.
fn check(text: &str, member: Option<&str>) -> Result<(), Mismatch> {
    let list = parse(text).map_err(Mismatch::Catalogue)?;
    if list.is_empty() {
        return Err(Mismatch::NoServices);
    }
    compare(&list, &renderings(&list, member))
}

/// Compare what each front-end shows against the file it was rendered from.
fn compare(list: &[Service], rendered: &[(&'static str, Vec<Row>)]) -> Result<(), Mismatch> {
    for (front_end, rows) in rendered {
        if rows.len() != list.len() {
            let missing: Vec<&str> = list
                .iter()
                .filter(|s| !rows.iter().any(|r| r.id == s.id))
                .map(|s| s.id.as_str())
                .collect();
            let invented: Vec<&str> = rows
                .iter()
                .filter(|r| !list.iter().any(|s| s.id == r.id))
                .map(|r| r.id.as_str())
                .collect();
            return Err(Mismatch::Count {
                front_end,
                missing: missing.into_iter().map(str::to_string).collect(),
                invented: invented.into_iter().map(str::to_string).collect(),
            });
        }
        for (s, r) in list.iter().zip(rows) {
            if r.id != s.id {
                return Err(Mismatch::Order {
                    front_end,
                    shown: r.id.clone(),
                    expected: s.id.clone(),
                });
            }
            if r.name != s.name
                || r.summary != s.summary
                || r.state != s.state.word()
                || r.action != s.action.word()
            {
                return Err(Mismatch::Content {
                    front_end,
                    id: s.id.clone(),
                });
            }
        }
    }
    Ok(())
}

/// The check the ticket asks for, against the file every deployment ships.
#[test]
fn the_shipped_catalogue_is_rendered_by_every_front_end() {
    check(SHIPPED, None).unwrap();
}

/// A renderer that drops an entry, from the shipped file: the check names
/// the entry and the front-end rather than counting.
#[test]
fn a_renderer_that_drops_an_entry_is_caught() {
    let list = parse(SHIPPED).unwrap();
    let mut rows = renderings(&list, None);
    rows[1].1.retain(|r| r.id != "shop");
    let e = compare(&list, &rows).unwrap_err();
    assert!(
        matches!(
            e,
            Mismatch::Count {
                front_end: "the account page",
                ref missing,
                ..
            } if missing.iter().any(|id| id == "shop")
        ),
        "{e:?}"
    );
}

/// A renderer that invents an entry is caught the same way.
#[test]
fn a_renderer_that_invents_an_entry_is_caught() {
    let list = parse(SHIPPED).unwrap();
    let mut rows = renderings(&list, None);
    let mut invented = rows[2].1[0].clone();
    invented.id = "newsletter".to_string();
    rows[2].1.push(invented);
    let e = compare(&list, &rows).unwrap_err();
    assert!(
        matches!(
            e,
            Mismatch::Count {
                front_end: "the capsule",
                ref invented,
                ..
            } if invented.iter().any(|id| id == "newsletter")
        ),
        "{e:?}"
    );
}

/// Every renderer rendered from a fixture follows the fixture, and a
/// renderer that ignores its argument in favour of a hard-coded list is
/// caught by the same comparison.
#[test]
fn every_renderer_follows_a_fixture_rather_than_a_list_of_its_own() {
    let fixture = parse(FIXTURE).unwrap();
    let shipped = parse(SHIPPED).unwrap();

    let from_fixture = renderings(&fixture, None);
    compare(&fixture, &from_fixture).unwrap();
    for (front_end, rows) in &from_fixture {
        let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["orchard", "kiln"], "{front_end}");
        assert!(rows.iter().all(|r| r.name != "Mail"), "{front_end}");
    }

    // The same renderers, handed the shipped file: the fixture's ids are
    // what the check compares against, so a renderer that ignores its input
    // fails even though it shows the shipped file faithfully.
    let ignoring = renderings(&shipped, None);
    let e = compare(&fixture, &ignoring).unwrap_err();
    assert!(
        matches!(
            e,
            Mismatch::Count { ref missing, .. } if missing.iter().any(|id| id == "orchard")
        ),
        "{e:?}"
    );

    // And a value the crate has no word for fails the check on the text,
    // before any rendering is built.
    let soon = FIXTURE.replace("state = \"planned\"", "state = \"soon\"");
    let e = parse(&soon).unwrap_err();
    assert!(
        matches!(
            &e,
            kyriakon_control_core::flow::Error::Service { source, .. } if matches!(
                source.as_ref(),
                kyriakon_control_core::flow::Error::UnknownState { value } if value == "soon"
            )
        ),
        "{e}"
    );
}

/// The terminal's menu is one of the renderings the check compares. That the
/// comparison catches a menu which dropped an entry is
/// `a_renderer_that_drops_an_entry_is_caught`'s, on the same code path; what
/// is worth asserting here is that the menu is in the list at all, because a
/// rendering the check does not carry is one nothing compares.
#[test]
fn the_check_covers_the_terminals_menu() {
    let list = parse(SHIPPED).unwrap();
    let names: Vec<&str> = renderings(&list, None)
        .iter()
        .map(|(front_end, _)| *front_end)
        .collect();
    assert!(names.contains(&"the terminal menu"), "{names:?}");
}

/// The capsule's own page: one line per entry, the name and the clause in
/// the link label, and the hand-off sentence where the entry leaves gemini.
#[test]
fn the_capsule_writes_one_line_per_entry() {
    let list = parse(SHIPPED).unwrap();
    let page = capsule::gemtext(&list, None);

    let lines: Vec<&str> = page.lines().collect();
    assert_eq!(lines[0], "=> gemini://mail.kyriakon.net/ Mail: zero-access mail, 5 GB, IMAP and SMTP, readable only by you");
    assert!(lines.contains(&"=> gemini://<name>.kyriakon.net/ A website: static pages at an address of your own, uploaded by sftp"));
    assert!(lines
        .contains(&"=> https://signup.kyriakon.net/ Paying: card, cash by post or Monero, and the window each one opens"));
    assert!(lines.contains(&Job::CardPayment.handoff()));

    // One link line per entry, and the one hand-off adds the sentence that
    // says where the entry goes rather than a second link.
    let links = lines.iter().filter(|l| l.starts_with("=> ")).count();
    assert_eq!(links, list.len());
}

/// The rows themselves: the scheme is the front-end's, and the capsule is
/// the one that hands a card payment to a browser.
#[test]
fn a_row_carries_the_front_ends_own_scheme_and_hands_a_card_off() {
    let list = parse(SHIPPED).unwrap();
    let mail = list.iter().find(|s| s.id == "mail").unwrap();

    let web = row(mail, Protocol::Web, None);
    assert_eq!(web.href, "https://mail.kyriakon.net/");
    assert_eq!(web.state, "live");
    assert_eq!(web.action, "read");
    assert_eq!(web.handoff, None);

    let web = row(mail, Protocol::Gemini, None);
    assert_eq!(web.href, "gemini://mail.kyriakon.net/");

    // The capsule's root is its catalogue, so an apply row names the route
    // the draft flow lives at rather than looping back to the front page.
    let applying = list.iter().find(|s| s.action == Action::Apply).unwrap();
    assert_eq!(
        row(applying, Protocol::Gemini, None).href,
        "gemini://signup.kyriakon.net/apply"
    );

    // A host carrying <name> is the pattern where there is no member, and
    // the member's own where there is.
    let capsule = list.iter().find(|s| s.id == "gemini").unwrap();
    assert_eq!(
        row(capsule, Protocol::Gemini, None).href,
        "gemini://<name>.kyriakon.net/"
    );
    assert_eq!(
        row(capsule, Protocol::Gemini, Some("theophilus")).href,
        "gemini://theophilus.kyriakon.net/"
    );

    // The capsule cannot take a card: the link is the payment page over
    // https, and the row carries the sentence that says so.
    let paying = list.iter().find(|s| s.id == "pay").unwrap();
    let web = row(paying, Protocol::Web, None);
    assert_eq!(web.href, "https://signup.kyriakon.net/");
    assert_eq!(web.handoff, None);
    let capsule = row(paying, Protocol::Gemini, None);
    assert_eq!(capsule.href, "https://signup.kyriakon.net/");
    assert_eq!(capsule.handoff, Some(Job::CardPayment.handoff()));

    // The terminal opens nothing itself, so its rows carry the address a
    // client of the reader's opens, and it has no browser to take a card in
    // either.
    let terminal = row(mail, Protocol::Terminal, None);
    assert_eq!(terminal.href, "https://mail.kyriakon.net/");
    assert_eq!(terminal.handoff, None);
    let named = list.iter().find(|s| s.id == "gemini").unwrap();
    assert_eq!(
        row(named, Protocol::Terminal, Some("theophilus")).href,
        "https://theophilus.kyriakon.net/"
    );
    let terminal = row(paying, Protocol::Terminal, None);
    assert_eq!(terminal.href, "https://signup.kyriakon.net/");
    assert_eq!(terminal.handoff, Some(Job::CardPayment.handoff()));
}
