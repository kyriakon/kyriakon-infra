//! The shared service catalogue: `openbsd/etc/onboard/catalogue.toml`, installed
//! to `/var/db/onboard/catalogue.toml`. One `[[service]]` table per entry, in
//! display order, which is the order every front-end renders.
//!
//! The file is the only place the list exists. This module parses it, holds the
//! word for each state and each action and the sentence that hands a job a
//! protocol cannot finish to one that can, and builds the row a front-end shows.
//! It does not restate an entry: an id the file does not carry is an entry no
//! front-end may show.
//!
//! The check the spec asks for lives here too, because it is the join between
//! the file and the renderings rather than something either side owns: the
//! renderers are pure functions of a parsed catalogue, so comparing the rows
//! they return against the file they were rendered from is what catches a
//! front-end that drops an entry or carries a list of its own.

use serde::Deserialize;

use crate::{capsule, page, portal};

/// The tracked file, named in the refusals so a failing check says which file to
/// look at rather than which function returned.
pub const TRACKED: &str = "openbsd/etc/onboard/catalogue.toml";

/// What state a service is in. The three tokens are the file's and the spec's;
/// a fourth is a value this crate has no word for, refused by name rather than
/// rendered as a blank.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Live,
    ByRequest,
    Planned,
}

impl State {
    fn parse(token: &str) -> Result<State, String> {
        match token {
            "live" => Ok(State::Live),
            "by_request" => Ok(State::ByRequest),
            "planned" => Ok(State::Planned),
            other => Err(format!("unknown state {other:?}")),
        }
    }

    /// The word a reader sees for this state. One table rather than one per
    /// front-end: the web card shows it as a tag, the terminal beside the name,
    /// and neither may invent a fourth.
    pub fn word(self) -> &'static str {
        match self {
            State::Live => "live",
            State::ByRequest => "by request",
            State::Planned => "planned",
        }
    }
}

/// What pressing an entry does, which is also the job it starts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Read,
    Apply,
    Account,
    Pay,
}

impl Action {
    fn parse(token: &str) -> Result<Action, String> {
        match token {
            "read" => Ok(Action::Read),
            "apply" => Ok(Action::Apply),
            "account" => Ok(Action::Account),
            "pay" => Ok(Action::Pay),
            other => Err(format!("unknown action {other:?}")),
        }
    }

    /// The word a reader sees for this action: what following the entry does.
    pub fn word(self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Apply => "apply",
            Action::Account => "your account",
            Action::Pay => "pay",
        }
    }
}

/// A job a protocol cannot finish, so a front-end hands the reader to one that
/// can rather than dead-ending. The spec's table has one row per job per
/// protocol; the sentences here are the ones the capsule's side of it gives,
/// because the capsule is the front-end that cannot take a card.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Job {
    CardPayment,
    PrepaidPayment,
    IllustratedDocument,
    OversizeKey,
    AccountChange,
    Export,
}

impl Job {
    /// The sentence that hands this job elsewhere, as a link the client can open
    /// rather than an address the reader transcribes.
    pub fn handoff(self) -> &'static str {
        match self {
            Job::CardPayment => {
                "Paying by card needs a browser, so this link opens the payment page over https."
            }
            Job::PrepaidPayment => {
                "The rail's own instructions are over https; the token and the address are here."
            }
            Job::IllustratedDocument => {
                "A document with images is read over https; the gemtext mirror is here."
            }
            Job::OversizeKey => {
                "A key too large to paste goes by Titan, or by mail to apply@kyriakon.net with the token as the subject."
            }
            Job::AccountChange => {
                "A gemini session cannot change an account yet: use the web page or the terminal."
            }
            Job::Export => "The data export is collected from the web page or the terminal.",
        }
    }
}

/// The protocol a front-end speaks. It decides the scheme an entry's host is
/// reached over, and whether the front-end can finish the job the entry starts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    Web,
    Gemini,
    /// The terminal. It opens nothing itself, so an entry's address is one the
    /// reader's own client opens, over the scheme a client of theirs reaches.
    Terminal,
}

impl Protocol {
    fn scheme(self) -> &'static str {
        match self {
            Protocol::Web => "https",
            Protocol::Gemini => "gemini",
            Protocol::Terminal => "https",
        }
    }

    /// Whether this front-end can finish the job an action starts. The web form
    /// finishes all four in place; the capsule cannot take a card and the terminal
    /// has no browser in the session to take one in, so `pay` is the one both hand
    /// off. That is the spec's rule, not a fifth action value.
    pub fn can_finish(self, action: Action) -> bool {
        !(matches!(self, Protocol::Gemini | Protocol::Terminal) && action == Action::Pay)
    }
}

/// One `[[service]]`, as the file writes it.
#[derive(Clone, Debug)]
pub struct Service {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub state: State,
    pub host: String,
    pub action: Action,
}

/// One entry as a front-end shows it: the row the check compares, and the row
/// the template or the gemtext writer formats. Compared as rows rather than as
/// strings, because the formatting is the front-end's own and a rendering that
/// came from somewhere else cannot produce a row the file does not have.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Row {
    pub id: String,
    pub name: String,
    pub summary: String,
    /// The entry's host under this front-end's own scheme, with `<name>`
    /// rendered from the session's member where there is one, and as the pattern
    /// itself where there is not. Where the front-end cannot finish the job, the
    /// scheme is the one that can, so the client opens it.
    pub href: String,
    /// The state's word and the action's word, from the one table.
    pub state: &'static str,
    pub action: &'static str,
    /// The sentence that hands this entry's job to a protocol that can finish
    /// it, where this front-end's own cannot. Only the capsule's `pay` entry
    /// reaches one today.
    pub handoff: Option<&'static str>,
}

/// The file, as serde reads it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    service: Vec<Entry>,
}

/// One `[[service]]`, before its tokens are checked against their vocabularies.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    name: String,
    summary: String,
    state: String,
    host: String,
    action: String,
}

/// Parse the file. An entry that is malformed, or that names a state or an
/// action outside its vocabulary, is refused by name rather than skipped: an
/// entry that disappears silently is a service no front-end mentions, and a
/// value with no word is one a front-end would render blank.
pub fn parse(text: &str) -> Result<Vec<Service>, String> {
    let file: File = toml::from_str(text).map_err(|e| format!("the catalogue: {e}"))?;

    let mut out = Vec::with_capacity(file.service.len());
    for e in file.service {
        let id = e.id;
        if id.is_empty() || e.name.is_empty() || e.summary.is_empty() || e.host.is_empty() {
            return Err(format!(
                "the service {id:?} has an empty id, name, summary or host"
            ));
        }
        let state = State::parse(&e.state).map_err(|why| format!("the service {id:?}: {why}"))?;
        let action =
            Action::parse(&e.action).map_err(|why| format!("the service {id:?}: {why}"))?;
        out.push(Service {
            id,
            name: e.name,
            summary: e.summary,
            state,
            host: e.host,
            action,
        });
    }
    Ok(out)
}

/// Build one entry's row for a front-end. `member` is the session's member where
/// there is one, which is what a host carrying `<name>` is rendered from.
pub fn row(s: &Service, protocol: Protocol, member: Option<&str>) -> Row {
    let host = match member {
        Some(name) => s.host.replace("<name>", name),
        None => s.host.clone(),
    };
    let finished = protocol.can_finish(s.action);
    // A `pay` entry starts the card job, which is what the capsule hands off.
    let handoff = if finished {
        None
    } else {
        Some(Job::CardPayment.handoff())
    };
    Row {
        id: s.id.clone(),
        name: s.name.clone(),
        summary: s.summary.clone(),
        href: format!(
            "{}://{host}/",
            if finished { protocol.scheme() } else { "https" }
        ),
        state: s.state.word(),
        action: s.action.word(),
        handoff,
    }
}

/// Every rendering that exists, as the rows it shows: the application page's
/// cards, the account page's list, the capsule's gemtext lines and the terminal's
/// menu. The check covers all four, which is what keeps a front-end that drops an
/// entry, or invents one, from reaching a reader.
pub fn renderings(list: &[Service], member: Option<&str>) -> Vec<(&'static str, Vec<Row>)> {
    vec![
        ("the application page", page::services(list, member)),
        ("the account page", page::services(list, member)),
        ("the capsule", capsule::entries(list, member)),
        ("the terminal menu", portal::entries(list, member)),
    ]
}

/// The check the spec asks for, on the file's own text: every entry the file
/// carries appears in every rendering that exists, compared as rows, and no
/// rendering shows one the file does not.
///
/// A state or an action with no word fails here rather than in a rendering,
/// because `parse` refuses a token outside the vocabulary the crate holds: the
/// file cannot name a value, and a state, that no front-end can say.
pub fn check(text: &str, member: Option<&str>) -> Result<(), String> {
    let list = parse(text)?;
    if list.is_empty() {
        return Err(format!("{TRACKED} has no services"));
    }
    compare(&list, &renderings(&list, member))
}

/// Compare what each front-end shows against the file it was rendered from.
///
/// This is the arm that catches a renderer carrying its own list: rendered from
/// a fixture, a renderer that ignores its input returns the shipped file's rows
/// and is refused here, which is the failure the id-by-id comparison alone
/// cannot see.
pub fn compare(list: &[Service], rendered: &[(&str, Vec<Row>)]) -> Result<(), String> {
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
            return Err(format!(
                "{front_end} shows {} entries where {TRACKED} carries {}: missing {missing:?}, invented {invented:?}",
                rows.len(),
                list.len()
            ));
        }
        for (s, r) in list.iter().zip(rows) {
            if r.id != s.id {
                return Err(format!(
                    "{front_end} shows {:?} where {TRACKED} has {:?}: the file's order is the display order",
                    r.id, s.id
                ));
            }
            if r.name != s.name
                || r.summary != s.summary
                || r.state != s.state.word()
                || r.action != s.action.word()
            {
                return Err(format!(
                    "{front_end} shows {:?} other than as {TRACKED} has it, so the rendering is not the file",
                    s.id
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tracked file, read at compile time, so a malformed commit of the data
    /// file fails the build rather than a deployment.
    const SHIPPED: &str = include_str!("../../openbsd/etc/onboard/catalogue.toml");

    /// A catalogue that differs from the shipped file in every column the
    /// renderings carry: different ids, names, summaries, states, hosts and
    /// actions, so a renderer reading anything but its argument shows none of
    /// it.
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

    #[test]
    fn the_shipped_catalogue_parses_in_display_order() {
        let list = parse(SHIPPED).unwrap();
        let ids: Vec<&str> = list.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "mail",
                "web",
                "gemini",
                "git",
                "account",
                "pay",
                "free",
                "own_domain",
                "managed",
                "key",
                "capsule_signup",
                "terminal",
                "press",
                "shop",
                "kleio",
            ]
        );

        // The shop is the bookshop row from the spec: decided, not built.
        let shop = list.iter().find(|s| s.id == "shop").unwrap();
        assert_eq!(shop.state, State::Planned);
        assert_eq!(shop.host, "press.kyriakon.net");

        // Every state and every action the file uses has a word, and the three
        // states and four actions are the whole vocabulary.
        for s in &list {
            assert!(!s.state.word().is_empty(), "{}", s.id);
            assert!(!s.action.word().is_empty(), "{}", s.id);
        }
        for state in [State::Live, State::ByRequest, State::Planned] {
            assert!(!state.word().is_empty());
        }
        for action in [Action::Read, Action::Apply, Action::Account, Action::Pay] {
            assert!(!action.word().is_empty());
        }
    }

    #[test]
    fn a_value_outside_the_vocabulary_is_refused_by_name() {
        let unknown_state = SHIPPED.replace("state = \"live\"", "state = \"retired\"");
        let e = parse(&unknown_state).unwrap_err();
        assert!(e.contains("mail"), "{e}");
        assert!(e.contains("retired"), "{e}");

        let unknown_action = SHIPPED.replace("action = \"read\"", "action = \"download\"");
        let e = parse(&unknown_action).unwrap_err();
        assert!(e.contains("mail"), "{e}");
        assert!(e.contains("download"), "{e}");

        // A column of the wrong type, a column that is not one, and an entry
        // with nothing in a column are all build errors rather than a blank card.
        assert!(parse(&SHIPPED.replace("host = \"mail.kyriakon.net\"", "host = 7")).is_err());
        assert!(parse(&SHIPPED.replace("summary =", "summery =")).is_err());
        assert!(parse(&SHIPPED.replace("name = \"Mail\"", "name = \"\"")).is_err());
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
        assert!(e.contains("the account page"), "{e}");
        assert!(e.contains("shop"), "{e}");
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
        assert!(e.contains("the capsule"), "{e}");
        assert!(e.contains("newsletter"), "{e}");
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
        assert!(e.contains("orchard"), "{e}");

        // And a value the crate has no word for fails the check on the text,
        // before any rendering is built.
        let soon = FIXTURE.replace("state = \"planned\"", "state = \"soon\"");
        let e = check(&soon, None).unwrap_err();
        assert!(e.contains("soon"), "{e}");
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

    /// The terminal's menu is one of the renderings the check compares, so a menu
    /// that dropped an entry, or carried a list of its own, fails here rather than
    /// at a reader.
    #[test]
    fn the_check_covers_the_terminals_menu() {
        let list = parse(SHIPPED).unwrap();
        let rendered = renderings(&list, None);
        let menu = rendered
            .iter()
            .find(|(front_end, _)| *front_end == "the terminal menu")
            .expect("the check compares the terminal's menu");
        assert_eq!(menu.1, portal::entries(&list, None));

        // And a menu that dropped an entry is caught by name, like any other.
        let mut rows = rendered;
        let at = rows
            .iter()
            .position(|(front_end, _)| *front_end == "the terminal menu")
            .unwrap();
        rows[at].1.retain(|r| r.id != "shop");
        let e = compare(&list, &rows).unwrap_err();
        assert!(e.contains("the terminal menu"), "{e}");
        assert!(e.contains("shop"), "{e}");
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
}
