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
//! The cross-render check lives in the acceptance suite, because it is the join
//! between this file and every front-end's renderer rather than something this
//! module owns.

use serde::Deserialize;

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
    /// The action itself, for a front-end that dispatches on it. The word above
    /// is display text and may change without changing what a row does.
    pub action_kind: Action,
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
    // The web form is the site root, and the capsule's root is its catalogue.
    // An apply row on the capsule therefore has to name the route the draft
    // flow lives at, and an account row the account route, or each loops back
    // to the page it was pressed on.
    let path = match (protocol, s.action) {
        (Protocol::Gemini, Action::Apply) => "/apply",
        (Protocol::Gemini | Protocol::Web, Action::Account) => "/account",
        _ => "/",
    };
    Row {
        id: s.id.clone(),
        name: s.name.clone(),
        summary: s.summary.clone(),
        href: format!(
            "{}://{host}{path}",
            if finished { protocol.scheme() } else { "https" }
        ),
        state: s.state.word(),
        action: s.action.word(),
        action_kind: s.action,
        handoff,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tracked file, read at compile time, so a malformed commit of the data
    /// file fails the build rather than a deployment.
    const SHIPPED: &str = include_str!("../../../../../openbsd/etc/onboard/catalogue.toml");

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
}
