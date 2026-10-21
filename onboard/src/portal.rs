//! The terminal front-end: the menu over the shared catalogue, and the two modes
//! one program draws it in.
//!
//! The catalogue is `openbsd/etc/onboard/catalogue.toml`, rendered by
//! `catalogue.rs`. This module holds the rows the menu shows, the way `capsule.rs`
//! holds the rows the capsule shows, which is what lets `catalogue::check`
//! compare this renderer with the other two on every build: a menu that dropped
//! an entry, or carried a list of its own, fails the crate's own test rather than
//! a reader noticing.
//!
//! The session is one loop over one set of words. The full-screen program draws
//! the rows and moves a selection with the arrow keys; the plain mode prints the
//! same rows, numbered, and takes a line. Nothing here is two programs that agree
//! by convention: there is one list of rows, one screen per state and one
//! dispatch, and the mode decides only how a screen is painted and how the reader
//! answers it. A screen reader and a bad link get the same program as everyone
//! else, which is the point rather than a convenience.
//!
//! Two tickets come after this one, and this module is where they attach. [#380]
//! starts the application from a row's `apply` action and [#381] opens the
//! member's own account from its `account` action; today `follow` hands the reader
//! the address the catalogue names for the row, which is what the web card and
//! the gemtext link render for the same entry, so no row is a dead end. Those two
//! tickets replace that address with their own screens and move nothing else here.
//! The member is the other half of the same seam: `entries` renders a host
//! carrying `<name>` from the session's member, so a member's session shows their
//! own addresses the moment something identifies them.
//!
//! [#380]: https://github.com/kyriakon/kyriakon-infra/issues/380
//! [#381]: https://github.com/kyriakon/kyriakon-infra/issues/381

use std::io::Write;

use crate::catalogue::{self, Protocol, Row, Service};
use crate::responder::HOST;

/// The first screen, in the words the spec fixes: what this is, that the web form
/// is another way in and needs no terminal, that a person reads every
/// application, how to leave, and that this is not a login.
///
/// It is the only screen here that makes a promise, and it makes the same one the
/// web form and the capsule make. Both modes open with it, because it is the one
/// screen a reader who has not started yet needs in full.
pub const OPENING: &str = "\
Kyriakon onboarding

This is one of three ways to apply for a Kyriakon account. It is the SSH way.
If you would rather not use a terminal, the same form is at
https://signup.kyriakon.net and needs none.

A person reads every application and decides. Nothing here is approved by a
program, and nothing here asks you for a password or a key of ours.

This is not a login. It files an application, or reads the status of one, and
it cannot change anything.

You can leave at any time with Ctrl-C or by closing the connection. Nothing is
filed until you confirm at the end.

Press Enter to start. Type \"status\" to check an application you have already filed.
";

/// What the drawing mode writes before each screen: clear the terminal and put the
/// cursor at the top. Every screen here is a whole one and the menu is repainted as
/// the selection moves, so without this the session would scroll one menu's height
/// per key. The plain mode carries none of it, which is most of what "without
/// drawing" means.
const CLEAR: &str = "\x1b[2J\x1b[H";

/// Which of the two ways this program reads and writes.
///
/// One value rather than two programs: a screen reader and a bad link get the
/// same screens, the same rows and the same dispatch as a reader with a terminal
/// that can be drawn on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// The rows drawn, the selection moved with the arrow keys, and Enter
    /// following it.
    Full,
    /// The same rows printed, numbered, and a line naming what the reader wants.
    /// No clear, no cursor movement and no key that is not a line.
    Plain,
}

/// One key of the drawing. A printable key that is not one of these is ignored
/// rather than read as input, because no screen here asks for one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    Up,
    Down,
    Enter,
    Quit,
    Other,
}

/// How a session ended, which is the program's exit status. A reader who left
/// with their own word has finished; a connection that closed under the program
/// has not. Neither files anything, and #380 is the ticket that must keep that
/// true when there is an intent to file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Departure {
    Quit,
    Gone,
}

/// The reader's input: a word ended by Enter, or one key with a screen being
/// drawn.
///
/// The session takes input through this and never from a terminal directly, so a
/// test drives both modes from a script and the calls that put a terminal in raw
/// mode stay in the binary. `None` from either method is a connection that closed,
/// which leaves the session rather than being an error: an sshd session whose
/// client went away is ordinary.
pub trait Input {
    /// A word the reader typed and ended with Enter. The terminal is in its
    /// ordinary state for this, so the reader sees what they type and backspace
    /// works.
    fn word(&mut self) -> Result<Option<String>, String>;

    /// One key, with a screen being drawn.
    fn key(&mut self) -> Result<Option<Key>, String>;
}

/// The menu's rows: the catalogue as this front-end shows it, one per entry, in
/// the file's order.
///
/// Here as well as in the drawing so the check can compare what this front-end
/// shows before it is formatted, which is what "compared as rows rather than as
/// strings" means.
pub fn entries(list: &[Service], member: Option<&str>) -> Vec<Row> {
    list.iter()
        .map(|s| catalogue::row(s, Protocol::Terminal, member))
        .collect()
}

/// Run a session: the first screen, then the menu the catalogue gives, until the
/// reader leaves or the connection closes.
///
/// An empty catalogue is refused rather than drawn: a menu with no rows in it is a
/// screen that promises nothing, and the arithmetic that moves a selection through
/// no rows has no answer.
pub fn run(
    rows: &[Row],
    mode: Mode,
    input: &mut dyn Input,
    out: &mut dyn Write,
) -> Result<Departure, String> {
    if rows.is_empty() {
        return Err(format!(
            "{} names no services, so there is nothing to show",
            catalogue::TRACKED
        ));
    }

    put(out, OPENING)?;
    loop {
        let Some(word) = input.word()? else {
            return Ok(Departure::Gone);
        };
        match word.trim() {
            "" => break,
            "quit" => return Ok(Departure::Quit),
            // The stage of a filed application. #380 prints the token and the
            // status address when it files one, and reads the stage back here in
            // the session; until it does, the reader is handed the address the
            // page answering it is on rather than a dead end.
            "status" => put(out, &status_screen())?,
            _ => put(out, "\nPress Enter to start, or type quit to leave.\n")?,
        }
    }

    let mut selected = 0;
    // Whether what the mode paints is already on the screen. The drawing is
    // repainted as the selection moves; the line mode prints the rows once and
    // then reads, because reprinting a list a reader is halfway through answering
    // is what a screen reader would have to read again.
    let mut painted = false;
    loop {
        if mode == Mode::Full || !painted {
            paint(mode, out, &screen(mode, rows, selected))?;
            painted = true;
        }
        let Some(made) = answer(rows, mode, selected, input)? else {
            return Ok(Departure::Gone);
        };
        match made {
            Answer::Next => selected = (selected + 1) % rows.len(),
            Answer::Previous => {
                selected = if selected == 0 {
                    rows.len() - 1
                } else {
                    selected - 1
                };
            }
            // Following a row shows where its action happens, and the reader
            // comes back to the menu: the flow [#380] and the account read
            // [#381] are what take over from the address.
            Answer::Follow(at) => {
                paint(mode, out, &page(&rows[at]))?;
                selected = at;
                match back(mode, input)? {
                    None => return Ok(Departure::Gone),
                    Some(Answer::Quit) => return Ok(Departure::Quit),
                    Some(_) => painted = false,
                }
            }
            Answer::Again => painted = false,
            Answer::Quit => return Ok(Departure::Quit),
        }
    }
}

/// What the reader did on a menu screen. The two modes produce different sets of
/// these: the drawing moves a selection and follows it with Enter, and the line
/// input names the row it wants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Answer {
    Next,
    Previous,
    Follow(usize),
    /// Nothing to act on. The screen is painted again, which is what an
    /// unreadable line or a key no screen uses comes to.
    Again,
    Quit,
}

/// Read one answer on a menu screen, in whichever mode is on. `None` is a
/// connection that closed.
fn answer(
    rows: &[Row],
    mode: Mode,
    selected: usize,
    input: &mut dyn Input,
) -> Result<Option<Answer>, String> {
    match mode {
        Mode::Full => Ok(match input.key()? {
            None => None,
            Some(Key::Up) => Some(Answer::Previous),
            Some(Key::Down) => Some(Answer::Next),
            Some(Key::Enter) => Some(Answer::Follow(selected)),
            Some(Key::Quit) => Some(Answer::Quit),
            Some(Key::Other) => Some(Answer::Again),
        }),
        Mode::Plain => Ok(match input.word()? {
            None => None,
            Some(line) => match line.trim() {
                "quit" | "q" => Some(Answer::Quit),
                "" => Some(Answer::Again),
                // A number that names no row is answered by painting the rows
                // again rather than by opening anything: the reader's own typing
                // is the only untrusted input this program takes, and a row
                // outside the list has none to open.
                word => Some(match word.parse::<usize>() {
                    Ok(n) if n >= 1 && n <= rows.len() => Answer::Follow(n - 1),
                    _ => Answer::Again,
                }),
            },
        }),
    }
}

/// Wait for the reader to acknowledge a page.
///
/// The page says the reader comes back with Enter and the menu's own key leaves,
/// so this reads until one of those arrives; a key no screen uses leaves the page
/// up rather than swallowing it, because a page the reader did not read is worse
/// than a keystroke that did nothing. `None` is a connection that closed.
fn back(mode: Mode, input: &mut dyn Input) -> Result<Option<Answer>, String> {
    loop {
        match mode {
            Mode::Full => match input.key()? {
                None => return Ok(None),
                Some(Key::Enter) => return Ok(Some(Answer::Again)),
                Some(Key::Quit) => return Ok(Some(Answer::Quit)),
                Some(_) => {}
            },
            // A line terminal has nothing to move and no key but Enter to give,
            // so any line the reader ends is the acknowledgement.
            Mode::Plain => match input.word()? {
                None => return Ok(None),
                Some(_) => return Ok(Some(Answer::Again)),
            },
        }
    }
}

/// The screen for the mode: the drawing, or the same rows as a numbered list.
fn screen(mode: Mode, rows: &[Row], selected: usize) -> String {
    match mode {
        Mode::Full => drawing(rows, selected),
        Mode::Plain => listing(rows),
    }
}

/// The menu drawn: the title, one row per entry with the state's word beside the
/// name, the selected row's own clause under it, and the keys that move.
///
/// The names are padded to the longest one so the states line up, which is the
/// only arithmetic a row needs. Nothing here wraps: the catalogue's rule is that a
/// `summary` fits one terminal row, so there is no width to read and no resize to
/// handle.
fn drawing(rows: &[Row], selected: usize) -> String {
    let width = rows
        .iter()
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::from(" Kyriakon\n\n");
    for (at, row) in rows.iter().enumerate() {
        let mark = if at == selected { '>' } else { ' ' };
        out.push_str(&format!(" {mark} {:<width$}  {}\n", row.name, row.state));
        if at == selected {
            out.push_str(&format!("     {}\n", row.summary));
        }
    }
    out.push_str("\n up and down move, Enter opens the row, q quits\n");
    out
}

/// The same words without drawing: each row numbered, with the state's word
/// beside the name and the entry's own clause under it, and the line that says
/// what to type.
///
/// A number is how a reader answers a menu with nothing to point at, and the
/// state's word is the same string the drawing shows beside the name.
fn listing(rows: &[Row]) -> String {
    let mut out = String::from("Kyriakon\n\n");
    for (at, row) in rows.iter().enumerate() {
        out.push_str(&format!("{}. {} ({})\n", at + 1, row.name, row.state));
        out.push_str(&format!("   {}\n", row.summary));
    }
    out.push_str("\nType the number of a service and press Enter, or type quit to leave.\n");
    out
}

/// One row followed by where its action happens: the row's own address, the
/// sentence that hands a job this program cannot finish to one that can, and how
/// to come back.
///
/// Every action ends at an address today, which is what the web card and the
/// gemtext link give the same entry. Two of those addresses are #380's and #381's
/// to replace with a screen of their own.
fn page(row: &Row) -> String {
    let mut out = format!(
        "\n{}\n\n{} ({})\n\n{}\n",
        row.name, row.state, row.summary, row.href
    );
    if let Some(sentence) = row.handoff {
        out.push_str(&format!("\n{sentence}\n"));
    }
    out.push_str("\nPress Enter to go back.\n");
    out
}

/// Where the stage of a filed application is read, which the web page answers
/// today under both front-ends. The address is the responder's own host, so the
/// route the terminal hands out cannot name a different service than the one that
/// answers it.
fn status_screen() -> String {
    format!(
        "\nYour application's status\n\
         \nThe stage of an application is at\n\
         https://{HOST}/status/<token>\n\
         with the token from the link you kept in place of <token>.\n\
         \nPress Enter to go back.\n"
    )
}

/// Paint a screen: the drawing mode clears the terminal first, because every
/// screen here is a whole one. The line mode writes nothing but the screen's own
/// words.
fn paint(mode: Mode, out: &mut dyn Write, text: &str) -> Result<(), String> {
    if mode == Mode::Full {
        put(out, CLEAR)?;
    }
    put(out, text)
}

/// Write a screen and flush, because the next thing this program does is wait for
/// a reader to answer it.
fn put(out: &mut dyn Write, text: &str) -> Result<(), String> {
    out.write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| format!("cannot write to the session: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// The tracked catalogue, read at compile time, so the sessions in these
    /// tests are driven by the rows a deployment installs rather than by a
    /// fixture that could agree with a broken menu.
    const SHIPPED: &str = include_str!("../../openbsd/etc/onboard/catalogue.toml");

    fn rows(member: Option<&str>) -> Vec<Row> {
        entries(&catalogue::parse(SHIPPED).unwrap(), member)
    }

    /// A session's input, from a script. One queue per kind of answer, because the
    /// two modes ask for different kinds and a script that queued the wrong one
    /// ends the session rather than passing.
    #[derive(Default)]
    struct Script {
        words: VecDeque<Option<String>>,
        keys: VecDeque<Option<Key>>,
    }

    impl Script {
        /// A full-screen session: Enter at the first screen, which is a line in
        /// both modes, and then these keys at the menu.
        fn full(keys: &[Key]) -> Script {
            Script {
                words: [Some(String::new())].into(),
                keys: keys.iter().copied().map(Some).collect(),
            }
        }

        /// A line session: the first line answers the first screen and the rest
        /// answer the menu.
        fn lines(lines: &[&str]) -> Script {
            Script {
                words: lines.iter().map(|l| Some((*l).to_string())).collect(),
                keys: VecDeque::new(),
            }
        }

        /// Whether the session read every answer the script had for it. A queue
        /// with something still in it is a screen the session did not wait at.
        fn spent(&self) -> bool {
            self.words.is_empty() && self.keys.is_empty()
        }
    }

    impl Input for Script {
        fn word(&mut self) -> Result<Option<String>, String> {
            Ok(self.words.pop_front().unwrap_or(None))
        }

        fn key(&mut self) -> Result<Option<Key>, String> {
            Ok(self.keys.pop_front().unwrap_or(None))
        }
    }

    /// One scripted session: how it ended, and everything the reader saw.
    fn session(rows: &[Row], mode: Mode, input: &mut Script) -> (Departure, String) {
        let mut out = Vec::new();
        let left = run(rows, mode, input, &mut out).unwrap();
        (left, String::from_utf8(out).unwrap())
    }

    /// The keys that move the selection down through every row and then leave,
    /// which is what shows every row's clause in a mode that shows one at a time.
    fn every_row_then_quit(count: usize) -> Vec<Key> {
        let mut keys = vec![Key::Down; count];
        keys.push(Key::Quit);
        keys
    }

    /// The clause under the row is that row's clause, for every row: a menu that
    /// showed the wrong clause under the mark, or none, is what this catches.
    #[test]
    fn the_clause_under_the_row_is_the_row_it_marks() {
        let rows = rows(None);
        for (at, row) in rows.iter().enumerate() {
            let drawn = drawing(&rows, at);
            assert!(
                drawn.contains(&format!("> {}", row.name)),
                "{} is not the row it marks",
                row.id
            );
            assert!(
                drawn.contains(&row.summary),
                "{} shows no clause of its own",
                row.id
            );
            for other in rows.iter().filter(|o| o.id != row.id) {
                assert!(
                    !drawn.contains(&other.summary),
                    "{} is marked and {}'s clause is under it",
                    row.id,
                    other.id
                );
            }
        }
    }

    /// Enter follows the row the reader moved to, not the first one and not the
    /// one after it, and the page waits for the reader before the menu comes back.
    #[test]
    fn enter_follows_the_action_of_the_row_the_reader_moved_to() {
        let rows = rows(None);
        let mut script = Script::full(&[Key::Down, Key::Enter, Key::Enter, Key::Quit]);
        let (left, seen) = session(&rows, Mode::Full, &mut script);
        assert_eq!(left, Departure::Quit);
        assert!(
            seen.contains(&page(&rows[1])),
            "Enter did not open the row it was on"
        );
        assert!(
            !seen.contains(&page(&rows[0])),
            "Enter opened the row the reader moved off"
        );
        assert!(
            script.spent(),
            "the session did not read every key the page asked for"
        );
    }

    /// A page waits for the reader: it is on the screen until Enter comes back,
    /// and the menu is painted after that rather than over it. A key no screen
    /// uses leaves the page up instead of swallowing it.
    #[test]
    fn a_page_waits_for_the_reader_to_come_back() {
        let rows = rows(None);
        let mut script = Script::full(&[Key::Enter, Key::Other, Key::Enter, Key::Quit]);
        let (left, seen) = session(&rows, Mode::Full, &mut script);
        assert_eq!(left, Departure::Quit);
        assert_eq!(
            seen.matches(&page(&rows[0])).count(),
            1,
            "the page was painted over rather than left for the reader"
        );
        assert!(
            script.spent(),
            "the session did not read every key the page asked for"
        );

        // And the menu's own key leaves from the page rather than going back to
        // the menu first.
        let mut script = Script::full(&[Key::Enter, Key::Quit]);
        let (left, _) = session(&rows, Mode::Full, &mut script);
        assert_eq!(left, Departure::Quit);
        assert!(script.spent());
    }

    /// Enter on the first row follows that row, and closing the connection after
    /// it is not a departure with a word.
    #[test]
    fn a_connection_that_closed_leaves_the_session_as_gone() {
        let rows = rows(None);
        for mode in [Mode::Full, Mode::Plain] {
            let (left, seen) = session(&rows, mode, &mut Script::default());
            assert_eq!(left, Departure::Gone, "{mode:?}");
            assert!(
                seen.starts_with(OPENING),
                "{mode:?} closed before the first screen"
            );
        }
    }

    /// The two modes say the same things: the same first screen, and a row's name,
    /// state and clause in each of them. The drawing shows one clause at a time, so
    /// the reader moving through every row is what puts them all on the screen.
    #[test]
    fn the_two_modes_show_the_same_rows_and_the_same_words() {
        let rows = rows(None);

        let mut full = Script::full(&every_row_then_quit(rows.len()));
        let (left, drawn) = session(&rows, Mode::Full, &mut full);
        assert_eq!(left, Departure::Quit);

        let mut plain = Script::lines(&["", "quit"]);
        let (left, listed) = session(&rows, Mode::Plain, &mut plain);
        assert_eq!(left, Departure::Quit);

        for (mode, seen) in [("the drawing", &drawn), ("the line input", &listed)] {
            assert!(
                seen.starts_with(OPENING),
                "{mode} does not open with the first screen"
            );
            for row in &rows {
                assert!(seen.contains(&row.name), "{mode} has no row for {}", row.id);
                assert!(
                    seen.contains(&row.summary),
                    "{mode} has no clause for {}",
                    row.id
                );
                assert!(
                    seen.contains(row.state),
                    "{mode} has no state for {}",
                    row.id
                );
            }
        }
    }

    /// The plain mode is a line at a time and nothing else, and the row it names
    /// is the row it opens. A number that names no row opens nothing and does not
    /// end the session, which matters because the reader's typing is the only
    /// input this program takes.
    #[test]
    fn the_plain_mode_names_a_row_and_refuses_a_number_that_is_not_one() {
        let rows = rows(None);

        let mut script = Script::lines(&["", "2", "", "quit"]);
        let (left, seen) = session(&rows, Mode::Plain, &mut script);
        assert_eq!(left, Departure::Quit);
        assert!(
            seen.contains(&page(&rows[1])),
            "row 2 opened row 1 or nothing"
        );
        assert!(
            !seen.contains(&page(&rows[0])),
            "row 2 opened the first row"
        );
        assert!(!seen.contains('\x1b'), "the line mode drew something");
        assert!(
            script.spent(),
            "the session did not read every line the page asked for"
        );

        let mut script = Script::lines(&["", "0", "99", "-1", "two", "", "quit"]);
        let (left, seen) = session(&rows, Mode::Plain, &mut script);
        assert_eq!(left, Departure::Quit);
        assert!(
            script.spent(),
            "the session stopped reading before the script ran out"
        );
        for row in &rows {
            assert!(
                !seen.contains(&page(row)),
                "{} opened for an answer naming no row",
                row.id
            );
        }

        // The drawing mode is the one that draws.
        let mut script = Script::full(&[Key::Quit]);
        let (_, seen) = session(&rows, Mode::Full, &mut script);
        assert!(seen.contains('\x1b'), "the drawing mode drew nothing");
    }

    /// The status word answers with the route the page that knows the stage is on,
    /// and the session carries on afterwards rather than ending on it.
    #[test]
    fn the_status_word_names_where_an_application_is_read() {
        let rows = rows(None);
        let mut script = Script::lines(&["status", "", "quit"]);
        let (left, seen) = session(&rows, Mode::Plain, &mut script);
        assert_eq!(left, Departure::Quit);
        assert!(
            seen.contains(&format!("https://{HOST}/status/")),
            "the status screen names no route"
        );
        assert!(
            script.spent(),
            "the session stopped reading at the status word"
        );
    }

    /// A member's session carries their own addresses, and an anonymous one shows
    /// the pattern the file writes. Losing that is how a member is shown somebody
    /// else's host or a placeholder they cannot use.
    #[test]
    fn a_members_own_address_replaces_the_pattern_a_host_carries() {
        let named = rows(Some("theophilus"));
        let web = named.iter().find(|r| r.id == "web").unwrap();
        assert_eq!(web.href, "https://theophilus.kyriakon.net/");
        assert!(page(web).contains("theophilus.kyriakon.net"));

        let anonymous = rows(None);
        let web = anonymous.iter().find(|r| r.id == "web").unwrap();
        assert_eq!(web.href, "https://<name>.kyriakon.net/");
    }

    /// A catalogue with no entries is refused rather than drawn: the arithmetic
    /// that moves a selection through no rows has no answer, and a menu with no
    /// rows is a screen that promises nothing.
    #[test]
    fn a_catalogue_with_no_services_is_refused_rather_than_drawn() {
        let mut out = Vec::new();
        let why = run(&[], Mode::Full, &mut Script::default(), &mut out).unwrap_err();
        assert!(why.contains(catalogue::TRACKED), "{why}");
        assert!(out.is_empty(), "the refusal drew a screen");
    }
}
