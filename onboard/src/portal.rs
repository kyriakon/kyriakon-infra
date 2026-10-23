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

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::catalogue::{self, Protocol, Row, Service};
use crate::store;

/// What the handler answered a status read with: the stage alone, or the one
/// notice that covers an unknown token, an expired one and a rate-limited read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    Stage(String),
    Notice(String),
}

/// Where a session reads an application's stage. The portal cannot read the
/// store, so the answer comes from the handler over its own socket; a test drives
/// the same trait with an answer instead.
pub trait StatusSource {
    fn read(&mut self, token: &str) -> Result<Lookup, String>;
}

/// The screen an address sees when it already holds the session cap. It names
/// the web form, because a reader who cannot get a session here must still have a
/// way in.
pub const TOO_MANY: &str = "\
Too many sessions are open from this address.

Wait a few minutes and try again. The web form at
https://signup.kyriakon.net works the same way and has no session limit.
";

/// Where the portal keeps its session locks, and how many one address may hold.
/// The cap matches sshd's `PerSourceMaxStartups 2`; the spec leaves the box-wide
/// total unset until the port is measured, so only the per-address cap is here.
pub const SESSION_DIR: &str = "/var/db/kyriakon-onboard-tui";
pub const SESSIONS_PER_ADDRESS: usize = 2;

/// A session's lock file. One file per live session, named for the address and
/// the process that holds it, and removed on exit. A file whose process is gone is
/// pruned by the next session, so an abandoned session cannot lock an address out
/// for good.
pub struct Sessions {
    file: Option<PathBuf>,
}

/// Whether a session may start.
pub enum Admission {
    Open(Sessions),
    Busy,
}

impl Sessions {
    /// Take a slot for `address`, or report that it holds the cap. `None` is a
    /// session with no address to key on: a manual run rather than an sshd
    /// session, which always carries `SSH_CONNECTION`.
    pub fn open(dir: &Path, address: Option<IpAddr>) -> Result<Admission, String> {
        fs::create_dir_all(dir)
            .map_err(|e| format!("cannot open the session directory {}: {e}", dir.display()))?;
        prune(dir)?;
        let Some(address) = address else {
            return Ok(Admission::Open(Sessions { file: None }));
        };

        // The count and the create are one critical section: two sessions starting
        // together must not both read a count of one and make three. The lock file
        // is per address and outlives the session, so its inode is stable.
        let lock_path = dir.join(format!("{address}.lock"));
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| format!("cannot open {}: {e}", lock_path.display()))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(format!(
                "cannot lock {}: {}",
                lock_path.display(),
                std::io::Error::last_os_error()
            ));
        }

        let prefix = format!("{address}@");
        let mut held = 0;
        for entry in fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))? {
            let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                held += 1;
            }
        }
        if held >= SESSIONS_PER_ADDRESS {
            return Ok(Admission::Busy);
        }

        // A pid is unique among live processes; the start time and the counter
        // keep a later process that reused the pid from colliding with a lock the
        // dead one left behind.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let started = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let file = dir.join(format!(
            "{prefix}{}-{started}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&file)
            .map_err(|e| format!("cannot write {}: {e}", file.display()))?;
        Ok(Admission::Open(Sessions { file: Some(file) }))
    }
}

impl Drop for Sessions {
    fn drop(&mut self) {
        if let Some(file) = &self.file {
            let _ = fs::remove_file(file);
        }
    }
}

/// Remove the locks whose process has gone. A file that cannot be parsed is not
/// this program's and is left alone: the directory is the portal's, but a name
/// this code did not write is not evidence of a session.
fn prune(dir: &Path) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some((_, rest)) = name.split_once('@') else {
            continue;
        };
        let Some(pid) = rest.split('-').next().and_then(|p| p.parse::<i32>().ok()) else {
            continue;
        };
        if pid > 0 && !running(pid) {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}

/// Whether a process is still there. `kill(pid, 0)` checks for existence and
/// permission rather than sending anything; a process this account may not signal
/// is alive, so only `ESRCH` means gone.
fn running(pid: i32) -> bool {
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

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
    status: &mut dyn StatusSource,
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
            // The stage of a filed application, read from the handler. A reader
            // reconnecting pastes the token straight into the first screen; a
            // reader already in the session types "status" and is asked for it.
            "status" => {
                if let Some(token) = token_word(input, out)? {
                    show_status(status, &token, out)?;
                }
            }
            token if store::is_status_token(token) => show_status(status, token, out)?,
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

/// The token the reader pasted, or `None` when they left the prompt empty and
/// want the first screen back.
fn token_word(input: &mut dyn Input, out: &mut dyn Write) -> Result<Option<String>, String> {
    put(
        out,
        "\nPaste the token from your status link, or press Enter to go back.\n",
    )?;
    let Some(word) = input.word()? else {
        return Ok(None);
    };
    let token = word.trim();
    Ok((!token.is_empty()).then(|| token.to_string()))
}

/// One status read. The stage is the whole of what this prints about a live
/// application: the handler sends no answer, contact address or key, and an
/// unknown token reads exactly as an expired one.
fn show_status(
    status: &mut dyn StatusSource,
    token: &str,
    out: &mut dyn Write,
) -> Result<(), String> {
    // A handler that is not answering is a screen, not the end of the session: the
    // reader can still use the menu, and a restart is the operator's repair. The
    // read is the only thing here that can fail for a reason outside this process.
    let text = match status.read(token) {
        Ok(Lookup::Stage(stage)) => format!("Stage: {stage}"),
        Ok(Lookup::Notice(notice)) => notice,
        Err(e) => format!("The status service is not answering. Try again in a moment.\n\n{e}"),
    };
    put(out, &format!("\n{text}\n\nPress Enter to go back.\n"))
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

    /// Scripted status reads. A read the script did not answer is an error rather
    /// than a default, so a screen that asks when it should not is caught.
    #[derive(Default)]
    struct Statuses {
        answers: VecDeque<Result<Lookup, String>>,
    }

    impl Statuses {
        fn new(answers: Vec<Lookup>) -> Statuses {
            Statuses {
                answers: answers.into_iter().map(Ok).collect(),
            }
        }
    }

    impl StatusSource for Statuses {
        fn read(&mut self, _token: &str) -> Result<Lookup, String> {
            self.answers
                .pop_front()
                .unwrap_or_else(|| Err("no status was scripted".into()))
        }
    }

    /// The source for a session that never reads a status.
    struct NoStatus;

    impl StatusSource for NoStatus {
        fn read(&mut self, _token: &str) -> Result<Lookup, String> {
            Err("this session asks no status".into())
        }
    }

    /// One scripted session: how it ended, and everything the reader saw.
    fn session(rows: &[Row], mode: Mode, input: &mut Script) -> (Departure, String) {
        session_with(rows, mode, input, &mut NoStatus)
    }

    fn session_with(
        rows: &[Row],
        mode: Mode,
        input: &mut Script,
        status: &mut dyn StatusSource,
    ) -> (Departure, String) {
        let mut out = Vec::new();
        let left = run(rows, mode, input, status, &mut out).unwrap();
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

    /// The status word asks for the token, prints the stage the handler answered
    /// with, and the session carries on afterwards rather than ending on it.
    #[test]
    fn the_status_word_reads_the_stage_and_nothing_else() {
        let rows = rows(None);
        let mut statuses = Statuses::new(vec![Lookup::Stage("with the reviewer".into())]);
        let mut script = Script::lines(&["status", "abcdefghjkmnpqrstvwxyz0123", "", "quit"]);
        let (left, seen) = session_with(&rows, Mode::Plain, &mut script, &mut statuses);
        assert_eq!(left, Departure::Quit);
        assert!(seen.contains("Stage: with the reviewer"), "{seen}");
        assert!(
            script.spent(),
            "the session stopped reading at the status word"
        );
    }

    /// A token pasted at the first screen is a status read without the word in
    /// front of it, and a token the handler knows nothing about prints the notice
    /// an expired one does.
    #[test]
    fn a_pasted_token_is_read_and_an_unknown_one_is_the_notice() {
        let rows = rows(None);
        let mut statuses = Statuses::new(vec![Lookup::Notice("This link is not in use.".into())]);
        let mut script = Script::lines(&["abcdefghjkmnpqrstvwxyz0123", "", "quit"]);
        let (left, seen) = session_with(&rows, Mode::Plain, &mut script, &mut statuses);
        assert_eq!(left, Departure::Quit);
        assert!(seen.contains("This link is not in use."), "{seen}");
        assert!(
            script.spent(),
            "the session stopped reading at the pasted token"
        );
    }

    /// A status read that cannot reach the handler is a screen, not a dead
    /// session: the reader must still be able to use the menu.
    #[test]
    fn a_status_read_that_fails_leaves_the_session_open() {
        let rows = rows(None);
        let mut statuses = Statuses {
            answers: VecDeque::from([Err("connection refused".to_string())]),
        };
        let mut script = Script::lines(&["status", "abcdefghjkmnpqrstvwxyz0123", "", "quit"]);
        let (left, seen) = session_with(&rows, Mode::Plain, &mut script, &mut statuses);
        assert_eq!(left, Departure::Quit);
        assert!(seen.contains("not answering"), "{seen}");
        assert!(script.spent(), "the session ended on the failed read");
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
        let why = run(
            &[],
            Mode::Full,
            &mut Script::default(),
            &mut NoStatus,
            &mut out,
        )
        .unwrap_err();
        assert!(why.contains(catalogue::TRACKED), "{why}");
        assert!(out.is_empty(), "the refusal drew a screen");
    }

    /// Two concurrent sessions per address, a third refused in the screen the
    /// spec words, and a lock whose process is gone pruned by the next start.
    #[test]
    fn a_third_session_from_one_address_is_refused() {
        let dir =
            std::env::temp_dir().join(format!("onboard-portal-sessions-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let address: IpAddr = "203.0.113.9".parse().unwrap();
        // A process that has just been waited for: its pid is gone, and a stale
        // lock naming it is exactly what the next start must prune.
        let mut gone = std::process::Command::new("true").spawn().unwrap();
        let dead = gone.id();
        gone.wait().unwrap();
        let stale = dir.join(format!("203.0.113.9@{dead}-0"));
        std::fs::write(&stale, "").unwrap();

        let Admission::Open(first) = Sessions::open(&dir, Some(address)).unwrap() else {
            panic!("the first session was refused");
        };
        assert!(!stale.exists(), "the stale lock survived the next start");
        let Admission::Open(second) = Sessions::open(&dir, Some(address)).unwrap() else {
            panic!("the second session was refused");
        };
        assert!(matches!(
            Sessions::open(&dir, Some(address)).unwrap(),
            Admission::Busy
        ));

        // The cap is per address: another one is not held by this one.
        assert!(matches!(
            Sessions::open(&dir, Some("203.0.113.10".parse().unwrap())).unwrap(),
            Admission::Open(_)
        ));

        drop(first);
        drop(second);
        let held = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains('@')
            })
            .count();
        assert_eq!(held, 0, "a finished session left its lock");
    }
}
