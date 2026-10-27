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
//! Following a row whose action is `apply` starts the applicant's flow: the
//! shared question list one question per screen, the counter for the branch the
//! reader's answers select, the key pages, a confirm screen, and one intent filed
//! through the handler. The answers live in memory for the connection's life and
//! nothing is filed until the confirm, so an abandoned or dropped session leaves
//! no record. Every other row still hands the reader the address the catalogue
//! names for it. [#381] replaces that address with the member's own account
//! screen and moves nothing else here.
//!
//! The member is the other half of the same seam: `entries` renders a host
//! carrying `<name>` from the session's member, so a member's session shows their
//! own addresses the moment something identifies them.
//!
//! [#381]: https://github.com/kyriakon/kyriakon-infra/issues/381

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::catalogue::{self, Action, Protocol, Row, Service};
use crate::portal_ipc::Answer as StatusAnswer;
use crate::questions::{Kind, Question, Rule};
use crate::responder::{flow_answers, flow_path, flow_problem, Page};
use crate::store;
use crate::{draft, keycheck};

/// Where a session reads an application's stage. The portal cannot read the
/// store, so the answer comes from the handler over its own socket; a test drives
/// the same trait with an answer instead.
pub trait StatusSource {
    fn read(&mut self, token: &str) -> Result<StatusAnswer, String>;
}

/// Where a completed application goes. The handler is the only writer and
/// validates every field again; the portal's job is the answers and the confirm.
/// A test drives the same trait with a form instead of a socket.
pub trait Filing {
    fn file(&mut self, form: &BTreeMap<String, String>) -> Result<String, String>;
}

/// The shared facts the applicant's flow reads: the crate's question list and
/// the platform's reserved names. Grouped rather than passed one by one, because
/// a front-end that carried its own copy of either would ask a different
/// application.
pub struct Flow<'a> {
    pub questions: &'a [Question],
    pub reserved: &'a HashSet<String>,
}

/// The screen an address sees when it already holds the session cap. It names
/// the web form, because a reader who cannot get a session here must still have a
/// way in.
pub const TOO_MANY: &str = "\
Too many sessions are open from this address.

Wait a few minutes and try again. The web form at
https://signup.kyriakon.net works the same way and has no session limit.
";

/// Where the portal keeps its session locks, how many one address may hold, and
/// the small box-wide total the spec asks for. The per-address cap matches sshd's
/// `PerSourceMaxStartups 2`; the box-wide number is a starting point, like the
/// spec's other limits, and the live port's baseline sets the final one.
pub const SESSION_DIR: &str = "/var/db/kyriakon-onboard-tui";
pub const SESSIONS_PER_ADDRESS: usize = 2;
pub const SESSIONS_TOTAL: usize = 16;

/// One session's lock file, held open for the session's life. The kernel releases
/// the lock when the process ends, so a file left behind by a crash can be told
/// from a live one without trusting a pid. The path is removed on a clean exit;
/// the next start prunes any it finds unlocked.
pub struct Sessions {
    path: Option<PathBuf>,
    /// The open file carries the lock; dropping it releases the lock. It is not
    /// read, so the field is here for its lifetime rather than its value.
    _lock: Option<File>,
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
            return Ok(Admission::Open(Sessions {
                path: None,
                _lock: None,
            }));
        };

        // One directory-wide lock, so the counts and the create are one critical
        // section across every address. It is the only permanent file here; the
        // session files are removed on exit or pruned.
        let count_path = dir.join("sessions.lock");
        let count_lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&count_path)
            .map_err(|e| format!("cannot open {}: {e}", count_path.display()))?;
        lock_exclusive(count_lock.as_raw_fd(), &count_path)?;

        let prefix = format!("{address}@");
        let mut held = 0;
        let mut total = 0;
        for entry in fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))? {
            let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.contains('@') {
                continue;
            }
            total += 1;
            if name.starts_with(&prefix) {
                held += 1;
            }
        }
        if held >= SESSIONS_PER_ADDRESS || total >= SESSIONS_TOTAL {
            return Ok(Admission::Busy);
        }

        // The pid and start time are for reading a file, not for deciding whether
        // its session is alive: the lock does that.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let started = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = dir.join(format!(
            "{prefix}{}-{started}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        lock_exclusive(file.as_raw_fd(), &path)?;
        Ok(Admission::Open(Sessions {
            path: Some(path),
            _lock: Some(file),
        }))
    }
}

impl Drop for Sessions {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

/// Lock one file, or say which one could not be locked.
fn lock_exclusive(fd: i32, path: &Path) -> Result<(), String> {
    if unsafe { libc::flock(fd, libc::LOCK_EX) } == 0 {
        Ok(())
    } else {
        Err(format!(
            "cannot lock {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ))
    }
}

/// Remove the session files no live process holds. A live session keeps an
/// exclusive lock on its own file; this tries the same lock without waiting, and
/// a grant means nobody holds it, so the session is gone. A file this code cannot
/// open is left alone: the directory is the portal's, but a name it did not write
/// is not evidence of a session.
fn prune(dir: &Path) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let name = entry.file_name();
        if !name.to_string_lossy().contains('@') {
            continue;
        }
        let path = entry.path();
        let Ok(file) = OpenOptions::new().read(true).write(true).open(&path) else {
            continue;
        };
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            let _ = fs::remove_file(&path);
        }
    }
    Ok(())
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
/// has not. Only the confirm screen files anything, so these two say how the
/// connection ended rather than what was filed.
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
    flow: &Flow,
    mode: Mode,
    input: &mut dyn Input,
    status: &mut dyn StatusSource,
    filing: &mut dyn Filing,
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
            // An `apply` row starts the application; every other row shows where
            // its action happens and the reader comes back to the menu. The
            // account read is [#381]'s.
            Answer::Follow(at) if rows[at].action_kind == Action::Apply => {
                return application(flow, mode, input, filing, out);
            }
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

/// The application's own opening, after the row is followed. It says the same
/// things the first screen says, in the words that matter once answering starts.
const APPLY_INTRO: &str = "\
Applying for a Kyriakon account.

One question at a time. Type back to return to the previous question, or quit
to leave. Nothing is filed until you confirm at the end, and a dropped
connection files nothing either.

";

/// The page the site publishes, read at build time so the terminal cannot drift
/// from the walkthrough the web form links. The terminal shows the sections that
/// apply before the paste; Android is left out until the prototype has tested it,
/// which is why the paragraph naming it is dropped rather than promising
/// something untested.
const KEY_WALKTHROUGH: &str = include_str!("../../docs/key-walkthrough.md");

/// The walkthrough cut to the sections a key page needs, stripped to plain
/// terminal text. This is not a Markdown renderer: the selected prose carries no
/// links, and the only markup it uses is the heading, emphasis and code ticks
/// removed below. The mail-key page wants the two ways to make a key and the
/// upload-key paragraph; the upload-key page wants only its own section, so the
/// step reads as a step rather than as a page of unrelated advice.
fn key_walkthrough(sections: &[&str], preamble: bool) -> String {
    let mut out = String::new();
    let mut in_preamble = true;
    let mut wanted = false;
    let mut skipping = false;
    for line in KEY_WALKTHROUGH.lines() {
        if let Some(title) = line.strip_prefix("## ") {
            in_preamble = false;
            wanted = sections.contains(&title.trim());
            if wanted {
                out.push('\n');
                out.push_str(&title.trim().to_uppercase());
                out.push('\n');
            }
            continue;
        }
        if in_preamble {
            if !preamble {
                continue;
            }
            if let Some(title) = line.strip_prefix("# ") {
                out.push('\n');
                out.push_str(&title.trim().to_uppercase());
                out.push('\n');
            } else if line.starts_with("You can make both in a browser") {
                // Its next sentence points at the recovery phrase section, which
                // this cut does not carry; the generator section gives the
                // instruction that matters here.
                continue;
            } else {
                out.push_str(&line.replace("**", "").replace('`', ""));
                out.push('\n');
            }
            continue;
        }
        if !wanted {
            continue;
        }
        if line.starts_with("Thunderbird for Android") {
            skipping = true;
        }
        if line.trim().is_empty() {
            skipping = false;
        }
        if skipping {
            continue;
        }
        out.push_str(&line.replace("**", "").replace('`', ""));
        out.push('\n');
    }
    out
}

/// The applicant's flow: the shared question list one page at a time, the
/// counter for the answers given so far, a confirm screen, and one intent filed
/// through the handler. The answers live in this process for the connection's
/// life; there is no draft on disk because one connection is the whole session.
fn application(
    flow: &Flow,
    mode: Mode,
    input: &mut dyn Input,
    filing: &mut dyn Filing,
    out: &mut dyn Write,
) -> Result<Departure, String> {
    let mut draft = draft::Draft::new(String::new());
    let mut index = 0;
    paint(mode, out, APPLY_INTRO)?;
    loop {
        let path = flow_path(flow.questions, &draft.answers);
        if index >= path.len() {
            paint(mode, out, &confirmation(flow.questions, &draft))?;
            let Some(word) = input.word()? else {
                return Ok(Departure::Gone);
            };
            match word.trim().to_ascii_lowercase().as_str() {
                "yes" | "y" => {
                    let form = application_form(&draft);
                    return match filing.file(&form) {
                        Ok(token) => {
                            put(out, &filed(&token))?;
                            Ok(Departure::Quit)
                        }
                        Err(e) => {
                            put(
                                out,
                                &format!("\nThe application could not be filed. Nothing was sent.\n\n{e}\n"),
                            )?;
                            Ok(Departure::Quit)
                        }
                    };
                }
                "back" => {
                    index = path.len().saturating_sub(1);
                    continue;
                }
                "quit" | "q" => return Ok(Departure::Quit),
                _ => continue,
            }
        }

        // `flow_path` already leaves the monastic pages out unless the orders
        // answer selects that path, so the question's own column is the rule here.
        let page = &path[index];
        let required = page.q.required;
        paint(mode, out, &prompt(page, index, path.len()))?;
        match read_answer(page, input)? {
            Entered::Gone => return Ok(Departure::Gone),
            Entered::Quit => return Ok(Departure::Quit),
            Entered::Back => {
                index = index.saturating_sub(1);
                continue;
            }
            Entered::Value(value) => {
                if let Some(why) =
                    flow_problem(page, &value, flow.reserved, required, &draft.answers)
                {
                    put(out, &format!("\n{why}. Press Enter to try again.\n"))?;
                    input.word()?;
                    continue;
                }
                // A mail key that trips one of the three conditions is a warning
                // at its own page and the flow carries on; a refusal here would
                // turn a heuristic into a support queue.
                let warnings = if page.mailbox.is_some() {
                    keycheck::pgp_findings(&value).unwrap_or_default()
                } else {
                    Vec::new()
                };
                store_answer(page, &mut draft, value);
                index += 1;
                if !warnings.is_empty() {
                    // The full mode paints the next screen over whatever is
                    // here, so a warning gets a screen of its own. Enter moves
                    // on and the answer is already kept; back returns to the key
                    // page so a warning the reader acts on is not a dead end.
                    for warning in warnings {
                        put(out, &format!("\nWarning: {warning}\n"))?;
                    }
                    put(out, "\nPress Enter to continue, or back to answer again.\n")?;
                    match input.word()?.as_deref() {
                        None => return Ok(Departure::Gone),
                        Some("back") => {
                            index = index.saturating_sub(1);
                            continue;
                        }
                        Some("quit") | Some("q") => return Ok(Departure::Quit),
                        Some(_) => {}
                    }
                }
                // The body's two line lists are checked together, because the
                // fault is the count rather than either list; the page just
                // answered is the one that gets corrected.
                if page.q.id == "body_account_names"
                    && draft.answers.get("whose").map(String::as_str) == Some("body")
                    && draft.answers.contains_key("body_addresses")
                {
                    let mut errors = Vec::new();
                    crate::responder::body_cross_checks(&draft.answers, &mut errors);
                    if !errors.is_empty() {
                        index -= 1;
                        put(
                            out,
                            &format!("\n{}. Press Enter to try again.\n", errors.join("; ")),
                        )?;
                        input.word()?;
                    }
                }
            }
        }
    }
}

/// One line of the reader's answer, or the word that leaves the page.
enum Entered {
    Value(String),
    Back,
    Quit,
    Gone,
}

/// Read one answer. A multi-line answer, and an address list, end with a full
/// stop on its own line; a mail key ends at the armour's own end line; the upload
/// key is one line, because that is the shape OpenSSH writes. `back` and `quit`
/// are read before a free-text answer starts, and on any line of a key, because
/// neither word can appear in an armoured block and a mistaken paste otherwise
/// has no way out.
fn read_answer(page: &Page, input: &mut dyn Input) -> Result<Entered, String> {
    let key = page.q.kind == Kind::Key;
    let multiline = matches!(page.q.kind, Kind::Multiline | Kind::Addresses);
    let mut lines = Vec::new();
    loop {
        let Some(word) = input.word()? else {
            return Ok(Entered::Gone);
        };
        let line = word.trim_end_matches(['\r', '\n']);
        if lines.is_empty() && matches!(line, "\x1b[D" | "\x1bOD") {
            return Ok(Entered::Back);
        }
        if (lines.is_empty() || key) && !multiline {
            match line.trim() {
                "back" => return Ok(Entered::Back),
                "quit" | "q" => return Ok(Entered::Quit),
                _ => {}
            }
        }
        // A blank answer is one line and done; a blank line inside a pasted key
        // block is part of the armour, so only the first one ends a page.
        if line.trim().is_empty() && lines.is_empty() {
            break;
        }
        lines.push(line.to_string());
        if multiline {
            if line.trim() == "." {
                lines.pop();
                break;
            }
            continue;
        }
        if key {
            // A public key block ends at its own last line; the upload key is a
            // single line and needs no terminator.
            let ended = line.starts_with("-----END PGP PUBLIC KEY BLOCK-----");
            let ssh = page.q.rule == Rule::UploadKey;
            if ended || ssh {
                break;
            }
            // A pasted block that never ends is a malformed key rather than an
            // invitation to read forever; the bound is far past a real block.
            if lines.len() > 200 {
                break;
            }
            continue;
        }
        break;
    }
    // Validation trims, so the value the branch and rail logic compares must be
    // trimmed too: `monk ` must open the blessing and `no_charge ` must not be
    // read as a paid rail.
    Ok(Entered::Value(lines.join("\n").trim().to_string()))
}

/// One question, its counter, and the shape of the answer it wants. The counter
/// is the applicant's own branch: a body's path is longer by the community block,
/// and the blessing appears only after a monastic answer.
fn prompt(page: &Page, index: usize, total: usize) -> String {
    let q = page.q;
    let mut out = format!("\nquestion {} of {}.\n\n", index + 1, total);
    match &page.mailbox {
        Some(mailbox) => out.push_str(&format!("Paste the public key for {}.\n", mailbox.address)),
        None => {
            out.push_str(&q.prompt);
            out.push('\n');
        }
    }
    match q.kind {
        Kind::Choice => {
            out.push_str("Answer one of: ");
            if let Rule::Choice(options) = &q.rule {
                for (i, option) in options.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&format!("{} ({})", option.value, option.label));
                }
            }
            out.push_str(".\n");
        }
        Kind::YesNo => out.push_str("Answer yes or no.\n"),
        Kind::Acceptance => out.push_str("Answer yes to accept.\n"),
        Kind::Addresses => out.push_str(
            "One per line, as localpart: own or localpart: alias localpart. \
             Finish with a single full stop on its own line.\n",
        ),
        Kind::Key if page.mailbox.is_some() => {
            out.push_str(&key_walkthrough(
                &[
                    "The recovery phrase",
                    "Thunderbird on a desktop",
                    "The browser generator",
                    "The upload key",
                ],
                true,
            ));
            out.push_str("Paste the whole block, ending with -----END PGP PUBLIC KEY BLOCK-----.\n")
        }
        Kind::Key => {
            out.push_str(&key_walkthrough(&["The upload key"], false));
            out.push_str("Paste the whole key on one line.\n")
        }
        Kind::Multiline => out.push_str("Finish with a single full stop on its own line.\n"),
        Kind::Text => {}
    }
    if !q.required {
        out.push_str("Press Enter to skip.\n");
    }
    out.push_str("Type back to go to the previous question, or quit to leave.\n");
    out
}

/// Keep one answer. A mail-key page is stored against its mailbox rather than
/// under the question's id, because one question asks once per mailbox.
fn store_answer(page: &Page, draft: &mut draft::Draft, value: String) {
    match &page.mailbox {
        Some(mailbox) => {
            draft.mail_keys.retain(|k| k.mailbox != mailbox.name);
            draft
                .mail_keys
                .push(keycheck::mail_key(mailbox.name.clone(), &value));
        }
        None => {
            draft.answers.insert(page.q.id.clone(), value);
        }
    }
}

/// The confirm screen: each answer once, with a key shown by fingerprint rather
/// than by its material. Nothing has been written at this point.
fn confirmation(questions: &[Question], draft: &draft::Draft) -> String {
    let mut out = String::from("Check your answers.\n\n");
    for page in flow_path(questions, &draft.answers) {
        let q = page.q;
        match &page.mailbox {
            Some(mailbox) => {
                let shown = draft
                    .mail_keys
                    .iter()
                    .find(|k| k.mailbox == mailbox.name)
                    .map(|k| k.fingerprint.clone())
                    .unwrap_or_else(|| "no key".to_string());
                out.push_str(&format!("{}: {shown}\n", mailbox.address));
            }
            None => {
                let value = draft.answers.get(&q.id).cloned().unwrap_or_default();
                if value.is_empty() {
                    continue;
                }
                let shown = if q.kind == Kind::Key {
                    keycheck::openssh_fingerprint(&value)
                        .or_else(|| keycheck::pgp_fingerprint(&value))
                        .unwrap_or_else(|| "a key".to_string())
                } else {
                    value
                };
                out.push_str(&format!("{}: {shown}\n", q.prompt));
            }
        }
    }
    out.push_str("\nType yes to file it, back to change the last answer, or quit to leave.\n");
    out
}

/// The form the handler validates and files: the answers, the keys rebuilt from
/// the pages in mailbox order, and the same field names the web form posts.
fn application_form(draft: &draft::Draft) -> BTreeMap<String, String> {
    let body = draft.answers.get("whose").map(String::as_str) == Some("body");
    flow_answers(draft, body)
}

/// The token and the status address, in the words the spec fixes.
fn filed(token: &str) -> String {
    format!(
        "\nYour application is filed.\n\n\
Keep this link. It is the only thing that identifies your application:\n\
https://{}/status/{token}\n\n\
The link shows the stage and never your answers. A person reads every\n\
application; approval is not automatic. If you gave an address, everything\n\
after this arrives there. Payment follows approval by email.\n\n\
Your account page, once there is an account, is on the web at\n\
https://{}.\n",
        crate::responder::HOST,
        crate::responder::HOST,
    )
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
        Ok(StatusAnswer::Stage(stage)) => format!("Stage: {stage}"),
        Ok(StatusAnswer::Notice(notice)) => notice,
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
        answers: VecDeque<Result<StatusAnswer, String>>,
    }

    impl Statuses {
        fn new(answers: Vec<StatusAnswer>) -> Statuses {
            Statuses {
                answers: answers.into_iter().map(Ok).collect(),
            }
        }
    }

    impl StatusSource for Statuses {
        fn read(&mut self, _token: &str) -> Result<StatusAnswer, String> {
            self.answers
                .pop_front()
                .unwrap_or_else(|| Err("no status was scripted".into()))
        }
    }

    /// The source for a session that never reads a status.
    struct NoStatus;

    impl StatusSource for NoStatus {
        fn read(&mut self, _token: &str) -> Result<StatusAnswer, String> {
            Err("this session asks no status".into())
        }
    }

    /// Scripted applications. Every form the session filed is kept, so a test can
    /// see that one confirm files one intent and an abandon files none.
    #[derive(Default)]
    struct Files {
        forms: Vec<BTreeMap<String, String>>,
    }

    impl Filing for Files {
        fn file(&mut self, form: &BTreeMap<String, String>) -> Result<String, String> {
            self.forms.push(form.clone());
            Ok("abcdefghjkmnpqrstvwxyz0123".to_string())
        }
    }

    /// The source for a session that never files.
    struct NoFiles;

    impl Filing for NoFiles {
        fn file(&mut self, _form: &BTreeMap<String, String>) -> Result<String, String> {
            Err("this session files nothing".into())
        }
    }

    /// The crate's own question list and the tracked reserved names, so a scripted
    /// application walks what a deployment asks.
    fn question_list() -> Vec<Question> {
        crate::questions::shipped().unwrap()
    }

    fn reserved_names() -> HashSet<String> {
        crate::validate::reserved(include_str!("../../reserved-usernames.txt"))
    }

    /// One scripted session: how it ended, and everything the reader saw.
    fn session(rows: &[Row], mode: Mode, input: &mut Script) -> (Departure, String) {
        session_with(rows, mode, input, &mut NoStatus, &mut NoFiles)
    }

    fn session_with(
        rows: &[Row],
        mode: Mode,
        input: &mut Script,
        status: &mut dyn StatusSource,
        filing: &mut dyn Filing,
    ) -> (Departure, String) {
        let questions = question_list();
        let reserved = reserved_names();
        let flow = Flow {
            questions: &questions,
            reserved: &reserved,
        };
        let mut out = Vec::new();
        let left = run(rows, &flow, mode, input, status, filing, &mut out).unwrap();
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
        let mut statuses = Statuses::new(vec![StatusAnswer::Stage("with the reviewer".into())]);
        let mut script = Script::lines(&["status", "abcdefghjkmnpqrstvwxyz0123", "", "quit"]);
        let (left, seen) =
            session_with(&rows, Mode::Plain, &mut script, &mut statuses, &mut NoFiles);
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
        let mut statuses = Statuses::new(vec![StatusAnswer::Notice(
            "This link is not in use.".into(),
        )]);
        let mut script = Script::lines(&["abcdefghjkmnpqrstvwxyz0123", "", "quit"]);
        let (left, seen) =
            session_with(&rows, Mode::Plain, &mut script, &mut statuses, &mut NoFiles);
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
        let (left, seen) =
            session_with(&rows, Mode::Plain, &mut script, &mut statuses, &mut NoFiles);
        assert_eq!(left, Departure::Quit);
        assert!(seen.contains("not answering"), "{seen}");
        assert!(script.spent(), "the session ended on the failed read");
    }

    // A clean key from the generator, so the portal's flow is tested with a key
    // the shared check actually parses. The old two-packet stub passed this
    // module's structural check only, which is exactly the duplication the
    // shared crate removed.
    const KEY_BLOCK: &str =
        include_str!("../../docs/planning/prototypes/keygen-spike/fixtures/generated-clean.asc");

    fn key_lines() -> Vec<String> {
        KEY_BLOCK.lines().map(str::to_string).collect()
    }

    /// The first row the catalogue marks `apply`, which is the row a reader
    /// follows to start an application.
    fn apply_row() -> usize {
        rows(None)
            .iter()
            .position(|r| r.action == Action::Apply.word())
            .expect("the catalogue has an apply row")
    }

    /// The answers to the individual path, as lines: the opening screen, the
    /// apply row's number in the plain mode, every question, and the confirm.
    fn person_lines(at: usize) -> Vec<String> {
        person_lines_with(at, KEY_BLOCK, &[])
    }

    /// The same path with another mail key, and any lines its warning screen
    /// asks for between the key and the next question.
    fn person_lines_with(at: usize, key: &str, after_key: &[&str]) -> Vec<String> {
        let row = (at + 1).to_string();
        let mut lines: Vec<String> = ["", row.as_str(), "theophilus", "person", "", ""]
            .into_iter()
            .map(str::to_string)
            .collect();
        lines.extend(key.lines().map(str::to_string));
        lines.extend(after_key.iter().map(|line| (*line).to_string()));
        lines.extend(
            ["", "no_charge", "", "layman", "", "", "", "yes", "yes"]
                .into_iter()
                .map(str::to_string),
        );
        lines
    }

    /// One completed application in the line mode.
    fn scripts(lines: &[String]) -> Script {
        Script {
            words: lines.iter().map(|l| Some(l.clone())).collect(),
            keys: VecDeque::new(),
        }
    }

    #[test]
    fn a_completed_application_files_exactly_one_intent() {
        let rows = rows(None);
        let at = apply_row();
        let mut script = scripts(&person_lines(at));
        let mut files = Files::default();

        let (left, seen) = session_with(&rows, Mode::Plain, &mut script, &mut NoStatus, &mut files);
        assert_eq!(left, Departure::Quit);
        assert!(script.spent(), "the session stopped before the confirm");
        assert_eq!(
            files.forms.len(),
            1,
            "one confirm filed {} intents",
            files.forms.len()
        );
        let form = &files.forms[0];
        assert_eq!(form.get("username").unwrap(), "theophilus");
        assert_eq!(form.get("whose").unwrap(), "person");
        assert!(
            form.get("mail_key")
                .unwrap()
                .contains("BEGIN PGP PUBLIC KEY BLOCK"),
            "the key did not reach the form"
        );
        assert!(
            !form.contains_key("front_end"),
            "the handler names the front end"
        );
        assert!(seen.contains("Your application is filed"), "{seen}");
        assert!(
            seen.contains("https://signup.kyriakon.net/status/abcdefghjkmnpqrstvwxyz0123"),
            "{seen}"
        );
    }

    /// The key page carries the site's walkthrough before the paste, from the
    /// file the web form publishes, and leaves Android out until it is tested.
    #[test]
    fn the_key_page_prints_the_walkthrough_before_the_paste() {
        let list = question_list();
        let mut person = BTreeMap::new();
        person.insert("username".to_string(), "theophilus".to_string());
        person.insert("whose".to_string(), "person".to_string());
        let mail = flow_path(&list, &person)
            .into_iter()
            .find(|p| p.q.id == "mail_key")
            .expect("the mail key page");
        let text = prompt(&mail, 0, 1);
        for expected in [
            "MAKING A KEY",
            "a step for anyone who wants a website",
            "THUNDERBIRD ON A DESKTOP",
            "https://signup.kyriakon.net/",
            "sftp on port 22",
            "git on port 2222",
            "THE UPLOAD KEY",
            "ssh-keygen -t ed25519",
        ] {
            assert!(text.contains(expected), "{expected} missing from {text}");
        }
        assert!(!text.contains("Android"), "the untested path is printed");
        assert!(
            !text.contains("##"),
            "markdown heading reached the terminal"
        );
    }

    /// The upload-key page prints its own section, because the walkthrough
    /// presents the upload key as a step for anyone who wants a website.
    #[test]
    fn the_upload_key_page_prints_its_own_step() {
        let list = question_list();
        let mut person = BTreeMap::new();
        person.insert("username".to_string(), "theophilus".to_string());
        person.insert("whose".to_string(), "person".to_string());
        let upload = flow_path(&list, &person)
            .into_iter()
            .find(|p| p.q.rule == Rule::UploadKey)
            .expect("the upload key page");
        let text = prompt(&upload, 0, 1);
        assert!(text.contains("THE UPLOAD KEY"), "{text}");
        assert!(!text.contains("THUNDERBIRD ON A DESKTOP"), "{text}");
        assert!(!text.contains("Android"), "{text}");
        assert!(
            !text.contains("# Making a key") && !text.contains("Your account has two keys"),
            "the upload page carries only its own section: {text}"
        );
    }

    /// A key that advertises AEAD is a warning screen and then the flow carries
    /// on, files the key and asks the next question.
    #[test]
    fn a_key_warning_is_shown_and_the_session_proceeds() {
        let rows = rows(None);
        let at = apply_row();
        let aead =
            include_str!("../../docs/planning/prototypes/keygen-spike/fixtures/gpg-aead.asc");
        // The warning screen asks for Enter before the next question.
        let mut script = scripts(&person_lines_with(at, aead, &[""]));
        let mut files = Files::default();
        let (left, seen) = session_with(&rows, Mode::Plain, &mut script, &mut NoStatus, &mut files);
        assert_eq!(left, Departure::Quit);
        assert!(seen.contains("Warning: The key asks for AEAD"), "{seen}");
        assert!(seen.contains("Press Enter to continue"), "{seen}");
        assert_eq!(files.forms.len(), 1, "the warning refused the key");
        assert!(script.spent(), "the session stopped at the warning");
    }

    /// The warning screen's `back` returns to the key page, and the key that is
    /// filed is the one answered after the warning rather than the one it named.
    #[test]
    fn a_key_warning_can_be_answered_again() {
        let rows = rows(None);
        let at = apply_row();
        let aead =
            include_str!("../../docs/planning/prototypes/keygen-spike/fixtures/gpg-aead.asc");
        let mut lines: Vec<String> = ["", &(at + 1).to_string(), "theophilus", "person", "", ""]
            .into_iter()
            .map(str::to_string)
            .collect();
        lines.extend(aead.lines().map(str::to_string));
        lines.push("back".to_string());
        lines.extend(KEY_BLOCK.lines().map(str::to_string));
        lines.extend(
            ["", "no_charge", "", "layman", "", "", "", "yes", "yes"]
                .into_iter()
                .map(str::to_string),
        );
        let mut script = scripts(&lines);
        let mut files = Files::default();
        let (left, seen) = session_with(&rows, Mode::Plain, &mut script, &mut NoStatus, &mut files);
        assert_eq!(left, Departure::Quit);
        assert!(seen.contains("Warning: The key asks for AEAD"), "{seen}");
        assert_eq!(
            files.forms.len(),
            1,
            "the corrected key was not filed: {seen}"
        );
        assert_eq!(
            files.forms[0].get("mail_key").unwrap().trim_end(),
            KEY_BLOCK.trim_end(),
            "the warned key stayed on the form"
        );
    }

    /// A paste longer than the capsule's 1024-byte prompt limit is read and
    /// filed here, because SSH has no such request limit.
    #[test]
    fn a_key_longer_than_the_capsule_limit_is_accepted() {
        let rows = rows(None);
        let at = apply_row();
        let long =
            include_str!("../../docs/planning/prototypes/keygen-spike/fixtures/gpg-rsa-long.asc");
        assert!(long.len() > 1024, "the fixture is not a long paste");
        let mut script = scripts(&person_lines_with(at, long, &[]));
        let mut files = Files::default();
        let (left, seen) = session_with(&rows, Mode::Plain, &mut script, &mut NoStatus, &mut files);
        assert_eq!(left, Departure::Quit);
        assert_eq!(files.forms.len(), 1);
        assert!(
            files.forms[0].get("mail_key").unwrap().len() > 1024,
            "the long key was truncated"
        );
        assert!(script.spent());
        assert!(seen.contains("Your application is filed"), "{seen}");
    }

    /// An upload key is an OpenSSH line and nothing else, and a line that is not
    /// one is refused with the reason rather than reaching the handler.
    #[test]
    fn an_upload_key_that_is_not_openssh_is_refused_with_the_reason() {
        let list = question_list();
        let page = Page {
            q: list
                .iter()
                .find(|q| q.id == "upload_key")
                .expect("the upload key question"),
            mailbox: None,
        };
        let why = flow_problem(
            &page,
            "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            &reserved_names(),
            true,
            &BTreeMap::new(),
        )
        .expect("a PGP block is not an upload key");
        assert!(why.contains("OpenSSH"), "{why}");
    }

    /// The answers to a body's path with two mailboxes, as lines. The address
    /// list and the account names are multi-line, so both end with a full stop.
    fn body_lines(at: usize) -> Vec<String> {
        let row = (at + 1).to_string();
        let mut lines: Vec<String> = [
            "",
            row.as_str(),
            "theophilus",
            "body",
            "The Parish of Example",
            "parish",
            "",
            "example.invalid",
            "yes",
            "secretary: own",
            "hall: alias secretary",
            ".",
            "secretary",
            "hall",
            ".",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        lines.extend(key_lines());
        lines.extend(key_lines());
        lines.extend(
            [
                "",
                "",
                "",
                "",
                "no_charge",
                "",
                "layman",
                "",
                "",
                "",
                "yes",
                "yes",
            ]
            .into_iter()
            .map(str::to_string),
        );
        lines
    }

    /// A body with more than one mailbox can finish: the address list and the
    /// account names are one per line, and each mailbox gets its own key page.
    #[test]
    fn a_body_with_two_mailboxes_files() {
        let rows = rows(None);
        let at = apply_row();
        let mut script = scripts(&body_lines(at));
        let mut files = Files::default();
        let (left, seen) = session_with(&rows, Mode::Plain, &mut script, &mut NoStatus, &mut files);
        assert_eq!(left, Departure::Quit);
        assert!(
            script.spent(),
            "the session stopped before the confirm: {seen}"
        );
        assert_eq!(files.forms.len(), 1);
        let form = &files.forms[0];
        assert_eq!(
            form.get("body_addresses").unwrap(),
            "secretary: own\nhall: alias secretary"
        );
        assert_eq!(form.get("body_account_names").unwrap(), "secretary\nhall");
        assert_eq!(
            form.get("body_mail_key")
                .unwrap()
                .matches("BEGIN PGP")
                .count(),
            2,
            "one key page per mailbox"
        );
        assert!(seen.contains("secretary@example.invalid"), "{seen}");
        assert!(seen.contains("hall@example.invalid"), "{seen}");
    }

    /// The value stored is the trimmed value, so a stray space cannot change the
    /// branch, the blessing or the rail.
    #[test]
    fn a_trailing_space_does_not_change_the_branch() {
        let rows = rows(None);
        let at = apply_row();
        let row = (at + 1).to_string();
        let mut script = scripts(&{
            let mut lines: Vec<String> = ["", row.as_str(), "theophilus", "person", "", ""]
                .into_iter()
                .map(str::to_string)
                .collect();
            lines.extend(key_lines());
            lines.extend(
                [
                    "",
                    "no_charge",
                    "",
                    "monk ",
                    "with my elder's blessing",
                    ".",
                    "",
                    "",
                    "",
                    "yes",
                    "yes",
                ]
                .into_iter()
                .map(str::to_string),
            );
            lines
        });
        let mut files = Files::default();
        let (left, seen) = session_with(&rows, Mode::Plain, &mut script, &mut NoStatus, &mut files);
        assert_eq!(left, Departure::Quit);
        assert!(seen.contains("question 10 of 14"), "{seen}");
        assert_eq!(files.forms.len(), 1);
        assert_eq!(files.forms[0].get("orders").unwrap(), "monk");
        assert_eq!(
            files.forms[0].get("blessing").unwrap(),
            "with my elder's blessing"
        );
    }

    /// A mistaken paste on a key page can be left with `back`, and the session
    /// files nothing when the reader then quits.
    #[test]
    fn a_key_page_can_leave_a_mistaken_paste() {
        let rows = rows(None);
        let at = apply_row();
        let row = (at + 1).to_string();
        let mut script = scripts(&[
            "".to_string(),
            row,
            "theophilus".to_string(),
            "person".to_string(),
            "".to_string(),
            "".to_string(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample".to_string(),
            "back".to_string(),
            "quit".to_string(),
        ]);
        let mut files = Files::default();
        let (left, seen) = session_with(&rows, Mode::Plain, &mut script, &mut NoStatus, &mut files);
        assert_eq!(left, Departure::Quit);
        assert!(files.forms.is_empty(), "an escaped session filed");
        assert!(script.spent());
        assert!(
            seen.matches("I understand that we can only reach me inside this account.")
                .count()
                >= 2,
            "back did not return to the previous question: {seen}"
        );
    }

    /// Every answer kind in the shipped list is read and accepted. A kind that
    /// reads one line where the question asks for several is how a two-mailbox
    /// body dead-ended, so the table is what makes a new kind obvious.
    #[test]
    fn every_answer_kind_is_read_and_accepted() {
        let list = question_list();
        let reserved = reserved_names();
        let page = |id: &str| Page {
            q: list.iter().find(|q| q.id == id).expect(id),
            mailbox: None,
        };
        let mut person = BTreeMap::new();
        person.insert("username".to_string(), "theophilus".to_string());
        person.insert("whose".to_string(), "person".to_string());
        let mail_page = flow_path(&list, &person)
            .into_iter()
            .find(|p| p.q.id == "mail_key")
            .expect("the mail key page");
        let key_block = KEY_BLOCK.trim().to_string();
        let upload = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA user@host";

        let cases: Vec<(&str, Page, Vec<String>, String)> = vec![
            (
                "username",
                page("username"),
                vec!["theophilus".to_string()],
                "theophilus".to_string(),
            ),
            (
                "whose",
                page("whose"),
                vec!["person".to_string()],
                "person".to_string(),
            ),
            (
                "body_records",
                page("body_records"),
                vec!["yes".to_string()],
                "yes".to_string(),
            ),
            (
                "cannot_pay",
                page("cannot_pay"),
                vec![
                    "line one".to_string(),
                    "line two".to_string(),
                    ".".to_string(),
                ],
                "line one\nline two".to_string(),
            ),
            (
                "body_addresses",
                page("body_addresses"),
                vec![
                    "a: own".to_string(),
                    "b: alias a".to_string(),
                    ".".to_string(),
                ],
                "a: own\nb: alias a".to_string(),
            ),
            ("mail_key", mail_page, key_lines(), key_block),
            (
                "upload_key",
                page("upload_key"),
                vec![upload.to_string()],
                upload.to_string(),
            ),
            (
                "accept_terms",
                page("accept_terms"),
                vec!["yes".to_string()],
                "yes".to_string(),
            ),
        ];

        for (id, page, lines, expected) in cases {
            let mut script = Script {
                words: lines.into_iter().map(Some).collect(),
                keys: VecDeque::new(),
            };
            match read_answer(&page, &mut script).unwrap() {
                Entered::Value(value) => assert_eq!(value, expected, "{id}"),
                _ => panic!("{id} did not read a value"),
            }
            assert!(script.spent(), "{id} left input unread");
            assert!(
                flow_problem(
                    &page,
                    &expected,
                    &reserved,
                    page.q.required,
                    &BTreeMap::new()
                )
                .is_none(),
                "{id} was read but refused"
            );
        }
    }

    /// The full mode's left arrow returns to the previous question as the spec
    /// says, even though the answer itself is read as a line.
    #[test]
    fn the_left_arrow_returns_to_the_previous_question() {
        let list = question_list();
        let page = Page {
            q: &list[0],
            mailbox: None,
        };
        let mut script = Script::lines(&["\u{1b}[D"]);
        assert!(matches!(
            read_answer(&page, &mut script).unwrap(),
            Entered::Back
        ));
    }

    #[test]
    fn an_abandoned_application_files_nothing() {
        let rows = rows(None);
        let at = apply_row();
        let mut script = scripts(&[
            "".to_string(),
            (at + 1).to_string(),
            "theophilus".into(),
            "quit".into(),
        ]);
        let mut files = Files::default();
        let (left, _) = session_with(&rows, Mode::Plain, &mut script, &mut NoStatus, &mut files);
        assert_eq!(left, Departure::Quit);
        assert!(files.forms.is_empty(), "an abandoned session filed");
        assert!(script.spent());
    }

    #[test]
    fn a_connection_dropped_before_the_confirm_files_nothing() {
        let rows = rows(None);
        let at = apply_row();
        let mut script = scripts(&["".to_string(), (at + 1).to_string(), "theophilus".into()]);
        let mut files = Files::default();
        let (left, _) = session_with(&rows, Mode::Plain, &mut script, &mut NoStatus, &mut files);
        assert_eq!(left, Departure::Gone);
        assert!(files.forms.is_empty(), "a dropped session filed");
    }

    /// The counter follows the answers: a body's path is longer than the
    /// individual one, and a monastic answer adds the blessing the flow will not
    /// let past empty.
    #[test]
    fn the_counter_is_the_applicants_branch_and_the_blessing_is_required() {
        let list = question_list();
        let individual = flow_path(&list, &BTreeMap::new()).len();

        let mut person = BTreeMap::new();
        person.insert("orders".to_string(), "monk".to_string());
        assert_eq!(flow_path(&list, &person).len(), individual + 1);

        let mut body = BTreeMap::new();
        body.insert("whose".to_string(), "body".to_string());
        body.insert("body_addresses".to_string(), "secretary: own".to_string());
        body.insert("body_account_names".to_string(), "secretary".to_string());
        assert!(
            flow_path(&list, &body).len() > individual,
            "the body's path is not longer than the individual one"
        );

        let rows = rows(None);
        let at = apply_row();
        let row = (at + 1).to_string();
        let mut lines: Vec<String> = ["", row.as_str(), "theophilus", "person", "", ""]
            .into_iter()
            .map(str::to_string)
            .collect();
        lines.extend(key_lines());
        lines.extend(
            [
                "",
                "no_charge",
                "",
                "monk",
                "",
                "",
                "with my elder's blessing",
                ".",
                "",
                "",
                "",
                "yes",
                "yes",
            ]
            .into_iter()
            .map(str::to_string),
        );
        let mut script = scripts(&lines);
        let mut files = Files::default();
        let (left, seen) = session_with(&rows, Mode::Plain, &mut script, &mut NoStatus, &mut files);
        assert_eq!(left, Departure::Quit);
        assert!(
            seen.contains("question 10 of 14"),
            "the monastic counter is not the branch's: {seen}"
        );
        assert!(
            seen.contains("this is needed"),
            "the empty blessing was accepted"
        );
        assert_eq!(files.forms.len(), 1);
        assert_eq!(
            files.forms[0].get("blessing").unwrap(),
            "with my elder's blessing"
        );
    }

    /// The two modes file the same answers: the drawing moves to the apply row
    /// with the arrows, and every answer after it is a line in both.
    #[test]
    fn the_two_modes_file_the_same_application() {
        let rows = rows(None);
        let at = apply_row();

        let mut plain = scripts(&person_lines(at));
        let mut plain_files = Files::default();
        let (left, _) = session_with(
            &rows,
            Mode::Plain,
            &mut plain,
            &mut NoStatus,
            &mut plain_files,
        );
        assert_eq!(left, Departure::Quit);

        // The same answers without the opening line and the menu's row number,
        // and with the arrows that reach the same row.
        let answers = &person_lines(at)[2..];
        let mut words: VecDeque<Option<String>> = VecDeque::from([Some(String::new())]);
        words.extend(answers.iter().cloned().map(Some));
        let mut keys: VecDeque<Option<Key>> = vec![Some(Key::Down); at].into();
        keys.push_back(Some(Key::Enter));
        let mut full = Script { words, keys };

        let mut full_files = Files::default();
        let (left, _) = session_with(&rows, Mode::Full, &mut full, &mut NoStatus, &mut full_files);
        assert_eq!(left, Departure::Quit);
        assert!(full.spent(), "the drawing session stopped early");
        assert_eq!(plain_files.forms.len(), 1);
        assert_eq!(full_files.forms, plain_files.forms);
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
        let questions = question_list();
        let reserved = reserved_names();
        let flow = Flow {
            questions: &questions,
            reserved: &reserved,
        };
        let mut out = Vec::new();
        let why = run(
            &[],
            &flow,
            Mode::Full,
            &mut Script::default(),
            &mut NoStatus,
            &mut NoFiles,
            &mut out,
        )
        .unwrap_err();
        assert!(why.contains(catalogue::TRACKED), "{why}");
        assert!(out.is_empty(), "the refusal drew a screen");
    }

    /// Two concurrent sessions per address, a third refused in the screen the
    /// spec words, and a session file no process holds pruned by the next start.
    #[test]
    fn a_third_session_from_one_address_is_refused() {
        let dir =
            std::env::temp_dir().join(format!("onboard-portal-sessions-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let address: IpAddr = "203.0.113.9".parse().unwrap();
        // A file with no lock held is what a killed session leaves behind.
        let stale = dir.join("203.0.113.9@999999-0");
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

    /// The box-wide total bounds the whole portal, not one address's share of
    /// it: the last slot is refused to a new address.
    #[test]
    fn the_box_wide_total_is_enforced() {
        let dir = std::env::temp_dir().join(format!("onboard-portal-total-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut open = Vec::new();
        for i in 0..SESSIONS_TOTAL {
            let address: IpAddr = format!("198.51.100.{}", i + 1).parse().unwrap();
            let Admission::Open(session) = Sessions::open(&dir, Some(address)).unwrap() else {
                panic!("session {i} was refused before the total");
            };
            open.push(session);
        }
        assert!(matches!(
            Sessions::open(&dir, Some("203.0.113.10".parse().unwrap())).unwrap(),
            Admission::Busy
        ));
    }
}
