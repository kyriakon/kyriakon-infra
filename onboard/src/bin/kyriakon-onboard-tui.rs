//! The portal: the program an ssh session on the onboarding instance runs.
//!
//! `kyriakon-onboard-tui [-c COMMAND] [--config PATH] [--plain | --full]`
//!
//! Installed to `/usr/local/sbin/kyriakon-onboard-tui`, which is the path
//! `openbsd/etc/login.conf.d/hello` gives the `hello` account as its session
//! shell and the path `openbsd/etc/sshd_config.onboard` pins with `ForceCommand`,
//! so a connection to the portal lands here and nowhere else.
//! `scripts/deploy-onboard.sh` installs it from the same build as the handler, so
//! the portal carries no copy of the catalogue, the question list or anything else
//! the library holds.
//!
//! sshd runs a forced command through the account's login class shell as
//! `<shell> -c <command>` (`sshd_config(5)`, and `do_child()` in `session.c`), so
//! the invocation this accepts and discards is
//!
//!   /usr/local/sbin/kyriakon-onboard-tui -c /usr/local/sbin/kyriakon-onboard-tui
//!
//! What is here is the terminal and nothing else. The rows, the screens and the
//! dispatch are the crate's library (`onboard/src/portal.rs`), because the menu is
//! the shared catalogue's third rendering and the crate is where the front-ends
//! share one implementation. The unsafe calls that put a terminal into raw mode
//! are here rather than there for the same reason: the library's session is driven
//! by a script in its own tests, and a session that needed a terminal could not be.
//!
//! The mode is chosen from the terminal the session arrived on rather than from an
//! argument, because no client can supply one: `ForceCommand` ignores any command
//! the client sends and the instance sets no `AcceptEnv`. Both ends must be a
//! terminal and `TERM` must name something to draw on, which is what a screen
//! reader's client and a bad link arrive without; a session that fails either test
//! gets the plain mode. `--plain` and `--full` force one, which is a testing seam
//! rather than a lever, in the shape the ksh program this replaces had.
//!
//! The session files nothing and holds no privilege. It is unprivileged `hello`,
//! it reads the catalogue the handler reads and nothing else on the box, and it
//! never sees a member's state: what a reader does with an answer is the flow the
//! next ticket builds, and that is what files an intent.

use std::io::{BufRead, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kyriakon_onboard::portal::{Departure, Input, Key, Mode};
use kyriakon_onboard::{catalogue, config, portal, portal_ipc};

/// The handler's own configuration, read for the one value the portal needs from
/// it: the path the catalogue is installed at. Named here rather than derived, the
/// same way the handler's unit names it.
const DEFAULT_CONFIG: &str = "/etc/onboard/onboard.toml";

fn main() -> ExitCode {
    match run() {
        // A reader who left with their own word has finished. A connection that
        // closed under the program has not, and neither filed anything: the exit
        // status is the only thing that says which, as it was for the ksh program
        // this replaces.
        Ok(Departure::Quit) => ExitCode::SUCCESS,
        Ok(Departure::Gone) => ExitCode::FAILURE,
        Err(why) => {
            eprintln!("kyriakon-onboard-tui: {why}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<Departure, String> {
    let mut cfg_path = PathBuf::from(DEFAULT_CONFIG);
    let mut state = PathBuf::from(portal::SESSION_DIR);
    let mut forced: Option<Mode> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            // sshd's shape for a forced command. The word after -c is this
            // program's own path, so there is nothing in it the program does not
            // already know.
            "-c" => {
                args.next().ok_or("-c needs the command sshd supplied")?;
            }
            "--config" => {
                cfg_path = PathBuf::from(args.next().ok_or("--config needs a path")?);
            }
            // The session-lock directory, the same testing seam as --plain: the
            // live path is the fixed one, and sshd sets no AcceptEnv, so no client
            // can reach either.
            "--state" => {
                state = PathBuf::from(args.next().ok_or("--state needs a path")?);
            }
            "--plain" => forced = Some(Mode::Plain),
            "--full" => forced = Some(Mode::Full),
            other => {
                return Err(format!(
                    "unknown argument {other:?}; usage: kyriakon-onboard-tui \
                     [-c COMMAND] [--config PATH] [--state PATH] [--plain | --full]"
                ))
            }
        }
    }

    let cfg = config::Config::load(&cfg_path)?;
    let text = std::fs::read_to_string(&cfg.catalogue)
        .map_err(|e| format!("cannot read {}: {e}", cfg.catalogue))?;
    let list = catalogue::parse(&text)?;

    // The session's member, where the key it presented names one: [#381] asks the
    // handler which account a key fingerprint belongs to and passes the answer
    // here. Nothing identifies a member on the applicant's port, so every host
    // carrying <name> renders as the pattern the file writes, which is what the
    // web page and the capsule do for an anonymous visitor.
    //
    // [#381]: https://github.com/kyriakon/kyriakon-infra/issues/381
    let rows = portal::entries(&list, None);

    // The address is the session's own, and the lock it takes is what bounds an
    // address to the two sessions `PerSourceMaxStartups 2` would let sshd start.
    // A session over the cap gets a screen rather than a dropped connection.
    let address = source_address();
    let _session = match portal::Sessions::open(&state, address)? {
        portal::Admission::Busy => {
            print!("{}", portal::TOO_MANY);
            return Ok(Departure::Quit);
        }
        portal::Admission::Open(session) => session,
    };

    let mut status = HandlerStatus {
        socket: cfg.portal_socket.clone(),
        address: address.map(|a| a.to_string()),
    };
    let mode = forced.unwrap_or_else(chosen);
    let mut term = Term::new(mode);
    let left = portal::run(&rows, mode, &mut term, &mut status, &mut std::io::stdout())?;
    if left == Departure::Gone {
        authlog("session abandoned");
    }
    Ok(left)
}

/// The client's address from `SSH_CONNECTION`, the quartet sshd puts in the
/// session environment. No address is a manual run rather than a session, so it
/// takes no lock.
fn source_address() -> Option<IpAddr> {
    std::env::var("SSH_CONNECTION")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// The handler's answer to a status read. It logs the stage to `authlog` and
/// nothing else: no address, no token and no answer. The handler's own log
/// carries the route and the address, which is where those belong.
struct HandlerStatus {
    socket: String,
    address: Option<String>,
}

impl portal::StatusSource for HandlerStatus {
    fn read(&mut self, token: &str) -> Result<portal::Lookup, String> {
        match portal_ipc::ask(Path::new(&self.socket), self.address.as_deref(), token)? {
            portal_ipc::Answer::Stage(stage) => {
                authlog(&format!("status read: {stage}"));
                Ok(portal::Lookup::Stage(stage))
            }
            portal_ipc::Answer::Notice(notice) => {
                authlog("status read: no stage");
                Ok(portal::Lookup::Notice(notice))
            }
        }
    }
}

/// One line at facility `AUTH`, which is where the front-ends' own stage events
/// go. `%s` is the format because a stage is a string this program did not
/// write, and a format string it cannot control.
fn authlog(message: &str) {
    let clean = message.replace('\0', " ");
    if let Ok(text) = std::ffi::CString::new(format!("kyriakon-onboard-tui: {clean}")) {
        unsafe {
            libc::syslog(
                libc::LOG_AUTH | libc::LOG_INFO,
                c"%s".as_ptr(),
                text.as_ptr(),
            );
        }
    }
}

/// Whether this session can be drawn on: both ends a terminal and `TERM` naming
/// something to draw with. A screen reader's client and a bad link are what arrive
/// without one of the three, and the plain mode is the mode for them.
fn chosen() -> Mode {
    let term = std::env::var("TERM").unwrap_or_default();
    let ttys =
        unsafe { libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1 };
    let drawable = ttys && !term.is_empty() && term != "dumb";
    if drawable {
        Mode::Full
    } else {
        Mode::Plain
    }
}

/// The session's terminal.
///
/// With a screen being drawn the terminal gives up canonical input and echo, so a
/// key arrives as itself rather than after an Enter, and it gives up signals too,
/// so Ctrl-C arrives as the byte the screen reads as a quit. A session that died
/// on a signal would leave a terminal it had put in raw mode raw, and the guard
/// below is what puts it back. Reading a word turns both off again: a prompt the
/// reader cannot see what they typed at is not a prompt.
struct Term {
    mode: Mode,
    /// The terminal's own settings, kept from the first time the screen was
    /// drawn and put back by `cooked` and by `Drop`.
    saved: Option<libc::termios>,
}

impl Term {
    fn new(mode: Mode) -> Term {
        Term { mode, saved: None }
    }

    /// Take the terminal's own settings, before anything is changed.
    fn save(&mut self) -> Result<(), String> {
        if self.saved.is_some() {
            return Ok(());
        }
        let mut now = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, now.as_mut_ptr()) } != 0 {
            return Err(format!(
                "cannot read the terminal's settings: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.saved = Some(unsafe { now.assume_init() });
        Ok(())
    }

    /// Draw on the terminal: canonical input, echo and signals off.
    fn drawing(&mut self) -> Result<(), String> {
        self.save()?;
        let mut raw = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, raw.as_mut_ptr()) } != 0 {
            return Err(format!(
                "cannot read the terminal's settings: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut raw = unsafe { raw.assume_init() };
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        set(&raw)
    }

    /// Read a word: the terminal's own settings back, so the reader sees what they
    /// type and backspace works.
    fn cooked(&mut self) {
        let Some(saved) = self.saved.as_ref() else {
            return;
        };
        if let Err(why) = set(saved) {
            // Nothing better is available here: the session is ending, or a prompt
            // is about to be read with the terminal in whatever state it is in,
            // and neither is something this program can act on.
            eprintln!("kyriakon-onboard-tui: {why}");
        }
    }

    /// One byte, or `None` when the connection closed.
    fn byte(&mut self) -> Result<Option<u8>, String> {
        let mut b = [0u8; 1];
        match std::io::stdin().lock().read(&mut b) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(b[0])),
            Err(e) => Err(format!("cannot read the session's input: {e}")),
        }
    }

    /// One key. The arrows arrive as `ESC [ A` and `ESC [ B`, or with `O` in
    /// place of `[` from a terminal in cursor-key mode; nothing else this screen
    /// reads is a sequence.
    fn key_of(&mut self, first: u8) -> Result<Option<Key>, String> {
        Ok(Some(match first {
            b'\r' | b'\n' => Key::Enter,
            b'q' | b'Q' => Key::Quit,
            // Ctrl-C, which arrives as a byte rather than as a signal because the
            // drawing turned ISIG off.
            0x03 => Key::Quit,
            // ponytail: a bare Esc waits for one more byte instead of timing out,
            // and the byte after it is read as the sequence's second half. The
            // arrows are the only sequence here, so the ceiling is a reader who
            // presses Esc alone and sees nothing until they press something else.
            0x1b => match self.byte()? {
                None => return Ok(None),
                Some(b'[') | Some(b'O') => match self.byte()? {
                    None => return Ok(None),
                    Some(b'A') => Key::Up,
                    Some(b'B') => Key::Down,
                    Some(_) => Key::Other,
                },
                Some(_) => Key::Other,
            },
            _ => Key::Other,
        }))
    }
}

impl Input for Term {
    fn word(&mut self) -> Result<Option<String>, String> {
        self.cooked();
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(line)),
            Err(e) => Err(format!("cannot read the session's input: {e}")),
        }
    }

    fn key(&mut self) -> Result<Option<Key>, String> {
        if self.mode == Mode::Plain {
            // A line terminal's one key is the line's own meaning, which is what
            // the plain session asks for at the one screen that waits for Enter.
            return Ok(self.word()?.map(|line| match line.trim() {
                "" => Key::Enter,
                "q" | "quit" => Key::Quit,
                _ => Key::Other,
            }));
        }
        self.drawing()?;
        match self.byte()? {
            None => Ok(None),
            Some(first) => self.key_of(first),
        }
    }
}

impl Drop for Term {
    fn drop(&mut self) {
        self.cooked();
    }
}

/// Put the terminal into `want`.
fn set(want: &libc::termios) -> Result<(), String> {
    if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, want) } != 0 {
        return Err(format!(
            "cannot set the terminal's settings: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
