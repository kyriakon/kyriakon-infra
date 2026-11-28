//! OpenPGP execution and armour parsing: one place for every gpg subprocess
//! the control plane runs and every armour block it reads.
//!
//! The structural checks live here too: a submitted key has to be exactly one
//! armour block carrying exactly one primary public key, and the fingerprint
//! is computed from that material. A second primary packet in one block would
//! otherwise be installed unseen and sign as if it were the first (#918).
//!
//! Signature verification imports the key into a scratch `0700` home and
//! requires the `VALIDSIG` fingerprint gpg reports to equal the expected one.
//! For a clearsigned message gpg's own verified plaintext is the only text
//! returned: a marker found by searching the file can be made to frame text
//! the signature never covered (#924).
//!
//! One adapter runs gpg. It writes stdin while draining stdout and stderr, so a
//! large export cannot fill a pipe while gpg fills the other (#929), and it
//! kills the child at a hard deadline.

use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha1::{Digest, Sha1};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use super::Error;

const BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const END: &str = "-----END PGP PUBLIC KEY BLOCK-----";
const SIGNED_BEGIN: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const SIGNED_END: &str = "-----END PGP SIGNATURE-----";

/// How long one gpg run may take. A key or a message is small; a run that hangs
/// must not hold the single-flight drain open forever.
const GPG_TIMEOUT: Duration = Duration::from_secs(30);

/// Production releases do not consult the environment for an executable.
#[cfg(not(any(test, feature = "test-fixtures")))]
const KEYGEN_CHECK: &str = "/usr/local/libexec/keygen-check";

/// The helper parses one key and exits. A parser that hangs on one key must not
/// hold the request open.
const KEYGEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Matches `keygen-check`'s stdin cap so oversized material fails without a spawn.
const MAX_KEYGEN_INPUT: usize = 1 << 20;

/// Real verdicts are a few hundred bytes; bound stdout against a runaway helper.
const MAX_KEYGEN_OUTPUT: usize = 64 * 1024;

#[derive(Debug)]
pub struct Checked {
    /// "works" when the shared check finds nothing, or its findings joined with
    /// "; " when one or more trips.
    pub verdict: String,
    /// False when the block is well framed but the crate could not read it. The
    /// verdict is then the advisory that a person will check the key, the one
    /// advisory that proceeds; a key is refused only when `inspected` and the
    /// verdict is not "works".
    pub inspected: bool,
    /// Why the helper could not answer, when it could not: a missing binary, a
    /// timeout, a non-zero exit or a broken protocol. `None` for a clean run and
    /// for the helper's own `uninspected`, which is a gap in its parse rather
    /// than a fault of this process; the advisory covers both alike.
    helper_error: Option<Error>,
}

impl Checked {
    /// The findings that refuse a submission, or `None` when the block was not
    /// inspected or the check found nothing. The parser-gap advisory proceeds.
    pub fn refusal(&self) -> Option<&str> {
        (self.inspected && self.verdict != "works").then_some(self.verdict.as_str())
    }

    /// The helper's own failure, so a daemon writes it to its log instead of
    /// losing it. The portal does not report this: its stderr is a member's
    /// terminal.
    pub fn helper_error(&self) -> Option<&Error> {
        self.helper_error.as_ref()
    }
}

/// One key as it will be installed: the block's own text and the fingerprint
/// computed over its one primary packet.
#[derive(Debug)]
pub struct Cert {
    pub material: String,
    pub fingerprint: String,
}

/// The plaintext GnuPG itself extracted from a clearsigned message, and the
/// fingerprint it reported.
#[derive(Debug)]
pub struct Clearsigned {
    pub fingerprint: String,
    pub plaintext: String,
}

struct Packet {
    tag: u8,
    body: Vec<u8>,
}

/// A scratch GNUPGHOME removed when it drops. gpg's agent socket lives under
/// the homedir, and a UNIX socket path is bounded: a long per-user temp
/// directory fails to connect the agent rather than failing to read the key.
/// /tmp is short on every box this runs on.
struct ScratchHome(PathBuf);

impl ScratchHome {
    fn new() -> Result<Self, Error> {
        let home = PathBuf::from("/tmp").join(format!("kyriakon-gpg-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).map_err(|source| Error::CreateScratchHome {
            path: home.clone(),
            source,
        })?;
        let scratch = Self(home);
        // gpg refuses a homedir another user could read, and the scratch
        // directory is created with the process umask otherwise.
        std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o700)).map_err(
            |source| Error::SetScratchMode {
                path: scratch.path().to_path_buf(),
                source,
            },
        )?;
        Ok(scratch)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct GpgOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn base_command(gpg: &str, home: &Path) -> Command {
    let mut command = Command::new(gpg);
    command
        .args(["--batch", "--no-tty", "--no-options", "--no-autostart"])
        .arg("--homedir")
        .arg(home);
    command
}

/// Run gpg once in a fresh scratch home, importing `key_file` first when one is
/// given. stdin, stdout and stderr are drained concurrently, and a run past the
/// deadline is killed rather than left running.
async fn run_gpg<F>(
    gpg: &str,
    key_file: Option<&Path>,
    stdin: Option<&[u8]>,
    tail: F,
) -> Result<GpgOutput, Error>
where
    F: FnOnce(&mut Command, &Path) -> Result<(), Error>,
{
    let home = ScratchHome::new()?;
    if let Some(key_file) = key_file {
        let mut import = base_command(gpg, home.path());
        import.arg("--import").arg(key_file);
        let out = execute(import, None, gpg).await?;
        if !out.success {
            return Err(Error::ImportKey {
                path: key_file.to_path_buf(),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
    }
    let mut command = base_command(gpg, home.path());
    tail(&mut command, home.path())?;
    execute(command, stdin, gpg).await
}

async fn execute(
    mut command: Command,
    stdin: Option<&[u8]>,
    gpg: &str,
) -> Result<GpgOutput, Error> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|source| Error::RunGpg {
        program: gpg.to_string(),
        source,
    })?;
    let mut child_stdin = child.stdin.take();
    let mut stdout = child.stdout.take().ok_or(Error::GpgNoStdout)?;
    let mut stderr = child.stderr.take().ok_or(Error::GpgNoStderr)?;
    let io = async move {
        let write = async move {
            if let Some(bytes) = stdin {
                if let Some(pipe) = child_stdin.as_mut() {
                    pipe.write_all(bytes).await?;
                }
            }
            if let Some(mut pipe) = child_stdin {
                pipe.shutdown().await?;
            }
            Ok::<(), std::io::Error>(())
        };
        let read_out = async move {
            let mut out = Vec::new();
            stdout.read_to_end(&mut out).await?;
            Ok::<_, std::io::Error>(out)
        };
        let read_err = async move {
            let mut err = Vec::new();
            stderr.read_to_end(&mut err).await?;
            Ok::<_, std::io::Error>(err)
        };
        tokio::join!(write, read_out, read_err)
    };
    let deadline = tokio::time::Instant::now() + GPG_TIMEOUT;
    let (written, out, err) = match tokio::time::timeout_at(deadline, io).await {
        Ok(result) => result,
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(timed_out(gpg));
        }
    };
    let status = match tokio::time::timeout_at(deadline, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(source)) => {
            return Err(Error::WaitGpg {
                program: gpg.to_string(),
                source,
            })
        }
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(timed_out(gpg));
        }
    };
    let stdout = out.map_err(|source| Error::ReadGpgOutput {
        program: gpg.to_string(),
        source,
    })?;
    let stderr = err.map_err(|source| Error::ReadGpgError {
        program: gpg.to_string(),
        source,
    })?;
    if status.success() {
        written.map_err(|source| Error::WriteGpg { source })?;
    }
    Ok(GpgOutput {
        success: status.success(),
        stdout,
        stderr,
    })
}

fn timed_out(gpg: &str) -> Error {
    Error::GpgTimedOut {
        program: gpg.to_string(),
        seconds: GPG_TIMEOUT.as_secs(),
    }
}

/// Inspect one armoured public key block: exactly one block, exactly one
/// primary public-key packet, and the fingerprint over that packet.
pub fn inspect_single_cert(armour: &str) -> Result<Cert, Error> {
    let blocks = labelled_blocks(armour);
    if blocks.is_empty() {
        return Err(Error::NotArmoured);
    }
    if blocks.len() > 1 {
        return Err(Error::MultipleArmourBlocks);
    }
    let (_, material) = &blocks[0];
    if !kyriakon_mailparse::lines(material.as_bytes())
        .any(|line| trim_bytes(line.text) == END.as_bytes())
    {
        return Err(Error::ArmourNoEnd);
    }
    let body = armour_body(material)?;
    let raw = base64_decode(&body).ok_or(Error::KeyBase64NotDecodable)?;
    let packets = packets(&raw).ok_or(Error::PacketStructureUnreadable)?;
    let mut primaries = packets.iter().filter(|packet| packet.tag == 6);
    let primary = primaries.next().ok_or(Error::NoPublicKeyPacket)?;
    if primaries.next().is_some() {
        return Err(Error::MultiplePrimaryKeys);
    }
    let fingerprint = fingerprint_of(primary).ok_or(Error::FingerprintUncomputable)?;
    Ok(Cert {
        material: material.clone(),
        fingerprint,
    })
}

/// Inspect an armoured PGP public key block. `Err` is the refusal reason; the
/// verdict is the shared crate's reading of the three conditions, joined when
/// more than one trips. `inspected` separates a finding from the advisory that
/// the parser could not read the block, and a helper that could not answer keeps
/// its error for the caller's log.
pub fn public_key(value: &str) -> Result<Checked, Error> {
    public_key_with(keygen_check_program(), value, now_secs(), KEYGEN_TIMEOUT)
}

/// The one inspection, with the helper named. [`public_key`] names the deployed
/// one; a test drives a helper that cannot answer, which is the path this keeps
/// observable.
fn public_key_with(
    program: String,
    value: &str,
    now: u64,
    timeout: Duration,
) -> Result<Checked, Error> {
    let cert = inspect_single_cert(value)?;
    Ok(
        match run_keygen_check(program, &cert.material, now, timeout) {
            Ok(KeygenVerdict::Parsed(findings)) if findings.is_empty() => Checked {
                verdict: "works".to_string(),
                inspected: true,
                helper_error: None,
            },
            Ok(KeygenVerdict::Parsed(findings)) => Checked {
                verdict: findings.join("; "),
                inspected: true,
                helper_error: None,
            },
            // The helper read the framing and could not read the key: a gap in the
            // check, not a fault in this process, so there is nothing to log.
            Ok(KeygenVerdict::Uninspected) => Checked {
                verdict: UNINSPECTED.to_string(),
                inspected: false,
                helper_error: None,
            },
            // A helper that could not answer is the same advisory to the applicant
            // and a line in the daemon's log for the operator.
            Err(err) => Checked {
                verdict: UNINSPECTED.to_string(),
                inspected: false,
                helper_error: Some(err),
            },
        },
    )
}

/// The three-condition findings, for a caller that only shows them. The
/// advisory a helper gap produces is one entry, which is what the caller
/// prints; no refusal is built from this.
pub fn findings(value: &str) -> Result<Vec<String>, Error> {
    let checked = public_key(value)?;
    Ok(if checked.verdict == "works" {
        Vec::new()
    } else {
        vec![checked.verdict]
    })
}

/// The helper's answer, with the parser gap kept distinct from a clean key.
enum KeygenVerdict {
    Parsed(Vec<String>),
    Uninspected,
}

/// Run `keygen-check` for one key. The helper is a separate build root so the
/// control plane does not link `pgp`; every failure here is the uninspected
/// advisory at the caller, never a refusal on a key the platform did not read.
fn run_keygen_check(
    program: String,
    material: &str,
    now: u64,
    timeout: Duration,
) -> Result<KeygenVerdict, Error> {
    if material.len() > MAX_KEYGEN_INPUT {
        return Err(Error::KeygenCheckProtocol { program });
    }
    let deadline = Instant::now() + timeout;
    let mut child = std::process::Command::new(&program)
        .env_clear()
        .arg("--now-secs")
        .arg(now.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| Error::RunKeygenCheck {
            program: program.clone(),
            source,
        })?;

    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let expired = || Error::KeygenCheckTimedOut {
        program: program.clone(),
        seconds: timeout.as_secs(),
    };
    thread::scope(|scope| {
        let (send, receive) = mpsc::channel();
        scope.spawn(move || {
            // The helper reads to EOF before it writes a verdict.
            let written = stdin.write_all(material.as_bytes());
            drop(stdin);
            let mut output = Vec::new();
            let read = stdout
                .take(MAX_KEYGEN_OUTPUT as u64 + 1)
                .read_to_end(&mut output)
                .map(|_| output);
            let _ = send.send((written, read));
        });
        let result = (|| {
            let (written, read) = receive
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => expired(),
                    mpsc::RecvTimeoutError::Disconnected => Error::KeygenCheckProtocol {
                        program: program.clone(),
                    },
                })?;
            if matches!(&read, Ok(output) if output.len() > MAX_KEYGEN_OUTPUT) {
                return Err(Error::KeygenCheckProtocol {
                    program: program.clone(),
                });
            }
            // EOF can precede exit. Only this thread may signal or reap the child.
            loop {
                if let Some(status) = child.try_wait().map_err(|source| Error::WaitKeygenCheck {
                    program: program.clone(),
                    source,
                })? {
                    if !status.success() {
                        return Err(Error::KeygenCheckExited {
                            program: program.clone(),
                            status,
                        });
                    }
                    break;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(expired());
                }
                thread::sleep(left.min(Duration::from_millis(1)));
            }
            written.map_err(|source| Error::WriteKeygenCheck {
                program: program.clone(),
                source,
            })?;
            let output = read.map_err(|source| Error::ReadKeygenCheck {
                program: program.clone(),
                source,
            })?;
            parse_keygen_output(&program, &output)
        })();
        if result.is_err() {
            // Child::kill is a no-op once try_wait has reaped this child.
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    })
}

/// The executable the sandbox unveils and the key check starts.
pub fn keygen_check_program() -> String {
    #[cfg(any(test, feature = "test-fixtures"))]
    {
        keygen_check_test_binary().to_string_lossy().into_owned()
    }
    #[cfg(not(any(test, feature = "test-fixtures")))]
    {
        #[cfg(debug_assertions)]
        if let Ok(program) = std::env::var("KYRIAKON_KEYGEN_CHECK") {
            if !program.is_empty() {
                return program;
            }
        }
        KEYGEN_CHECK.to_owned()
    }
}

/// The check protocol: `ok` and one finding per line, or `uninspected`.
fn parse_keygen_output(program: &str, stdout: &[u8]) -> Result<KeygenVerdict, Error> {
    let protocol = || Error::KeygenCheckProtocol {
        program: program.to_string(),
    };
    let text = std::str::from_utf8(stdout).map_err(|_| protocol())?;
    let Some(body) = text.strip_suffix('\n') else {
        return Err(protocol());
    };
    let mut lines = body.split('\n');
    match lines.next() {
        Some("ok") => {
            let mut findings = Vec::new();
            for line in lines {
                if line.is_empty() {
                    return Err(protocol());
                }
                findings.push(line.to_string());
            }
            Ok(KeygenVerdict::Parsed(findings))
        }
        Some("uninspected") if lines.next().is_none() => Ok(KeygenVerdict::Uninspected),
        _ => Err(protocol()),
    }
}

/// Resolve the fixture helper once per test process, before the sandbox locks.
#[cfg(any(test, feature = "test-fixtures"))]
fn keygen_check_test_binary() -> &'static Path {
    use std::sync::LazyLock;

    static PATH: LazyLock<PathBuf> = LazyLock::new(|| {
        if let Some(program) = std::env::var_os("KYRIAKON_KEYGEN_CHECK").filter(|v| !v.is_empty()) {
            return PathBuf::from(program);
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let manifest = root.join("keygen/Cargo.toml");
        let target = root.join("keygen/target");
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = std::process::Command::new(cargo)
            .args([
                "build",
                "--quiet",
                "--no-default-features",
                "--bin",
                "keygen-check",
                "--manifest-path",
            ])
            .arg(&manifest)
            .arg("--target-dir")
            .arg(target.as_path())
            .status()
            .expect("cargo builds keygen-check");
        assert!(status.success(), "cargo build keygen-check failed");
        target.join("debug/keygen-check")
    });
    &PATH
}

/// The advisory a well-framed block gets when the crate cannot parse it. It is
/// not a verdict on the key, and a caller that refuses findings must not refuse
/// this one.
const UNINSPECTED: &str = "The key could not be inspected automatically, so a person will \
     check it against the key on the box. The application can still be filed.";

/// The User ID and user-attribute packets a key would publish, as warnings
/// rather than refusals. The default identity is `<localpart>@kyriakon.net`
/// alone; a display name, another address or a photo is allowed, because a
/// member may want it, but `keys/<localpart>.asc` is public forever and the
/// reviewer must see what it would carry. `None` when the armour does not parse
/// (the framing check already speaks for that case).
pub fn uid_warnings(value: &str, address: &str) -> Vec<String> {
    let Some(packets) = raw_packets(value) else {
        return Vec::new();
    };
    let expected = address.to_ascii_lowercase();
    let mut warnings = Vec::new();
    let mut uids = 0usize;
    for packet in &packets {
        match packet.tag {
            13 => {
                uids += 1;
                let uid = String::from_utf8_lossy(&packet.body).trim().to_string();
                if uid.to_ascii_lowercase() != expected {
                    warnings.push(format!(
                        "the key's User ID is {uid:?}, which is published with the key. \
                         The default is {expected} alone; a name or another address is \
                         allowed, but it is public forever"
                    ));
                }
            }
            17 => {
                uids += 1;
                warnings.push(
                    "the key carries a user-attribute packet (such as a photo), which will \
                     be published with the key"
                        .to_string(),
                );
            }
            _ => {}
        }
    }
    if uids == 0 {
        warnings.push(format!(
            "the key carries no User ID; the published key will carry none, and the default \
             is {expected}"
        ));
    }
    warnings
}

/// The decoded packets of the first armoured block, for the warnings above.
/// `None` on framing this parser cannot read, which the key check already
/// reports.
fn raw_packets(value: &str) -> Option<Vec<Packet>> {
    let material = labelled_blocks(value).first()?.1.clone();
    let body = armour_body(&material).ok()?;
    let raw = base64_decode(&body)?;
    packets(&raw)
}

/// The clock the crate asks its caller for, because `SystemTime::now()` panics
/// on wasm32 and the browser supplies its own.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The OpenPGP fingerprint of the one public key packet in an armoured block,
/// in the upper-case hex gpg prints: the SHA-1 of the version 4 packet's framing
/// (`0x99`, the packet's length, the packet) or the SHA-256 of a version 6 one
/// (`0x9b`, a four-byte length, the packet), which is RFC 9580's own definition.
/// `None` when the block carries no key packet, more than one, or a version with
/// no fingerprint defined here, which is not a number to guess at.
pub fn fingerprint(value: &str) -> Option<String> {
    inspect_single_cert(value).ok().map(|cert| cert.fingerprint)
}

fn fingerprint_of(key: &Packet) -> Option<String> {
    let version = key.body.first().copied()?;
    let len = key.body.len();
    let mut framed = Vec::with_capacity(len + 5);
    let digest = match version {
        4 => {
            framed.push(0x99);
            framed.extend_from_slice(&u16::try_from(len).ok()?.to_be_bytes());
            framed.extend_from_slice(&key.body);
            Sha1::digest(&framed).to_vec()
        }
        6 => {
            framed.push(0x9b);
            framed.extend_from_slice(&u32::try_from(len).ok()?.to_be_bytes());
            framed.extend_from_slice(&key.body);
            Sha256::digest(&framed).to_vec()
        }
        _ => return None,
    };
    Some(digest.iter().map(|b| format!("{b:02X}")).collect())
}

/// Split a key answer into armoured blocks, one per mailbox. The handler's two
/// front-ends and the drain's mail route all take a paste that may carry more
/// than one block, so the split is one function rather than three copies.
pub fn blocks(value: &str) -> Vec<String> {
    labelled_blocks(value)
        .into_iter()
        .map(|(_, block)| block)
        .collect()
}

/// Armoured blocks with the line above each, which is where the applicant names
/// the mailbox. A block's label is the nearest non-empty line before its BEGIN.
/// The line-ending rule is the shared parser's, so a bare CR cannot hide a
/// block from one caller and show it to another.
pub fn labelled_blocks(text: &str) -> Vec<(Option<String>, String)> {
    let lines: Vec<&str> = kyriakon_mailparse::lines(text.as_bytes())
        .map(|line| std::str::from_utf8(line.text).unwrap_or(""))
        .collect();
    let begin = BEGIN.as_bytes();
    let end = END.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if trim_bytes(lines[i].as_bytes()) != begin {
            i += 1;
            continue;
        }
        let label = lines[..i]
            .iter()
            .rev()
            .map(|line| line.trim())
            .find(|line| !line.is_empty())
            .map(str::to_string);
        let mut block = String::new();
        while i < lines.len() {
            block.push_str(lines[i].trim_end());
            block.push('\n');
            let done = trim_bytes(lines[i].as_bytes()) == end;
            i += 1;
            if done {
                break;
            }
        }
        out.push((label, block.trim().to_string()));
    }
    out
}

/// The base64 body of an armoured block: everything between the armour headers
/// (and the blank line after them) and the checksum or END line.
fn armour_body(value: &str) -> Result<String, Error> {
    let mut out = String::new();
    let mut started = false;
    for line in kyriakon_mailparse::lines(value.as_bytes()) {
        let line = std::str::from_utf8(line.text).unwrap_or("");
        if !started {
            if line.trim_start() == BEGIN {
                started = true;
            }
            continue;
        }
        let line = line.trim();
        if line == END || line.starts_with('=') {
            break;
        }
        if line.is_empty() || line.contains(':') {
            continue;
        }
        out.push_str(line);
    }
    if out.is_empty() {
        return Err(Error::ArmourNoMaterial);
    }
    Ok(out)
}

/// Walk the packet headers. `None` if a header is malformed or a partial length
/// is met, which is a structure this check does not read.
fn packets(raw: &[u8]) -> Option<Vec<Packet>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < raw.len() {
        let b = raw[i];
        if b & 0x80 == 0 {
            return None;
        }
        let (tag, len, hdr) = if b & 0x40 != 0 {
            // New-format header.
            let tag = b & 0x3f;
            let l1 = *raw.get(i + 1)? as usize;
            if l1 < 192 {
                (tag, l1, 2usize)
            } else if l1 < 224 {
                let l2 = *raw.get(i + 2)? as usize;
                (tag, ((l1 - 192) << 8) + l2 + 192, 3usize)
            } else if l1 == 255 {
                let l = u32::from_be_bytes([
                    *raw.get(i + 2)?,
                    *raw.get(i + 3)?,
                    *raw.get(i + 4)?,
                    *raw.get(i + 5)?,
                ]);
                (tag, l as usize, 6usize)
            } else {
                return None; // partial body length
            }
        } else {
            // Old-format header.
            let tag = (b >> 2) & 0x0f;
            let lt = b & 0x03;
            match lt {
                0 => (tag, *raw.get(i + 1)? as usize, 2usize),
                1 => (
                    tag,
                    u16::from_be_bytes([*raw.get(i + 1)?, *raw.get(i + 2)?]) as usize,
                    3usize,
                ),
                2 => {
                    let l = u32::from_be_bytes([
                        *raw.get(i + 1)?,
                        *raw.get(i + 2)?,
                        *raw.get(i + 3)?,
                        *raw.get(i + 4)?,
                    ]);
                    (tag, l as usize, 5usize)
                }
                _ => return None, // indeterminate length
            }
        };
        let start = i.checked_add(hdr)?;
        let end = start.checked_add(len)?;
        if end > raw.len() {
            return None;
        }
        out.push(Packet {
            tag,
            body: raw[start..end].to_vec(),
        });
        i = end;
    }
    Some(out)
}

/// Standard base64, padding optional at the end, whitespace ignored. `None` on
/// any character outside the alphabet or a length that cannot decode.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut n = 0u32;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        buf = (buf << 6) | u32::from(val(c)?);
        n += 1;
        if n == 4 {
            out.extend_from_slice(&[(buf >> 16) as u8, (buf >> 8) as u8, buf as u8]);
            buf = 0;
            n = 0;
        }
    }
    match n {
        0 => {}
        2 => out.push((buf >> 4) as u8),
        3 => {
            out.push((buf >> 10) as u8);
            out.push((buf >> 2) as u8);
        }
        // A single trailing character is six bits, which is not a byte, and is
        // not valid base64.
        _ => return None,
    }
    Some(out)
}

/// Standard base64 without padding, which is the form OpenSSH prints a
/// fingerprint in.
pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(A[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(A[n as usize & 63] as char);
        }
    }
    out
}

/// Verify `payload` with the public key in `key_file`, requiring gpg's
/// `VALIDSIG` fingerprint to equal `expected_fpr`. A valid signature by a key
/// hidden in the same block is not a signature by the key in use (#918).
/// `Ok(false)` is a signature that does not verify; `Err` is gpg failing to
/// run or the key not importing.
pub async fn verify_detached(
    gpg: &str,
    key_file: &Path,
    expected_fpr: &str,
    payload: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    let out = run_gpg(gpg, Some(key_file), Some(payload), |command, home| {
        let path = home.join("signature.asc");
        std::fs::write(&path, signature).map_err(|source| Error::WriteSignature {
            path: path.clone(),
            source,
        })?;
        command
            .args(["--status-fd", "2", "--verify"])
            .arg(&path)
            .arg("-");
        Ok(())
    })
    .await?;
    if !out.success {
        return Ok(false);
    }
    Ok(reports_expected(&out.stderr, expected_fpr))
}

/// Verify a clearsigned message and return only the plaintext GnuPG itself
/// emitted for it, alongside the fingerprint it reported. `Ok(None)` is a
/// message carrying no anchored clearsigned block; `Err` is framing that tries
/// to hide a block, a signature that does not verify, or gpg failing to run.
pub async fn verify_clearsigned(
    gpg: &str,
    key_file: &Path,
    expected_fpr: &str,
    message: &[u8],
) -> Result<Option<Clearsigned>, Error> {
    let Some(span) = clearsigned_span(message)? else {
        return Ok(None);
    };
    let block = &message[span];
    let out = run_gpg(gpg, Some(key_file), Some(block), |command, _home| {
        command.args(["--status-fd", "2", "--decrypt"]);
        Ok(())
    })
    .await?;
    if !out.success || !reports_expected(&out.stderr, expected_fpr) {
        return Err(Error::ClearsignedDoesNotVerify);
    }
    let fingerprint = valid_primary_fingerprints(&out.stderr)
        .into_iter()
        .next()
        .ok_or(Error::NoSigningFingerprint)?;
    let plaintext = String::from_utf8(out.stdout).map_err(|_| Error::ClearsignedNotUtf8)?;
    Ok(Some(Clearsigned {
        fingerprint,
        plaintext,
    }))
}

/// Encrypt `plaintext` to the cert in `key_file`, returning gpg's armoured
/// ciphertext. The runner drains the output while it writes, so a large export
/// cannot deadlock the drain (#929).
pub async fn encrypt_to_cert(
    gpg: &str,
    key_file: &Path,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let out = run_gpg(gpg, None, Some(plaintext), |command, _home| {
        command
            .args([
                "--encrypt",
                "--armor",
                "--no-encrypt-to",
                "--recipient-file",
            ])
            .arg(key_file);
        Ok(())
    })
    .await?;
    if !out.success {
        return Err(Error::Encrypt {
            path: key_file.to_path_buf(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(out.stdout)
}

/// The headers outside a clearsigned block, or a message's own headers when it
/// is not clearsigned.
pub fn outer_headers(message: &[u8]) -> Result<&[u8], Error> {
    match clearsigned_span(message)? {
        Some(span) => Ok(&message[..span.start]),
        None => message_headers(message),
    }
}

/// A message's header block, using the shared RFC 5322 split.
pub fn message_headers(message: &[u8]) -> Result<&[u8], Error> {
    kyriakon_mailparse::split_message(message)
        .map(|message| message.headers)
        .map_err(|source| Error::HeadersUnreadable { source })
}

fn clearsigned_span(message: &[u8]) -> Result<Option<std::ops::Range<usize>>, Error> {
    let lines: Vec<kyriakon_mailparse::Line<'_>> = kyriakon_mailparse::lines(message).collect();
    let begin = SIGNED_BEGIN.as_bytes();
    let end = SIGNED_END.as_bytes();
    // A client's clearsigned export is the block itself; its own `Hash:` line is
    // armour, not a message header.
    if let Some(first) = lines
        .iter()
        .position(|line| !trim_bytes(line.text).is_empty())
    {
        if trim_bytes(lines[first].text) == begin {
            return extract_signed(&lines, first, begin, end).map(Some);
        }
    }
    let split = match kyriakon_mailparse::split_message(message) {
        Ok(split) => split,
        Err(_) => {
            // A body line behind a separator the parser cannot see, with a real
            // block below it, is unsigned text before the block.
            let Some(block) = lines.iter().position(|line| trim_bytes(line.text) == begin) else {
                return Ok(None);
            };
            if let Some((index, _)) = lines[..block].iter().enumerate().find(|(_, line)| {
                !trim_bytes(line.text).is_empty()
                    && !matches!(line.text.first(), Some(b' ' | b'\t'))
                    && kyriakon_mailparse::headers(line.text).is_empty()
            }) {
                return Err(unsigned_text(index, &lines[index]));
            }
            return Err(unsigned_text(block, &lines[block]));
        }
    };
    let body_start = split.headers.len() + split.separator.len();
    let body: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.start >= body_start)
        .map(|(index, _)| index)
        .collect();
    if !body
        .iter()
        .any(|&index| trim_bytes(lines[index].text) == begin)
    {
        return Ok(None);
    }
    // A block below text that the header split folded into its header block is
    // still text no signature covers: every line before the blank line must be a
    // header or one of its continuations.
    if let Some((index, line)) = invalid_header_line(&lines, body_start) {
        return Err(unsigned_text(index, line));
    }
    let first = body
        .iter()
        .copied()
        .find(|&index| !trim_bytes(lines[index].text).is_empty());
    if let Some(first) = first {
        if trim_bytes(lines[first].text) == begin {
            if split
                .headers
                .windows(begin.len())
                .any(|window| window == begin)
            {
                return Err(Error::MarkerInsideHeader);
            }
            return extract_signed(&lines, first, begin, end).map(Some);
        }
    }
    if let Some(block) = body
        .iter()
        .copied()
        .find(|&index| trim_bytes(lines[index].text) == begin)
    {
        let index = first.unwrap_or(block);
        return Err(unsigned_text(index, &lines[index]));
    }
    Ok(None)
}

/// The first line before `end` that is neither a header nor a continuation of
/// one, using the shared header span scan so this check and the split agree.
fn invalid_header_line<'a>(
    lines: &'a [kyriakon_mailparse::Line<'a>],
    end: usize,
) -> Option<(usize, &'a kyriakon_mailparse::Line<'a>)> {
    let mut saw_header = false;
    for (index, line) in lines.iter().enumerate() {
        if line.start >= end {
            break;
        }
        if trim_bytes(line.text).is_empty() {
            continue;
        }
        if matches!(line.text.first(), Some(b' ' | b'\t')) {
            if saw_header {
                continue;
            }
            return Some((index, line));
        }
        if kyriakon_mailparse::headers(line.text).is_empty() {
            return Some((index, line));
        }
        saw_header = true;
    }
    None
}

fn extract_signed(
    lines: &[kyriakon_mailparse::Line<'_>],
    start: usize,
    begin: &[u8],
    end: &[u8],
) -> Result<std::ops::Range<usize>, Error> {
    let offset = lines[start].start;
    for (index, line) in lines.iter().enumerate().skip(start) {
        let text = trim_bytes(line.text);
        if index > start && text == begin {
            return Err(Error::SecondSignedMarker);
        }
        if text == end {
            return Ok(offset..line.next);
        }
    }
    Err(Error::SignedBlockNoEnd)
}

fn unsigned_text(index: usize, line: &kyriakon_mailparse::Line<'_>) -> Error {
    Error::UnsignedText {
        line: index + 1,
        text: std::str::from_utf8(line.text)
            .unwrap_or("")
            .chars()
            .take(80)
            .collect::<String>(),
    }
}

fn trim_bytes(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = bytes {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

/// The address in one header block's `From:`, with RFC 5322 continuation lines
/// unfolded first. `None` when the block carries no `From:`.
pub fn header_from(block: &[u8]) -> Result<Option<String>, Error> {
    // Only the header block is a source for `From:`. A body that quotes mail
    // can carry one too, and reading it would let quoted text name the sender.
    // A block the split cannot read has no header block to trust.
    let block = match kyriakon_mailparse::split_message(block) {
        Ok(message) => message.headers,
        Err(_) => return Ok(None),
    };
    let mut values = Vec::new();
    for header in kyriakon_mailparse::headers(block) {
        if header.is("from") {
            let value = String::from_utf8_lossy(header.value(block));
            values.push(value.split_whitespace().collect::<Vec<_>>().join(" "));
        }
    }
    let Some(value) = values.first() else {
        return Ok(None);
    };
    if values.len() > 1 {
        return Err(Error::MultipleFromHeaders);
    }
    let address = match (value.rfind('<'), value.rfind('>')) {
        (Some(open), Some(close)) if open < close => &value[open + 1..close],
        _ => value.as_str(),
    };
    if address.trim().is_empty() {
        return Err(Error::FromHeaderNoAddress);
    }
    Ok(Some(address.trim().to_string()))
}

/// The primary-key fingerprint in each `[GNUPG:] VALIDSIG ...` line. gpg puts
/// the signing key first, which is a subkey when one signed, and the primary
/// key last, which is the fingerprint the platform records.
fn valid_primary_fingerprints(status: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(status)
        .lines()
        .filter_map(|line| line.strip_prefix("[GNUPG:] VALIDSIG "))
        .filter_map(|rest| rest.split_whitespace().last())
        .map(str::to_string)
        .collect()
}

/// Every signature gpg reported must be by the expected key, and there must be
/// at least one: a second hidden signer cannot ride alongside the expected one.
fn reports_expected(status: &[u8], expected: &str) -> bool {
    let status_text = String::from_utf8_lossy(status);
    if status_text.lines().any(|line| {
        line.starts_with("[GNUPG:] BADSIG ")
            || line.starts_with("[GNUPG:] ERRSIG ")
            || line.starts_with("[GNUPG:] NO_PUBKEY ")
    }) {
        return false;
    }
    let expected = normalize_fingerprint(expected);
    let found = valid_primary_fingerprints(status);
    !found.is_empty()
        && !expected.is_empty()
        && found
            .iter()
            .all(|fingerprint| normalize_fingerprint(fingerprint) == expected)
}

fn normalize_fingerprint(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Output;

    use super::*;
    use crate::mail::keycheck::fixtures::{
        AEAD, CLEAN, EXPIRED_SUBKEY, NO_ENCRYPTION, PLATFORM_UID,
    };

    // A public key packet (tag 6, algo 18 ECDH) and a public subkey packet
    // (tag 14, algo 18): 16 bytes, the smallest thing with the structure of a
    // key. The fingerprint test below reads it; the three-condition checks use
    // the fixtures the prototype tested, because those rules live in its crate.
    const GOOD: &str = "mAYEAAAAABK4BgQAAAAAEg==";
    // One signature packet (tag 2, algo 18), no key packet at all.
    const NO_KEY: &str = "iAYEAAAAABI=";
    const SIGNED: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n\
                          From: Alice <alice@kyriakon.net>\n\nPlease send me a copy.\n\
                          -----BEGIN PGP SIGNATURE-----\n\nAAAA\n\
                          -----END PGP SIGNATURE-----\n";

    fn armoured(b64: &str) -> String {
        format!("{BEGIN}\n\n{b64}\n{END}\n")
    }

    #[test]
    fn helper_eof_does_not_cancel_its_deadline() {
        let home = ScratchHome::new().unwrap();
        let path = home.path().join("check");
        std::fs::write(&path, "#!/bin/sh\nexec 1>&-\nexec sleep 5\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            run_keygen_check(path.display().to_string(), "", 0, Duration::from_millis(50)),
            Err(Error::KeygenCheckTimedOut { .. })
        ));
    }

    #[test]
    fn keygen_protocol_rejects_truncated_blank_and_trailing_output() {
        assert!(matches!(
            parse_keygen_output("check", b"ok"),
            Err(Error::KeygenCheckProtocol { .. })
        ));
        assert!(matches!(
            parse_keygen_output("check", b"ok\n\n"),
            Err(Error::KeygenCheckProtocol { .. })
        ));
        assert!(matches!(
            parse_keygen_output("check", b"uninspected\nextra\n"),
            Err(Error::KeygenCheckProtocol { .. })
        ));
        assert!(matches!(
            parse_keygen_output("check", b"ok\n"),
            Ok(KeygenVerdict::Parsed(findings)) if findings.is_empty()
        ));
        assert!(matches!(
            parse_keygen_output("check", b"uninspected\n"),
            Ok(KeygenVerdict::Uninspected)
        ));
    }

    #[test]
    fn keygen_helper_gets_clean_env_and_bounded_stdout() {
        let home = ScratchHome::new().unwrap();
        let env_check = home.path().join("env-check");
        std::fs::write(
            &env_check,
            "#!/bin/sh\ncat >/dev/null\nif [ -n \"${HOME:-}\" ]; then echo leak; else echo ok; fi\n",
        )
        .unwrap();
        std::fs::set_permissions(&env_check, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            run_keygen_check(env_check.display().to_string(), "", 0, Duration::from_secs(2)),
            Ok(KeygenVerdict::Parsed(findings)) if findings.is_empty()
        ));

        let flood = home.path().join("flood");
        std::fs::write(
            &flood,
            "#!/bin/sh\ncat >/dev/null\necho ok\nhead -c 70000 /dev/zero | tr '\\0' x\necho\n",
        )
        .unwrap();
        std::fs::set_permissions(&flood, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            run_keygen_check(flood.display().to_string(), "", 0, Duration::from_secs(2)),
            Err(Error::KeygenCheckProtocol { .. })
        ));
    }

    #[test]
    fn the_generators_own_key_checks_clean() {
        let c = public_key(CLEAN).unwrap();
        assert_eq!(c.verdict, "works");
    }

    #[test]
    fn each_condition_carries_its_own_message_and_never_refuses() {
        let aead = public_key(AEAD).expect("a warning is not a refusal");
        assert!(aead.verdict.contains("AEAD"), "{}", aead.verdict);
        assert!(aead.verdict.contains("Remove AEAD"), "{}", aead.verdict);

        let no_encryption = public_key(NO_ENCRYPTION).expect("a warning is not a refusal");
        assert!(
            no_encryption
                .verdict
                .contains("no encryption-capable subkey"),
            "{}",
            no_encryption.verdict
        );

        let expired = public_key(EXPIRED_SUBKEY).expect("a warning is not a refusal");
        assert!(
            expired.verdict.contains("encryption subkey expired"),
            "{}",
            expired.verdict
        );
    }

    #[test]
    fn framing_and_base64_are_refused_with_a_reason() {
        assert!(matches!(
            public_key("hello").unwrap_err(),
            Error::NotArmoured
        ));
        let bad = armoured("not base64 !!!");
        assert!(matches!(
            public_key(&bad).unwrap_err(),
            Error::KeyBase64NotDecodable
        ));
    }

    #[test]
    fn a_block_with_no_public_key_packet_is_refused() {
        let e = public_key(&armoured(NO_KEY)).unwrap_err();
        assert!(matches!(&e, Error::NoPublicKeyPacket), "{e}");
    }

    #[test]
    fn a_framed_block_the_parser_cannot_read_warns_and_proceeds() {
        // `GOOD` has the framing and a public key packet, and nothing the
        // parser can understand. A refusal here would lose an application over
        // a gap in the check, so it is a warning with a reader named, and it is
        // marked uninspected so a caller that refuses findings lets it through.
        let c = public_key(&armoured(GOOD)).expect("a warning is not a refusal");
        assert!(
            c.verdict.contains("could not be inspected"),
            "{}",
            c.verdict
        );
        assert!(!c.inspected, "{}", c.verdict);

        let clean = public_key(CLEAN).unwrap();
        assert!(clean.inspected);
    }

    #[test]
    fn a_helper_that_cannot_run_is_the_advisory_with_its_error_kept() {
        // ADR 0008: a key this platform could not inspect must still proceed.
        // The operator learns why from the error the advisory carries, which is
        // the one thing the old catch-all dropped.
        let missing = public_key_with(
            "/nonexistent/keygen-check".to_string(),
            CLEAN,
            0,
            Duration::from_millis(50),
        )
        .expect("a helper that cannot run is not a framing refusal");
        assert!(!missing.inspected, "{}", missing.verdict);
        assert!(missing.refusal().is_none(), "{}", missing.verdict);
        assert!(
            matches!(missing.helper_error(), Some(Error::RunKeygenCheck { .. })),
            "{:?}",
            missing.helper_error()
        );

        let home = ScratchHome::new().unwrap();
        let path = home.path().join("check");
        std::fs::write(&path, "#!/bin/sh\nexit 3\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let failed = public_key_with(path.display().to_string(), CLEAN, 0, Duration::from_secs(2))
            .expect("a helper that exits non-zero is not a framing refusal");
        assert!(!failed.inspected);
        assert!(failed.refusal().is_none());
        assert!(
            matches!(failed.helper_error(), Some(Error::KeygenCheckExited { .. })),
            "{:?}",
            failed.helper_error()
        );
    }

    #[test]
    fn base64_round_trips() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(base64_decode("mAYEAAAAABK4BgQAAAAAEg==").unwrap().len(), 16);
        assert!(base64_decode("!!!!").is_none());
    }

    #[test]
    fn a_v4_fingerprint_is_the_hash_of_the_framed_key_packet() {
        // GOOD's key packet is six bytes: version 4, four bytes of creation time,
        // algorithm 18. Its fingerprint is the SHA-1 of 0x99, that length in two
        // bytes, and those six bytes, which is the number gpg prints for the same
        // packet.
        assert_eq!(
            fingerprint(&armoured(GOOD)).as_deref(),
            Some("E6EC346E2ADF3273FC2427550A3E4823302ED1D3")
        );
        // Not a key at all, and a packet of no version: no number to give.
        assert_eq!(fingerprint("hello"), None);
        assert_eq!(fingerprint(&armoured(NO_KEY)), None);
    }

    #[test]
    fn a_delivered_message_takes_its_from_outside_the_armour() {
        let message = format!(
            "From: Alice <alice@kyriakon.net>\nTo: admin@kyriakon.net\n\
             Subject: my data\n\n{SIGNED}"
        );
        let block = clearsigned_block(message.as_bytes()).unwrap().unwrap();
        assert!(block.starts_with(SIGNED_BEGIN.as_bytes()));
        assert!(!String::from_utf8_lossy(block).contains("Subject: my data"));
        assert_eq!(
            header_from(outer_headers(message.as_bytes()).unwrap()).unwrap(),
            Some("alice@kyriakon.net".to_string())
        );
    }

    #[test]
    fn a_folded_from_header_is_unfolded() {
        let headers = b"From: A Long Name\n <alice@kyriakon.net>\nTo: admin@kyriakon.net\n\n";
        assert_eq!(
            header_from(headers).unwrap(),
            Some("alice@kyriakon.net".to_string())
        );
    }

    /// A signed request can quote mail, so the body may carry a `From:` line.
    /// Only the header block before the blank line decides the sender.
    #[test]
    fn header_from_does_not_read_the_body() {
        let quoted =
            b"From: alice@kyriakon.net\nSubject: my data\n\n> From: quoted@example.invalid\n";
        assert_eq!(
            header_from(quoted).unwrap(),
            Some("alice@kyriakon.net".to_string())
        );
        let body_only = b"Subject: my data\n\nFrom: attacker@example.invalid\n";
        assert_eq!(header_from(body_only).unwrap(), None);
        // A block with content that is not a header has no header block to
        // trust, so a later From: is not read out of it.
        let no_separator = b"Hello\nFrom: attacker@example.invalid\n";
        assert_eq!(header_from(no_separator).unwrap(), None);
    }

    /// Unsigned request text between the headers and the armour is refused: gpg
    /// would verify the armour and the operator would record the text above it.
    #[test]
    fn unsigned_text_before_the_armour_is_refused() {
        let message = format!(
            "From: alice@kyriakon.net\nTo: admin@kyriakon.net\n\n\
             please delete my account and everything in it\n\n{SIGNED}"
        );
        let err = clearsigned_block(message.as_bytes()).unwrap_err();
        assert!(
            matches!(&err, Error::UnsignedText { text, .. }
                if text.contains("please delete my account")),
            "{err}"
        );
    }

    /// A colon-less line of request text is not a header even when the sender
    /// never writes the blank line that would end the header block.
    #[test]
    fn request_text_without_a_blank_line_is_refused() {
        let message = format!(
            "From: alice@kyriakon.net\n\
             please delete my account and everything in it\n\n{SIGNED}"
        );
        let err = clearsigned_block(message.as_bytes()).unwrap_err();
        assert!(
            matches!(&err, Error::UnsignedText { text, .. }
                if text.contains("please delete my account")),
            "{err}"
        );
    }

    /// #924: a marker hidden inside a header line, a forged signature line, and
    /// a real clearsigned block below it. gpg skips the malformed marker and
    /// verifies the real block; a substring split then printed only the forged
    /// request. The marker must be a complete line, and the forged text above
    /// the real block is refused before gpg runs.
    #[test]
    fn a_forged_armour_marker_inside_a_header_cannot_frame_unsigned_text() {
        let forged = "From: alice@kyriakon.net\n\
                      Subject: req -----BEGIN PGP SIGNED MESSAGE-----x\n\
                      \n\
                      Please erase my account immediately!\n\
                      -----BEGIN PGP SIGNATURE-----x\n\
                      \n";
        let message = format!("{forged}{SIGNED}");
        let err = clearsigned_block(message.as_bytes()).unwrap_err();
        assert!(
            matches!(&err, Error::UnsignedText { text, .. }
                if text.contains("Please erase my account immediately!")),
            "{err}"
        );
    }

    /// A client's clearsigned export has no headers outside the armour: the
    /// whole file is the block, and its own `From:` is inside it.
    #[test]
    fn a_clearsigned_export_is_the_whole_block() {
        let block = clearsigned_block(SIGNED.as_bytes()).unwrap().unwrap();
        assert_eq!(block, SIGNED.as_bytes());
        assert!(outer_headers(SIGNED.as_bytes()).unwrap().is_empty());
    }

    /// A clearsigned block with a second marker before its end is refused
    /// rather than read to whichever signature came first.
    #[test]
    fn a_nested_clearsigned_marker_is_refused() {
        let message = format!("{SIGNED}\n{SIGNED}");
        let block = clearsigned_block(message.as_bytes()).unwrap().unwrap();
        assert_eq!(block, SIGNED.as_bytes());
        let nested = format!("{SIGNED_BEGIN}\nHash: SHA512\n\n{SIGNED}");
        let err = clearsigned_block(nested.as_bytes()).unwrap_err();
        assert!(matches!(&err, Error::SecondSignedMarker), "{err}");
    }

    /// Two exported certs decoded and concatenated into one armour block, so
    /// the test depends on the packet shape rather than on how one gpg version
    /// groups a multi-key export.
    fn two_primary_block(first: &str, second: &str) -> String {
        let mut raw = base64_decode(&armour_body(first).unwrap()).unwrap();
        raw.extend(base64_decode(&armour_body(second).unwrap()).unwrap());
        format!("{BEGIN}\n\n{}\n{END}\n", base64_encode(&raw))
    }

    fn clearsigned_block(message: &[u8]) -> Result<Option<&[u8]>, Error> {
        clearsigned_span(message).map(|span| span.map(|span| &message[span]))
    }

    struct Home(PathBuf);

    struct Key {
        public: String,
        fingerprint: String,
    }

    impl Home {
        fn new() -> Self {
            let home = PathBuf::from("/tmp").join(format!("pgpt{}", ulid::Ulid::new()));
            std::fs::create_dir_all(&home).unwrap();
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(home)
        }

        fn run(&self, args: &[&str]) -> Output {
            std::process::Command::new("gpg")
                .env("GNUPGHOME", &self.0)
                .args(args)
                .output()
                .expect("gpg is on PATH")
        }

        fn key(&self, usage: &str) -> Key {
            let uid = format!("pgp test <{}@example.invalid>", ulid::Ulid::new());
            let generated = self.run(&[
                "--batch",
                "--no-tty",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                &uid,
                "rsa2048",
                usage,
                "0",
            ]);
            assert!(
                generated.status.success(),
                "key generation failed: {}",
                String::from_utf8_lossy(&generated.stderr)
            );
            let listing = self.run(&[
                "--batch",
                "--no-tty",
                "--with-colons",
                "--fingerprint",
                &uid,
            ]);
            let fingerprint = String::from_utf8_lossy(&listing.stdout)
                .lines()
                .find_map(|line| line.strip_prefix("fpr:::::::::"))
                .and_then(|rest| rest.split(':').next())
                .expect("gpg prints the new key's fingerprint")
                .to_string();
            let export = self.run(&["--batch", "--no-tty", "--armor", "--export", &fingerprint]);
            assert!(export.status.success(), "the key could not be exported");
            Key {
                public: String::from_utf8(export.stdout).unwrap(),
                fingerprint,
            }
        }

        /// A certify-only primary with a signing subkey, the ordinary shape of
        /// a mail certificate. gpg reports the subkey first in VALIDSIG and the
        /// primary last, which is the fingerprint the platform records.
        fn key_with_signing_subkey(&self) -> Key {
            let primary = self.key("cert");
            let added = self.run(&[
                "--batch",
                "--no-tty",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-add-key",
                &primary.fingerprint,
                "rsa2048",
                "sign",
                "0",
            ]);
            assert!(
                added.status.success(),
                "signing subkey generation failed: {}",
                String::from_utf8_lossy(&added.stderr)
            );
            let export = self.run(&[
                "--batch",
                "--no-tty",
                "--armor",
                "--export",
                &primary.fingerprint,
            ]);
            assert!(export.status.success(), "the key could not be exported");
            Key {
                public: String::from_utf8(export.stdout).unwrap(),
                fingerprint: primary.fingerprint,
            }
        }

        fn sign(&self, key: &Key, payload: &[u8]) -> Vec<u8> {
            let payload_path = self.0.join(format!("payload-{}", ulid::Ulid::new()));
            std::fs::write(&payload_path, payload).unwrap();
            let signature = self.0.join(format!("signature-{}", ulid::Ulid::new()));
            let signed = self.run(&[
                "--batch",
                "--no-tty",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--armor",
                "--local-user",
                &key.fingerprint,
                "--output",
                signature.to_str().unwrap(),
                "--detach-sign",
                payload_path.to_str().unwrap(),
            ]);
            assert!(
                signed.status.success(),
                "signing failed: {}",
                String::from_utf8_lossy(&signed.stderr)
            );
            std::fs::read(signature).unwrap()
        }

        fn clearsign(&self, key: &Key, payload: &[u8]) -> Vec<u8> {
            let payload_path = self.0.join(format!("payload-{}", ulid::Ulid::new()));
            std::fs::write(&payload_path, payload).unwrap();
            let signature = self.0.join(format!("signature-{}", ulid::Ulid::new()));
            let signed = self.run(&[
                "--batch",
                "--no-tty",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--local-user",
                &key.fingerprint,
                "--output",
                signature.to_str().unwrap(),
                "--clearsign",
                payload_path.to_str().unwrap(),
            ]);
            assert!(
                signed.status.success(),
                "clearsigning failed: {}",
                String::from_utf8_lossy(&signed.stderr)
            );
            std::fs::read(signature).unwrap()
        }

        fn cert(&self, block: &str) -> PathBuf {
            let path = self.0.join(format!("cert-{}", ulid::Ulid::new()));
            std::fs::write(&path, block).unwrap();
            path
        }
    }

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// #929: a 512 KiB uncompressible payload through the concurrent-drain
    /// runner must not deadlock on gpg's output pipe.
    #[tokio::test]
    async fn a_large_payload_encrypts_without_filling_a_pipe() {
        let home = Home::new();
        let recipient = home.key("encr");
        let cert = home.cert(&recipient.public);
        let mut state = 0x1234_5678u32;
        let mut payload = Vec::with_capacity(512 * 1024);
        for _ in 0..512 * 1024 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            payload.push((state >> 24) as u8);
        }
        let ciphertext = tokio::time::timeout(
            Duration::from_secs(20),
            encrypt_to_cert("gpg", &cert, &payload),
        )
        .await
        .expect("encryption finishes")
        .expect("gpg encrypts");
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));
        assert!(
            ciphertext.len() > 400 * 1024,
            "the armour carries the whole payload: {}",
            ciphertext.len()
        );
    }

    /// #918: one armour block carrying two primary keys is refused, because the
    /// whole material would be installed while one fingerprint is shown.
    #[test]
    fn one_armour_block_with_two_primary_keys_is_refused() {
        let home = Home::new();
        let first = home.key("sign");
        let second = home.key("sign");
        let block = two_primary_block(&first.public, &second.public);
        let err = inspect_single_cert(&block).unwrap_err();
        assert!(matches!(&err, Error::MultiplePrimaryKeys), "{err}");
        assert_eq!(fingerprint(&block), None);
        assert!(public_key(&block).is_err());
    }

    /// #918: a valid signature by a second key in the same block is not a
    /// signature by the expected key.
    #[tokio::test]
    async fn verify_detached_requires_the_expected_fingerprint() {
        let home = Home::new();
        let expected = home.key("sign");
        let hidden = home.key("sign");
        // Two clean blocks, one per key: the point here is the expected
        // fingerprint, and `inspect_single_cert` covers the one-block case.
        let block = format!("{}\n{}", expected.public, hidden.public);
        let cert = home.cert(&block);
        let payload = b"the pending key's fingerprint";

        let hidden_signature = home.sign(&hidden, payload);
        assert!(
            !verify_detached(
                "gpg",
                &cert,
                &expected.fingerprint,
                payload,
                &hidden_signature
            )
            .await
            .unwrap(),
            "the hidden key signed as though it were the expected one"
        );
        let expected_signature = home.sign(&expected, payload);
        assert!(verify_detached(
            "gpg",
            &cert,
            &expected.fingerprint,
            payload,
            &expected_signature
        )
        .await
        .unwrap());
    }

    /// A certificate commonly signs with a subkey. VALIDSIG names the signing
    /// subkey first and the primary last, and the platform records the primary,
    /// so verification must compare the last field.
    #[tokio::test]
    async fn a_signature_by_a_signing_subkey_matches_the_primary_fingerprint() {
        let home = Home::new();
        let signer = home.key_with_signing_subkey();
        let cert = home.cert(&signer.public);
        let payload = b"the pending key's fingerprint\n";

        let signature = home.sign(&signer, payload);
        assert!(
            verify_detached("gpg", &cert, &signer.fingerprint, payload, &signature)
                .await
                .unwrap()
        );

        let signed = home.clearsign(&signer, payload);
        let verified = verify_clearsigned("gpg", &cert, &signer.fingerprint, &signed)
            .await
            .unwrap()
            .expect("the clearsigned message verifies");
        assert_eq!(verified.plaintext.as_bytes(), payload);
        assert_eq!(verified.fingerprint, signer.fingerprint);
    }

    /// #918 and #960: only gpg's verified plaintext is returned, and a forged
    /// marker that gpg would skip past is refused before it runs.
    #[tokio::test]
    async fn verify_clearsigned_returns_only_gpg_plaintext_for_the_expected_key() {
        let home = Home::new();
        let signer = home.key("sign");
        let cert = home.cert(&signer.public);
        let payload = b"Hello, I like tea.\n";
        let signed = home.clearsign(&signer, payload);

        let message = format!(
            "From: alice@kyriakon.net\nSubject: my data\n\n{}",
            String::from_utf8(signed.clone()).unwrap()
        );
        let verified = verify_clearsigned("gpg", &cert, &signer.fingerprint, message.as_bytes())
            .await
            .unwrap()
            .expect("the real block verifies");
        assert_eq!(verified.plaintext.as_bytes(), payload);
        assert_eq!(verified.fingerprint, signer.fingerprint);

        let forged = format!(
            "From: alice@kyriakon.net\n\
             Subject: req -----BEGIN PGP SIGNED MESSAGE-----x\n\
             \n\
             Please erase my account immediately!\n\
             -----BEGIN PGP SIGNATURE-----x\n\
             \n{}",
            String::from_utf8(signed.clone()).unwrap()
        );
        let err = verify_clearsigned("gpg", &cert, &signer.fingerprint, forged.as_bytes())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::UnsignedText { text, .. }
                if text.contains("Please erase my account immediately!")),
            "{err}"
        );

        // A valid signature by another key is not the expected one.
        let other = home.key("sign");
        let other_signed = home.clearsign(&other, payload);
        let err = verify_clearsigned("gpg", &cert, &signer.fingerprint, &other_signed)
            .await
            .unwrap_err();
        assert!(matches!(&err, Error::ClearsignedDoesNotVerify), "{err}");
    }

    #[test]
    fn a_uid_warning_is_not_a_refusal() {
        assert!(uid_warnings(PLATFORM_UID, "alice@kyriakon.net").is_empty());
        assert!(!uid_warnings(CLEAN, "spike@kyriakon.net").is_empty());
    }
}
