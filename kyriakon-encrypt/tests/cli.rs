//! Tests for kyriakon-encrypt via its stdin/stdout seam and its unix socket.
//!
//! A throwaway keypair is generated in a temp GNUPGHOME (never in the repo);
//! the armored public cert is exported to `keyring/alice.asc`, mirroring the
//! on-box keyring layout. All assertions are observable behavior: ciphertext
//! round-trips to the exact input, `+tag` resolves to the base localpart,
//! missing/invalid recipients fail closed with no output.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_kyriakon-encrypt");

const MESSAGE: &[u8] = b"From: alice@example.invalid
To: bob@example.invalid
Subject: test \xe2\x98\x95
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello, this is a test body.
Line 2: caf\xc3\xa9 \xe2\x98\x95
";

struct TestEnv {
    gpg_home: PathBuf,
    keyring: PathBuf,
}

impl TestEnv {
    fn get() -> &'static TestEnv {
        static ENV: OnceLock<TestEnv> = OnceLock::new();
        ENV.get_or_init(|| {
            let root = std::env::temp_dir().join(format!(
                "kt{}-{:x}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let gpg_home = root.join("gnupg");
            let keyring = root.join("keyring");
            std::fs::create_dir_all(&gpg_home).unwrap();
            std::fs::create_dir_all(&keyring).unwrap();
            // gpg refuses to use a world-writable homedir.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&gpg_home, std::fs::Permissions::from_mode(0o700)).unwrap();

            // No-passphrase encrypt-only key, 2048-bit RSA (fast to generate).
            let gen = Command::new("gpg")
                .env("GNUPGHOME", &gpg_home)
                .args([
                    "--batch",
                    "--no-tty",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--quick-generate-key",
                    "kyriakon test <test@example.invalid>",
                    "rsa2048",
                    "encr",
                    "0",
                ])
                .output()
                .expect("gpg available");
            assert!(
                gen.status.success(),
                "keygen failed: {}",
                String::from_utf8_lossy(&gen.stderr)
            );

            let export = Command::new("gpg")
                .env("GNUPGHOME", &gpg_home)
                .args([
                    "--batch",
                    "--no-tty",
                    "--armor",
                    "--export",
                    "test@example.invalid",
                ])
                .output()
                .expect("gpg available");
            assert!(export.status.success(), "key export failed");
            std::fs::write(keyring.join("alice.asc"), &export.stdout).unwrap();

            TestEnv { gpg_home, keyring }
        })
    }

    /// Decrypt armored ciphertext with the throwaway private key.
    fn decrypt(&self, armor: &[u8]) -> Vec<u8> {
        let mut child = Command::new("gpg")
            .env("GNUPGHOME", &self.gpg_home)
            .args(["--batch", "--no-tty", "--decrypt"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(armor).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "decrypt failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }
}

fn encrypt_seam(env: &TestEnv, user: &str) -> (bool, Vec<u8>) {
    let mut child = Command::new(BIN)
        .args(["encrypt", "--user", user, "--keyring"])
        .arg(&env.keyring)
        .arg("--gpg-home")
        .arg(&env.gpg_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(MESSAGE).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.success(), out.stdout)
}

/// Extract the `application/octet-stream` part (the armored ciphertext) from
/// a `multipart/encrypted` envelope.
fn octet_stream(envelope: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(envelope);
    let start = text
        .find("Content-Type: application/octet-stream\n\n")
        .unwrap_or_else(|| panic!("no octet-stream part in:\n{text}"))
        + "Content-Type: application/octet-stream\n\n".len();
    let boundary = text
        .split("boundary=\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .expect("boundary");
    let end = text[start..]
        .find(&format!("\n--{boundary}--"))
        .map(|i| start + i)
        .expect("closing boundary");
    text[start..end].as_bytes().to_vec()
}

fn assert_valid_envelope(envelope: &[u8]) {
    let head = String::from_utf8_lossy(&envelope[..envelope.len().min(300)]);
    assert!(
        head.starts_with(
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";"
        ),
        "not multipart/encrypted:\n{head}"
    );
    assert!(
        head.contains("Content-Type: application/pgp-encrypted"),
        "missing version part"
    );
    assert!(head.contains("Version: 1"), "missing Version: 1");
}

#[test]
fn encrypts_whole_message_round_trip() {
    let env = TestEnv::get();
    let (ok, out) = encrypt_seam(env, "alice");
    assert!(ok, "encrypt failed for alice");
    assert_valid_envelope(&out);
    // Outer envelope must not leak message headers.
    let outer = String::from_utf8_lossy(&out);
    assert!(
        !outer.contains("Subject:"),
        "plaintext headers leaked into envelope"
    );
    // Ciphertext decrypts to the exact input - headers and body.
    assert_eq!(env.decrypt(&octet_stream(&out)), MESSAGE);
}

#[test]
fn plus_tag_resolves_to_base_localpart() {
    let env = TestEnv::get();
    let (ok, out) = encrypt_seam(env, "alice+work");
    assert!(ok, "encrypt failed for alice+work");
    assert_eq!(env.decrypt(&octet_stream(&out)), MESSAGE);
}

#[test]
fn missing_key_fails_closed() {
    let env = TestEnv::get();
    let (ok, out) = encrypt_seam(env, "nobody");
    assert!(!ok, "missing key must fail");
    assert!(
        out.is_empty(),
        "no output on failure, got {} bytes",
        out.len()
    );
}

#[test]
fn traversal_user_rejected() {
    let env = TestEnv::get();
    let (ok, out) = encrypt_seam(env, "../x");
    assert!(!ok, "path-traversal user must fail");
    assert!(out.is_empty());
}

#[test]
fn daemon_serves_over_unix_socket() {
    let env = TestEnv::get();
    let socket = env.keyring.parent().unwrap().join("encrypt.sock");
    let mut child = Command::new(BIN)
        .args(["serve", "--socket"])
        .arg(&socket)
        .arg("--keyring")
        .arg(&env.keyring)
        .arg("--gpg-home")
        .arg(&env.gpg_home)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Wait for the socket to appear.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not create socket");
        std::thread::sleep(Duration::from_millis(20));
    }

    let request = |user: &str| -> Vec<u8> {
        let mut conn = UnixStream::connect(&socket).unwrap();
        conn.write_all(format!("{user}\n").as_bytes()).unwrap();
        conn.write_all(MESSAGE).unwrap();
        conn.shutdown(std::net::Shutdown::Write).unwrap();
        let mut resp = Vec::new();
        conn.read_to_end(&mut resp).unwrap();
        resp
    };

    let ok = request("alice+tag");
    assert_valid_envelope(&ok);
    assert_eq!(env.decrypt(&octet_stream(&ok)), MESSAGE);

    // Fail-closed over the socket: empty response for a missing key.
    assert!(
        request("nobody").is_empty(),
        "missing key must yield empty response"
    );

    child.kill().unwrap();
    child.wait().unwrap();
}
