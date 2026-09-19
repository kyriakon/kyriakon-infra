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

            // No-passphrase encrypt-only keys, 2048-bit RSA (fast to generate).
            // Two of them: alice for the recipient under test, and a second key
            // so a message encrypted to someone else can be told apart from an
            // envelope of ours.
            let make_key = |uid: &str, file: &str| {
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
                        uid,
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
                    .args(["--batch", "--no-tty", "--armor", "--export", uid])
                    .output()
                    .expect("gpg available");
                assert!(export.status.success(), "key export failed");
                std::fs::write(keyring.join(file), &export.stdout).unwrap();
            };
            make_key("kyriakon test <test@example.invalid>", "alice.asc");
            make_key("kyriakon second <second@example.invalid>", "bob.asc");

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
    encrypt_seam_input(env, user, MESSAGE)
}

/// The same seam with the caller's bytes, so a test can feed it ciphertext.
fn encrypt_seam_input(env: &TestEnv, user: &str, input: &[u8]) -> (bool, Vec<u8>) {
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
    child.stdin.take().unwrap().write_all(input).unwrap();
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

/// What the ciphertext must decrypt to: the original message with the
/// protected-headers parameter added to its Content-Type, which is what tells a
/// client where the real headers are.
fn expected_payload() -> String {
    String::from_utf8_lossy(MESSAGE).replace(
        "Content-Type: text/plain; charset=utf-8\n",
        "Content-Type: text/plain; charset=utf-8; protected-headers=\"v1\"\n",
    )
}

fn assert_valid_envelope(envelope: &[u8]) {
    let text = String::from_utf8_lossy(envelope);
    assert!(
        text.starts_with(
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";"
        ),
        "not multipart/encrypted:\n{text}"
    );
    assert!(
        text.contains("\nContent-Type: application/pgp-encrypted\n"),
        "missing version part"
    );
    assert!(text.contains("\nVersion: 1\n"), "missing Version: 1");
    // Exposed headers come first, so the version part is not within any fixed
    // prefix of the envelope; scan the whole thing.
    assert!(
        !text.contains("\nContent-Type: text/plain"),
        "the payload's Content-Type leaked into the wrapper"
    );
}

#[test]
fn encrypts_whole_message_round_trip() {
    let env = TestEnv::get();
    let (ok, out) = encrypt_seam(env, "alice");
    assert!(ok, "encrypt failed for alice");
    assert_valid_envelope(&out);

    // The wrapper carries the envelope metadata a mail store cannot hide and a
    // subject placeholder. The real subject and the body stay in the payload.
    let outer = String::from_utf8_lossy(&out);
    assert!(
        outer.contains("From: alice@example.invalid\n"),
        "a client reads the sender from the wrapper"
    );
    assert!(
        outer.contains("Subject: ...\n"),
        "expected a subject placeholder in the wrapper"
    );
    assert!(
        !outer.contains("test \u{2615}"),
        "the real subject leaked into the wrapper"
    );
    assert!(
        !outer.contains("Hello, this is a test body."),
        "the body leaked into the wrapper"
    );

    // Ciphertext decrypts to the whole message, marked protected.
    assert_eq!(
        env.decrypt(&octet_stream(&out)),
        expected_payload().as_bytes(),
        "payload must carry the message plus the protected-headers parameter"
    );
}

#[test]
fn plus_tag_resolves_to_base_localpart() {
    let env = TestEnv::get();
    let (ok, out) = encrypt_seam(env, "alice+work");
    assert!(ok, "encrypt failed for alice+work");
    assert_eq!(
        env.decrypt(&octet_stream(&out)),
        expected_payload().as_bytes()
    );
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
fn resaving_our_own_envelope_does_not_encrypt_it_again() {
    let env = TestEnv::get();
    let (ok, envelope) = encrypt_seam(env, "alice");
    assert!(ok, "encrypt failed for alice");
    assert_valid_envelope(&envelope);

    // What a client re-uploading a message does to it: ciphertext goes back
    // through the save path. It has to come back untouched, one layer deep, or
    // a client decrypting once shows an encrypted blob instead of the mail.
    let (ok, again) = encrypt_seam_input(env, "alice", &envelope);
    assert!(ok, "re-saving our own ciphertext must succeed");
    assert_eq!(again, envelope, "the envelope must come back byte for byte");
    assert_eq!(
        env.decrypt(&octet_stream(&again)),
        expected_payload().as_bytes(),
        "one decrypt must yield the message, not another envelope"
    );
}

#[test]
fn a_lookalike_for_another_key_is_still_encrypted() {
    let env = TestEnv::get();
    // A real envelope, but for bob. It carries the marker, so only the key id
    // separates it from ours, and skipping on the marker alone would store a
    // sender's file unencrypted.
    let (ok, for_bob) = encrypt_seam(env, "bob");
    assert!(ok, "encrypt failed for bob");

    let (ok, for_alice) = encrypt_seam_input(env, "alice", &for_bob);
    assert!(ok, "encrypting a lookalike must succeed");
    assert_ne!(for_alice, for_bob, "it is encrypted again, not skipped");
    assert_valid_envelope(&for_alice);

    let inner = octet_stream(&for_bob);
    let payload = env.decrypt(&octet_stream(&for_alice));
    assert!(
        payload.windows(inner.len()).any(|w| w == inner),
        "the other key's ciphertext belongs inside the new envelope"
    );
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
    assert_eq!(
        env.decrypt(&octet_stream(&ok)),
        expected_payload().as_bytes()
    );

    // Fail-closed over the socket: empty response for a missing key.
    assert!(
        request("nobody").is_empty(),
        "missing key must yield empty response"
    );

    child.kill().unwrap();
    child.wait().unwrap();
}
