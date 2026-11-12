//! Tests for kyriakon-encrypt via its stdin/stdout seam, the one the Dovecot
//! save path runs.
//!
//! A throwaway keypair is generated in a temp GNUPGHOME (never in the repo);
//! the armored public cert is exported to `keyring/alice.asc`, mirroring the
//! on-box keyring layout. All assertions are observable behavior: ciphertext
//! round-trips to the exact input, `+tag` resolves to the base localpart,
//! missing/invalid recipients fail closed with no output.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

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
    encrypt_seam_input(env, user, MESSAGE, &env.gpg_home)
}

/// The same seam with the caller's bytes and a chosen gpg homedir, so a test
/// can feed it ciphertext and give it the homedir the save path really has.
fn encrypt_seam_input(
    env: &TestEnv,
    user: &str,
    input: &[u8],
    gpg_home: &std::path::Path,
) -> (bool, Vec<u8>) {
    let mut child = Command::new(BIN)
        .args(["encrypt", "--user", user, "--keyring"])
        .arg(&env.keyring)
        .arg("--gpg-home")
        .arg(gpg_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.success(), out.stdout)
}

/// A gpg homedir with no secret keys, which is what the save path has in
/// production: the plugin's own fresh scratch directory. A test that hands the
/// encryptor the keyring's own homedir instead lets gpg decrypt, and anything
/// reading that dump then behaves differently from the deployed save path.
fn scratch_gpg_home(env: &TestEnv) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = env.keyring.parent().unwrap().join("scratch-gnupg");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
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
    // through the save path, and the encryptor's own scratch homedir holds no
    // secret key, which is what gpg sees in production.
    let (ok, again) = encrypt_seam_input(env, "alice", &envelope, &scratch_gpg_home(env));
    assert!(ok, "re-saving our own ciphertext must succeed");
    assert_valid_envelope(&again);
    assert_eq!(
        octet_stream(&again),
        octet_stream(&envelope),
        "the ciphertext must come back untouched"
    );
    assert_eq!(
        env.decrypt(&octet_stream(&again)),
        expected_payload().as_bytes(),
        "one decrypt must yield the message, not another envelope"
    );
    let text = String::from_utf8_lossy(&again);
    assert_eq!(
        text.matches("Content-Type: multipart/encrypted;").count(),
        1,
        "a single layer:\n{text}"
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

    let (ok, for_alice) = encrypt_seam_input(env, "alice", &for_bob, &scratch_gpg_home(env));
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
fn a_plaintext_message_carrying_ciphertext_is_encrypted() {
    let env = TestEnv::get();
    // First line is the marker and an attachment is real ciphertext for alice,
    // so a scan for the marker and the key id anywhere in the stream would
    // store this message in the clear: subject, body and all.
    let (ok, inner) = encrypt_seam(env, "alice");
    assert!(ok, "encrypt failed for alice");
    let mut msg = b"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\n\
        \tboundary=\"outer\"\n\
        From: alice@example.invalid\n\
        Subject: forwarded in the clear\n\
        MIME-Version: 1.0\n\
        Content-Type: multipart/mixed; boundary=\"fwd\"\n\
        \n\
        --fwd\n\
        Content-Type: text/plain\n\
        \n\
        the plaintext body\n\
        --fwd\n\
        Content-Type: message/rfc822\n\
        \n"
    .to_vec();
    msg.extend_from_slice(&inner);
    msg.extend_from_slice(b"\n--fwd--\n");

    let (ok, out) = encrypt_seam_input(env, "alice", &msg, &scratch_gpg_home(env));
    assert!(ok, "the message must be encrypted");
    assert_ne!(out, msg, "it is a message, not an envelope of ours");
    assert_valid_envelope(&out);
    let payload = env.decrypt(&octet_stream(&out));
    assert!(
        payload
            .windows(b"the plaintext body".len())
            .any(|w| w == b"the plaintext body"),
        "the whole message must be the payload"
    );
}

#[test]
fn a_message_with_plaintext_in_its_version_part_is_encrypted() {
    let env = TestEnv::get();
    let (ok, real) = encrypt_seam(env, "alice");
    assert!(ok, "encrypt failed for alice");
    let armor = octet_stream(&real);

    // Everything outside the octet-stream part is stored in the clear, so the
    // version part is the place to hide plaintext. Only the fixed
    // application/pgp-encrypted part with Version: 1 is an envelope.
    let boundary = "kt511-version";
    let mut msg = format!(
        "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\n\
         \tboundary=\"{boundary}\"\n\
         From: alice@example.invalid\n\
         Subject: plaintext in the version part\n\
         MIME-Version: 1.0\n\
         \n\
         This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156).\n\
         \n\
         --{boundary}\n\
         Content-Type: text/plain\n\
         \n\
         the secret body\n\
         --{boundary}\n\
         Content-Type: application/octet-stream\n\
         \n"
    )
    .into_bytes();
    msg.extend_from_slice(&armor);
    msg.extend_from_slice(format!("\n--{boundary}--\n").as_bytes());

    let (ok, out) = encrypt_seam_input(env, "alice", &msg, &scratch_gpg_home(env));
    assert!(ok, "the message must be encrypted");
    assert_ne!(out, msg, "a text/plain version part is not an envelope");
    assert_valid_envelope(&out);
    let payload = env.decrypt(&octet_stream(&out));
    assert!(
        payload
            .windows(b"the secret body".len())
            .any(|w| w == b"the secret body"),
        "the plaintext part must be inside the ciphertext"
    );
}

#[test]
fn a_message_with_a_foreign_preamble_is_resaved_without_it() {
    let env = TestEnv::get();
    let (ok, real) = encrypt_seam(env, "alice");
    assert!(ok, "encrypt failed for alice");

    // An external client's own preamble is normal inbound PGP/MIME. The rebuild
    // replaces it, so whatever it held is not stored in the clear and the
    // ciphertext keeps its one layer.
    let text = String::from_utf8(real).expect("envelope is ASCII");
    let foreign = text.replacen(
        "This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156).",
        "hidden plaintext in the preamble",
        1,
    );
    assert_ne!(foreign, text, "the preamble was replaced");
    let foreign = foreign.into_bytes();

    let (ok, out) = encrypt_seam_input(env, "alice", &foreign, &scratch_gpg_home(env));
    assert!(ok, "the message must be saved");
    assert_valid_envelope(&out);
    assert!(
        !String::from_utf8_lossy(&out).contains("hidden plaintext in the preamble"),
        "the preamble must not stay in the clear"
    );
    assert_eq!(
        env.decrypt(&octet_stream(&out)),
        expected_payload().as_bytes(),
        "the ciphertext is untouched"
    );
}

#[test]
fn an_inbound_pgp_mime_message_is_not_encrypted_again() {
    let env = TestEnv::get();
    let (ok, real) = encrypt_seam(env, "alice");
    assert!(ok, "encrypt failed for alice");
    let armor = octet_stream(&real);

    // What arrives from smtpd for external PGP/MIME: transport headers and a
    // plaintext Subject before Content-Type, and the sender's own preamble.
    let boundary = "kt592-inbound";
    let mut inbound = format!(
        "Return-Path: <sender@example.invalid>\n\
         Received: from mx.example.invalid by kyriakon.net\n\
         Subject: inbound plaintext subject\n\
         Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\n\
         \tboundary=\"{boundary}\"\n\
         MIME-Version: 1.0\n\
         \n\
         Sender's own preamble.\n\
         \n\
         --{boundary}\n\
         Content-Type: application/pgp-encrypted\n\
         \n\
         Version: 1\n\
         \n\
         --{boundary}\n\
         Content-Type: application/octet-stream\n\
         \n"
    )
    .into_bytes();
    inbound.extend_from_slice(&armor);
    inbound.extend_from_slice(format!("\n--{boundary}--\n").as_bytes());

    let (ok, out) = encrypt_seam_input(env, "alice", &inbound, &scratch_gpg_home(env));
    assert!(ok, "the inbound message must be saved");
    assert_valid_envelope(&out);

    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("Subject: ...\n"), "{text}");
    for leaked in [
        "inbound plaintext subject",
        "Return-Path",
        "Sender's own preamble",
    ] {
        assert!(!text.contains(leaked), "{leaked} leaked:\n{text}");
    }
    assert_eq!(
        octet_stream(&out),
        armor,
        "the inbound ciphertext keeps its single layer"
    );
    assert_eq!(
        env.decrypt(&octet_stream(&out)),
        expected_payload().as_bytes(),
        "one decrypt yields the message"
    );
}

#[test]
fn a_failed_stdout_write_is_a_failed_save() {
    let env = TestEnv::get();

    // The save path reads stdout to EOF and treats exit 0 as "every byte
    // arrived", so a write nobody reads has to fail. The shell ignores SIGPIPE
    // before exec, so the CLI sees EPIPE and has to report it instead of dying
    // on a signal, which is the branch under test.
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("trap '' 13; exec \"$0\" \"$@\"")
        .arg(BIN)
        .args(["encrypt", "--user", "alice", "--keyring"])
        .arg(&env.keyring)
        .arg("--gpg-home")
        .arg(scratch_gpg_home(env))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // The child cannot have written yet: it reads stdin to EOF first, and that
    // pipe is still held here.
    drop(child.stdout.take());
    child.stdin.take().unwrap().write_all(MESSAGE).unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let status = child.wait().unwrap();

    assert_eq!(
        status.code(),
        Some(1),
        "a failed ciphertext write must exit 1, not die on a signal: {status}, {stderr}"
    );
    assert!(
        stderr.contains("write ciphertext"),
        "the failure must name the write: {stderr}"
    );
}
