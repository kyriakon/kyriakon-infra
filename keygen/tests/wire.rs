// The process protocol `keygen-check` speaks to the control plane: exit status
// and exact stdout bytes, on a fixed clock. The policy tests in fixtures.rs
// assert findings; this pins the bytes those findings become.

use std::io::Write;
use std::process::{Command, Stdio};

use keygen::Finding;

const NOW: &str = "1800000000";

fn run(input: &str) -> (std::process::ExitStatus, Vec<u8>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_keygen-check"))
        .args(["--now-secs", NOW])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("keygen-check starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(input.as_bytes())
        .expect("input is written");
    let output = child.wait_with_output().expect("keygen-check finishes");
    (output.status, output.stdout)
}

#[test]
fn a_clean_key_is_ok() {
    let (status, stdout) = run(include_str!("../fixtures/generated-clean.asc"));
    assert!(status.success(), "{status:?}");
    assert_eq!(stdout, b"ok\n");
}

#[test]
fn a_non_key_is_uninspected() {
    let (status, stdout) = run("not a key\n");
    assert!(status.success(), "{status:?}");
    assert_eq!(stdout, b"uninspected\n");
}

#[test]
fn a_finding_keeps_its_exact_sentence() {
    let (status, stdout) = run(include_str!("../fixtures/gpg-no-encryption-subkey.asc"));
    assert!(status.success(), "{status:?}");
    let mut expected = b"ok\n".to_vec();
    expected.extend_from_slice(Finding::NoEncryptionSubkey.to_string().as_bytes());
    expected.push(b'\n');
    assert_eq!(stdout, expected);
}
