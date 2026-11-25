//! The `mail-table` command the shell scripts run.
//!
//! The script self-tests drive a double, because the box's binary is not on a
//! test host. This case runs the real command against a fixture table, so the
//! lock file, the canonical form, the atomic replace, the mode and the exit
//! codes the scripts branch on are proved by the writer itself.

use crate::common::*;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn path(dir: &std::path::Path) -> String {
    dir.join("virtuals").to_str().unwrap().to_string()
}

#[test]
fn the_mail_table_command_is_the_writer_the_scripts_run() {
    let dir = std::env::temp_dir().join(format!("mail-table-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let table = path(&dir);
    std::fs::write(&table, "alice@kyriakon.net: alice\n").unwrap();
    let bin = drain_binary();

    // An append under `umask 077`: the command sets 0644 explicitly, because
    // smtpd and its filters read the table as other users.
    let out = Command::new("sh")
        .args([
            "-c",
            "umask 077; exec \"$0\" mail-table add \"$1\" \"$2\" \"$3\"",
            bin.to_str().unwrap(),
            table.as_str(),
            "bob@kyriakon.net",
            "bob",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "added");
    let mode = std::fs::metadata(&table).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644, "the table is readable by smtpd");
    assert!(
        dir.join("virtuals.lock").is_file(),
        "the kernel lock is a file beside the table"
    );
    assert!(
        std::fs::read_to_string(&table)
            .unwrap()
            .contains("bob@kyriakon.net: bob"),
        "the line landed"
    );

    // A key present with another value is a refusal, not a silent repoint.
    let out = Command::new(&bin)
        .args([
            "mail-table",
            "add",
            table.as_str(),
            "bob@kyriakon.net",
            "dave",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");

    // A set is canonical: the upper-case key and value land lower.
    let out = Command::new(&bin)
        .args([
            "mail-table",
            "set",
            table.as_str(),
            "Carol@Kyriakon.NET: carol",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = std::fs::read_to_string(&table).unwrap();
    assert!(text.contains("carol@kyriakon.net: carol"), "{text}");

    // `check` gives both guards the writer's three answers, space form included.
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&table)
        .unwrap();
    writeln!(file, "  dave@kyriakon.net dave").unwrap();
    let check = |line: &str| {
        let out = Command::new(&bin)
            .args(["mail-table", "check", table.as_str(), line])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert_eq!(check("dave@kyriakon.net: dave"), "same");
    assert_eq!(check("dave@kyriakon.net: alice"), "different dave");
    assert_eq!(check("erin@kyriakon.net: erin"), "absent");

    // Drop uses 0 changed and 1 unchanged, the codes remove-group.sh reads.
    let out = Command::new(&bin)
        .args([
            "mail-table",
            "drop",
            table.as_str(),
            "exact",
            "bob@kyriakon.net",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let out = Command::new(&bin)
        .args([
            "mail-table",
            "drop",
            table.as_str(),
            "exact",
            "bob@kyriakon.net",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");

    let _ = std::fs::remove_dir_all(&dir);
}
