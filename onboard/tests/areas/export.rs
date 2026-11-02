use crate::common::*;

/// The export prints the tax year's dated lines and nothing else: a credit
/// outside the year is absent, the approval's undated `window_open` row is
/// absent, and no row carries a name, an address or a free-text note.
#[test]
fn the_export_prints_only_the_tax_year_and_never_a_name() {
    let fix = Fix::new("ledger-export-year");
    let inside = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &inside,
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    let outside = approved_paid(&fix, "treasurer", "cash-hand");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &outside,
        "--rail",
        "cash-hand",
        "--amount",
        "20.00",
        "--received",
        "2026-04-05",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    let out = fix.ctl(&[
        "ledger",
        "export",
        "--tax-year",
        "2026-27",
        "--format",
        "csv",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let csv = String::from_utf8_lossy(&out.stdout).into_owned();
    let keyed: Vec<&str> = csv.lines().take_while(|line| !line.is_empty()).collect();
    assert_eq!(keyed[0], EXPORT_HEADER, "{csv}");
    assert_eq!(
        keyed.len(),
        2,
        "one credit is in the year, one is not: {csv}"
    );

    let row: Vec<&str> = keyed[1].split(',').collect();
    assert_eq!(row[1], inside, "{csv}");
    assert_eq!(row[2], "payment", "{csv}");
    assert_eq!(row[3], "cash", "{csv}");
    assert_eq!(row[4], "2026-10-04", "{csv}");
    assert_eq!(row[5], "20.00", "{csv}");
    assert_eq!(row[6], "20.00", "{csv}");
    assert_eq!(row[7], "2027-10-04", "{csv}");

    assert!(!csv.contains(&outside), "{csv}");
    assert!(!csv.contains("secretary"), "{csv}");
    assert!(!csv.contains("treasurer"), "{csv}");
    assert!(!csv.contains('@'), "{csv}");
}

/// A refund is a negative line of its own, naming the `seq` it reverses, and
/// the free-text note stays out of the export.
#[test]
fn the_export_prints_a_refund_as_a_negative_row_naming_its_seq() {
    let fix = Fix::new("ledger-export-refund");
    let token = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let credit_seq = payment_lines(&fix)[0]["seq"].as_u64().unwrap();

    let out = fix.ctl(&[
        "refund",
        "--token",
        &token,
        "--amount",
        "20.00",
        "--rail",
        "cash",
        "--reason",
        "secretary, cancelled inside 14 days",
        "--close",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let out = fix.ctl(&["refund", "--token", &token, "--settled", "2026-11-05"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());
    let refund_seq = refund_lines(&fix)[0]["seq"].as_u64().unwrap();

    let out = fix.ctl(&[
        "ledger",
        "export",
        "--tax-year",
        "2026-27",
        "--format",
        "csv",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let csv = String::from_utf8_lossy(&out.stdout).into_owned();
    let row = csv
        .lines()
        .find(|line| line.starts_with(&format!("{refund_seq},")))
        .expect("the refund's row");
    let cells: Vec<&str> = row.split(',').collect();
    assert_eq!(cells[1], token, "{csv}");
    assert_eq!(cells[2], "refund", "{csv}");
    assert_eq!(cells[5], "-20.00", "{csv}");
    assert_eq!(cells[10], credit_seq.to_string(), "refund_of: {csv}");
    assert_eq!(cells[11], "2026-11-05", "settled_on: {csv}");
    assert!(!csv.contains("cancelled"), "{csv}");
    assert!(!csv.contains("secretary"), "{csv}");
}

/// Held money is not income and is not keyed, so it follows the keyed rows
/// under its own marker and header. A returned line, and a held line outside
/// the year, stay out; no keyed row loses its token. The ids come from the
/// commands that produce them, never a hand-typed `UN-` string.
#[test]
fn the_export_puts_held_money_after_its_own_marker() {
    let fix = Fix::new("ledger-export-held");
    let token = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    // One held envelope, one returned envelope and one held payment from last
    // year. Each is filed and applied through the real console and drain.
    for (received, note) in [
        ("2026-10-08", "no token on the envelope"),
        ("2026-10-09", "returned envelope"),
        ("2026-04-05", "last year's post"),
    ] {
        let out = fix.ctl(&[
            "credit",
            "--rail",
            "cash",
            "--amount",
            "20.00",
            "--received",
            received,
            "--note",
            note,
        ]);
        assert!(out.status.success(), "{}", body(&out));
        assert!(fix.drain().status.success());
    }
    let held_id = held_lines(&fix)
        .iter()
        .find(|line| line["received_on"] == json!("2026-10-08"))
        .and_then(|line| line["id"].as_str())
        .expect("the held envelope has an id")
        .to_string();
    let returned_id = held_lines(&fix)
        .iter()
        .find(|line| line["received_on"] == json!("2026-10-09"))
        .and_then(|line| line["id"].as_str())
        .expect("the returned envelope has an id")
        .to_string();
    let out = fix.ctl(&[
        "reconcile",
        "return",
        &returned_id,
        "--note",
        "posted back 2026-10-10, receipt in book",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    let out = fix.ctl(&[
        "ledger",
        "export",
        "--tax-year",
        "2026-27",
        "--format",
        "csv",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let csv = String::from_utf8_lossy(&out.stdout).into_owned();
    let (keyed, held) = csv
        .split_once("\n\n# unattributed\n")
        .expect("the held section is after a blank line");

    assert!(
        keyed.contains(&token),
        "the keyed row kept its token: {csv}"
    );
    assert!(!keyed.contains("UN-"), "held money is not keyed: {csv}");

    let mut lines = held.lines();
    assert_eq!(lines.next(), Some("id,rail,received_on,amount_gbp"));
    let rows: Vec<&str> = lines.collect();
    assert_eq!(
        rows,
        vec![format!("{held_id},cash,2026-10-08,20.00")],
        "a returned line and a held line from another year stay out: {csv}"
    );
    assert!(!csv.contains(&returned_id), "{csv}");
    assert!(!csv.contains("no token on the envelope"), "{csv}");
}

/// The export reads both ledgers strictly: a line that does not parse is a
/// failure, not a year with less money in it.
#[test]
fn the_export_refuses_a_ledger_it_cannot_read() {
    let fix = Fix::new("ledger-export-corrupt");
    let token = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "credit",
        "--token",
        &token,
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.drain().status.success());

    let export = |fix: &Fix| {
        fix.ctl(&[
            "ledger",
            "export",
            "--tax-year",
            "2026-27",
            "--format",
            "csv",
        ])
    };
    for rel in ["ledger/payments.jsonl", "ledger/unattributed.jsonl"] {
        let path = fix.dir.join("store").join(rel);
        let before = std::fs::read_to_string(&path).unwrap_or_default();
        std::fs::write(&path, format!("{before}{{not json}}\n")).unwrap();
        let out = export(&fix);
        assert!(!out.status.success(), "{rel} was read as empty");
        assert!(
            body(&out).contains("does not parse"),
            "{rel}: {}",
            body(&out)
        );
        std::fs::write(&path, before).unwrap();
    }
}

/// A year it cannot read and a format it does not print are refused; an empty
/// or missing ledger prints the headers and no rows.
#[test]
fn the_export_refuses_a_bad_year_and_a_format_that_is_not_csv() {
    let fix = Fix::new("ledger-export-refuses");
    for bad in ["2026-28", "2026-2028", "2026", "abcd-ef"] {
        let out = fix.ctl(&["ledger", "export", "--tax-year", bad, "--format", "csv"]);
        assert!(!out.status.success(), "{bad:?} was accepted");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("--tax-year"),
            "{bad:?}: {}",
            body(&out)
        );
    }
    let out = fix.ctl(&[
        "ledger",
        "export",
        "--tax-year",
        "2026-27",
        "--format",
        "json",
    ]);
    assert!(
        !out.status.success(),
        "a format that is not csv was accepted"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not csv"),
        "{}",
        body(&out)
    );
    let out = fix.ctl(&["ledger", "export", "--tax-year", "2026-27"]);
    assert!(!out.status.success(), "--format is required");

    let out = fix.ctl(&[
        "ledger",
        "export",
        "--tax-year",
        "2026-27",
        "--format",
        "csv",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{EXPORT_HEADER}\n\n# unattributed\nid,rail,received_on,amount_gbp\n"),
        "a missing ledger reads as empty"
    );
}

/// A throwaway public key, generated for this suite and holding no private half
/// anywhere: the mailed path only needs something gpg will encrypt to. It is
/// public key material, not a secret.
const EXPORT_TEST_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
mDMEauZdXxYJKwYBBAHaRw8BAQdAUI2d9ahgJ7dCRCpMCpZuXkyAO3ODPjDTuo70\n\
294GsJW0Mkt5cmlha29uIEV4cG9ydCBUZXN0IDxleHBvcnQtdGVzdEBleGFtcGxl\n\
LmludmFsaWQ+iK8EExYKAFcWIQRH5ksicdvER5HUFAZXZl05+hflaQUCauZdXxsU\n\
gAAAAAAEAA5tYW51MiwyLjUrMS4xMiwwLDMCGwMFCwkIBwICIgIGFQoJCAsCBBYC\n\
AwECHgcCF4AACgkQV2ZdOfoX5WnvWwD+NSPNa/x07eUrmHEGFxGDON640u6H2orN\n\
oRfI1xBRF5oBAJiCWilPhDSebpBJsCtnASBIEBjkPv4Vp1Ig3tCTdXcHuDgEauZd\n\
XxIKKwYBBAGXVQEFAQEHQG8QQfkxLxrqCRhEzb70PZ5PlCo/ACtG/e0KVlpqHvxV\n\
AwEIB4iUBBgWCgA8FiEER+ZLInHbxEeR1BQGV2ZdOfoX5WkFAmrmXV8bFIAAAAAA\n\
BAAObWFudTIsMi41KzEuMTIsMCwzAhsMAAoJEFdmXTn6F+VpZBMA/i8hNEEptZ3x\n\
7q2OocvPeqicHB1aU/KqbDczZmlJYNJiAP0WKxBIoc9yaXgdqrBfPfovf/utdpsm\n\
C1OLsuAPT41dCg==\n\
=EW+s\n\
-----END PGP PUBLIC KEY BLOCK-----\n";

fn export_root(fix: &Fix, username: &str) -> PathBuf {
    fix.dir
        .join("home/www")
        .join(format!("{username}.kyriakon.net"))
        .join("export")
}

/// The bundle's directory, for the export just written. One export per second
/// names one directory, and the tests that take two wait out the second.
fn bundle(fix: &Fix, username: &str) -> PathBuf {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(export_root(fix, username))
        .expect("the export directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    dirs.sort();
    dirs.pop().expect("one export")
}

fn file(dir: &Path, rel: &str) -> String {
    std::fs::read_to_string(dir.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A live account-page session for `username`, as the login route makes one,
/// returning the id the export intent carries.
fn session_id(fix: &Fix, username: &str) -> String {
    let store = kyriakon_onboard::store::Store::new(&fix.path("store"));
    let cookie = runtime()
        .block_on(kyriakon_onboard::session::open(
            &store,
            username,
            OffsetDateTime::now_utc(),
        ))
        .unwrap();
    cookie.split('.').next().unwrap().to_string()
}

/// Put one session's record in the past, without touching its secret.
fn expire_session(fix: &Fix, id: &str) {
    let path = fix.dir.join("store/sessions").join(format!("{id}.json"));
    let mut record: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    record["expires_at"] = json!("2020-01-01T00:00:00Z");
    std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
}

/// The written part lands inside the chroot the member's sftp already sees,
/// beside `www/` and `gemini/`, and the account's own `notices.jsonl` records
/// the ready notice.
#[test]
fn the_bundle_lands_in_the_chroot_and_the_notice_is_recorded() {
    let fix = Fix::new("data-export-bundle");
    fix.member_tree("secretary");
    let token = approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&[
        "request",
        "record",
        "--username",
        "secretary",
        "--kind",
        "access",
        "--received",
        "2026-10-01",
        "--evidence",
        "the account page",
    ]);
    assert!(out.status.success(), "{}", body(&out));

    let out = fix.ctl(&["export", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));

    let dir = bundle(&fix, "secretary");
    // Beside the two directories the member already uploads to.
    let chroot = fix.dir.join("home/www/secretary.kyriakon.net");
    assert!(chroot.join("www").is_dir());
    assert!(chroot.join("gemini").is_dir());
    // The parent the member reads through is root's and never theirs to write.
    let export = chroot.join("export");
    let md = std::fs::symlink_metadata(&export).unwrap();
    assert!(md.file_type().is_dir());
    assert_eq!(md.uid(), unsafe { libc::geteuid() });
    assert_eq!(md.permissions().mode() & 0o777, 0o755);
    assert_eq!(
        dir.strip_prefix(&chroot).unwrap().components().count(),
        2,
        "{}",
        dir.display()
    );

    for rel in [
        "account.json",
        "notices.jsonl",
        "application.json",
        "journal.jsonl",
        "requests.jsonl",
        "keys/secretary.asc",
        "ledger/payments.jsonl",
        "MANIFEST.txt",
        "answer.txt",
    ] {
        assert!(dir.join(rel).is_file(), "{rel} is missing");
    }

    // The account's own document, not a summary of it.
    let account: Value = serde_json::from_str(&file(&dir, "account.json")).unwrap();
    assert_eq!(account["username"], "secretary");
    // The token's ledger line and no other account's.
    let ledger = file(&dir, "ledger/payments.jsonl");
    assert!(ledger.contains(&token), "{ledger}");
    assert_eq!(ledger.lines().count(), 1, "{ledger}");
    // The account's journal lines, one per transition.
    let journal = file(&dir, "journal.jsonl");
    assert!(!journal.is_empty());
    for line in journal.lines() {
        let entry: Value = serde_json::from_str(line).unwrap();
        assert_eq!(entry["application"]["username"], "secretary", "{line}");
    }
    // The request that asked for it.
    assert!(file(&dir, "requests.jsonl").contains("\"kind\":\"access\""));
    // The keyring entry, as the keyring holds it.
    let keyring = std::fs::read_to_string(fix.dir.join("keyring/secretary.asc")).unwrap();
    assert_eq!(file(&dir, "keys/secretary.asc"), keyring);

    // The whole tree is the member's. A non-root test runs as the tree's own
    // owner, which is the same rule `store::write_record_owned` applies; on the
    // box the chown does this to the account's uid and gid.
    let euid = unsafe { libc::geteuid() };
    let md = std::fs::metadata(&dir).unwrap();
    assert_eq!(md.uid(), euid);
    assert_eq!(md.permissions().mode() & 0o777, 0o700);
    for rel in ["account.json", "answer.txt", "keys/secretary.asc"] {
        let md = std::fs::metadata(dir.join(rel)).unwrap();
        assert_eq!(md.uid(), euid, "{rel}");
        assert_eq!(md.permissions().mode() & 0o777, 0o600, "{rel}");
    }

    // The ready notice is in the account's record and the mail left.
    assert!(fix
        .read("accounts/secretary/notices.jsonl")
        .contains("\"type\":\"export.ready\""));
    assert!(
        fix.sent()
            .contains("Subject: Your kyriakon.net data export is ready"),
        "{}",
        fix.sent()
    );
}

/// The application answers are in the bundle only inside ADR 0005's 90 days.
/// After the window the file is not there and the manifest says where it went,
/// rather than leaving a silence.
#[test]
fn the_application_is_in_the_bundle_only_inside_the_purge() {
    let fix = Fix::new("data-export-purge");
    fix.member_tree("secretary");
    approved_paid(&fix, "secretary", "cash");

    let out = fix.ctl(&["export", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let first = bundle(&fix, "secretary");
    assert!(first.join("application.json").is_file());
    assert!(file(&first, "MANIFEST.txt").contains("included"));

    // Age the retained copy past the window. The purge's own sweep is not what
    // this test exercises: the export must apply the boundary to the copy it
    // finds, so a purge that has not run cannot leak the answers.
    let path = fix.dir.join("store/accounts/secretary/application.json");
    let mut copy: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let old = OffsetDateTime::now_utc() - time::Duration::days(100);
    copy["filed_at"] = json!(old
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap());
    std::fs::write(&path, serde_json::to_vec_pretty(&copy).unwrap()).unwrap();

    // One export per second names one directory.
    std::thread::sleep(std::time::Duration::from_secs(1));
    let out = fix.ctl(&["export", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let second = bundle(&fix, "secretary");
    assert!(!second.join("application.json").exists());
    let manifest = file(&second, "MANIFEST.txt");
    let ended = (old.date() + time::Duration::days(90)).to_string();
    assert!(manifest.contains("purged"), "{manifest}");
    assert!(manifest.contains(&ended), "{manifest}");
}

/// A filing date that cannot be read fails the purge rule closed: the answers
/// stay out of the bundle, and the manifest says why rather than staying silent.
#[test]
fn an_unreadable_filing_date_keeps_the_answers_out() {
    let fix = Fix::new("data-export-undated");
    fix.member_tree("secretary");
    approved_paid(&fix, "secretary", "cash");
    let path = fix.dir.join("store/accounts/secretary/application.json");
    let mut copy: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    copy["filed_at"] = json!("last Tuesday");
    std::fs::write(&path, serde_json::to_vec_pretty(&copy).unwrap()).unwrap();

    let out = fix.ctl(&["export", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let dir = bundle(&fix, "secretary");
    assert!(!dir.join("application.json").exists());
    let manifest = file(&dir, "MANIFEST.txt");
    assert!(manifest.contains("no readable filing date"), "{manifest}");
    assert!(manifest.contains("not included"), "{manifest}");
}

/// The manifest names the member's tree as paths they pull, copies none of it,
/// and the written answer names the three exclusions the spec states.
#[test]
fn the_manifest_and_the_answer_say_what_is_not_in_the_bundle() {
    let fix = Fix::new("data-export-wording");
    fix.member_tree("secretary");
    approved_paid(&fix, "secretary", "cash");
    let out = fix.ctl(&["export", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let dir = bundle(&fix, "secretary");

    let manifest = file(&dir, "MANIFEST.txt");
    assert!(manifest.contains("does not copy"), "{manifest}");
    assert!(manifest.contains("/home/secretary/Maildir"), "{manifest}");
    assert!(manifest.contains("/home/secretary/repos"), "{manifest}");
    assert!(
        manifest.contains("home/www/secretary.kyriakon.net/www"),
        "{manifest}"
    );
    assert!(
        manifest.contains("home/www/secretary.kyriakon.net/gemini"),
        "{manifest}"
    );

    let answer = file(&dir, "answer.txt");
    assert!(answer.contains("The operator's own mailbox"), "{answer}");
    assert!(answer.contains("log records"), "{answer}");
    assert!(answer.contains("Nothing about another member"), "{answer}");
    // And the member who can produce neither the key nor the password is told
    // what is still reachable.
    assert!(answer.contains("what is still reachable"), "{answer}");
    assert!(answer.contains("password path"), "{answer}");
}

/// The page's "Take my data out" is an intent carrying the account and the
/// session that asked for it; the drain proves the session, records the request
/// line, writes the same bundle and removes the intent.
#[test]
fn the_page_files_an_export_intent_and_the_drain_records_the_request() {
    let fix = Fix::new("data-export-intent");
    fix.member_tree("secretary");
    approved_paid(&fix, "secretary", "cash");
    let store = kyriakon_onboard::store::Store::new(&fix.path("store"));
    let session = session_id(&fix, "secretary");
    let id = runtime()
        .block_on(kyriakon_onboard::intents::file_export(
            &store,
            &session,
            "secretary",
        ))
        .unwrap();

    let filed: Value = serde_json::from_str(&fix.read(&format!("intents/{id}.json"))).unwrap();
    let mut keys: Vec<&str> = filed
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        ["filed_at", "id", "kind", "session", "username"],
        "{filed}"
    );
    assert_eq!(filed["kind"], "export");
    assert_eq!(filed["username"], "secretary");
    assert_eq!(filed["session"], session.as_str());

    assert!(fix.drain().status.success());
    assert!(bundle(&fix, "secretary").join("account.json").is_file());
    assert!(!fix
        .dir
        .join("store/intents")
        .join(format!("{id}.json"))
        .exists());
    assert!(fix.journal().contains("\"kind\":\"export\""));

    // One data-subject request line, keyed by the intent that asked for it.
    let record = fix.read("accounts/secretary/requests.jsonl");
    let line: Value = serde_json::from_str(record.lines().last().unwrap()).unwrap();
    assert_eq!(line["id"], id.as_str());
    assert_eq!(line["kind"], "access");
    assert_eq!(line["username"], "secretary");
    assert!(
        line["evidence"].as_str().unwrap().contains("account page"),
        "{line}"
    );
    // And the bundle carries it.
    assert!(file(&bundle(&fix, "secretary"), "requests.jsonl").contains(&id));
}

/// A forged or expired session is refused before root writes anything: no
/// bundle, no request line, and the intent stays for the operator to see.
#[test]
fn a_forged_or_expired_session_writes_nothing() {
    let fix = Fix::new("data-export-session");
    fix.member_tree("secretary");
    approved_paid(&fix, "secretary", "cash");
    let store = kyriakon_onboard::store::Store::new(&fix.path("store"));

    // A session that belongs to someone else, asking for this account's record.
    let wrong = session_id(&fix, "alice");
    let id = runtime()
        .block_on(kyriakon_onboard::intents::file_export(
            &store,
            &wrong,
            "secretary",
        ))
        .unwrap();
    assert!(fix.drain().status.success());
    assert!(!export_root(&fix, "secretary").exists());
    assert!(fix
        .dir
        .join("store/intents")
        .join(format!("{id}.json"))
        .exists());
    assert!(
        fix.failed_note().contains("belongs to") && fix.failed_note().contains("alice"),
        "{}",
        fix.failed_note()
    );
    assert!(fix.read("accounts/secretary/requests.jsonl").is_empty());

    // The right account, on a session that has run out.
    std::fs::remove_file(fix.dir.join("store/intents").join(format!("{id}.json"))).unwrap();
    let expired = session_id(&fix, "secretary");
    expire_session(&fix, &expired);
    let id = runtime()
        .block_on(kyriakon_onboard::intents::file_export(
            &store,
            &expired,
            "secretary",
        ))
        .unwrap();
    assert!(fix.drain().status.success());
    assert!(!export_root(&fix, "secretary").exists());
    assert!(fix
        .dir
        .join("store/intents")
        .join(format!("{id}.json"))
        .exists());
    assert!(
        fix.failed_note().contains("expired"),
        "{}",
        fix.failed_note()
    );
    assert!(fix.read("accounts/secretary/requests.jsonl").is_empty());
}

/// A planted `export` symlink is refused before anything is written through
/// it, and no ready notice claims a bundle exists.
#[test]
fn a_planted_export_symlink_is_refused() {
    let fix = Fix::new("data-export-symlink");
    fix.member_tree("secretary");
    approved_paid(&fix, "secretary", "cash");
    let chroot = fix.dir.join("home/www/secretary.kyriakon.net");
    let target = fix.dir.join("planted-target");
    std::fs::create_dir_all(&target).unwrap();
    std::os::unix::fs::symlink(&target, chroot.join("export")).unwrap();

    let out = fix.ctl(&["export", "secretary"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("symlink"), "{err}");
    assert!(err.contains("refusing"), "{err}");
    assert_eq!(
        std::fs::read_dir(&target).unwrap().count(),
        0,
        "nothing was written through the symlink"
    );
    assert!(!fix
        .read("accounts/secretary/notices.jsonl")
        .contains("export.ready"));
}

/// A member who cannot log in but still holds their key gets the written part
/// as one attachment, encrypted to that public key.
#[test]
fn the_written_part_is_mailed_encrypted_to_the_members_key() {
    let fix = Fix::new("data-export-mail");
    fix.member_tree("secretary");
    approved_paid(&fix, "secretary", "cash");
    fix.mail_key("secretary", EXPORT_TEST_KEY);

    let out = fix.ctl(&["export", "secretary", "--by-mail"]);
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    assert!(
        sent.contains("Content-Disposition: attachment; filename=\"export-"),
        "{sent}"
    );
    assert!(sent.contains("-----BEGIN PGP MESSAGE-----"), "{sent}");
    // The account document left only inside the ciphertext: the plain body is
    // the written answer, which names no record field.
    assert!(!sent.contains("\"username\": \"secretary\""), "{sent}");
    assert!(fix
        .read("accounts/secretary/notices.jsonl")
        .contains("\"type\":\"export.ready\""));
}

/// A member with neither the key nor the password is told what is reachable
/// rather than promised the whole; nothing is sent.
#[test]
fn a_member_with_no_key_is_told_what_is_still_reachable() {
    let fix = Fix::new("data-export-nokey");
    fix.member_tree("secretary");
    approved_paid(&fix, "secretary", "cash");
    std::fs::remove_file(fix.dir.join("keyring/secretary.asc")).unwrap();

    let out = fix.ctl(&["export", "secretary", "--by-mail"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no public key"), "{err}");
    assert!(err.contains("still reachable"), "{err}");
    assert!(err.contains("password path"), "{err}");
    assert!(err.contains("promising the whole"), "{err}");
}
