//! The drain's acceptance criteria, run with no root and no live store.
//!
//! Every path the drain touches is a configuration value, so a test rebinds the
//! store, the script directory, the enqueuer and the secret files to fixtures
//! under a temporary directory, the way `scripts/provision-member-capsule.sh
//! --self-test` rebinds its own. The two binaries are the real ones, driven the
//! way cron and the reviewer drive them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Output;

use serde_json::{json, Value};

const DRAIN: &str = env!("CARGO_BIN_EXE_kyriakon-onboard-drain");
const CTL: &str = env!("CARGO_BIN_EXE_kyriakon-onboardctl");

/// A status token: 26 lowercase Crockford characters, which is 128 bits.
const TOKEN: &str = "0123456789abcdefghjkmnpqrs";

struct Fix {
    dir: PathBuf,
}

impl Fix {
    fn new(name: &str) -> Fix {
        let dir = std::env::temp_dir().join(format!("onboard-it-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["store/intents", "store/applications", "bin"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let fix = Fix { dir };
        std::fs::write(fix.path("key"), "the approval key\n").unwrap();
        let sent = fix.path("sent");
        fix.script("enqueuer.sh", &format!("#!/bin/sh\ncat >> '{sent}'\n"));
        for s in ["add-user.sh", "provision-member.sh", "delete-user.sh"] {
            let log = fix.path("scripts.log");
            fix.script(s, &format!("#!/bin/sh\necho \"{s} $*\" >> '{log}'\n"));
        }
        let cfg = format!(
            "store_root = \"{}\"\n\
             scripts = \"{}\"\n\
             sendmail = \"{}\"\n\
             approval_key = \"{}\"\n\
             stripe_webhook_secret = \"{}/stripe\"\n\
             keyring_publish_token = \"{}/keyring\"\n\
             reviewer = \"reviewer@example.invalid\"\n\
             base_url = \"https://signup.kyriakon.net\"\n\
             price_gbp = \"20.00\"\n\
             postal_address = \"1 Example Street, Example\"\n\
             release = \"2026-10-10 abc1234\"\n",
            fix.path("store"),
            fix.path("bin"),
            fix.path("bin/enqueuer.sh"),
            fix.path("key"),
            fix.dir.display(),
            fix.dir.display(),
        );
        std::fs::write(fix.path("drain.toml"), cfg).unwrap();
        fix
    }

    fn path(&self, rel: &str) -> String {
        self.dir.join(rel).to_str().unwrap().to_string()
    }

    fn script(&self, name: &str, body: &str) {
        let p = self.dir.join("bin").join(name);
        std::fs::write(&p, body).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn config(&self) -> String {
        self.path("drain.toml")
    }

    /// Write the application record the handler would have written.
    fn filed(&self, username: &str, rail: &str, answers: &[(&str, &str)]) -> Value {
        self.filed_with(username, rail, answers, Some(("I want mail", "works")))
    }

    fn filed_with(
        &self,
        username: &str,
        rail: &str,
        answers: &[(&str, &str)],
        upload: Option<(&str, &str)>,
    ) -> Value {
        let answers: BTreeMap<&str, &str> = answers.iter().cloned().collect();
        let mut upload_key = Value::Null;
        if let Some((material, verdict)) = upload {
            upload_key = json!({
                "mailbox": "",
                "fingerprint": "AAAA BBBB CCCC DDDD",
                "material": material,
                "verdict": verdict,
            });
        }
        let record = json!({
            "username": username,
            "status_token": TOKEN,
            "filed_at": "2026-10-01T09:00:00Z",
            "front_end": "web",
            "stage": "received",
            "answers": answers,
            "mail_keys": [{
                "mailbox": "",
                "fingerprint": "1111 2222 3333 4444",
                "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----",
                "verdict": "works",
            }],
            "upload_key": upload_key,
            "rail": rail,
            "no_charge": rail == "no_charge",
            "acceptances": [{"document": "terms", "version": "2026-10-01 abc1234"}],
            "question_list": "2026-10-01 abc1234",
        });
        std::fs::write(
            self.dir.join("store/applications").join(format!("{TOKEN}.json")),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        record
    }

    /// File an application intent, as the handler does.
    fn file_application(&self, record: &Value) -> String {
        let id = ulid();
        let mut intent = record.clone();
        intent["id"] = json!(id);
        intent["kind"] = json!("application");
        intent["application"] =
            json!({"username": record["username"], "status_token": record["status_token"]});
        for k in ["stage", "decided_at", "password_link"] {
            intent.as_object_mut().unwrap().remove(k);
        }
        self.write_intent(&id, &intent);
        id
    }

    fn write_intent(&self, id: &str, intent: &Value) {
        std::fs::write(
            self.dir.join("store/intents").join(format!("{id}.json")),
            serde_json::to_vec_pretty(intent).unwrap(),
        )
        .unwrap();
    }

    fn decide(&self, kind: &str, username: &str) -> String {
        let id = ulid();
        self.write_intent(
            &id,
            &json!({
                "id": id,
                "kind": kind,
                "filed_at": "2026-10-02T09:00:00Z",
                "application": {"username": username, "status_token": TOKEN},
            }),
        );
        id
    }

    fn drain(&self) -> Output {
        std::process::Command::new(DRAIN)
            .arg("--config")
            .arg(self.config())
            .output()
            .unwrap()
    }

    fn ctl(&self, args: &[&str]) -> Output {
        std::process::Command::new(CTL)
            .arg("--config")
            .arg(self.config())
            .args(args)
            .output()
            .unwrap()
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.dir.join("store").join(rel)).unwrap_or_default()
    }

    /// The names in one store directory, sorted.
    fn names(&self, rel: &str) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.dir.join("store").join(rel))
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    fn sent(&self) -> String {
        std::fs::read_to_string(self.dir.join("sent")).unwrap_or_default()
    }

    fn scripts_log(&self) -> String {
        std::fs::read_to_string(self.dir.join("scripts.log")).unwrap_or_default()
    }

    fn journal(&self) -> String {
        self.read("journal.jsonl")
    }

    fn account(&self, username: &str) -> Value {
        serde_json::from_str(&self.read(&format!("accounts/{username}/account.json"))).unwrap()
    }

    /// Every file under the store, by relative path, for an equality check
    /// across two runs.
    fn snapshot(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        walk(&self.dir.join("store"), &self.dir.join("store"), &mut out);
        out
    }

    fn intents(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.dir.join("store/intents"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }
}

impl Drop for Fix {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
    for entry in std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_dir() {
            walk(root, &p, out);
        } else {
            let key = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            out.insert(key, std::fs::read_to_string(&p).unwrap_or_default());
        }
    }
}

fn ulid() -> String {
    ulid::Ulid::new().to_string()
}

fn body(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// One filed application produces one review email carrying every answer, the
/// mail-key result, upload-key presence, the rail, the no-charge flag and three
/// signed links.
#[test]
fn a_filed_application_produces_one_review_email() {
    let fix = Fix::new("review");
    let record = fix.filed(
        "secretary",
        "cash",
        &[("rail", "cash"), ("cannot_pay", "I have no money"), ("intended_use", "For parish mail")],
    );
    fix.file_application(&record);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    // One message, to the reviewer.
    assert_eq!(sent.matches("Subject:").count(), 1, "{}", body(&out));
    assert!(sent.contains("To: reviewer@example.invalid"), "{sent}");
    // Every answer, keyed by its question id.
    assert!(sent.contains("cannot_pay: I have no money"), "{sent}");
    assert!(sent.contains("intended_use: For parish mail"), "{sent}");
    // The mail-key result and the upload-key presence.
    assert!(sent.contains("1111 2222 3333 4444"), "{sent}");
    assert!(sent.contains("works"), "{sent}");
    assert!(sent.contains("Upload key: supplied"), "{sent}");
    // The rail and the no-charge flag.
    assert!(sent.contains("Rail: cash"), "{sent}");
    assert!(sent.contains("No charge asked for: no"), "{sent}");
    // Three signed links, and the onboardctl equivalents.
    assert_eq!(sent.matches("/decide/").count(), 3, "{sent}");
    assert_eq!(sent.matches("sig=").count(), 3, "{sent}");
    assert!(sent.contains("action=approve&"), "{sent}");
    assert!(sent.contains("action=approve-free&"), "{sent}");
    assert!(sent.contains("action=decline&"), "{sent}");
    assert!(sent.contains("onboardctl approve secretary"), "{sent}");
    assert!(sent.contains("onboardctl approve-free secretary"), "{sent}");
    assert!(sent.contains("onboardctl decline secretary"), "{sent}");

    // The intent is consumed.
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
}

/// A click on an already-decided application changes nothing in the store and
/// sends nothing, and the journal records that it was seen.
#[test]
fn a_replayed_approval_changes_nothing() {
    let fix = Fix::new("replay");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success(), "first approve");
    let after_first = fix.snapshot();
    let sent_after_first = fix.sent().matches("Subject:").count();

    // The same click again.
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    // The application, the account, the token and the ledger are untouched.
    let after_second = fix.snapshot();
    let touching: Vec<_> = after_first
        .keys()
        .chain(after_second.keys())
        .filter(|k| !k.ends_with("journal.jsonl"))
        .filter(|k| after_first.get(*k) != after_second.get(*k))
        .collect();
    assert!(touching.is_empty(), "changed: {touching:?}");
    // No second decision email.
    assert_eq!(fix.sent().matches("Subject:").count(), sent_after_first);
    // The journal records that the replay was seen.
    assert!(fix.journal().contains("already-decided"), "{}", fix.journal());
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
}

/// A paid approval draws a token from the OS randomness, opens a window with a
/// null `paid_until` and writes it into the account; an approval without charge
/// writes no token and no ledger line.
#[test]
fn a_paid_approval_writes_a_token_and_a_no_charge_approval_does_not() {
    let paid = Fix::new("paid");
    let record = paid.filed("secretary", "monero", &[("rail", "monero")]);
    paid.file_application(&record);
    assert!(paid.drain().status.success());
    paid.decide("approve", "secretary");
    let out = paid.drain();
    assert!(out.status.success(), "{}", body(&out));

    let account = paid.account("secretary");
    let token = account["token_ref"].as_str().expect("a paid approval writes a token");
    assert!(token.starts_with("KYR-"), "{token}");
    assert_eq!(token.len(), 18, "{token}");
    assert!(account["paid_until"].is_null(), "{}", account);
    assert!(!account["window"].is_null(), "a paid approval opens a window");
    // The join and the ledger line, keyed by the token and holding no username.
    assert!(paid.read(&format!("tokens/{token}.json")).contains(token));
    let ledger = paid.read("ledger/payments.jsonl");
    assert_eq!(ledger.lines().count(), 1, "{ledger}");
    assert!(ledger.contains(token), "{ledger}");
    assert!(!ledger.contains("secretary"), "the ledger holds no username: {ledger}");
    // The password link is written for the account that has no password.
    let app: Value =
        serde_json::from_str(&paid.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(app["password_link"].as_str().unwrap().contains("/password/"), "{app}");

    // The free path: no token, no window, no ledger line.
    let free = Fix::new("free");
    let record = free.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    free.file_application(&record);
    assert!(free.drain().status.success());
    free.decide("provision", "secretary");
    let out = free.drain();
    assert!(out.status.success(), "{}", body(&out));
    let account = free.account("secretary");
    assert!(account["token_ref"].is_null(), "{account}");
    assert!(account["paid_until"].is_null(), "{account}");
    assert!(account["window"].is_null(), "{account}");
    assert_eq!(account["no_charge"], json!(true));
    assert!(free.read("ledger/payments.jsonl").is_empty(), "no ledger line without money");
    assert!(free.names("tokens").is_empty(), "no token without a charge");
}

/// An application that asked for no charge is never charged, even by the
/// charge-carrying intent: the reviewer's own button and the applicant's answer
/// both have to say pay before a token is drawn.
#[test]
fn an_application_that_asked_for_no_charge_is_never_charged() {
    let fix = Fix::new("safety");
    let record = fix.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let account = fix.account("secretary");
    assert!(account["token_ref"].is_null(), "{account}");
    assert!(account["window"].is_null(), "{account}");
    assert!(fix.read("ledger/payments.jsonl").is_empty(), "nothing owed, no ledger line");
}

/// The three decision verbs write the intent the drain reads, and `show` reads
/// one application back.
#[test]
fn onboardctl_files_a_decision_and_shows_the_application() {
    let fix = Fix::new("ctl");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);

    let out = fix.ctl(&["approve", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.intents().len(), 1, "{:?}", fix.intents());
    let intent: Value =
        serde_json::from_str(&fix.read(&format!("intents/{}", fix.intents()[0]))).unwrap();
    assert_eq!(intent["kind"], json!("approve"));
    assert_eq!(intent["application"]["username"], json!("secretary"));
    assert_eq!(intent["application"]["status_token"], json!(TOKEN));

    // approve-free files the no-charge kind; decline files a decline.
    for (verb, kind) in [("approve-free", "provision"), ("decline", "decline")] {
        for name in fix.intents() {
            std::fs::remove_file(fix.dir.join("store/intents").join(name)).unwrap();
        }
        let out = fix.ctl(&[verb, "secretary"]);
        assert!(out.status.success(), "{}", body(&out));
        let names = fix.intents();
        assert_eq!(names.len(), 1, "{}", body(&out));
        let v: Value = serde_json::from_str(&fix.read(&format!("intents/{}", names[0]))).unwrap();
        assert_eq!(v["kind"], json!(kind), "{verb} should file {kind}");
    }

    let out = fix.ctl(&["show", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let text = body(&out);
    assert!(text.contains("application secretary"), "{text}");
    assert!(text.contains("cash"), "{text}");

    // A verb that is not one of the four is refused, and an unknown username
    // names nothing.
    assert!(!fix.ctl(&["suspend", "secretary"]).status.success());
    assert!(!fix.ctl(&["approve", "nobody"]).status.success());
    let _ = record;
}

/// A decline purges nothing on the first run; the run after its week clears the
/// application away and releases the username.
#[test]
fn a_decline_purges_after_its_week_and_releases_the_username() {
    let fix = Fix::new("decline");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("decline", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    // The first run decides and holds; nothing is purged.
    assert!(
        fix.dir.join(format!("store/applications/{TOKEN}.json")).exists(),
        "a fresh decline is held for its week"
    );
    assert!(fix.sent().contains("was declined"), "{}", fix.sent());
    assert!(
        !fix.scripts_log().contains("delete-user.sh"),
        "nothing is released before the week: {}",
        fix.scripts_log()
    );

    // Move the decision a week back, as a week of cron would, and run again.
    let mut app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    app["decided_at"] = json!("2026-09-01T00:00:00Z");
    std::fs::write(
        fix.dir.join(format!("store/applications/{TOKEN}.json")),
        serde_json::to_vec_pretty(&app).unwrap(),
    )
    .unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        !fix.dir.join(format!("store/applications/{TOKEN}.json")).exists(),
        "the week past, the application is cleared away"
    );
    assert!(
        fix.scripts_log().contains("delete-user.sh secretary"),
        "the username is released: {}",
        fix.scripts_log()
    );
    let _ = record;
}

/// Running the drain twice over one `intents/` directory leaves the same store
/// and sends no notice twice.
#[test]
fn two_runs_leave_the_same_store_and_send_nothing_twice() {
    let fix = Fix::new("twice");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);

    assert!(fix.drain().status.success());
    let after_first = fix.snapshot();
    let sent_after_first = fix.sent().matches("Subject:").count();

    assert!(fix.drain().status.success());
    let after_second = fix.snapshot();

    assert_eq!(after_first, after_second, "the second run changed the store");
    assert_eq!(fix.sent().matches("Subject:").count(), sent_after_first);
    assert_eq!(sent_after_first, 1, "one review email, not two");
}

/// A kind this build does not implement is refused by name and left in place,
/// and two runs record the refusal once.
#[test]
fn an_unimplemented_kind_is_left_in_place_and_refused_once() {
    let fix = Fix::new("unknown");
    let id = ulid();
    fix.write_intent(
        &id,
        &json!({
            "id": id,
            "kind": "credit",
            "filed_at": "2026-10-02T09:00:00Z",
            "application": {"username": "secretary", "status_token": TOKEN},
        }),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    // Left in place, the second run sees it again.
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(fix.journal().contains("refused"), "{}", fix.journal());
    assert!(fix.journal().contains("credit"), "{}", fix.journal());

    assert!(fix.drain().status.success());
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    // The refusal is recorded once, not once per run.
    assert_eq!(fix.journal().matches("refused").count(), 1, "{}", fix.journal());
}

/// A link the review email carried is the one the drain accepts, and a tampered
/// signature changes nothing: the click is verified against the same key, and
/// the application is decided only when it verifies.
#[test]
fn a_signed_link_decides_and_a_tampered_one_does_not() {
    let fix = Fix::new("signature");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());

    // Pull the approve link out of the message the drain just sent.
    let sent = fix.sent();
    let marker = format!("/decide/{TOKEN}?action=approve&sig=");
    let start = sent.find(&marker).expect(&sent) + marker.len();
    let sig: String = sent[start..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    assert_eq!(sig.len(), 64, "{sig}");

    // A tampered signature is refused and the application is untouched.
    let tampered = format!("{}0", &sig[..63]);
    let id = ulid();
    fix.write_intent(
        &id,
        &json!({
            "id": id, "kind": "approve", "filed_at": "2026-10-02T09:00:00Z",
            "application": {"username": "secretary", "status_token": TOKEN},
            "action": "approve", "sig": tampered,
        }),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.dir.join("store/accounts/secretary/account.json").exists(),
        "a tampered signature must not decide the application"
    );
    std::fs::remove_file(fix.dir.join("store/intents").join(format!("{id}.json"))).unwrap();

    // The signature the email actually carried is accepted.
    let id = ulid();
    fix.write_intent(
        &id,
        &json!({
            "id": id, "kind": "approve", "filed_at": "2026-10-02T09:00:00Z",
            "application": {"username": "secretary", "status_token": TOKEN},
            "action": "approve", "sig": sig,
        }),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.dir.join("store/accounts/secretary/account.json").exists());
}

/// The approval runs the two provisioning scripts in the order the spec fixes.
#[test]
fn an_approval_provisions_with_add_user_first() {
    let fix = Fix::new("provision");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());

    let log = fix.scripts_log();
    let add = log.find("add-user.sh secretary").expect(&log);
    let member = log.find("provision-member.sh secretary").expect(&log);
    assert!(add < member, "add-user.sh comes first: {log}");
    // The account holds its own copy of the application and its notices.
    assert!(fix.dir.join("store/accounts/secretary/account.json").exists());
    assert!(fix.dir.join("store/accounts/secretary/application.json").exists());
    assert!(!fix.read("accounts/secretary/notices.jsonl").is_empty());
}
