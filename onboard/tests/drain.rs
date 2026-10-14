//! The drain's acceptance criteria, run with no root and no live store.
//!
//! Every path the drain touches is a configuration value, so a test rebinds the
//! store, the script directory, the enqueuer and the secret files to fixtures
//! under a temporary directory, the way `scripts/provision-member-capsule.sh
//! --self-test` rebinds its own. The two binaries are the real ones, driven the
//! way cron and the reviewer drive them.

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Output;

use kyriakon_onboard::sign;
use serde_json::{json, Value};

const DRAIN: &str = env!("CARGO_BIN_EXE_kyriakon-onboard-drain");
const CTL: &str = env!("CARGO_BIN_EXE_kyriakon-onboardctl");

/// A status token: 26 lowercase Crockford characters, which is 128 bits.
const TOKEN: &str = "0123456789abcdefghjkmnpqrs";

/// A second status token, for a second application on the same username.
const OTHER_TOKEN: &str = "fedcba98765432100123456789";

/// The key file's body: `read_key` reads this and strips the trailing newline,
/// and the fixtures must be 0600 for it to be accepted at all.
const KEY: &[u8] = b"the approval key\n";

/// A bare SSH public key line, the shape `provision-member.sh` accepts and what
/// the upload key file it reads holds.
const UPLOAD_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample secretary@example";

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
        std::fs::write(fix.path("key"), KEY).unwrap();
        std::fs::set_permissions(
            fix.path("key"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        // The box's account list, empty to start: the drain reads it to tell its
        // own half-finished approval from somebody else's account.
        std::fs::write(fix.path("passwd"), "").unwrap();
        let sent = fix.path("sent");
        fix.script("enqueuer.sh", &format!("#!/bin/sh\ncat >> '{sent}'\n"));
        for s in ["provision-member.sh", "delete-user.sh", "cron-apply.sh"] {
            let log = fix.path("scripts.log");
            fix.script(s, &format!("#!/bin/sh\necho \"{s} $*\" >> '{log}'\n"));
        }
        fix.add_user_writes_passwd();
        let cfg = format!(
            "store_root = \"{}\"\n\
             scripts = \"{}\"\n\
             sendmail = \"{}\"\n\
             passwd = \"{}\"\n\
             approval_key = \"{}\"\n\
             keyring_dir = \"{}\"\n\
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
            fix.path("passwd"),
            fix.path("key"),
            fix.path("keyring"),
            fix.dir.display(),
            fix.dir.display(),
        );
        std::fs::write(fix.path("drain.toml"), cfg).unwrap();
        fix
    }

    fn path(&self, rel: &str) -> String {
        self.dir.join(rel).to_str().unwrap().to_string()
    }

    fn passwd_file(&self) -> String {
        std::fs::read_to_string(self.dir.join("passwd")).unwrap_or_default()
    }

    fn set_passwd(&self, text: &str) {
        std::fs::write(self.dir.join("passwd"), text).unwrap();
    }

    /// An add-user.sh that makes the account in the passwd fixture and refuses a
    /// name already there, the shape the real script has. The box is what the
    /// drain reads to tell its own half-finished approval from somebody else's
    /// account.
    fn add_user_writes_passwd(&self) {
        let p = self.path("passwd");
        let log = self.path("scripts.log");
        self.script(
            "add-user.sh",
            &format!(
                "#!/bin/sh\nif grep -q \"^$1:\" '{p}'; then\n\techo \"user $1 already exists\" >&2\n\texit 1\nfi\nprintf '%s:x:1000:1000::/home/%s:/sbin/nologin\\n' \"$1\" \"$1\" >> '{p}'\necho \"add-user.sh $*\" >> '{log}'\n"
            ),
        );
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
        self.filed_with(username, rail, answers, None, Some((UPLOAD_KEY, "works")))
    }

    fn filed_with(
        &self,
        username: &str,
        rail: &str,
        answers: &[(&str, &str)],
        outside_address: Option<&str>,
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
            "outside_address": outside_address,
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
        let action = action_for(kind);
        let sig = self.sign_action(action);
        self.write_decision(kind, action, &sig, username)
    }

    /// A decision intent with whatever action and signature the caller gives, so
    /// a test can try one the drain must refuse.
    fn write_decision(&self, kind: &str, action: &str, sig: &str, username: &str) -> String {
        let id = ulid();
        self.write_intent(
            &id,
            &json!({
                "id": id,
                "kind": kind,
                "filed_at": "2026-10-02T09:00:00Z",
                "application": {"username": username, "status_token": TOKEN},
                "action": action,
                "sig": sig,
            }),
        );
        id
    }

    /// The signature the drain will accept for an action, from the same key the
    /// fixture's onboardctl reads.
    fn sign_action(&self, action: &str) -> String {
        sign::sign(b"the approval key", &sign::decide_payload(TOKEN, action)).unwrap()
    }

    /// A provision-member.sh that refuses when the upload key file is not there,
    /// the shape the real script has, so an approval that fails to write it
    /// fails the way it would on the box.
    fn provision_requires_key(&self) {
        let key = self.dir.join("store/keys/$1.pub");
        let log = self.path("scripts.log");
        self.script(
            "provision-member.sh",
            &format!(
                "#!/bin/sh\nif [ ! -f \"{}\" ]; then echo \"no public key at {}\" >&2; exit 1; fi\necho \"provision-member.sh $*\" >> '{log}'\n",
                key.display(),
                key.display()
            ),
        );
    }

    /// A provision-member.sh that always fails, for a retry test's first run.
    fn provision_fails(&self) {
        self.script(
            "provision-member.sh",
            "#!/bin/sh\necho 'builder refused' >&2\nexit 1\n",
        );
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

    /// Move every failed attempt in the journal into the past, so a test can
    /// reach the retry a backoff is holding back without waiting out the minute.
    fn age_failures(&self) {
        let path = self.dir.join("store/journal.jsonl");
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let mut out = String::new();
        for line in text.lines() {
            match serde_json::from_str::<Value>(line) {
                Ok(mut v) if v.get("outcome").and_then(Value::as_str) == Some("failed") => {
                    v["at"] = json!("2026-09-01T00:00:00Z");
                    out.push_str(&serde_json::to_string(&v).unwrap());
                }
                _ => out.push_str(line),
            }
            out.push('\n');
        }
        std::fs::write(path, out).unwrap();
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

/// The signed action each decision kind carries: the free outcome is the
/// `provision` kind and the `approve-free` action.
fn action_for(kind: &str) -> &'static str {
    match kind {
        "approve" => "approve",
        "provision" => "approve-free",
        "decline" => "decline",
        other => panic!("no action for kind {other}"),
    }
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
    // Every decision intent is signed: the drain refuses one that is not.
    assert_eq!(intent["action"], json!("approve"));
    let sig = intent["sig"].as_str().unwrap();
    assert!(
        sign::verify(b"the approval key", &sign::decide_payload(TOKEN, "approve"), sig),
        "{intent}"
    );

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

/// `show` names a window only where the account has one. A charged approval
/// opens a window, so its output carries it and the date it closes; a no-charge
/// approval has none and its output says so instead, rather than naming a window
/// the member would watch for in vain.
#[test]
fn show_names_a_window_only_when_the_account_has_one() {
    let charged = Fix::new("show-charged");
    let record = charged.filed("secretary", "monero", &[("rail", "monero")]);
    charged.file_application(&record);
    assert!(charged.drain().status.success());
    charged.decide("approve", "secretary");
    let out = charged.drain();
    assert!(out.status.success(), "{}", body(&out));

    let account = charged.account("secretary");
    let window = &account["window"];
    let opened = window["opened_at"].as_str().expect("a charged approval opens a window");
    let closes = window["closes_at"].as_str().unwrap();
    let out = charged.ctl(&["show", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let text = body(&out);
    assert!(text.contains(&format!("  window   {opened} to {closes}")), "{text}");

    let free = Fix::new("show-free");
    let record = free.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    free.file_application(&record);
    assert!(free.drain().status.success());
    free.decide("provision", "secretary");
    let out = free.drain();
    assert!(out.status.success(), "{}", body(&out));

    let out = free.ctl(&["show", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let text = body(&out);
    assert!(!text.contains("window"), "no window exists to name: {text}");
    assert!(text.contains("no charge"), "the line should say what is true: {text}");
}

/// A decline purges nothing on the first run; the run after its week clears the
/// application away and releases the username.
#[test]
fn a_decline_purges_after_its_week_and_releases_the_username() {
    let fix = Fix::new("decline");
    // The applicant gave an address outside the platform, so the decline is
    // mailed. Without one nothing is sent, which the next test covers.
    let record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
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
/// and sends no notice twice. The second pass is made to re-read the same intent,
/// the state a run that died before it deleted the file leaves, so the pass
/// reaches the dedup rather than merely seeing an empty directory.
#[test]
fn two_runs_over_one_intent_directory_send_nothing_twice() {
    let fix = Fix::new("twice");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    let id = fix.file_application(&record);
    let intent = fix.read(&format!("intents/{id}.json"));

    assert!(fix.drain().status.success());
    let after_first = fix.snapshot();
    assert_eq!(fix.sent().matches("Subject:").count(), 1, "one review email");

    // The same intent again, as a crash before the delete leaves it: the second
    // pass re-reads it and must find the application already reviewed.
    std::fs::write(
        fix.dir.join("store/intents").join(format!("{id}.json")),
        &intent,
    )
    .unwrap();
    assert!(fix.drain().status.success());
    let after_second = fix.snapshot();

    assert_eq!(after_first, after_second, "the second run changed the store");
    assert_eq!(fix.sent().matches("Subject:").count(), 1, "no second review email");
    assert!(fix.intents().is_empty(), "the re-read intent is consumed: {:?}", fix.intents());
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
    // The lanes wrote the member's daemon files, so the web index and reload
    // pass runs for a hosting member.
    assert!(
        log.contains("cron-apply.sh --web"),
        "the web index and reload should run: {log}"
    );
    // The account holds its own copy of the application and its notices.
    assert!(fix.dir.join("store/accounts/secretary/account.json").exists());
    assert!(fix.dir.join("store/accounts/secretary/application.json").exists());
    assert!(!fix.read("accounts/secretary/notices.jsonl").is_empty());
    // The completion line is written, so a finished approval does not read like
    // one that died midway.
    assert!(fix.journal().contains("\"applied\""), "{}", fix.journal());
}

/// The upload key the application carried is written where `provision-member.sh`
/// reads it before that script runs, so an approval completes against the real
/// script's contract rather than only against a stub that ignores the key.
#[test]
fn an_approval_writes_the_upload_key_the_builder_reads() {
    let fix = Fix::new("keyfile");
    fix.provision_requires_key();
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).is_empty(),
        "the approval reported an error: {}",
        body(&out)
    );
    let key = fix.read("keys/secretary.pub");
    assert!(key.contains(UPLOAD_KEY), "{key}");
    assert!(
        fix.scripts_log().contains("provision-member.sh secretary"),
        "{}",
        fix.scripts_log()
    );
    assert!(fix.dir.join("store/accounts/secretary/account.json").exists());
}

/// An approval publishes the member's mail key into the box keyring the
/// encrypting LMTP reads, named for the localpart and at the mode deploy-mail
/// installs the tracked keys with, before anything can deliver.
#[test]
fn an_approval_publishes_the_mail_key_to_the_keyring() {
    let fix = Fix::new("keyring");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let path = fix.dir.join("keyring/secretary.asc");
    let published = std::fs::read_to_string(&path).expect("the key is in the keyring");
    assert!(published.contains("BEGIN PGP PUBLIC KEY BLOCK"), "{published}");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644,
        "the keyring file carries the mode deploy-mail installs"
    );
}

/// An application with no mail key is refused rather than approved into an
/// account whose mail bounces: delivery fails closed without a key.
#[test]
fn an_application_with_no_mail_key_is_refused() {
    let fix = Fix::new("no-mail-key");
    let mut record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    record["mail_keys"] = json!([]);
    std::fs::write(
        fix.dir.join(format!("store/applications/{TOKEN}.json")),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.dir.join("store/accounts/secretary/account.json").exists(),
        "an account with no mail key must not be made"
    );
    assert!(body(&out).contains("no mail key"), "{}", body(&out));
    assert_eq!(fix.intents().len(), 1, "the intent is left in place");
    assert!(
        !fix.dir.join("keyring/secretary.asc").exists(),
        "nothing was published for a keyless application"
    );
}

/// An application with no upload key is still built: mail is unconditional, and
/// the builder is what writes the member's address and allowance. The key file
/// is written only when the application carried one.
#[test]
fn an_approval_without_an_upload_key_still_builds_the_member() {
    let fix = Fix::new("mail-only");
    let record = fix.filed_with("secretary", "cash", &[("rail", "cash")], None, None);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    // The builder that writes the member's address and allowance ran, with no
    // key to build hosting from. That is the address path, which every member
    // takes, mail-only included, and it is where provision-member.sh restarts
    // smtpd; only the web lanes and the public tree wait on a key.
    assert!(
        fix.scripts_log().contains("provision-member.sh secretary"),
        "{}",
        fix.scripts_log()
    );
    assert_eq!(
        fix.scripts_log().matches("provision-member.sh").count(),
        1,
        "the builder runs once, address path included: {}",
        fix.scripts_log()
    );
    assert!(fix.dir.join("store/accounts/secretary/account.json").exists());
    assert!(fix.names("keys").is_empty(), "no key, no key file: {:?}", fix.names("keys"));
    // No vhost files were written, so the web reload does not run and prints
    // nothing.
    assert!(
        !fix.scripts_log().contains("cron-apply.sh"),
        "a mail-only member has no web files to index: {}",
        fix.scripts_log()
    );
}

/// A retry completes after a run that died at the builder. The box holds the
/// account the first run made and the journal shows this application started it,
/// so the retry skips add-user.sh, which is not idempotent, and finishes.
#[test]
fn a_retried_approval_completes() {
    let fix = Fix::new("retry");
    // The first run's builder fails, leaving the account half-made: add-user.sh
    // ran and made the box account, no account.json exists, and the intent stays.
    fix.provision_fails();
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());
    assert!(
        !fix.dir.join("store/accounts/secretary/account.json").exists(),
        "the first run must fail at the builder"
    );
    assert_eq!(fix.intents().len(), 1, "{:?}", fix.intents());
    assert!(
        fix.passwd_file().contains("secretary:"),
        "the box should hold the name the first run made: {}",
        fix.passwd_file()
    );

    // The builder works on the retry; the box oracle and the journal say the
    // account is this application's, so add-user.sh is not run again. The
    // backoff is moved out of the way the way a real minute would.
    fix.age_failures();
    fix.provision_requires_key();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        fix.dir.join("store/accounts/secretary/account.json").exists(),
        "the retry did not complete: {}",
        body(&out)
    );
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert_eq!(
        fix.scripts_log().matches("add-user.sh").count(),
        1,
        "add-user.sh ran once, not once per pass: {}",
        fix.scripts_log()
    );
}

/// A failing intent is reported once rather than every pass, and is not retried
/// again inside its backoff window. A stuck intent therefore costs the operator
/// one mail, not one a minute.
#[test]
fn a_failing_intent_reports_once_and_backs_off() {
    let fix = Fix::new("stuck");
    // An approve intent for an application that is not on disk: a failure the
    // drain cannot get past on its own.
    fix.decide("approve", "secretary");

    let first = fix.drain();
    assert!(first.status.success(), "{}", body(&first));
    assert_eq!(
        body(&first).matches("there is no application").count(),
        1,
        "the first failure is reported once: {}",
        body(&first)
    );
    assert_eq!(fix.intents().len(), 1, "the intent is left in place: {:?}", fix.intents());
    assert!(fix.journal().contains("\"failed\""), "{}", fix.journal());

    // Inside the backoff window the intent is not retried and nothing is printed.
    let second = fix.drain();
    assert!(second.status.success(), "{}", body(&second));
    assert!(body(&second).is_empty(), "a backed-off failure is silent: {}", body(&second));
    assert_eq!(fix.journal().matches("\"failed\"").count(), 1, "{}", fix.journal());

    let third = fix.drain();
    assert!(body(&third).is_empty(), "still inside the minute: {}", body(&third));
}

/// An approval whose username is already on the box without this application
/// having started it is refused rather than adopting somebody else's account,
/// and the refusal names the name and leaves the intent in place.
#[test]
fn an_approval_for_a_name_the_box_already_has_is_refused() {
    let fix = Fix::new("taken");
    fix.set_passwd("secretary:x:1000:1000::/home/secretary:/sbin/nologin\n");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.dir.join("store/accounts/secretary/account.json").exists(),
        "an account the application did not make must not be adopted"
    );
    assert!(
        body(&out).contains("secretary") && body(&out).contains("in use"),
        "the refusal names the name: {}",
        body(&out)
    );
    // Nothing was run against the box's account: no add-user, no builder, no
    // release.
    assert!(fix.scripts_log().is_empty(), "{}", fix.scripts_log());
    assert!(fix.passwd_file().contains("secretary:"), "the box account is untouched");
    assert_eq!(fix.intents().len(), 1, "the intent is left in place");
}

/// The purge leaves a name the box holds alone, whether or not this service
/// wrote a record for it, and clears the declined application away.
#[test]
fn a_purge_leaves_a_name_the_box_holds_alone() {
    let fix = Fix::new("purge-box");
    fix.set_passwd("secretary:x:1000:1000::/home/secretary:/sbin/nologin\n");
    let declined = json!({
        "username": "secretary",
        "status_token": TOKEN,
        "filed_at": "2026-08-01T09:00:00Z",
        "front_end": "web",
        "stage": "declined: no reason given",
        "decided_at": "2026-09-01T00:00:00Z",
        "answers": {},
        "mail_keys": [],
        "rail": "cash",
        "no_charge": false,
        "acceptances": [],
        "question_list": "2026-08-01 abc1234",
    });
    std::fs::write(
        fix.dir.join(format!("store/applications/{TOKEN}.json")),
        serde_json::to_vec_pretty(&declined).unwrap(),
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(!fix.dir.join(format!("store/applications/{TOKEN}.json")).exists());
    assert!(
        !fix.scripts_log().contains("delete-user.sh"),
        "the box account's name was released: {}",
        fix.scripts_log()
    );
    assert!(fix.passwd_file().contains("secretary:"), "the box account is untouched");
}

/// An address the applicant wrote cannot become a second recipient or a header
/// line when the decision email is built.
#[test]
fn an_address_that_could_inject_a_header_is_refused() {
    for (i, bad) in ["x,attacker@evil.example", "x\nBcc: attacker@evil.example"]
        .iter()
        .enumerate()
    {
        let fix = Fix::new(&format!("address-{i}"));
        let record = fix.filed_with(
            "secretary",
            "cash",
            &[("rail", "cash")],
            Some(bad),
            Some((UPLOAD_KEY, "works")),
        );
        fix.file_application(&record);
        assert!(fix.drain().status.success());
        fix.decide("approve", "secretary");
        let out = fix.drain();
        assert!(out.status.success(), "{}", body(&out));
        assert!(
            !fix.dir.join("store/accounts/secretary/account.json").exists(),
            "{bad:?} must not decide the application"
        );
        assert!(
            !fix
                .sent()
                .lines()
                .any(|l| l.starts_with("To:") && l.contains("attacker")),
            "an injected recipient became a header: {}",
            fix.sent()
        );
        assert_eq!(fix.intents().len(), 1, "the intent is left for the reviewer");
    }
}

/// A decision intent with no signature, and one whose signature is over another
/// action, are both refused: `intents/` belongs to the unprivileged half, so an
/// unsigned decision would be root provisioning driven by a file it wrote.
#[test]
fn a_decision_without_a_good_signature_is_refused() {
    let fix = Fix::new("unsigned");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());

    // No action and no signature at all.
    let id = ulid();
    fix.write_intent(
        &id,
        &json!({
            "id": id, "kind": "approve", "filed_at": "2026-10-02T09:00:00Z",
            "application": {"username": "secretary", "status_token": TOKEN},
        }),
    );
    assert!(fix.drain().status.success());
    assert!(
        !fix.dir.join("store/accounts/secretary/account.json").exists(),
        "an unsigned decision must not provision anything"
    );

    // A signature over a different action than the kind carries.
    let id = ulid();
    fix.write_intent(
        &id,
        &json!({
            "id": id, "kind": "approve", "filed_at": "2026-10-02T09:00:00Z",
            "application": {"username": "secretary", "status_token": TOKEN},
            "action": "decline", "sig": fix.sign_action("decline"),
        }),
    );
    assert!(fix.drain().status.success());
    assert!(
        !fix.dir.join("store/accounts/secretary/account.json").exists(),
        "a signature over the wrong action must not decide the application"
    );
    // Both are left in place, not silently dropped.
    assert_eq!(fix.intents().len(), 2, "{:?}", fix.intents());
}

/// The record the drain rewrites stays readable by the handler: it keeps the
/// mode and the owner of the directory the handler owns, so the status link goes
/// on answering for its seven days.
#[test]
fn a_decided_record_keeps_the_handler_directorys_owner_and_mode() {
    let fix = Fix::new("owner");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());

    let file =
        std::fs::metadata(fix.dir.join(format!("store/applications/{TOKEN}.json"))).unwrap();
    let dir = std::fs::metadata(fix.dir.join("store/applications")).unwrap();
    assert_eq!(file.mode() & 0o777, 0o600, "the record stays 0600");
    assert_eq!(file.uid(), dir.uid(), "and owned like the directory it lives in");
    assert_eq!(file.gid(), dir.gid(), "and its group is the directory's group");
}

/// A decline with no address outside the platform sends nothing: no mailbox was
/// created for it, so the status link is the channel, and the decision is still
/// recorded on the application.
#[test]
fn a_decline_with_no_outside_address_sends_nothing() {
    let fix = Fix::new("decline-silent");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    assert_eq!(fix.sent().matches("Subject:").count(), 1, "the review email");

    fix.decide("decline", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.sent().matches("Subject:").count(), 1, "no decline email was sent");
    assert!(!fix.sent().contains("declined"), "{}", fix.sent());
    let app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(app["decided_at"].is_string(), "{app}");
    assert!(app["stage"].as_str().unwrap().starts_with("declined"), "{app}");
}

/// The purge clears a declined application away but never releases a username a
/// live account holds: the front end does not check whether a name is taken, so
/// an approved account and a declined application can share one.
#[test]
fn a_purge_never_releases_a_name_an_account_holds() {
    let fix = Fix::new("collision");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());
    assert!(fix.dir.join("store/accounts/secretary/account.json").exists());

    // A second application for the same username, for another token, declined a
    // week and more ago.
    let declined = json!({
        "username": "secretary",
        "status_token": OTHER_TOKEN,
        "filed_at": "2026-08-01T09:00:00Z",
        "front_end": "web",
        "stage": "declined: no reason given",
        "decided_at": "2026-09-01T00:00:00Z",
        "answers": {},
        "mail_keys": [],
        "rail": "cash",
        "no_charge": false,
        "acceptances": [],
        "question_list": "2026-08-01 abc1234",
    });
    std::fs::write(
        fix.dir.join(format!("store/applications/{OTHER_TOKEN}.json")),
        serde_json::to_vec_pretty(&declined).unwrap(),
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    // The declined application is cleared away, the live account is untouched,
    // and no release script ran for a name that is in use.
    assert!(!fix.dir.join(format!("store/applications/{OTHER_TOKEN}.json")).exists());
    assert!(fix.dir.join("store/accounts/secretary/account.json").exists());
    assert!(
        !fix.scripts_log().contains("delete-user.sh"),
        "a live account's name was released: {}",
        fix.scripts_log()
    );
}
