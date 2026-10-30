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

use askama::Template;
use kyriakon_onboard::store::{self, Record};
use kyriakon_onboard::{capsule, page, responder, sign};
use serde_json::{json, Value};
use time::OffsetDateTime;

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

/// A public key block with the structure of a key the check can read.
const GOOD_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
mAYEAAAAABK4BgQAAAAAEg==\n-----END PGP PUBLIC KEY BLOCK-----\n";

struct Fix {
    dir: PathBuf,
}

impl Fix {
    fn new(name: &str) -> Fix {
        let dir = std::env::temp_dir().join(format!("onboard-it-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in [
            "store/intents",
            "store/applications",
            "store/mail/new",
            "bin",
        ] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let fix = Fix { dir };
        std::fs::write(fix.path("key"), KEY).unwrap();
        std::fs::set_permissions(fix.path("key"), std::fs::Permissions::from_mode(0o600)).unwrap();
        // The box's account list, empty to start: the drain reads it to tell its
        // own half-finished approval from somebody else's account.
        std::fs::write(fix.path("passwd"), "").unwrap();
        // The virtual tables deploy-mail.sh seeds: the platform's domain and no
        // address entries yet, so a group's lines are the drain's.
        std::fs::write(fix.path("mail_domains"), "kyriakon.net\n").unwrap();
        std::fs::write(fix.path("virtuals"), "").unwrap();
        std::fs::write(fix.path("dkim_domains"), "kyriakon.net\n").unwrap();
        // The held-back names, copied from the tracked list so that a test can add
        // one to the fixture's without touching the repository's.
        let tracked = std::fs::read_to_string(format!(
            "{}/../reserved-usernames.txt",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap_or_default();
        std::fs::write(fix.path("reserved"), tracked).unwrap();
        let sent = fix.path("sent");
        fix.script("enqueuer.sh", &format!("#!/bin/sh\ncat >> '{sent}'\n"));
        for s in [
            "provision-member.sh",
            "cron-apply.sh",
            "publish-mail-key.sh",
            "reload-smtpd.sh",
        ] {
            let log = fix.path("scripts.log");
            fix.script(s, &format!("#!/bin/sh\necho \"{s} $*\" >> '{log}'\n"));
        }
        // delete-user.sh removes the box account and the store record; the
        // stub does both so a test sees what the box sees.
        let log = fix.path("scripts.log");
        let passwd = fix.path("passwd");
        let accounts = fix.path("store/accounts");
        fix.script(
            "delete-user.sh",
            &format!(
                "#!/bin/sh\necho \"delete-user.sh $*\" >> '{log}'\ngrep -v \"^$1:\" '{passwd}' > '{passwd}.del'\nmv '{passwd}.del' '{passwd}'\nrm -rf '{accounts}/'\"$1\"\n",
            ),
        );
        fix.add_user_writes_passwd();
        // The DNS sweep's resolver. It answers every query with one non-empty
        // line, so a group with records is not an outage; a test that wants one
        // rewrites it with `resolver`.
        fix.resolver(None);
        let cfg = format!(
            "store_root = \"{}\"\n\
             reserved = \"{}\"\n\
             scripts = \"{}\"\n\
             sendmail = \"{}\"\n\
             passwd = \"{}\"\n\
             mail_domains = \"{}\"\n\
             virtuals = \"{}\"\n\
             dkim_domains = \"{}\"\n\
             approval_key = \"{}\"\n\
             keyring_dir = \"{}\"\n\
             stripe_webhook_secret = \"{}/stripe\"\n\
             keyring_publish_token = \"{}/keyring-token\"\n\
             reviewer = \"reviewer@example.invalid\"\n\
             from = \"kyriakon <hello@example.invalid>\"\n\
             base_url = \"https://signup.kyriakon.net\"\n\
             price_gbp = \"20.00\"\n\
             postal_address = \"1 Example Street, Example\"\n\
             mail_dir = \"{}/store/mail/new\"\n\
             release = \"2026-10-10 abc1234\"\n\
             mail_host = \"mail.kyriakon.net\"\n\
             ipv4 = \"192.0.2.10\"\n\
             ipv6 = \"2001:db8::10\"\n\
             dkim_selector = \"mail\"\n\
             dkim_public_key = \"v=DKIM1; k=rsa; p=examplepublickey\"\n\
             dmarc_rua = \"mailto:dmarc@kyriakon.net\"\n\
             resolver = \"{}\"\n",
            fix.path("store"),
            fix.path("reserved"),
            fix.path("bin"),
            fix.path("bin/enqueuer.sh"),
            fix.path("passwd"),
            fix.path("mail_domains"),
            fix.path("virtuals"),
            fix.path("dkim_domains"),
            fix.path("key"),
            fix.path("keyring"),
            fix.dir.display(),
            fix.dir.display(),
            fix.dir.display(),
            fix.path("bin/dig"),
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

    /// Hold one more name back, as adding a hostname to the tracked list does.
    fn reserve(&self, name: &str) {
        let p = self.dir.join("reserved");
        let mut text = std::fs::read_to_string(&p).unwrap_or_default();
        text.push_str(name);
        text.push('\n');
        std::fs::write(&p, text).unwrap();
    }

    /// The note on the last failed journal line. It is what the operator's mail
    /// carries, and the only place a refused name can be read: a failure is
    /// journalled against an empty application, so a name that is not in the note
    /// is a name the operator cannot see.
    fn failed_note(&self) -> String {
        self.journal()
            .lines()
            .rfind(|l| l.contains("\"outcome\":\"failed\""))
            .unwrap_or_default()
            .to_string()
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

    /// The DNS sweep's resolver: it logs every query and answers the row the
    /// recipe names, unless `missing` is that row's key, in which case it
    /// answers nothing, or `unmarked` is, in which case it answers a TXT string
    /// without the expected marker. Keys are `MX`, `A-apex`, `A-www`,
    /// `AAAA-apex`, `AAAA-www`, `SPF`, `DKIM` and `DMARC`. It is a stub by
    /// design, so no test resolves a name.
    fn resolver(&self, missing: Option<&str>) {
        self.resolver_with(missing, None);
    }

    fn resolver_with(&self, missing: Option<&str>, unmarked: Option<&str>) {
        let log = self.path("scripts.log");
        let missing = missing.unwrap_or("");
        let unmarked = unmarked.unwrap_or("");
        self.script(
            "dig",
            &format!(
                "#!/bin/sh\n\
                 printf 'dig %s\\n' \"$*\" >> '{log}'\n\
                 case \"$2\" in\n\
                 MX) key=MX; answer='10 mail.kyriakon.net.' ;;\n\
                 A) case \"$3\" in www.*) key=A-www ;; *) key=A-apex ;; esac; answer='192.0.2.10' ;;\n\
                 AAAA) case \"$3\" in www.*) key=AAAA-www ;; *) key=AAAA-apex ;; esac; answer='2001:db8::10' ;;\n\
                 TXT) case \"$3\" in\n\
                 _dmarc.*) key=DMARC; answer='v=DMARC1; p=none; rua=mailto:dmarc@kyriakon.net' ;;\n\
                 *._domainkey.*) key=DKIM; answer='v=DKIM1; k=rsa; p=examplepublickey' ;;\n\
                 *) key=SPF; answer='v=spf1 mx -all' ;;\n\
                 esac ;;\n\
                 *) exit 1 ;;\n\
                 esac\n\
                 [ '{unmarked}' = \"$key\" ] && answer='some-other-txt'\n\
                 [ '{missing}' = \"$key\" ] && exit 0\n\
                 printf '%s\\n' \"$answer\"\n"
            ),
        );
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
            self.dir
                .join("store/applications")
                .join(format!("{TOKEN}.json")),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        record
    }

    /// Write one `provision-group` intent under `id`, as an approval files it.
    fn write_group(
        &self,
        id: &str,
        domain: &str,
        site_owner: &str,
        addresses: &[(&str, &str)],
        mailboxes: &[&str],
        upload: Option<&str>,
    ) {
        let mail_keys: Vec<Value> = mailboxes
            .iter()
            .map(|mailbox| {
                json!({
                    "mailbox": mailbox,
                    "fingerprint": "1111 2222 3333 4444",
                    "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----",
                    "verdict": "works",
                })
            })
            .collect();
        let addresses: Vec<Value> = addresses
            .iter()
            .map(|(address, mailbox)| json!({"address": address, "mailbox": mailbox}))
            .collect();
        self.write_intent(
            id,
            &json!({
                "id": id,
                "kind": "provision-group",
                "filed_at": "2026-10-02T09:00:00Z",
                "application": {"username": "warden", "status_token": TOKEN},
                "domain": domain,
                "name": "Parish of Example",
                "body_kind": "parish",
                "payment": {"rail": "cash", "no_charge": false, "paid_until": null},
                "addresses": addresses,
                "mailboxes": mailboxes,
                "site_owner": site_owner,
                "upload_key": upload.unwrap_or(""),
                "mail_keys": mail_keys,
            }),
        );
    }

    /// File one `provision-group` intent and hand back its id.
    fn file_group(
        &self,
        domain: &str,
        site_owner: &str,
        addresses: &[(&str, &str)],
        mailboxes: &[&str],
        upload: Option<&str>,
    ) -> String {
        let id = ulid();
        self.write_group(&id, domain, site_owner, addresses, mailboxes, upload);
        id
    }

    /// File one `group-address` intent, signed the way the console signs it.
    /// `key` is the new mailbox's armored mail key, when the change makes one.
    fn file_address(
        &self,
        domain: &str,
        action: &str,
        address: &str,
        mailbox: &str,
        key: Option<&str>,
        site_owner: Option<&str>,
    ) -> String {
        let id = ulid();
        let sig = sign::sign(
            b"the approval key",
            &sign::address_payload(
                domain,
                action,
                address,
                mailbox,
                site_owner.unwrap_or(""),
                key.unwrap_or(""),
            ),
        )
        .unwrap();
        let mail_key = key.map(|material| {
            json!({
                "mailbox": mailbox,
                "fingerprint": "1111 2222 3333 4444",
                "material": material,
                "verdict": "works",
            })
        });
        self.write_intent(
            &id,
            &json!({
                "id": id,
                "kind": "group-address",
                "filed_at": "2026-10-02T09:00:00Z",
                "domain": domain,
                "action": action,
                "address": address,
                "mailbox": mailbox,
                "mail_key": mail_key,
                "site_owner": site_owner,
                "sig": sig,
            }),
        );
        id
    }

    /// A virtual table beside the store, as the drain left it.
    fn table(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.join(name)).unwrap_or_default()
    }

    /// A body's application record, as the community block files it: two
    /// addresses sharing one mailbox, one mail key for it, and the block's
    /// upload key.
    fn filed_body(&self, applicant: &str) -> Value {
        let answers: BTreeMap<&str, &str> = [
            ("whose", "body"),
            ("body_name", "Parish of Example"),
            ("body_kind", "parish"),
            ("body_domain", "parish.example"),
            ("body_records", "yes"),
            ("body_addresses", "secretary: own\noffice: alias secretary"),
            ("body_account_names", "parish-secretary\nparish-secretary"),
            ("body_dns_contact", "warden@example.invalid"),
            ("rail", "cash"),
        ]
        .into_iter()
        .collect();
        let mail_keys = vec![json!({
            "mailbox": "parish-secretary",
            "fingerprint": "1111 2222 3333 4444",
            "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----",
            "verdict": "works",
        })];
        let record = json!({
            "username": applicant,
            "status_token": TOKEN,
            "filed_at": "2026-10-01T09:00:00Z",
            "front_end": "web",
            "stage": "received",
            "domain": "parish.example",
            "outside_address": Value::Null,
            "answers": answers,
            "mail_keys": mail_keys,
            "upload_key": {
                "mailbox": "",
                "fingerprint": "AAAA BBBB CCCC DDDD",
                "material": UPLOAD_KEY,
                "verdict": "works",
            },
            "rail": "cash",
            "no_charge": false,
            "acceptances": [{"document": "terms", "version": "2026-10-01 abc1234"}],
            "question_list": "2026-10-01 abc1234",
        });
        std::fs::write(
            self.dir
                .join("store/applications")
                .join(format!("{TOKEN}.json")),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        record
    }

    /// Replace the application record `filed_body` wrote, when a test changes
    /// its answers after building it.
    fn rewrite_record(&self, record: &Value) {
        std::fs::write(
            self.dir
                .join("store/applications")
                .join(format!("{TOKEN}.json")),
            serde_json::to_vec_pretty(record).unwrap(),
        )
        .unwrap();
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

    /// An enqueuer that refuses: the box's mail path is broken, which is when the
    /// fallback a printed alert relies on is the only channel left.
    fn enqueuer_fails(&self) {
        self.script("enqueuer.sh", "#!/bin/sh\ncat >/dev/null\nexit 1\n");
    }

    /// The working enqueuer back, for a test that broke the mail path and then
    /// wants the retry to go through.
    fn enqueuer_works(&self) {
        let sent = self.path("sent");
        self.script("enqueuer.sh", &format!("#!/bin/sh\ncat >> '{sent}'\n"));
    }

    /// A publish-mail-key.sh that refuses, in the shape the real one has when the
    /// forge will not take the change: the member and the key named on stderr,
    /// and a non-zero exit.
    fn publish_fails(&self) {
        let log = self.path("scripts.log");
        self.script(
            "publish-mail-key.sh",
            &format!(
                "#!/bin/sh\necho \"publish-mail-key.sh $*\" >> '{log}'\n\
                 printf 'publish-mail-key.sh: %s (1111 2222 3333 4444): the token cannot read the repository\\n' \"$1\" >&2\n\
                 exit 2\n"
            ),
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

    /// A draft on disk, as the capsule leaves it before a key page.
    fn write_draft(&self, token: &str, answers: &[(&str, &str)]) {
        let answers: BTreeMap<String, String> = answers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let draft = json!({
            "version": 1,
            "token": token,
            "answers": answers,
            "cursor": 0,
            "created_at": "2026-10-10T00:00:00Z",
            "updated_at": "2026-10-10T00:00:00Z",
        });
        std::fs::create_dir_all(self.dir.join("store/drafts")).unwrap();
        std::fs::write(
            self.dir.join("store/drafts").join(format!("{token}.json")),
            serde_json::to_vec_pretty(&draft).unwrap(),
        )
        .unwrap();
    }

    /// One raw message in the apply@ spool, the way smtpd delivers it.
    fn mail(&self, name: &str, from: &str, subject: &str, body: &str) {
        std::fs::write(
            self.dir.join("store/mail/new").join(name),
            format!("From: {from}\nSubject: {subject}\n\n{body}\n"),
        )
        .unwrap();
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
        &[
            ("rail", "cash"),
            ("cannot_pay", "I have no money"),
            ("intended_use", "For parish mail"),
        ],
    );
    fix.file_application(&record);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    // One message, to the reviewer.
    assert_eq!(sent.matches("Subject:").count(), 1, "{}", body(&out));
    assert!(sent.contains("To: reviewer@example.invalid"), "{sent}");
    // The subject says what happened, in the shape every operator mail carries,
    // so a crowded mailbox can be triaged from the list.
    assert!(
        sent.contains("Subject: kyriakon: onboard: application filed (secretary,"),
        "{sent}"
    );
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
    assert!(
        sent.contains("\n  kyriakon-onboardctl approve secretary\n"),
        "{sent}"
    );
    assert!(
        sent.contains("\n  kyriakon-onboardctl approve-free secretary\n"),
        "{sent}"
    );
    assert!(
        sent.contains("\n  kyriakon-onboardctl decline secretary\n"),
        "{sent}"
    );
    // Each decision link is on a line of its own, so a client that wraps at a
    // fixed width has a chance of keeping the URL whole; and the terminal form
    // is printed before them, because it cannot be wrapped at all.
    let lines: Vec<&str> = sent.lines().collect();
    let link_lines = lines
        .iter()
        .filter(|l| l.trim_start().starts_with("https://") && l.contains("/decide/"))
        .count();
    assert_eq!(link_lines, 3, "{sent}");
    let terminal = sent.find("onboardctl approve-free").unwrap();
    let first_link = sent.find("/decide/").unwrap();
    assert!(terminal < first_link, "the terminal form comes first");

    // The intent is consumed.
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
}

/// A password set through the one-time link is applied once, and only with a
/// signature over the link's own token and date. The hash reaches the script,
/// the record stops holding the link, and a replay or a forged signature is
/// refused without the script being run.
#[test]
fn a_password_link_applies_once_and_only_when_signed() {
    let fix = Fix::new("password");
    let log = fix.path("password.log");
    fix.script(
        "set-mail-password.sh",
        &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\n"),
    );
    let key = sign::read_key(std::path::Path::new(&fix.path("key"))).unwrap();
    let until = kyriakon_onboard::util::date_after_days(7);
    let hash = kyriakon_onboard::password::make("correct horse battery").unwrap();

    let mut record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    record["password_link"] = json!(format!(
        "https://signup.example.invalid/password/{TOKEN}?until={until}&sig=x"
    ));
    std::fs::write(
        fix.path(&format!("store/applications/{TOKEN}.json")),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();

    let sig = sign::sign(&key, &sign::password_payload(TOKEN, &until)).unwrap();
    let intent = json!({
        "id": "01J00000000000000000PASSWORD",
        "kind": "set-password",
        "filed_at": "2026-10-21T09:00:00Z",
        "application": { "username": "secretary", "status_token": TOKEN },
        "until": until,
        "sig": sig,
        "hash": hash,
    });
    fix.write_intent("01J00000000000000000PASSWORD", &intent);
    let out = fix.drain();
    assert!(
        out.status.success(),
        "status {:?}\nstdout: {}\nstderr: {}",
        out.status,
        body(&out),
        String::from_utf8_lossy(&out.stderr)
    );

    // The script ran once, with the account and the hash and never a plaintext.
    let written = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        written.contains(&format!("secretary {hash}")),
        "journal: {}",
        std::fs::read_to_string(fix.path("store/journal.jsonl")).unwrap_or_default()
    );
    assert!(!written.contains("correct horse"), "{written}");

    // The link is spent: the record no longer carries it.
    let after: Value = serde_json::from_str(
        &std::fs::read_to_string(fix.path(&format!("store/applications/{TOKEN}.json"))).unwrap(),
    )
    .unwrap();
    assert!(after["password_link"].is_null(), "{after}");
    // And the intent is removed once it is applied, as every transition does:
    // leaving it makes every later pass re-read it.
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    // And the fields this build does not model survive the write: the record
    // carries the answers and the rest, and losing them would be silent.
    assert!(after["answers"].is_object(), "{after}");
    assert_eq!(after["status_token"], json!(TOKEN), "{after}");
    assert!(
        std::fs::read_to_string(fix.path("store/journal.jsonl"))
            .unwrap_or_default()
            .contains("\"outcome\":\"applied\""),
        "the journal should record the apply"
    );

    // A replay of the same intent is caught by the journal's own dedup, a fresh
    // click on a spent link by the record, and a forged signature by the key.
    // None of the three runs the script again.
    fix.write_intent("01J00000000000000000PASSWORD", &intent);
    let mut fresh = intent.clone();
    fresh["id"] = json!("01J00000000000000000SPENT");
    fix.write_intent("01J00000000000000000SPENT", &fresh);
    let mut forged = intent.clone();
    forged["id"] = json!("01J00000000000000000FORGED");
    forged["sig"] = json!("00".repeat(32));
    fix.write_intent("01J00000000000000000FORGED", &forged);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let written = std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(written.lines().count(), 1, "{written}");
    let journal = std::fs::read_to_string(fix.path("store/journal.jsonl")).unwrap_or_default();
    assert!(
        journal.contains("the link has already been used"),
        "{journal}"
    );
    assert!(
        journal.contains("the link's signature does not verify"),
        "{journal}"
    );
}

/// A click on an already-decided application changes nothing in the store and
/// sends nothing, and the journal records that it was seen.
/// The decision email carries the one-time password link, not only the status
/// page: the spec asks for both, and the member whose mailbox has no password
/// yet cannot read the mail that was sent to it.
#[test]
fn an_approval_email_carries_the_password_link() {
    let fix = Fix::new("password-in-mail");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    let key = sign::read_key(std::path::Path::new(&fix.path("key"))).unwrap();
    let sig = sign::sign(&key, &sign::decide_payload(TOKEN, "approve-free")).unwrap();
    fix.write_decision("provision", "approve-free", &sig, "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let sent = fix.sent();
    assert!(sent.contains("/password/"), "{sent}");
    assert!(sent.contains("works once"), "{sent}");
}

/// After a failed pass and its backoff, the next pass applies the intent: a
/// failed journal line is the reason to retry, not a settlement.
#[test]
fn a_failed_password_pass_is_retried_after_the_backoff() {
    let fix = Fix::new("password-retry");
    let log = fix.path("password.log");
    fix.script(
        "set-mail-password.sh",
        &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\n"),
    );
    let key = sign::read_key(std::path::Path::new(&fix.path("key"))).unwrap();
    let until = kyriakon_onboard::util::date_after_days(7);
    let hash = kyriakon_onboard::password::make("correct horse battery").unwrap();
    let mut record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    record["password_link"] = json!("https://signup.example.invalid/password/x");
    std::fs::write(
        fix.path(&format!("store/applications/{TOKEN}.json")),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    let sig = sign::sign(&key, &sign::password_payload(TOKEN, &until)).unwrap();
    fix.write_intent(
        "01J00000000000000000RETRY",
        &json!({
            "id": "01J00000000000000000RETRY",
            "kind": "set-password",
            "filed_at": "2026-10-21T09:00:00Z",
            "application": { "username": "secretary", "status_token": TOKEN },
            "until": until,
            "sig": sig,
            "hash": hash,
        }),
    );
    std::fs::write(
        fix.path("store/journal.jsonl"),
        format!(
            "{{\"version\":1,\"at\":\"2020-01-01T00:00:00Z\",\"intent\":\"01J00000000000000000RETRY\",\"kind\":\"intent\",\"release\":\"test\",\"application\":{{\"username\":\"secretary\",\"status_token\":\"{TOKEN}\"}},\"outcome\":\"failed\",\"note\":\"an earlier pass\"}}\n"
        ),
    )
    .unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("secretary"),
        "the script should have run"
    );
}

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
    assert!(
        fix.journal().contains("already-decided"),
        "{}",
        fix.journal()
    );
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
    let payment = &account["payment"];
    let token = payment["token_ref"]
        .as_str()
        .expect("a paid approval writes a token");
    assert!(token.starts_with("KYR-"), "{token}");
    assert_eq!(token.len(), 18, "{token}");
    assert!(
        payment["token_issued_at"].is_string(),
        "the block records when the token was drawn: {account}"
    );
    assert!(payment["paid_until"].is_null(), "{}", account);
    assert!(
        !payment["window"].is_null(),
        "a paid approval opens a window"
    );
    // The fields are the spec's `payment.*` and nothing beside them: a top-level
    // copy would be a second place to keep one fact.
    for flat in ["token_ref", "token_issued_at", "paid_until", "window"] {
        assert!(
            account.get(flat).is_none(),
            "{flat} is top-level: {account}"
        );
    }
    // The join and the ledger line, keyed by the token and holding no username.
    assert!(paid.read(&format!("tokens/{token}.json")).contains(token));
    let ledger = paid.read("ledger/payments.jsonl");
    assert_eq!(ledger.lines().count(), 1, "{ledger}");
    assert!(ledger.contains(token), "{ledger}");
    assert!(
        !ledger.contains("secretary"),
        "the ledger holds no username: {ledger}"
    );
    // The password link is written for the account that has no password.
    let app: Value =
        serde_json::from_str(&paid.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(
        app["password_link"]
            .as_str()
            .unwrap()
            .contains("/password/"),
        "{app}"
    );

    // The free path: no token, no window, no ledger line.
    let free = Fix::new("free");
    let record = free.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    free.file_application(&record);
    assert!(free.drain().status.success());
    free.decide("provision", "secretary");
    let out = free.drain();
    assert!(out.status.success(), "{}", body(&out));
    let account = free.account("secretary");
    assert!(
        account.get("payment").is_none(),
        "a free account has no payment block at all: {account}"
    );
    assert_eq!(account["no_charge"], json!(true));
    assert!(
        free.read("ledger/payments.jsonl").is_empty(),
        "no ledger line without money"
    );
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
    assert!(account.get("payment").is_none(), "{account}");
    assert!(
        fix.read("ledger/payments.jsonl").is_empty(),
        "nothing owed, no ledger line"
    );
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
        sign::verify(
            b"the approval key",
            &sign::decide_payload(TOKEN, "approve"),
            sig
        ),
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
    let window = &account["payment"]["window"];
    let opened = window["opened_at"]
        .as_str()
        .expect("a charged approval opens a window");
    let closes = window["closes_at"].as_str().unwrap();
    let out = charged.ctl(&["show", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let text = body(&out);
    assert!(
        text.contains("  paid     null: the window is open"),
        "{text}"
    );
    assert!(
        text.contains(&format!("  window   {opened} to {closes}")),
        "{text}"
    );

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
    assert!(
        text.contains("  paid     none: no charge was made, so nothing expires"),
        "the line should say what is true: {text}"
    );
}

/// The account record as the service reads it.
fn stored_account(fix: &Fix, username: &str) -> store::Account {
    serde_json::from_str(&fix.read(&format!("accounts/{username}/account.json"))).unwrap()
}

/// Whether a page puts the token in a link, which is the only way a page can put
/// it in a URL for relayd to log. The status page's own address is the status
/// token's and never the payment token's.
fn token_is_a_link(page: &str, token: &str) -> bool {
    page.lines().any(|line| {
        (line.contains("href=") || line.trim_start().starts_with("=> ")) && line.contains(token)
    })
}

/// The token is a bearer secret with a lifetime: the status page and both account
/// pages show it in full while the account is unpaid, the amount and the window
/// beside it, and a credit's date replaces it there. The credit path is not built
/// yet, so the paid state below is the account a credit leaves: `paid_until` set
/// and the window closed.
#[test]
fn the_token_shows_while_unpaid_and_the_date_replaces_it() {
    let fix = Fix::new("token-display");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let now = OffsetDateTime::now_utc();
    let post = "1 Example Street, Example";
    let account = stored_account(&fix, "secretary");
    let payment = account.payment.as_ref().expect("a paid approval's block");
    let token = payment.token_ref.clone().expect("a paid approval's token");
    let closes_at = payment.window.as_ref().unwrap().closes_at.clone();
    let closes_on = closes_at[..10].to_string();

    // The status page: the token in full, the amount and the close date.
    let application: Record =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    let view = |account: &store::Account| page::payment(account, "20.00", post, now).unwrap();
    let status = responder::status_page(Some(application.clone()), Some(view(&account)), now);
    let html = status.render().unwrap();
    assert!(html.contains(&token), "{html}");
    assert!(html.contains("GBP 20.00"), "{html}");
    assert!(html.contains(&closes_on), "{html}");
    assert!(
        !token_is_a_link(&html, &token),
        "the token is in a URL: {html}"
    );
    let gemtext = capsule::status(&status);
    assert!(gemtext.contains(&token), "{gemtext}");
    assert!(gemtext.contains(&closes_on), "{gemtext}");
    assert!(
        !token_is_a_link(&gemtext, &token),
        "the token is in a link: {gemtext}"
    );

    // The account page, web and gemini: the block above the catalogue, with the
    // rail and the instructions a member has to act on.
    let web = page::account(&[], Some("secretary"), None, Some(view(&account)))
        .render()
        .unwrap();
    assert!(web.contains(&token), "{web}");
    assert!(web.contains("Rail: cash"), "{web}");
    assert!(web.contains(post), "{web}");
    assert!(web.contains("GBP 20.00"), "{web}");
    assert!(
        !token_is_a_link(&web, &token),
        "the token is in a URL: {web}"
    );
    let gemini = capsule::account(&account, &[], None, Some(&view(&account)));
    assert!(gemini.contains(&token), "{gemini}");
    assert!(gemini.contains(post), "{gemini}");
    assert!(
        !token_is_a_link(&gemini, &token),
        "the token is in a link: {gemini}"
    );

    // The credit: `paid_until` set, the window closed. Written by hand because
    // the credit path does not exist yet.
    let mut paid = fix.account("secretary");
    paid["payment"]["paid_until"] = json!("2027-10-04T00:00:00Z");
    paid["payment"]["window"]["state"] = json!("paid");
    std::fs::write(
        fix.dir.join("store/accounts/secretary/account.json"),
        serde_json::to_vec_pretty(&paid).unwrap(),
    )
    .unwrap();

    let account = stored_account(&fix, "secretary");
    let paid = view(&account);
    assert_eq!(paid.paid_until.as_deref(), Some("2027-10-04T00:00:00Z"));
    assert_eq!(paid.token, None, "a paid account shows no token");
    assert_eq!(paid.rail, "cash", "the rail stays visible");
    let status = responder::status_page(Some(application), Some(paid), now);
    let html = status.render().unwrap();
    assert!(html.contains("Paid until 2027-10-04T00:00:00Z"), "{html}");
    assert!(!html.contains(&token), "the token is back: {html}");
    let gemtext = capsule::status(&status);
    assert!(gemtext.contains("Paid until 2027-10-04"), "{gemtext}");
    assert!(!gemtext.contains(&token), "the token is back: {gemtext}");
    let paid = view(&account);
    let web = page::account(&[], Some("secretary"), None, Some(paid))
        .render()
        .unwrap();
    assert!(web.contains("Paid until 2027-10-04T00:00:00Z"), "{web}");
    assert!(!web.contains(&token), "the token is back: {web}");
    assert!(web.contains("Rail: cash"), "{web}");

    // A free account has no payment block at all, on either page.
    let free = Fix::new("token-display-free");
    let record = free.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    free.file_application(&record);
    assert!(free.drain().status.success());
    free.decide("provision", "secretary");
    let out = free.drain();
    assert!(out.status.success(), "{}", body(&out));
    let account = stored_account(&free, "secretary");
    assert!(page::payment(&account, "20.00", post, now).is_none());
    let web = page::account(&[], Some("secretary"), None, None)
        .render()
        .unwrap();
    assert!(
        !web.contains("Payment"),
        "a free account has no block: {web}"
    );
    let gemini = capsule::account(&account, &[], None, None);
    assert!(
        !gemini.contains("Payment"),
        "a free account has no block: {gemini}"
    );
}

/// A status token that resolves to nothing reads exactly as it reads today, and
/// a decided application past its seven days reads the same: no stage, no token,
/// no payment state.
#[test]
fn a_status_token_that_resolves_to_nothing_carries_no_payment() {
    let fix = Fix::new("status-unknown");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let now = OffsetDateTime::now_utc();
    let account = stored_account(&fix, "secretary");
    let payment = page::payment(&account, "20.00", "1 Example Street, Example", now);
    assert!(payment.is_some(), "the account owes for the year");

    // Past the seven days the record's page is the unknown-token page, and the
    // payment block goes with it.
    let record: Record =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    let later = now + time::Duration::days(8);
    let expired = responder::status_page(Some(record), None, later);
    let unknown = responder::status_page(None, None, now);
    assert!(
        expired.payment.is_none(),
        "{:?}",
        expired.payment.as_ref().map(|p| &p.token)
    );
    assert_eq!(
        expired.render().unwrap(),
        unknown.render().unwrap(),
        "an expired link reads as an unknown one"
    );
    assert_eq!(capsule::status(&expired), capsule::status(&unknown));
}

/// `onboardctl token resend` sends the same token again and mints nothing: one
/// file under `tokens/`, one token in the account, and the member's mail holding
/// the instructions one more time. A second resend sends a second copy, because
/// a member asking twice is the whole point of the verb.
#[test]
fn a_token_resend_sends_the_same_token_and_mints_nothing() {
    let fix = Fix::new("resend");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let token = stored_account(&fix, "secretary")
        .payment
        .and_then(|p| p.token_ref)
        .expect("a paid approval's token");
    let tokens_before = fix.names("tokens");
    assert_eq!(
        tokens_before,
        vec![format!("{token}.json")],
        "{tokens_before:?}"
    );
    let sent_before = fix.sent().matches(&token).count();
    let mails_before = fix.sent().matches("Subject:").count();

    let out = fix.ctl(&["token", "resend", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.intents().len(), 1, "{:?}", fix.intents());
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());

    // The same string, one more time, and nothing new minted.
    let sent = fix.sent();
    assert_eq!(sent.matches("Subject:").count(), mails_before + 1);
    assert_eq!(sent.matches(&token).count(), sent_before + 1, "{sent}");
    assert_eq!(
        fix.names("tokens"),
        tokens_before,
        "a second token was written"
    );
    assert_eq!(
        stored_account(&fix, "secretary")
            .payment
            .and_then(|p| p.token_ref)
            .as_deref(),
        Some(token.as_str())
    );
    assert!(fix
        .read("accounts/secretary/notices.jsonl")
        .contains("prepaid.instructions"));

    // A second resend sends a second copy rather than being deduplicated: the
    // member asked again.
    let out = fix.ctl(&["token", "resend", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        mails_before + 2,
        "{}",
        fix.sent()
    );
    assert_eq!(fix.names("tokens").len(), 1);

    // A free account has no token to resend, and the console says so now rather
    // than filing an intent the drain would refuse.
    let free = Fix::new("resend-free");
    let record = free.filed("secretary", "no_charge", &[("rail", "no_charge")]);
    free.file_application(&record);
    assert!(free.drain().status.success());
    free.decide("provision", "secretary");
    let out = free.drain();
    assert!(out.status.success(), "{}", body(&out));
    let out = free.ctl(&["token", "resend", "secretary"]);
    assert!(!out.status.success());
    assert!(body(&out).contains("without charge"), "{}", body(&out));
    assert!(free.intents().is_empty(), "{:?}", free.intents());
}

/// Criterion (d): the token is a bearer secret, so the drain's own output never
/// carries it. Cron mails what the drain prints, and that log is read by more
/// people than the member's mail is.
#[test]
fn the_drain_prints_no_payment_token() {
    let fix = Fix::new("token-logs");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    // Filing prints the review mail's path and nothing of the account's.
    assert!(!body(&fix.drain()).contains("KYR-"));
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let token = stored_account(&fix, "secretary")
        .payment
        .and_then(|p| p.token_ref)
        .expect("a paid approval's token");
    assert!(
        !body(&out).contains(&token),
        "the approval printed the token: {}",
        body(&out)
    );
    // A later pass over the same store prints none either, and the resend's
    // console output names the intent and not the token.
    assert!(!body(&fix.drain()).contains("KYR-"));
    let out = fix.ctl(&["token", "resend", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    assert!(!body(&out).contains(&token), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(!body(&out).contains(&token), "{}", body(&out));
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
        fix.dir
            .join(format!("store/applications/{TOKEN}.json"))
            .exists(),
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
        !fix.dir
            .join(format!("store/applications/{TOKEN}.json"))
            .exists(),
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
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        1,
        "one review email"
    );

    // The same intent again, as a crash before the delete leaves it: the second
    // pass re-reads it and must find the application already reviewed.
    std::fs::write(
        fix.dir.join("store/intents").join(format!("{id}.json")),
        &intent,
    )
    .unwrap();
    assert!(fix.drain().status.success());
    let after_second = fix.snapshot();

    assert_eq!(
        after_first, after_second,
        "the second run changed the store"
    );
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        1,
        "no second review email"
    );
    assert!(
        fix.intents().is_empty(),
        "the re-read intent is consumed: {:?}",
        fix.intents()
    );
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
    assert_eq!(
        fix.journal().matches("refused").count(),
        1,
        "{}",
        fix.journal()
    );
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
    let sig: String = sent[start..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
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
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
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
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
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
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
    assert!(fix
        .dir
        .join("store/accounts/secretary/application.json")
        .exists());
    assert!(!fix.read("accounts/secretary/notices.jsonl").is_empty());
    // The completion line is written, so a finished approval does not read like
    // one that died midway.
    assert!(fix.journal().contains("\"applied\""), "{}", fix.journal());
}

/// An add-user.sh that logs whether the confirmation had already reached the
/// enqueuer when the first provisioning script ran. `sent` is the enqueuer's
/// own output file, so this is the order the envelope saw, not a guess.
fn add_user_asks_whether_the_confirmation_left(fix: &Fix) {
    let passwd = fix.path("passwd");
    let log = fix.path("scripts.log");
    let sent = fix.path("sent");
    fix.script(
        "add-user.sh",
        &format!(
            "#!/bin/sh\n\
             if grep -q 'digital content' '{sent}' 2>/dev/null; then echo confirmation-seen >> '{log}'; else echo confirmation-missing >> '{log}'; fi\n\
             printf '%s:x:1000:1000::/home/%s:/sbin/nologin\\n' \"$1\" \"$1\" >> '{passwd}'\n"
        ),
    );
}

/// The confirmation the spec promises: to the address the applicant gave,
/// restating both things the second checkbox recorded and quoting every document
/// with its version, before the account exists.
#[test]
fn an_approval_sends_the_confirmation_to_the_outside_address() {
    let fix = Fix::new("confirmation");
    let mut record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    record["acceptances"] = json!([
        {"document": "terms", "version": "2026-10-01 abc1234"},
        {"document": "privacy", "version": "2026-09-01 def5678"},
    ]);
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    assert_eq!(
        sent.matches("Subject: Your application to kyriakon.net was confirmed")
            .count(),
        1,
        "{sent}"
    );
    assert!(sent.contains("To: applicant@example.invalid"), "{sent}");
    assert!(sent.contains("digital content"), "{sent}");
    assert!(sent.contains("terms: 2026-10-01 abc1234"), "{sent}");
    assert!(sent.contains("privacy: 2026-09-01 def5678"), "{sent}");
    assert!(sent.contains("fourteen days"), "{sent}");
    assert!(sent.contains("admin@kyriakon.net"), "{sent}");
    assert!(
        sent.contains("cancel for any reason, or none"),
        "the right is stated plainly: {sent}"
    );

    // The stamp is on the application record, where a retry reads it.
    let app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(app["confirmation_at"].is_string(), "{app}");
}

/// The confirmation reaches the enqueuer before add-user.sh runs: the envelope
/// is the record of what was agreed, and it must exist before the service does.
#[test]
fn the_confirmation_leaves_before_add_user() {
    let fix = Fix::new("confirmation-order");
    add_user_asks_whether_the_confirmation_left(&fix);
    let record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let log = fix.scripts_log();
    assert!(
        log.contains("confirmation-seen"),
        "add-user.sh ran before the confirmation left: {log}"
    );
    assert!(!log.contains("confirmation-missing"), "{log}");
}

/// A retry after a failed provisioning sends no second confirmation: the stamp
/// is written before the enqueue, so a crash costs an email rather than a
/// duplicate.
#[test]
fn a_retried_approval_sends_no_second_confirmation() {
    let fix = Fix::new("confirmation-retry");
    fix.provision_fails();
    let record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.sent().matches("was confirmed").count(),
        1,
        "the first run sends one: {}",
        fix.sent()
    );
    assert_eq!(fix.intents().len(), 1, "{:?}", fix.intents());

    // The builder works on the retry, as in `a_retried_approval_completes`.
    fix.age_failures();
    fix.provision_requires_key();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
    assert_eq!(
        fix.sent().matches("was confirmed").count(),
        1,
        "the retry sends no second confirmation: {}",
        fix.sent()
    );
}

/// An approval with no address outside the platform sends no confirmation and
/// still provisions: before the account exists there is no mailbox to reach, so
/// the status page is the applicant's record instead.
#[test]
fn an_approval_without_an_outside_address_sends_no_confirmation() {
    let fix = Fix::new("confirmation-none");
    add_user_asks_whether_the_confirmation_left(&fix);
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
    let log = fix.scripts_log();
    assert!(
        log.contains("confirmation-missing"),
        "a confirmation left before provisioning: {log}"
    );
    assert!(!fix.sent().contains("digital content"), "{}", fix.sent());
    assert!(
        !fix.sent().contains("was confirmed"),
        "no confirmation was sent: {}",
        fix.sent()
    );
}

/// A confirmation the enqueuer refuses is not recorded as sent: the approval
/// stops before provisioning, the stamp goes back, and the retry sends it. A
/// stamp left behind would provision the applicant with the letter lost.
#[test]
fn a_confirmation_that_cannot_be_sent_is_not_recorded_as_sent() {
    let fix = Fix::new("confirmation-send-fails");
    let sent = fix.path("sent");
    fix.script(
        "enqueuer.sh",
        &format!(
            "#!/bin/sh\nmsg=$(cat)\ncase \"$msg\" in\n*'cancellation period ends'*) echo 'the mail path is broken' >&2; exit 1;;\nesac\nprintf '%s' \"$msg\" >> '{sent}'\n"
        ),
    );
    let record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    assert!(fix.drain().status.success());

    // No account was made, and the application does not claim the letter left.
    assert!(
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "an approval whose confirmation failed must not provision"
    );
    let app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(app.get("confirmation_at").is_none(), "{app}");
    assert!(!fix.sent().contains("was confirmed"), "{}", fix.sent());

    // With the mail path back, the retry sends the confirmation once and goes on.
    fix.enqueuer_works();
    fix.age_failures();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.sent().matches("was confirmed").count(),
        1,
        "{}",
        fix.sent()
    );
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
}

/// A body's approval sends the applicant the same confirmation before any of the
/// body's accounts exist, as the person path does.
#[test]
fn a_body_approval_sends_the_confirmation() {
    let fix = Fix::new("group-confirmation");
    let mut record = fix.filed_body("warden");
    record["outside_address"] = json!("warden@example.invalid");
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    assert_eq!(sent.matches("was confirmed").count(), 1, "{sent}");
    assert!(sent.contains("To: warden@example.invalid"), "{sent}");
    assert!(sent.contains("terms: 2026-10-01 abc1234"), "{sent}");
    assert!(sent.contains("fourteen days"), "{sent}");
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
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
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
    assert!(
        published.contains("BEGIN PGP PUBLIC KEY BLOCK"),
        "{published}"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644,
        "the keyring file carries the mode deploy-mail installs"
    );
}

/// An approval offers the member's mail key to the published set through the
/// script the box owns, after the keyring entry and after the member is built:
/// the keyring is what delivers, so nothing about the publish comes before
/// either, and the forge is never on a path the member waits on.
#[test]
fn an_approval_offers_the_mail_key_for_publication() {
    let fix = Fix::new("publish");
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let log = fix.scripts_log();
    let offered = log
        .lines()
        .find(|l| l.starts_with("publish-mail-key.sh "))
        .unwrap_or_else(|| panic!("the mail key was not offered to the published set: {log}"));
    assert_eq!(
        offered,
        format!(
            "publish-mail-key.sh secretary {} {}",
            fix.path("keyring/secretary.asc"),
            fix.path("keyring-token"),
        ),
        "the member, the key file and the token are what the script is handed"
    );
    let member = log.find("provision-member.sh secretary").expect(&log);
    let published = log.find("publish-mail-key.sh").expect(&log);
    assert!(
        member < published,
        "the member is built before the publish: {log}"
    );
}

/// A publish that fails is reported with the member and the key, holds the
/// approval back from its record and its notice rather than from mail, and is
/// retried without touching the keyring file: the seven days the drift check
/// allows an unpublished key are the age of that file, so a retry that rewrote
/// it would restart the window forever.
#[test]
fn a_failed_publish_is_reported_and_retried_without_touching_the_key() {
    let fix = Fix::new("publish-fails");
    fix.publish_fails();
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    // The failure is mailed, not printed, and the mail names the member and the
    // key: the drain's alert is where a failure report goes now.
    let sent = fix.sent();
    assert!(sent.contains("publish-mail-key.sh"), "{sent}");
    assert!(
        sent.contains("secretary"),
        "the failure names the member: {sent}"
    );
    assert!(
        sent.contains("1111 2222 3333 4444"),
        "the failure names the key: {sent}"
    );
    assert!(
        body(&out).is_empty(),
        "a mailed failure is not printed as well: {}",
        body(&out)
    );

    // The member is live: the key is in the keyring and delivery works. What is
    // held back is the account record and the notice.
    let key = fix.dir.join("keyring/secretary.asc");
    let written = std::fs::metadata(&key)
        .expect("an approval that fails to publish still serves the key")
        .modified()
        .unwrap();
    assert!(
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "an approval whose publish failed is not finished"
    );
    assert_eq!(fix.intents().len(), 1, "{:?}", fix.intents());

    // The retry moves the backoff out of the way the way a real minute would. It
    // tries the publish again, reports nothing new, and leaves the key alone.
    fix.age_failures();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.scripts_log().matches("publish-mail-key.sh").count(),
        2,
        "the publish is retried: {}",
        fix.scripts_log()
    );
    assert_eq!(
        std::fs::metadata(&key).unwrap().modified().unwrap(),
        written,
        "the keyring file was rewritten, which restarts the drift check's seven days"
    );
    assert_eq!(
        fix.intents().len(),
        1,
        "the intent stays until the publish succeeds"
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
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "an account with no mail key must not be made"
    );
    assert!(fix.sent().contains("no mail key"), "{}", fix.sent());
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
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
    assert!(
        fix.names("keys").is_empty(),
        "no key, no key file: {:?}",
        fix.names("keys")
    );
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
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
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
        fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
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

/// A failing intent is mailed once rather than every pass, and is not retried
/// again inside its backoff window. A stuck intent therefore costs the operator
/// one mail, not one a minute. The mail is the report, so the run prints nothing:
/// cron mails a job's output under a subject of its own, and that copy would be
/// the same news under a subject naming neither the component nor the event.
#[test]
fn a_failing_intent_reports_once_and_backs_off() {
    let fix = Fix::new("stuck");
    // An approve intent for an application that is not on disk: a failure the
    // drain cannot get past on its own.
    fix.decide("approve", "secretary");

    let first = fix.drain();
    assert!(first.status.success(), "{}", body(&first));
    let sent = fix.sent();
    assert!(
        sent.contains("Subject: kyriakon: onboard: drain failed"),
        "{sent}"
    );
    assert!(sent.contains("there is no application"), "{sent}");
    // The subject names the intent and the body says what to do about it, so the
    // mail is readable without the journal.
    assert!(sent.contains("what to do:"), "{sent}");
    assert!(sent.contains("run: kyriakon-onboard-drain"), "{sent}");
    assert_eq!(sent.matches("Subject:").count(), 1, "{}", body(&first));
    assert!(
        body(&first).is_empty(),
        "a mailed alert is not printed as well: {}",
        body(&first)
    );
    assert_eq!(
        fix.intents().len(),
        1,
        "the intent is left in place: {:?}",
        fix.intents()
    );
    assert!(fix.journal().contains("\"failed\""), "{}", fix.journal());

    // Inside the backoff window the intent is not retried and nothing is mailed.
    let second = fix.drain();
    assert!(second.status.success(), "{}", body(&second));
    assert!(
        body(&second).is_empty(),
        "a backed-off failure is silent: {}",
        body(&second)
    );
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        1,
        "one mail, not one a pass"
    );
    assert_eq!(
        fix.journal().matches("\"failed\"").count(),
        1,
        "{}",
        fix.journal()
    );

    let third = fix.drain();
    assert!(
        body(&third).is_empty(),
        "still inside the minute: {}",
        body(&third)
    );
}

/// A drain that cannot mail its alert prints it instead, subject and all. The
/// fallback is what covers the day the mail path is the broken thing: cron still
/// mails what a job prints, so the operator gets the subject even when the
/// enqueuer is what failed.
#[test]
fn an_alert_the_box_cannot_mail_is_printed_instead() {
    let fix = Fix::new("no-mail");
    fix.enqueuer_fails();
    fix.decide("approve", "secretary");

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let printed = String::from_utf8_lossy(&out.stderr);
    assert!(
        printed.contains("kyriakon: onboard: drain failed"),
        "{printed}"
    );
    assert!(printed.contains("there is no application"), "{printed}");
    assert!(printed.contains("could not be mailed"), "{printed}");
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "the alert is one message: {}",
        body(&out)
    );
}

/// A box whose approval key is missing is misconfigured rather than idle. It is
/// mailed once under the same subject every drain failure carries, because a
/// silence here reads exactly like a drain with nothing to do.
#[test]
fn a_missing_approval_key_is_mailed_as_the_drains_own_configuration() {
    let fix = Fix::new("nokey");
    fix.file_application(&fix.filed("secretary", "cash", &[("rail", "cash")]));
    std::fs::remove_file(fix.path("key")).unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let sent = fix.sent();
    assert!(
        sent.contains("Subject: kyriakon: onboard: drain failed"),
        "{sent}"
    );
    assert!(sent.contains("its own configuration"), "{sent}");
    assert_eq!(sent.matches("Subject:").count(), 1, "{}", body(&out));
    assert!(
        body(&out).is_empty(),
        "mailed, so not printed: {}",
        body(&out)
    );
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
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
        "an account the application did not make must not be adopted"
    );
    // The refusal is mailed, and it names the name: which account is which is the
    // operator's decision, so the mail says which name is in use. Nothing is
    // printed for a failure that was mailed.
    let sent = fix.sent();
    assert!(
        sent.contains("Subject: kyriakon: onboard: drain failed")
            && sent.contains("secretary")
            && sent.contains("in use"),
        "the refusal names what it found: {sent}"
    );
    assert!(
        body(&out).is_empty(),
        "mailed, so not printed: {}",
        body(&out)
    );
    // Nothing was run against the box's account: no add-user, no builder, no
    // release.
    assert!(fix.scripts_log().is_empty(), "{}", fix.scripts_log());
    assert!(
        fix.passwd_file().contains("secretary:"),
        "the box account is untouched"
    );
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
    assert!(!fix
        .dir
        .join(format!("store/applications/{TOKEN}.json"))
        .exists());
    assert!(
        !fix.scripts_log().contains("delete-user.sh"),
        "the box account's name was released: {}",
        fix.scripts_log()
    );
    assert!(
        fix.passwd_file().contains("secretary:"),
        "the box account is untouched"
    );
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
            !fix.dir
                .join("store/accounts/secretary/account.json")
                .exists(),
            "{bad:?} must not decide the application"
        );
        assert!(
            !fix.sent()
                .lines()
                .any(|l| l.starts_with("To:") && l.contains("attacker")),
            "an injected recipient became a header: {}",
            fix.sent()
        );
        assert_eq!(
            fix.intents().len(),
            1,
            "the intent is left for the reviewer"
        );
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
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
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
        !fix.dir
            .join("store/accounts/secretary/account.json")
            .exists(),
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

    let file = std::fs::metadata(fix.dir.join(format!("store/applications/{TOKEN}.json"))).unwrap();
    let dir = std::fs::metadata(fix.dir.join("store/applications")).unwrap();
    assert_eq!(file.mode() & 0o777, 0o600, "the record stays 0600");
    assert_eq!(
        file.uid(),
        dir.uid(),
        "and owned like the directory it lives in"
    );
    assert_eq!(
        file.gid(),
        dir.gid(),
        "and its group is the directory's group"
    );
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
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        1,
        "the review email"
    );

    fix.decide("decline", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        1,
        "no decline email was sent"
    );
    assert!(!fix.sent().contains("declined"), "{}", fix.sent());
    let app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(app["decided_at"].is_string(), "{app}");
    assert!(
        app["stage"].as_str().unwrap().starts_with("declined"),
        "{app}"
    );
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
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());

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
        fix.dir
            .join(format!("store/applications/{OTHER_TOKEN}.json")),
        serde_json::to_vec_pretty(&declined).unwrap(),
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    // The declined application is cleared away, the live account is untouched,
    // and no release script ran for a name that is in use.
    assert!(!fix
        .dir
        .join(format!("store/applications/{OTHER_TOKEN}.json"))
        .exists());
    assert!(fix
        .dir
        .join("store/accounts/secretary/account.json")
        .exists());
    assert!(
        !fix.scripts_log().contains("delete-user.sh"),
        "a live account's name was released: {}",
        fix.scripts_log()
    );
}

/// The review email is the only copy of the answers and of the links, and the
/// marker that stops a second one is written before the send. A send that
/// returns an error is not a crash, so the next pass must send it, and must not
/// send a second copy once one has gone.
#[test]
fn a_review_email_that_could_not_be_sent_goes_on_the_next_pass() {
    let fix = Fix::new("review-retry");
    fix.enqueuer_fails();
    let record = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    fix.drain();

    assert!(fix.journal().contains("review-sent"), "{}", fix.journal());
    assert!(
        fix.sent().is_empty(),
        "the box could not mail, so nothing was sent: {}",
        fix.sent()
    );
    assert_eq!(
        fix.intents().len(),
        1,
        "the intent is left in place: {:?}",
        fix.intents()
    );

    // The mail path works again, and the backoff is what holds the retry back.
    fix.enqueuer_works();
    fix.age_failures();
    fix.drain();
    assert!(
        fix.sent().contains("secretary"),
        "the review email went out on the retry: {}",
        fix.sent()
    );
    assert_eq!(
        fix.intents().len(),
        0,
        "and the intent is cleared: {:?}",
        fix.intents()
    );

    // A re-filed application is not mailed a second time.
    fix.file_application(&record);
    fix.drain();
    assert_eq!(
        fix.sent().matches("Subject:").count(),
        1,
        "one review email per application: {}",
        fix.sent()
    );
}

/// A decline's own record is what stops a second mail, and it is written after
/// the send, so a send that failed cannot leave a decision saying the applicant
/// had been told when nothing reached them.
#[test]
fn a_decline_that_could_not_be_sent_goes_on_the_next_pass() {
    let fix = Fix::new("decline-retry");
    let record = fix.filed_with(
        "secretary",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    fix.file_application(&record);
    fix.drain();
    fix.decide("decline", "secretary");
    fix.enqueuer_fails();
    fix.drain();

    let app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(
        app["decided_at"].is_null(),
        "nothing claims the applicant was told: {app}"
    );
    assert_eq!(
        fix.intents().len(),
        1,
        "the intent is left in place: {:?}",
        fix.intents()
    );

    fix.enqueuer_works();
    fix.age_failures();
    fix.drain();
    assert!(
        fix.sent().contains("was declined"),
        "the notice went out on the retry: {}",
        fix.sent()
    );
    let app: Value =
        serde_json::from_str(&fix.read(&format!("applications/{TOKEN}.json"))).unwrap();
    assert!(
        !app["decided_at"].is_null(),
        "and the decision is recorded after it: {app}"
    );
    assert_eq!(
        fix.intents().len(),
        0,
        "the intent is cleared: {:?}",
        fix.intents()
    );
}

/// The drain is the second gate for the names the platform holds back. The
/// handler refuses one when an application is filed, and the half that creates
/// the account as root cannot take the other half's word for it.
#[test]
fn an_application_for_a_held_back_name_is_refused() {
    let fix = Fix::new("reserved-filed");
    let record = fix.filed("signup", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    fix.drain();

    assert!(fix.journal().contains("held back"), "{}", fix.journal());
    assert!(
        fix.failed_note().contains("signup"),
        "the failure names the name that was held back: {}",
        fix.failed_note()
    );
    assert_eq!(
        fix.intents().len(),
        1,
        "the intent is left in place: {:?}",
        fix.intents()
    );
    assert!(
        fix.passwd_file().is_empty(),
        "no account was made: {}",
        fix.passwd_file()
    );
    assert!(!fix.dir.join("store/accounts/signup").exists());
}

/// A name held back after the application was filed stops the approval, because
/// that is where an account would be made. The list's own header tells a
/// maintainer to add a new platform hostname to it, which is exactly this.
#[test]
fn an_approval_for_a_name_held_back_since_filing_is_refused() {
    let fix = Fix::new("reserved-approve");
    let record = fix.filed("theophilus", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    fix.drain();
    fix.reserve("theophilus");
    fix.decide("approve", "theophilus");
    fix.drain();

    assert!(fix.journal().contains("held back"), "{}", fix.journal());
    assert!(
        fix.failed_note().contains("theophilus"),
        "the failure names the name that was held back: {}",
        fix.failed_note()
    );
    assert!(
        !fix.dir.join("store/accounts/theophilus").exists(),
        "no account was made"
    );
    assert!(fix.passwd_file().is_empty(), "{}", fix.passwd_file());
}

/// The same check must not sit where the intent is read, or a decline of a
/// held-back name could never be carried out and the application would sit
/// undecided for ever.
#[test]
fn a_decline_of_a_held_back_name_is_still_carried_out() {
    let fix = Fix::new("reserved-decline");
    let record = fix.filed_with(
        "theophilus",
        "cash",
        &[("rail", "cash")],
        Some("applicant@example.invalid"),
        Some((UPLOAD_KEY, "works")),
    );
    fix.file_application(&record);
    fix.drain();
    fix.reserve("theophilus");
    fix.decide("decline", "theophilus");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        fix.sent().contains("was declined"),
        "the applicant is told: {}",
        fix.sent()
    );
    assert!(
        !fix.journal().contains("held back"),
        "a decline is not an admission: {}",
        fix.journal()
    );
}

/// A second application for a username that already has an account is not the
/// first application's to inherit. The first approval drew a payment token,
/// opened a window and wrote a ledger row, and approving the second must not
/// rewrite the account from that state, which would leave the account and the
/// ledger disagreeing about what is owed.
#[test]
fn a_second_application_does_not_reuse_the_first_approvals_payment() {
    let fix = Fix::new("second-application");
    let first = fix.filed("secretary", "cash", &[("rail", "cash")]);
    fix.file_application(&first);
    fix.drain();
    fix.decide("approve", "secretary");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let token = fix.account("secretary")["payment"]["token_ref"].clone();
    let ledger = fix.read("ledger/payments.jsonl");
    assert!(
        !ledger.is_empty(),
        "the first approval opened a window: {ledger}"
    );

    // The same person applies again, later, and that application is approved.
    let second = json!({
        "username": "secretary",
        "status_token": OTHER_TOKEN,
        "filed_at": "2026-10-05T09:00:00Z",
        "front_end": "web",
        "stage": "received",
        "outside_address": null,
        "answers": {"rail": "cash"},
        "mail_keys": [{
            "mailbox": "",
            "fingerprint": "1111 2222 3333 4444",
            "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----",
            "verdict": "works",
        }],
        "upload_key": null,
        "rail": "cash",
        "no_charge": false,
        "acceptances": [{"document": "terms", "version": "2026-10-01 abc1234"}],
        "question_list": "2026-10-01 abc1234",
    });
    std::fs::write(
        fix.dir
            .join(format!("store/applications/{OTHER_TOKEN}.json")),
        serde_json::to_vec_pretty(&second).unwrap(),
    )
    .unwrap();
    fix.file_application(&second);
    fix.drain();
    // The console looks the application up by username and takes the newest, which
    // is how the operator reaches a second application for one person.
    let out = fix.ctl(&["approve", "secretary"]);
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.intents().len(), 1, "{:?}", fix.intents());
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        fix.journal().contains("already-member"),
        "{}",
        fix.journal()
    );
    assert_eq!(
        fix.intents().len(),
        0,
        "the second intent is cleared: {:?}",
        fix.intents()
    );
    assert_eq!(
        fix.account("secretary")["payment"]["token_ref"],
        token,
        "the first approval's token is untouched"
    );
    assert_eq!(
        fix.read("ledger/payments.jsonl"),
        ledger,
        "and no second window was opened and no second row written"
    );
}

// --- the apply@ key spool ------------------------------------------------

/// A key mailed to apply@ is filed against the draft its subject names, with
/// the fingerprint and verdict the handler would have recorded, and the spool
/// is empty afterwards.
#[test]
fn a_mailed_key_is_filed_against_the_draft_and_the_spool_empties() {
    let fix = Fix::new("mail-key");
    fix.write_draft(TOKEN, &[("username", "secretary"), ("whose", "person")]);
    fix.mail("one", "applicant@example.invalid", TOKEN, GOOD_KEY);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.names("mail/new").is_empty(), "the spool is drained");

    let draft: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    let key = &draft["mail_keys"][0];
    assert_eq!(key["mailbox"], "secretary");
    assert!(
        !key["fingerprint"].as_str().unwrap_or_default().is_empty(),
        "the fingerprint is computed over the mailed material: {draft}"
    );
    assert!(
        !key["verdict"].as_str().unwrap_or_default().is_empty(),
        "the verdict is recorded: {draft}"
    );
}

/// A body's key page is one page per mailbox, so the message has to say which
/// mailbox each block belongs to. Two labelled blocks file both.
#[test]
fn two_labelled_keys_for_a_body_are_both_filed() {
    let fix = Fix::new("mail-body-keys");
    fix.write_draft(
        TOKEN,
        &[
            ("whose", "body"),
            ("body_domain", "parish.example"),
            ("body_account_names", "secretary\nhall"),
        ],
    );
    let message = format!("secretary@parish.example\n{GOOD_KEY}\nhall@parish.example\n{GOOD_KEY}");
    fix.mail("one", "applicant@example.invalid", TOKEN, &message);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.names("mail/new").is_empty());

    let draft: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    let keys = draft["mail_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "{draft}");
    assert_eq!(keys[0]["mailbox"], "secretary");
    assert_eq!(keys[1]["mailbox"], "hall");
}

/// A body with more than one mailbox and an unlabelled block is refused, and
/// the reply names the mailboxes the message failed to label.
#[test]
fn an_unlabelled_key_for_two_mailboxes_is_refused_by_name() {
    let fix = Fix::new("mail-unlabelled");
    fix.write_draft(
        TOKEN,
        &[
            ("whose", "body"),
            ("body_domain", "parish.example"),
            ("body_account_names", "secretary\nhall"),
        ],
    );
    fix.mail("one", "applicant@example.invalid", TOKEN, GOOD_KEY);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let sent = fix.sent();
    assert!(sent.contains("secretary"), "{sent}");
    assert!(sent.contains("hall"), "{sent}");
    let draft: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    assert!(
        draft["mail_keys"].as_array().is_none_or(|k| k.is_empty()),
        "nothing was filed: {draft}"
    );
}

/// A token that no longer resolves gets one reply with a fresh link and creates
/// no draft. The second message from the same sender is not answered again.
#[test]
fn a_key_for_a_dead_token_gets_one_reply_and_files_no_draft() {
    let fix = Fix::new("mail-dead-token");
    fix.mail("one", "applicant@example.invalid", OTHER_TOKEN, GOOD_KEY);
    fix.mail("two", "applicant@example.invalid", OTHER_TOKEN, GOOD_KEY);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    let drafts: Vec<String> = fix
        .names("drafts")
        .into_iter()
        .filter(|n| n.ends_with(".json"))
        .collect();
    assert!(drafts.is_empty(), "a mail creates no draft: {drafts:?}");
    assert_eq!(
        fix.sent()
            .matches("Subject: Your Kyriakon application key")
            .count(),
        1,
        "one reply per sender:\n{}",
        fix.sent()
    );
    assert!(fix.sent().contains("gemini://signup.kyriakon.net/apply"));
    assert!(fix.names("mail/new").is_empty());
}

/// A live token files its key even when the message has no usable From. The
/// reply address is only needed on the paths that answer.
#[test]
fn a_key_with_no_reply_address_is_still_filed() {
    let fix = Fix::new("mail-no-from");
    fix.write_draft(TOKEN, &[("username", "secretary"), ("whose", "person")]);
    fix.mail("one", "", TOKEN, GOOD_KEY);

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.sent().is_empty(), "nothing to answer: {}", fix.sent());
    let draft: Value = serde_json::from_str(&fix.read(&format!("drafts/{TOKEN}.json"))).unwrap();
    assert_eq!(draft["mail_keys"][0]["mailbox"], "secretary", "{draft}");
}

/// A message with no key block is not answered at all.
#[test]
fn mail_without_a_key_block_is_not_answered() {
    let fix = Fix::new("mail-no-key");
    fix.mail("one", "applicant@example.invalid", TOKEN, "hello");

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.sent().is_empty(), "{}", fix.sent());
    assert!(fix.names("mail/new").is_empty());
}

/// One `provision-group` intent makes the group record, the mailbox account, the
/// two virtual entries, the mail domain line and the site owner's upload key.
#[test]
fn a_group_intent_provisions_its_record_accounts_and_addresses() {
    let fix = Fix::new("group");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-secretary"),
        ],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());

    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(group["domain"], "parish.example");
    assert_eq!(group["name"], "Parish of Example");
    assert_eq!(group["kind"], "parish");
    assert_eq!(group["accounts"], json!(["parish-secretary"]));
    assert_eq!(group["site_owner"], "parish-secretary");
    assert_eq!(group["payment"]["rail"], "cash");
    assert_eq!(group["payment"]["no_charge"], false);

    // The account is the mailbox's, with a group reference and no paid-until
    // field of its own.
    let account = fix.account("parish-secretary");
    assert_eq!(account["group"], "parish.example");
    assert!(account.get("payment").is_none(), "{account}");
    assert!(
        fix.passwd_file().contains("parish-secretary:"),
        "{}",
        fix.passwd_file()
    );

    // One mail domain line and one virtual entry per address, on the body's
    // domain rather than the platform's.
    let domains = fix.table("mail_domains");
    assert_eq!(
        domains.lines().filter(|l| *l == "parish.example").count(),
        1,
        "{domains}"
    );
    let virtuals = fix.table("virtuals");
    for address in ["secretary", "office"] {
        let key = format!("{address}@parish.example:");
        assert_eq!(
            virtuals.lines().filter(|l| l.starts_with(&key)).count(),
            1,
            "{virtuals}"
        );
        assert!(
            virtuals.contains(&format!("{key} parish-secretary")),
            "{virtuals}"
        );
    }

    // The block's upload key is where provision-member.sh reads it.
    let key = fix.read("keys/parish-secretary.pub");
    assert!(key.contains(UPLOAD_KEY), "{key}");

    let log = fix.scripts_log();
    assert!(log.contains("add-user.sh parish-secretary"), "{log}");
    assert!(
        log.contains("provision-member.sh parish-secretary"),
        "{log}"
    );
}

/// The same intent applied a second time leaves one account, one virtual entry
/// per address, one public tree and one upload key: the property a retry after a
/// crash depends on.
#[test]
fn a_group_intent_applied_twice_leaves_one_of_each() {
    let fix = Fix::new("group-twice");
    let id = fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-secretary"),
        ],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());

    // The same intent again, as a crash before the delete leaves it.
    fix.write_group(
        &id,
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-secretary"),
        ],
        &["parish-secretary"],
        Some(UPLOAD_KEY),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert_eq!(
        fix.scripts_log().matches("add-user.sh").count(),
        1,
        "add-user.sh ran once, not once per pass: {}",
        fix.scripts_log()
    );
    assert_eq!(
        fix.passwd_file()
            .lines()
            .filter(|l| l.starts_with("parish-secretary:"))
            .count(),
        1,
        "{}",
        fix.passwd_file()
    );
    let virtuals = fix.table("virtuals");
    for address in ["secretary", "office"] {
        assert_eq!(
            virtuals
                .lines()
                .filter(|l| l.starts_with(&format!("{address}@parish.example:")))
                .count(),
            1,
            "{virtuals}"
        );
    }
    assert_eq!(
        fix.table("mail_domains")
            .lines()
            .filter(|l| *l == "parish.example")
            .count(),
        1
    );
    assert_eq!(fix.names("accounts"), vec!["parish-secretary"]);
    // The key file holds one key, and the tree is the builder's to keep
    // idempotent: it ran against the same account, not a second one.
    let key = fix.read("keys/parish-secretary.pub");
    assert_eq!(
        key.lines().filter(|l| !l.trim().is_empty()).count(),
        1,
        "{key}"
    );
    assert_eq!(
        fix.scripts_log()
            .matches("provision-member.sh parish-secretary")
            .count(),
        2,
        "the builder is idempotent, so a retry runs it again"
    );
}

/// A group whose account name is held back, or already taken, is refused and
/// the intent stays in place for the operator to fix.
#[test]
fn a_group_intent_for_a_reserved_name_is_refused() {
    let fix = Fix::new("group-reserved");
    fix.reserve("parish-secretary");
    let id = fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("parish-secretary"),
        "{}",
        fix.failed_note()
    );
    assert!(
        !fix.dir
            .join("store/groups/parish.example/group.json")
            .exists(),
        "a refused group makes no record"
    );
    assert!(!fix.passwd_file().contains("parish-secretary:"));
}

#[test]
fn a_group_intent_for_a_taken_name_is_refused() {
    let fix = Fix::new("group-taken");
    // An account made some other way: the box has it and the store does not.
    fix.set_passwd("parish-secretary:x:1000:1000::/home/parish-secretary:/sbin/nologin\n");
    let id = fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("already in use on this box"),
        "{}",
        fix.failed_note()
    );
    assert!(
        !fix.dir
            .join("store/groups/parish.example/group.json")
            .exists(),
        "a refused group makes no record"
    );
}

/// The approval of a body's application files and applies the group intent in
/// the same pass: the mailboxes are the address table's, and the applicant's own
/// username is not made into an account.
#[test]
fn a_body_approval_makes_the_group_and_its_mailboxes() {
    let fix = Fix::new("group-approval");
    let record = fix.filed_body("warden");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());

    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(group["accounts"], json!(["parish-secretary"]));
    assert_eq!(group["site_owner"], "parish-secretary");
    assert_eq!(group["kind"], "parish");
    assert_eq!(group["payment"]["rail"], "cash");

    assert!(fix
        .dir
        .join("store/accounts/parish-secretary/account.json")
        .exists());
    assert!(
        !fix.dir.join("store/accounts/warden/account.json").exists(),
        "the accountable person is not a mailbox"
    );
    assert!(fix
        .table("virtuals")
        .contains("office@parish.example: parish-secretary"));
    assert!(fix.passwd_file().contains("parish-secretary:"));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    // The application is decided, so a replay changes nothing.
    assert!(fix.journal().contains("\"applied\""), "{}", fix.journal());
}

/// A box whose deploy left a recipe placeholder refuses a body's approval
/// before the journal line and before any account or table is made.
#[test]
fn an_approval_with_a_placeholder_dns_value_makes_nothing() {
    let fix = Fix::new("group-dns-placeholder");
    let cfg = std::fs::read_to_string(fix.config())
        .unwrap()
        .replace("ipv4 = \"192.0.2.10\"", "ipv4 = \"REPLACE_ME_IPV4\"");
    std::fs::write(fix.config(), cfg).unwrap();
    let record = fix.filed_body("warden");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        !fix.dir
            .join("store/groups/parish.example/group.json")
            .exists(),
        "a refused approval makes no group record"
    );
    assert!(
        !fix.dir
            .join("store/accounts/parish-secretary/account.json")
            .exists(),
        "and no mailbox account"
    );
    assert!(!fix.passwd_file().contains("parish-secretary:"));
    assert!(!fix.table("mail_domains").contains("parish.example"));
}

/// A body's approval carries the DNS recipe, generated from its own domain and
/// the platform's published values, because mail and the website do not work
/// until the body creates those records.
#[test]
fn a_body_approval_email_carries_the_dns_recipe() {
    let fix = Fix::new("group-dns-recipe-email");
    let record = fix.filed_body("warden");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    for needle in [
        "10 mail.kyriakon.net.",
        "192.0.2.10",
        "2001:db8::10",
        "v=spf1 mx ip6:2001:db8::10 -all",
        "mail._domainkey",
        "v=DKIM1; k=rsa; p=examplepublickey",
        "v=DMARC1; p=none; rua=mailto:dmarc@kyriakon.net",
        "does not host your zone",
        "cannot set a reverse DNS record for parish.example",
        "can only observe your records",
    ] {
        assert!(sent.contains(needle), "{needle:?} missing:\n{sent}");
    }
    // A body has no account of the applicant's own, so the fallback is the site
    // owner's mailbox on the body's domain.
    assert!(
        sent.contains("To: parish-secretary@parish.example"),
        "{sent}"
    );
}

/// A broken zone is notified once per outage to the application's DNS contact,
/// the state records that it was, and the group record is not touched.
#[test]
fn a_broken_zone_notifies_the_dns_contact_once() {
    let fix = Fix::new("group-dns-broken");
    fix.resolver(Some("MX"));
    let record = fix.filed_body("warden");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let group = fix.read("groups/parish.example/group.json");
    let subject = "Subject: The DNS records for parish.example are not resolving";
    let sent = fix.sent();
    assert_eq!(
        sent.matches(subject).count(),
        1,
        "one notice per outage:\n{sent}"
    );
    assert!(sent.contains("To: warden@example.invalid"), "{sent}");
    assert!(
        fix.dir
            .join("store/groups/parish.example/dns-check.json")
            .exists(),
        "the check is recorded"
    );
    let notices = fix.read("accounts/parish-secretary/notices.jsonl");
    assert!(
        notices.contains("\"type\":\"dns.broken\""),
        "the account records the notice: {notices}"
    );
    let queries = fix
        .scripts_log()
        .lines()
        .filter(|l| l.starts_with("dig "))
        .count();
    assert_eq!(
        queries, 1,
        "the first record that answers nothing stops the check"
    );

    // The next pass is not due, so it neither queries nor sends again, and the
    // group record still carries no DNS values.
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.sent().matches(subject).count(),
        1,
        "a second pass sends none:\n{}",
        fix.sent()
    );
    assert_eq!(
        fix.scripts_log()
            .lines()
            .filter(|l| l.starts_with("dig "))
            .count(),
        1,
        "not due, so the resolver is not run again"
    );
    assert_eq!(fix.read("groups/parish.example/group.json"), group);
}

/// With no DNS contact in the application copy, the notice goes to the
/// accountable address the applicant gave.
#[test]
fn a_broken_zone_falls_back_to_the_accountable_address() {
    let fix = Fix::new("group-dns-fallback");
    fix.resolver(Some("MX"));
    let mut record = fix.filed_body("warden");
    record["answers"]["body_dns_contact"] = json!("");
    record["outside_address"] = json!("warden@example.invalid");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let sent = fix.sent();
    assert_eq!(
        sent.matches("Subject: The DNS records for parish.example are not resolving")
            .count(),
        1,
        "{sent}"
    );
    assert!(sent.contains("To: warden@example.invalid"), "{sent}");
}

/// Every row the recipe publishes is observed: a missing `www` name, AAAA, SPF,
/// DKIM or DMARC record is an outage even when the MX and apex A still answer.
#[test]
fn each_missing_recipe_row_is_an_outage() {
    for missing in [
        "MX",
        "A-apex",
        "A-www",
        "AAAA-apex",
        "AAAA-www",
        "SPF",
        "DKIM",
        "DMARC",
    ] {
        let fix = Fix::new(&format!("group-dns-missing-{missing}"));
        fix.resolver(Some(missing));
        fix.file_group(
            "parish.example",
            "parish-secretary",
            &[("secretary", "parish-secretary")],
            &["parish-secretary"],
            None,
        );
        let out = fix.drain();
        assert!(out.status.success(), "{missing}: {}", body(&out));
        assert_eq!(
            fix.sent()
                .matches("Subject: The DNS records for parish.example are not resolving")
                .count(),
            1,
            "{missing} was not reported as an outage:\n{}",
            fix.sent()
        );
    }
}

/// A complete set of the rows the recipe names is not an outage.
#[test]
fn a_complete_recipe_sends_no_dns_notice() {
    let fix = Fix::new("group-dns-complete");
    fix.resolver(None);
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.sent().contains("not resolving"),
        "a healthy zone was reported:\n{}",
        fix.sent()
    );
}

/// A resolver that cannot answer says nothing about the body's zone. It must not
/// mail the contact to repair a zone that may be healthy, and it must not record
/// an observation it did not make.
#[test]
fn a_resolver_that_cannot_answer_is_not_an_outage() {
    let fix = Fix::new("group-dns-resolver-down");
    fix.script("dig", "#!/bin/sh\nexit 1\n");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.sent().contains("not resolving"),
        "a failed lookup was reported as the zone's fault:\n{}",
        fix.sent()
    );
    assert!(
        !fix.dir
            .join("store/groups/parish.example/dns-check.json")
            .exists(),
        "a check that did not run was recorded"
    );
}

/// One group's unreadable record is reported and skipped; the other groups are
/// still watched and the pass carries on.
#[test]
fn one_bad_group_record_does_not_stop_the_sweep() {
    let fix = Fix::new("group-dns-bad-record");
    fix.resolver(Some("MX"));
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    let bad = fix.dir.join("store/groups/broken.example");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("group.json"), "not json").unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.sent()
            .matches("Subject: The DNS records for parish.example are not resolving")
            .count(),
        1,
        "the healthy group was not watched after the bad record:\n{}",
        fix.sent()
    );
}

/// A TXT answer without the record's marker is not the record: an unrelated
/// string at the SPF, DKIM or DMARC name is an outage.
#[test]
fn a_txt_without_its_marker_is_an_outage() {
    for unmarked in ["SPF", "DKIM", "DMARC"] {
        let fix = Fix::new(&format!("group-dns-unmarked-{unmarked}"));
        fix.resolver_with(None, Some(unmarked));
        fix.file_group(
            "parish.example",
            "parish-secretary",
            &[("secretary", "parish-secretary")],
            &["parish-secretary"],
            None,
        );
        let out = fix.drain();
        assert!(out.status.success(), "{unmarked}: {}", body(&out));
        assert_eq!(
            fix.sent()
                .matches("Subject: The DNS records for parish.example are not resolving")
                .count(),
            1,
            "an unmarked {unmarked} answer was not reported:\n{}",
            fix.sent()
        );
    }
}

/// An application the form accepts can be approved: the alias line names its own
/// account, and the address shares the mailbox its `own` target names.
#[test]
fn a_body_alias_may_name_itself_and_shares_the_mailbox() {
    let fix = Fix::new("group-alias-name");
    let mut record = fix.filed_body("warden");
    record["answers"]["body_account_names"] = json!("parish-secretary\nparish-office");
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !fix.journal().contains("\"failed\""),
        "an aliased body was refused: {}",
        fix.journal()
    );

    let virtuals = fix.table("virtuals");
    assert!(
        virtuals.contains("office@parish.example: parish-secretary"),
        "{virtuals}"
    );
    assert!(
        !fix.passwd_file().contains("parish-office:"),
        "the alias names no account: {}",
        fix.passwd_file()
    );
}

/// A forge outage does not stop the rest of the body: every account and table
/// line is made first, and the publish is retried from the intent next pass.
#[test]
fn a_forge_outage_still_makes_every_mailbox() {
    let fix = Fix::new("group-publish-fails");
    fix.publish_fails();
    let mut record = fix.filed_body("warden");
    record["answers"]["body_addresses"] = json!("secretary: own\noffice: own");
    record["answers"]["body_account_names"] = json!("parish-secretary\nparish-office");
    record["mail_keys"] = json!([
        {
            "mailbox": "parish-secretary",
            "fingerprint": "1111 2222 3333 4444",
            "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----",
            "verdict": "works"
        },
        {
            "mailbox": "parish-office",
            "fingerprint": "5555 6666 7777 8888",
            "material": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nyy\n-----END PGP PUBLIC KEY BLOCK-----",
            "verdict": "works"
        }
    ]);
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    let passwd = fix.passwd_file();
    assert!(passwd.contains("parish-secretary:"), "{passwd}");
    assert!(passwd.contains("parish-office:"), "{passwd}");
    let virtuals = fix.table("virtuals");
    for address in ["secretary", "office"] {
        assert!(
            virtuals.contains(&format!("{address}@parish.example: parish-")),
            "{virtuals}"
        );
    }
    assert!(
        fix.dir
            .join("store/accounts/parish-office/account.json")
            .exists(),
        "the later mailbox was made"
    );
    assert!(
        fix.failed_note().contains("publish-mail-key.sh"),
        "{}",
        fix.failed_note()
    );
    assert!(!fix.intents().is_empty(), "the intent waits for the retry");
}

/// A virtual table line that already points elsewhere is a refusal, and the
/// drain does not overrule it.
#[test]
fn a_conflicting_virtual_line_is_refused() {
    let fix = Fix::new("group-conflict");
    std::fs::write(
        fix.path("virtuals"),
        "office@parish.example: somebody-else\n",
    )
    .unwrap();
    let id = fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("office", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    assert!(
        fix.failed_note().contains("already maps"),
        "{}",
        fix.failed_note()
    );
    assert!(
        fix.table("virtuals")
            .contains("office@parish.example: somebody-else"),
        "{}",
        fix.table("virtuals")
    );
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
}

/// An address table that cannot be read is a refusal before the approval begins:
/// no journal line and no group record.
#[test]
fn a_body_whose_addresses_do_not_form_a_table_is_refused_before_the_journal() {
    let fix = Fix::new("group-bad-table");
    let mut record = fix.filed_body("warden");
    record["answers"]["body_addresses"] = json!("office: alias nobody");
    record["answers"]["body_account_names"] = json!("parish-secretary");
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert!(
        fix.failed_note().contains("not a mailbox in the table"),
        "{}",
        fix.failed_note()
    );
    assert!(
        !fix.journal().contains("\"applying\""),
        "a refusal began an approval: {}",
        fix.journal()
    );
    assert!(
        !fix.dir
            .join("store/groups/parish.example/group.json")
            .exists(),
        "a refused table made a record"
    );
}

/// Adding an alias writes one virtual entry pointing at a mailbox in the group.
/// It creates no account, key, allowance or hosting, and the group record's
/// accounts and payment are untouched.
#[test]
fn an_alias_added_to_a_group_writes_one_entry_and_no_account() {
    let fix = Fix::new("group-add-alias");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());
    let passwd = fix.passwd_file();
    let group = fix.read("groups/parish.example/group.json");
    let accounts = fix.names("accounts");
    let scripts = fix.scripts_log();

    fix.file_address(
        "parish.example",
        "add-alias",
        "office",
        "parish-secretary",
        None,
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());

    let virtuals = fix.table("virtuals");
    assert_eq!(
        virtuals
            .lines()
            .filter(|l| l.starts_with("office@parish.example:"))
            .count(),
        1,
        "{virtuals}"
    );
    assert!(
        virtuals.contains("office@parish.example: parish-secretary"),
        "{virtuals}"
    );
    assert_eq!(fix.passwd_file(), passwd, "an alias made an account");
    assert_eq!(fix.names("accounts"), accounts);
    assert!(
        !fix.dir.join("keyring/office.asc").exists(),
        "an alias made a key"
    );
    assert_eq!(
        fix.read("groups/parish.example/group.json"),
        group,
        "an alias changed the group record"
    );
    let log = fix.scripts_log();
    assert_eq!(
        log.matches("reload-smtpd.sh").count(),
        1,
        "the alias was not made live: {log}"
    );
    assert_eq!(
        log.matches("add-user.sh").count(),
        scripts.matches("add-user.sh").count(),
        "an alias made an account: {log}"
    );
    assert_eq!(
        log.matches("provision-member.sh").count(),
        scripts.matches("provision-member.sh").count(),
        "an alias built a member: {log}"
    );
}

/// Adding a mailbox creates its account, installs its key and points its entry
/// at it. The group gains the account and keeps everything else.
#[test]
fn a_mailbox_added_to_a_group_gets_an_account_key_and_entry() {
    let fix = Fix::new("group-add-mailbox");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    fix.file_address(
        "parish.example",
        "add-mailbox",
        "office",
        "parish-office",
        Some(GOOD_KEY),
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());

    assert!(
        fix.passwd_file().contains("parish-office:"),
        "{}",
        fix.passwd_file()
    );
    let key = std::fs::read_to_string(fix.dir.join("keyring/parish-office.asc"))
        .expect("the mailbox's key is on the box");
    assert!(key.contains("BEGIN PGP PUBLIC KEY BLOCK"), "{key}");
    assert_eq!(fix.account("parish-office")["group"], "parish.example");

    let virtuals = fix.table("virtuals");
    assert!(
        virtuals.contains("office@parish.example: parish-office"),
        "{virtuals}"
    );
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(
        group["accounts"],
        json!(["parish-secretary", "parish-office"])
    );

    let log = fix.scripts_log();
    assert!(log.contains("add-user.sh parish-office"), "{log}");
    assert!(log.contains("provision-member.sh parish-office"), "{log}");
    assert!(log.contains("publish-mail-key.sh parish-office"), "{log}");
}

/// Upgrading an alias makes the account and key and repoints the entry. The
/// address already existed, so the count does not move.
#[test]
fn upgrading_an_alias_repoints_it_without_changing_the_count() {
    let fix = Fix::new("group-upgrade-alias");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-secretary"),
        ],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());
    let before = fix
        .table("virtuals")
        .lines()
        .filter(|l| l.ends_with("@parish.example: parish-secretary"))
        .count();
    assert_eq!(before, 2);

    fix.file_address(
        "parish.example",
        "upgrade",
        "office",
        "parish-office",
        Some(GOOD_KEY),
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());

    let virtuals = fix.table("virtuals");
    assert!(
        virtuals.contains("office@parish.example: parish-office"),
        "{virtuals}"
    );
    assert!(
        !virtuals.contains("office@parish.example: parish-secretary"),
        "{virtuals}"
    );
    assert_eq!(
        virtuals
            .lines()
            .filter(|l| l.ends_with("@parish.example: parish-secretary")
                || l.ends_with("@parish.example: parish-office"))
            .count(),
        2,
        "the upgrade changed the address count: {virtuals}"
    );
    assert!(fix.passwd_file().contains("parish-office:"));
    assert!(fix.dir.join("keyring/parish-office.asc").exists());
    let log = fix.scripts_log();
    let built = log
        .rfind("provision-member.sh parish-office")
        .expect("the upgraded mailbox was built");
    let reload = log
        .rfind("reload-smtpd.sh")
        .expect("the repointed entry was made live");
    assert!(
        built < reload,
        "the repoint was not reloaded after the builder: {log}"
    );
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(
        group["accounts"],
        json!(["parish-secretary", "parish-office"])
    );
}

/// Removing a mailbox takes its account, key and every entry pointing at it,
/// and leaves the group's paid-until date and every other account byte for
/// byte. The closed name is held for ninety days.
#[test]
fn removing_a_mailbox_takes_exactly_its_account_and_entries() {
    let fix = Fix::new("group-remove-mailbox");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-office"),
            ("desk", "parish-office"),
        ],
        &["parish-secretary", "parish-office"],
        None,
    );
    assert!(fix.drain().status.success());
    // The group's renewal date is the group's: set one and make sure removal
    // does not move it.
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    group["payment"]["paid_until"] = json!("2027-03-01T00:00:00Z");
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    let other = fix.read("accounts/parish-secretary/account.json");

    fix.file_address("parish.example", "remove", "", "parish-office", None, None);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());

    assert!(
        !fix.passwd_file().contains("parish-office:"),
        "{}",
        fix.passwd_file()
    );
    assert!(
        !fix.dir.join("store/accounts/parish-office").exists(),
        "the account record stayed"
    );
    assert!(
        fix.dir.join("keyring/parish-office.asc").exists(),
        "the box keyring entry stays until the published key goes, as delete-user.sh leaves it"
    );
    let virtuals = fix.table("virtuals");
    assert!(
        !virtuals.contains("office@parish.example") && !virtuals.contains("desk@parish.example"),
        "an entry was left pointing at the removed mailbox: {virtuals}"
    );
    assert!(
        virtuals.contains("secretary@parish.example: parish-secretary"),
        "{virtuals}"
    );

    let after: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(after["accounts"], json!(["parish-secretary"]));
    assert_eq!(
        after["payment"]["paid_until"], "2027-03-01T00:00:00Z",
        "the group's renewal date moved"
    );
    assert_eq!(
        fix.read("accounts/parish-secretary/account.json"),
        other,
        "another account changed"
    );
    assert_eq!(fix.names("holds"), vec!["parish-office.json"]);
    assert!(fix.scripts_log().contains("delete-user.sh parish-office"));
}

/// A removal intent that names the sitting site owner while closing somebody
/// else must not move the site's key on a retry: the state below is what a crash
/// after the group write leaves, and the departing mailbox's own key is still in
/// the store. Copying it would give that member the body's upload key.
#[test]
fn retrying_a_non_owner_removal_does_not_take_the_sites_key() {
    let fix = Fix::new("group-remove-retry");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-office"),
        ],
        &["parish-secretary", "parish-office"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());
    let office_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOffice example";
    std::fs::write(fix.dir.join("store/keys/parish-office.pub"), office_key).unwrap();

    // The crash point: the group record no longer lists the mailbox and its
    // virtual line is gone, but its account and keys are still there.
    let mut group: Value =
        serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    group["accounts"] = json!(["parish-secretary"]);
    std::fs::write(
        fix.dir.join("store/groups/parish.example/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    let virtuals: Vec<String> = fix
        .table("virtuals")
        .lines()
        .filter(|l| !l.starts_with("office@"))
        .map(str::to_string)
        .collect();
    std::fs::write(fix.dir.join("virtuals"), virtuals.join("\n") + "\n").unwrap();

    fix.file_address(
        "parish.example",
        "remove",
        "",
        "parish-office",
        None,
        Some("parish-secretary"),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.read("keys/parish-secretary.pub").trim(),
        UPLOAD_KEY.trim(),
        "the departing mailbox's key replaced the site's"
    );
    let after: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(after["site_owner"], "parish-secretary");
    assert_eq!(after["accounts"], json!(["parish-secretary"]));
}

/// The same address intent handed to the drain again changes nothing: one
/// account, one entry, one key.
#[test]
fn an_address_intent_applied_twice_changes_nothing() {
    let fix = Fix::new("group-address-twice");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());
    let id = fix.file_address(
        "parish.example",
        "add-mailbox",
        "office",
        "parish-office",
        Some(GOOD_KEY),
        None,
    );
    assert!(fix.drain().status.success());
    let intent = fix.read(&format!("intents/{id}.json"));
    let group = fix.read("groups/parish.example/group.json");
    let passwd = fix.passwd_file();
    let virtuals = fix.table("virtuals");
    let account = fix.read("accounts/parish-office/account.json");

    // The file back, as a crash before the delete would leave it.
    std::fs::write(
        fix.dir.join("store/intents").join(format!("{id}.json")),
        intent,
    )
    .unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert_eq!(fix.read("groups/parish.example/group.json"), group);
    assert_eq!(fix.passwd_file(), passwd);
    assert_eq!(fix.table("virtuals"), virtuals);
    assert_eq!(fix.read("accounts/parish-office/account.json"), account);
    assert_eq!(
        fix.scripts_log()
            .matches("add-user.sh parish-office")
            .count(),
        1,
        "{}",
        fix.scripts_log()
    );
    assert_eq!(
        fix.names("accounts"),
        vec!["parish-office", "parish-secretary"]
    );
}

/// The ten-address cap counts mailboxes and aliases together: an eleventh
/// address is refused before anything is written or journaled as applying.
#[test]
fn the_eleventh_address_is_refused() {
    let fix = Fix::new("group-eleven");
    let names = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"];
    let addresses: Vec<(&str, &str)> = names.iter().map(|n| (*n, "parish-secretary")).collect();
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &addresses,
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());
    assert_eq!(
        fix.table("virtuals")
            .lines()
            .filter(|l| l.ends_with("@parish.example: parish-secretary"))
            .count(),
        10
    );

    let id = fix.file_address(
        "parish.example",
        "add-alias",
        "office",
        "parish-secretary",
        None,
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));

    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("ten addresses"),
        "{}",
        fix.failed_note()
    );
    assert!(
        !fix.table("virtuals").contains("office@parish.example"),
        "{}",
        fix.table("virtuals")
    );
    assert!(
        !fix.journal()
            .lines()
            .any(|l| l.contains("\"kind\":\"group-address\"")
                && l.contains("\"outcome\":\"applying\"")),
        "a refused eleventh address began: {}",
        fix.journal()
    );
}

/// A departing site owner hands the upload key and the generated roots to a
/// replacement before the account is deleted. Without a replacement the intent
/// is refused and nothing moves.
#[test]
fn a_departing_site_owner_must_name_a_replacement() {
    let fix = Fix::new("group-site-owner");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-office"),
        ],
        &["parish-secretary", "parish-office"],
        Some(UPLOAD_KEY),
    );
    assert!(fix.drain().status.success());
    assert!(fix.dir.join("store/keys/parish-secretary.pub").exists());

    let refused = fix.file_address(
        "parish.example",
        "remove",
        "",
        "parish-secretary",
        None,
        None,
    );
    assert!(fix.drain().status.success());
    assert_eq!(fix.intents(), vec![format!("{refused}.json")]);
    assert!(
        fix.failed_note().contains("owns the site"),
        "{}",
        fix.failed_note()
    );
    assert!(
        fix.passwd_file().contains("parish-secretary:"),
        "a refused removal deleted the owner"
    );

    std::fs::remove_file(
        fix.dir
            .join("store/intents")
            .join(format!("{refused}.json")),
    )
    .unwrap();
    fix.file_address(
        "parish.example",
        "remove",
        "",
        "parish-secretary",
        None,
        Some("parish-office"),
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix.intents().is_empty(), "{:?}", fix.intents());
    assert!(
        fix.journal()
            .lines()
            .any(|l| l.contains("\"kind\":\"group-address\"")
                && l.contains("\"outcome\":\"applied\"")),
        "{}",
        fix.journal()
    );

    assert!(!fix.passwd_file().contains("parish-secretary:"));
    let moved = fix.read("keys/parish-office.pub");
    assert!(moved.contains(UPLOAD_KEY), "{moved}");
    assert!(
        !fix.dir.join("store/keys/parish-secretary.pub").exists(),
        "the old owner kept the upload key"
    );
    let group: Value = serde_json::from_str(&fix.read("groups/parish.example/group.json")).unwrap();
    assert_eq!(group["site_owner"], "parish-office");
    assert_eq!(group["accounts"], json!(["parish-office"]));

    let log = fix.scripts_log();
    let builder = log
        .rfind("provision-member.sh parish-office")
        .expect("the replacement was built");
    let delete = log
        .rfind("delete-user.sh parish-secretary")
        .expect("the old owner was deleted");
    assert!(builder < delete, "the replacement was built first: {log}");
    assert!(log.contains("cron-apply.sh --web"), "{log}");
}

/// A name a removed mailbox left cannot be reused inside ninety days, on an
/// add-mailbox or on a new group's approval.
#[test]
fn a_closed_username_is_held_for_ninety_days() {
    let fix = Fix::new("group-hold");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-office"),
        ],
        &["parish-secretary", "parish-office"],
        None,
    );
    assert!(fix.drain().status.success());
    fix.file_address("parish.example", "remove", "", "parish-office", None, None);
    assert!(fix.drain().status.success());
    assert_eq!(fix.names("holds"), vec!["parish-office.json"]);

    let id = fix.file_address(
        "parish.example",
        "add-mailbox",
        "office",
        "parish-office",
        Some(GOOD_KEY),
        None,
    );
    assert!(fix.drain().status.success());
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("held until"),
        "{}",
        fix.failed_note()
    );
    assert!(!fix.passwd_file().contains("parish-office:"));

    // The approval gate reads the same hold. A different domain, so the name is
    // not already this group's account and the check reaches the hold.
    std::fs::write(
        fix.dir.join("store/holds/parish-secretary.json"),
        br#"{"username":"parish-secretary","until":"2099-01-01T00:00:00Z"}"#,
    )
    .unwrap();
    let mut record = fix.filed_body("warden");
    record["domain"] = json!("other.example");
    record["answers"]["body_domain"] = json!("other.example");
    fix.rewrite_record(&record);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "warden");
    assert!(fix.drain().status.success());
    assert!(
        fix.failed_note().contains("held until"),
        "{}",
        fix.failed_note()
    );
}

/// The hold is not only a group rule: a person's approval creates an account
/// too, so a closed group mailbox's name cannot be taken by an applicant.
#[test]
fn a_person_cannot_take_a_held_group_name() {
    let fix = Fix::new("person-held");
    std::fs::create_dir_all(fix.dir.join("store/holds")).unwrap();
    std::fs::write(
        fix.dir.join("store/holds/theophilus.json"),
        br#"{"username":"theophilus","until":"2099-01-01T00:00:00Z"}"#,
    )
    .unwrap();
    let record = fix.filed("theophilus", "cash", &[("rail", "cash")]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", "theophilus");
    assert!(fix.drain().status.success());
    assert!(
        fix.failed_note().contains("held until"),
        "{}",
        fix.failed_note()
    );
    assert!(!fix.dir.join("store/accounts/theophilus").exists());
    assert!(fix.passwd_file().is_empty(), "{}", fix.passwd_file());
}

/// The console files a signed address intent the drain then applies, which is
/// the operator's path when there is no account page for it yet.
#[test]
fn the_console_files_an_address_intent() {
    let fix = Fix::new("group-ctl-address");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    let out = fix.ctl(&[
        "address",
        "--domain",
        "parish.example",
        "--action",
        "add-alias",
        "--address",
        "office",
        "--mailbox",
        "parish-secretary",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let intents = fix.intents();
    assert_eq!(intents.len(), 1, "{intents:?}");
    let filed: Value = serde_json::from_str(&fix.read(&format!("intents/{}", intents[0]))).unwrap();
    assert_eq!(filed["kind"], "group-address");
    assert_eq!(filed["action"], "add-alias");

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(fix
        .table("virtuals")
        .contains("office@parish.example: parish-secretary"));
}

/// An address intent without the root key's signature changes nothing:
/// `intents/` is writable by the unprivileged handler, and this one would
/// otherwise create or remove a root account.
#[test]
fn an_address_intent_with_a_bad_signature_is_refused() {
    let fix = Fix::new("group-address-sig");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    let id = fix.file_address(
        "parish.example",
        "add-mailbox",
        "office",
        "parish-office",
        Some(GOOD_KEY),
        None,
    );
    let mut filed: Value = serde_json::from_str(&fix.read(&format!("intents/{id}.json"))).unwrap();
    filed["sig"] = json!("00");
    std::fs::write(
        fix.dir.join("store/intents").join(format!("{id}.json")),
        serde_json::to_vec_pretty(&filed).unwrap(),
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("signature does not verify"),
        "{}",
        fix.failed_note()
    );
    assert!(
        !fix.table("virtuals").contains("office@parish.example"),
        "{}",
        fix.table("virtuals")
    );
    assert!(!fix.passwd_file().contains("parish-office:"));
}

/// A valid signature does not cover a swapped mail key: the material is hashed
/// into the payload, so changing it while keeping `sig` is refused and nothing
/// is installed or published.
#[test]
fn a_swapped_mail_key_is_refused() {
    let fix = Fix::new("group-address-key-swap");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[("secretary", "parish-secretary")],
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    let id = fix.file_address(
        "parish.example",
        "add-mailbox",
        "office",
        "parish-office",
        Some(GOOD_KEY),
        None,
    );
    let mut filed: Value = serde_json::from_str(&fix.read(&format!("intents/{id}.json"))).unwrap();
    filed["mail_key"]["material"] =
        json!("-----BEGIN PGP PUBLIC KEY BLOCK-----\nattacker\n-----END PGP PUBLIC KEY BLOCK-----");
    std::fs::write(
        fix.dir.join("store/intents").join(format!("{id}.json")),
        serde_json::to_vec_pretty(&filed).unwrap(),
    )
    .unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("signature does not verify"),
        "{}",
        fix.failed_note()
    );
    assert!(
        !fix.dir.join("keyring/parish-office.asc").exists(),
        "the swapped key reached the keyring"
    );
    assert!(!fix.passwd_file().contains("parish-office:"));
}

/// A hold that has run out no longer blocks the name, once the account record
/// has gone with the removal.
#[test]
fn an_expired_hold_releases_the_name() {
    let fix = Fix::new("group-hold-expired");
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &[
            ("secretary", "parish-secretary"),
            ("office", "parish-office"),
        ],
        &["parish-secretary", "parish-office"],
        None,
    );
    assert!(fix.drain().status.success());
    fix.file_address("parish.example", "remove", "", "parish-office", None, None);
    assert!(fix.drain().status.success());
    assert!(!fix.dir.join("store/accounts/parish-office").exists());
    assert_eq!(fix.names("holds"), vec!["parish-office.json"]);

    std::fs::write(
        fix.dir.join("store/holds/parish-office.json"),
        br#"{"username":"parish-office","until":"2020-01-01T00:00:00Z"}"#,
    )
    .unwrap();
    fix.file_address(
        "parish.example",
        "add-mailbox",
        "desk",
        "parish-office",
        Some(GOOD_KEY),
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(!fix.journal().contains("\"failed\""), "{}", fix.journal());
    assert!(fix.passwd_file().contains("parish-office:"));
    assert!(fix.dir.join("store/accounts/parish-office").exists());
    assert!(fix
        .table("virtuals")
        .contains("desk@parish.example: parish-office"));
}

/// The cap counts a new entry even when the mailbox it points at is already in
/// the group: adding a second address to an existing mailbox is still the
/// eleventh address.
#[test]
fn a_second_address_on_an_existing_mailbox_still_counts() {
    let fix = Fix::new("group-eleven-existing");
    let names = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"];
    let addresses: Vec<(&str, &str)> = names.iter().map(|n| (*n, "parish-secretary")).collect();
    fix.file_group(
        "parish.example",
        "parish-secretary",
        &addresses,
        &["parish-secretary"],
        None,
    );
    assert!(fix.drain().status.success());

    let id = fix.file_address(
        "parish.example",
        "add-mailbox",
        "office",
        "parish-secretary",
        Some(GOOD_KEY),
        None,
    );
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(fix.intents(), vec![format!("{id}.json")]);
    assert!(
        fix.failed_note().contains("ten addresses"),
        "{}",
        fix.failed_note()
    );
    assert!(
        !fix.table("virtuals").contains("office@parish.example"),
        "{}",
        fix.table("virtuals")
    );
}
