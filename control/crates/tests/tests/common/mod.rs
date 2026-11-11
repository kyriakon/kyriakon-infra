//! Shared fixture and helpers for the control plane integration tests.
//!
//! The fixture rebinds every path the drain and the console touch to a
//! temporary store. A test that only exercises an intent uses `drain`, which
//! runs the same pass in-process; `drain_binary` drives the installed binary
//! when the process boundary is the thing under test.
//!
//! Each area is its own test binary, so it uses only part of this fixture. The
//! unused-method lint is what a shared test helper buys and is not a signal.
#![allow(dead_code)]

use std::os::unix::process::ExitStatusExt;

use kyriakon_control_core::config::DrainConfig;
use kyriakon_control_core::store::Store;

pub use std::collections::BTreeMap;

pub use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub use std::path::{Path, PathBuf};

pub use std::process::Output;

pub use askama::Template;

pub use kyriakon_control_core::store::{self, Record};

pub use kyriakon_control_core::account::sign;
pub use kyriakon_control_handler::{capsule, page, responder};

pub use serde_json::{json, Value};

pub use time::OffsetDateTime;

/// The test binary sits in `target/debug/deps`; the service binaries sit one
/// directory above it.
fn bin(name: &str) -> PathBuf {
    let mut path = std::env::current_exe().expect("the test binary has a path");
    path.pop();
    path.pop();
    path.push(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    assert!(path.exists(), "missing built binary {}", path.display());
    path
}

pub fn drain_binary() -> PathBuf {
    bin("kyriakon-control-drain")
}

pub fn ctl_binary() -> PathBuf {
    bin("kyriakon-admin")
}

/// The repository root, from the test package's manifest directory.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("the repository root resolves")
}

/// A status token: 26 lowercase Crockford characters, which is 128 bits.
pub const TOKEN: &str = "0123456789abcdefghjkmnpqrs";

/// A second status token, for a second application on the same username.
pub const OTHER_TOKEN: &str = "fedcba98765432100123456789";

/// A transaction id in the shape a Monero wallet prints: 64 hex characters.
pub const TXID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The key file's body: `read_key` reads this and strips the trailing newline,
/// and the fixtures must be 0600 for it to be accepted at all.
pub const KEY: &[u8] = b"the approval key\n";

/// The fixture's Stripe signing secret, without the trailing newline
/// `sign::read_key` strips from the file.
pub const WEBHOOK_SECRET: &[u8] = b"the webhook secret";

/// The subscription every card fixture attaches unless a test says otherwise.
pub const SUBSCRIPTION: &str = "sub_example";

/// A bare SSH public key line, the shape `provision-member.sh` accepts and what
/// the upload key file it reads holds.
pub const UPLOAD_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample secretary@example";

/// A public key block with the structure of a key the check can read.
pub const GOOD_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
mAYEAAAAABK4BgQAAAAAEg==\n-----END PGP PUBLIC KEY BLOCK-----\n";

pub struct Fix {
    pub dir: PathBuf,
}

impl Fix {
    pub fn new(name: &str) -> Fix {
        let dir = std::env::temp_dir().join(format!("control-it-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in [
            "store/intents",
            "store/applications",
            "store/mail/new",
            "bin",
            "host/httpd.d",
            "host/gmid.d",
            "host/acme-client.d",
            "host/ssl/private",
            "host/queue/pending",
            "home/www",
            "keyring",
            "proofs",
        ] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let fix = Fix { dir };
        std::fs::write(fix.path("key"), KEY).unwrap();
        std::fs::set_permissions(fix.path("key"), std::fs::Permissions::from_mode(0o600)).unwrap();
        // Stripe's webhook signing secret and the restricted API key, both
        // root-only in the shape `sign::read_key` and the API script refuse to
        // use otherwise.
        std::fs::write(fix.path("stripe"), [WEBHOOK_SECRET, b"\n"].concat()).unwrap();
        std::fs::write(
            fix.path("stripe-key"),
            b"rk_test_example_000000000
",
        )
        .unwrap();
        for file in ["stripe", "stripe-key"] {
            std::fs::set_permissions(fix.path(file), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        // The box's account list, empty to start: the drain reads it to tell its
        // own half-finished approval from somebody else's account.
        std::fs::write(fix.path("passwd"), "").unwrap();
        // The virtual tables deploy-mail.sh seeds: the platform's domain and no
        // address entries yet, so a group's lines are the drain's.
        std::fs::write(fix.path("mail_domains"), "kyriakon.net\n").unwrap();
        std::fs::write(fix.path("virtuals"), "").unwrap();
        std::fs::write(fix.path("dkim_domains"), "kyriakon.net\n").unwrap();
        // The greylist pass-through list, as deploy-mail.sh seeds it: the
        // platform's own domain with a body's line added by a group provision.
        std::fs::write(
            fix.path("spamd.alloweddomains"),
            "# greylist pass-through\n@kyriakon.net\n",
        )
        .unwrap();
        // The held-back names, copied from the tracked list so that a test can add
        // one to the fixture's without touching the repository's.
        let tracked =
            std::fs::read_to_string(repo_root().join("reserved-usernames.txt")).unwrap_or_default();
        std::fs::write(fix.path("reserved"), tracked).unwrap();
        let sent = fix.path("sent");
        fix.script("enqueuer.sh", &format!("#!/bin/sh\ncat >> '{sent}'\n"));
        for s in [
            "provision-member.sh",
            "lapse-user.sh",
            "provision-group-web.sh",
            "provision-group-capsule.sh",
            "provision-group-acme.sh",
            "cron-apply.sh",
            "publish-mail-key.sh",
            "reload-smtpd.sh",
            "reload-spamd.sh",
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
        // remove-group.sh is the host-file half of the removal: the fixture's
        // stub does the same table and file removals against the fixture tree,
        // so the drain's assertions see what the box would. The script's own
        // self-test covers that logic in ksh.
        let log = fix.path("scripts.log");
        let mail_domains = fix.path("mail_domains");
        let virtuals = fix.path("virtuals");
        let dkim_domains = fix.path("dkim_domains");
        let spamd_allowed = fix.path("spamd.alloweddomains");
        let host = fix.dir.join("host").to_str().unwrap().to_string();
        fix.script(
            "remove-group.sh",
            &format!(
                "#!/bin/sh\n\
                 echo \"remove-group.sh $*\" >> '{log}'\n\
                 d=$1\n\
                 for f in '{mail_domains}' '{dkim_domains}'; do\n\
                 \tawk -v d=\"$d\" '$0 != d' \"$f\" > \"$f.new\" && mv \"$f.new\" \"$f\"\n\
                 done\n\
                 awk -v s=\"@$d\" '$0 != s' '{spamd_allowed}' > '{spamd_allowed}.new' && mv '{spamd_allowed}.new' '{spamd_allowed}'\n\
                 awk -v s=\"@$d\" -F: '{{ k = $1; gsub(/^[ \\t]+|[ \\t]+$/, \"\", k); if (length(k) >= length(s) && substr(k, length(k) - length(s) + 1) == s) next; print }}' '{virtuals}' > '{virtuals}.new' && mv '{virtuals}.new' '{virtuals}'\n\
                 rm -f '{host}/httpd.d/'\"$d\"'.conf' '{host}/gmid.d/'\"$d\"'.conf' '{host}/acme-client.d/'\"$d\"'.conf'\n\
                 rm -f '{host}/ssl/'\"$d\"'.fullchain.pem' '{host}/ssl/private/'\"$d\"'.key' '{host}/ssl/'\"$d\"'.crt'\n\
                 rm -f '{host}/ssl/capsule-'\"$d\"'.cnf' '{host}/ssl/capsule-'\"$d\"'.crt' '{host}/ssl/private/capsule-'\"$d\"'.key'\n\
                 rm -f '{host}/queue/pending/'\"$d\"\n",
            ),
        );
        fix.add_user_writes_passwd();
        // The DNS sweep's resolver. It answers every query with one non-empty
        // line, so a group with records is not an outage; a test that wants one
        // rewrites it with `resolver`.
        fix.resolver(None);
        // The quota sweep's report: an empty table, which is what a filesystem
        // with quotas off prints. A test that wants usage writes one.
        fix.repquota(None);
        fix.stripe_subscription("active", 1_790_000_000);
        // The rate fetch: unreachable by default, so no test reaches CoinGecko
        // unless it says which rate the source answers with.
        fix.rate_source(None);
        let cfg = format!(
            "store_root = \"{}\"\n\
             reserved = \"{}\"\n\
             scripts = \"{}\"\n\
             sendmail = \"{}\"\n\
             passwd = \"{}\"\n\
             mail_domains = \"{}\"\n\
             virtuals = \"{}\"\n\
             dkim_domains = \"{}\"\n\
             spamd_alloweddomains = \"{}\"\n\
             approval_key = \"{}\"\n\
             keyring_dir = \"{}\"\n\
             stripe_webhook_secret = \"{}/stripe\"\n\
             stripe_api_key = \"{}/stripe-key\"\n\
             stripe_payment_link = \"https://buy.stripe.com/test_example\"\n\
             keyring_publish_token = \"{}/keyring-token\"\n\
             reviewer = \"reviewer@example.invalid\"\n\
             from = \"kyriakon <hello@example.invalid>\"\n\
             base_url = \"https://signup.kyriakon.net\"\n\
             price_gbp = \"20.00\"\n\
             group_price_gbp = \"40.00\"\n\
             postal_address = \"1 Example Street, Example\"\n\
             mail_dir = \"{}/store/mail/new\"\n\
             release = \"2026-10-10 abc1234\"\n\
             mail_host = \"mail.kyriakon.net\"\n\
             ipv4 = \"192.0.2.10\"\n\
             ipv6 = \"2001:db8::10\"\n\
             dkim_selector = \"mail\"\n\
             dkim_public_key = \"v=DKIM1; k=rsa; p=examplepublickey\"\n\
             dmarc_rua = \"mailto:dmarc@kyriakon.net\"\n\
             resolver = \"{}\"\n\
             repquota = \"{}\"\n\
             quota_mount = \"{}\"\n\
             rates = \"{}/store/rates/xmr-gbp.json\"\n\
             rate_endpoint = \"https://rates.example.invalid/simple/price\"\n\
             rates_fetch = \"{}\"\n\
             public_root = \"{}\"\n\
             gpg = \"gpg\"\n\
             proof_dir = \"{}\"\n",
            fix.path("store"),
            fix.path("reserved"),
            fix.path("bin"),
            fix.path("bin/enqueuer.sh"),
            fix.path("passwd"),
            fix.path("mail_domains"),
            fix.path("virtuals"),
            fix.path("dkim_domains"),
            fix.path("spamd.alloweddomains"),
            fix.path("key"),
            fix.path("keyring"),
            fix.dir.display(),
            fix.dir.display(),
            fix.dir.display(),
            fix.dir.display(),
            fix.path("bin/dig"),
            fix.path("bin/repquota"),
            "/home",
            fix.dir.display(),
            fix.path("bin/curl"),
            fix.path("home/www"),
            fix.path("proofs"),
        );
        std::fs::write(fix.path("drain.toml"), cfg).unwrap();
        fix
    }

    pub fn path(&self, rel: &str) -> String {
        self.dir.join(rel).to_str().unwrap().to_string()
    }

    pub fn passwd_file(&self) -> String {
        std::fs::read_to_string(self.dir.join("passwd")).unwrap_or_default()
    }

    pub fn set_passwd(&self, text: &str) {
        std::fs::write(self.dir.join("passwd"), text).unwrap();
    }

    /// Hold one more name back, as adding a hostname to the tracked list does.
    pub fn reserve(&self, name: &str) {
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
    pub fn failed_note(&self) -> String {
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
    pub fn add_user_writes_passwd(&self) {
        let p = self.path("passwd");
        let log = self.path("scripts.log");
        self.script(
            "add-user.sh",
            &format!(
                "#!/bin/sh\nif grep -q \"^$1:\" '{p}'; then\n\techo \"user $1 already exists\" >&2\n\texit 1\nfi\nprintf '%s:x:1000:1000::/home/%s:/sbin/nologin\\n' \"$1\" \"$1\" >> '{p}'\necho \"add-user.sh $*\" >> '{log}'\n"
            ),
        );
    }

    pub fn script(&self, name: &str, body: &str) {
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
    pub fn resolver(&self, missing: Option<&str>) {
        self.resolver_with(missing, None);
    }

    pub fn resolver_with(&self, missing: Option<&str>, unmarked: Option<&str>) {
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

    /// The member's sftp chroot as `scripts/provision-member.sh` leaves it: the
    /// public root with the two directories the member already uploads to, and
    /// nothing else.
    pub fn member_tree(&self, username: &str) {
        let root = self
            .dir
            .join("home/www")
            .join(format!("{username}.kyriakon.net"));
        for sub in ["www", "gemini"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
    }

    /// The member's mail key in the box keyring, the file the encrypting LMTP
    /// reads and the export mails to.
    pub fn mail_key(&self, localpart: &str, material: &str) {
        std::fs::write(
            self.dir.join("keyring").join(format!("{localpart}.asc")),
            material,
        )
        .unwrap();
    }

    pub fn config(&self) -> String {
        self.path("drain.toml")
    }

    /// The subscription the Stripe API stub answers with. `status` is what the
    /// retrieval returns, which is the fact `invoice.paid` checks before it
    /// extends anything.
    pub fn stripe_subscription(&self, status: &str, period_end: i64) {
        self.script(
            "stripe-api.sh",
            &format!(
                "#!/bin/sh\ncat <<'JSON'\n{{\"id\":\"{SUBSCRIPTION}\",\"status\":\"{status}\",\"current_period_end\":{period_end},\"customer\":\"cus_example\"}}\nJSON\n"
            ),
        );
    }

    /// The rate source's stub. `Some(rate)` answers the CoinGecko shape with
    /// that GBP-per-XMR rate and logs the call, so a test can see whether the
    /// source was asked at all; `None` is an unreachable source.
    pub fn rate_source(&self, rate: Option<&str>) {
        let log = self.path("rates.log");
        let body = match rate {
            Some(rate) => format!("cat <<'JSON'\n{{\"monero\":{{\"gbp\":{rate},\"last_updated_at\":1790857880}}}}\nJSON\n"),
            None => "printf 'curl: (6) Could not resolve host\\n' >&2\nexit 6\n".to_string(),
        };
        self.script(
            "curl",
            &format!("#!/bin/sh\nprintf 'curl %s\\n' \"$*\" >> '{log}'\n{body}"),
        );
    }

    /// How many times the source has been asked for a rate.
    pub fn rate_fetches(&self) -> usize {
        std::fs::read_to_string(self.path("rates.log"))
            .unwrap_or_default()
            .lines()
            .filter(|line| line.starts_with("curl "))
            .count()
    }

    /// The cache path the config names.
    pub fn rates_path(&self) -> String {
        self.path("store/rates/xmr-gbp.json")
    }

    pub fn rate_cache(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.rates_path()).unwrap()).unwrap()
    }

    /// Seed the cache as a previous pass wrote it, `fetched_at` included, so a
    /// test can say whether it is inside the twenty-four hours.
    pub fn write_rate_cache(&self, rate: &str, fetched_at: &str) {
        std::fs::create_dir_all(self.dir.join("store/rates")).unwrap();
        let cached = json!({
            "version": 1,
            "rate_gbp_per_xmr": rate,
            "source": "coingecko",
            "fetched_at": fetched_at,
        });
        std::fs::write(
            self.rates_path(),
            serde_json::to_vec_pretty(&cached).unwrap(),
        )
        .unwrap();
    }

    /// A Stripe stub that answers both calls the repair makes: the subscription
    /// and the Checkout Session the list filter returns, carrying `reference`.
    pub fn stripe_session_repair(&self, reference: &str) {
        self.script(
            "stripe-api.sh",
            &format!(
                "#!/bin/sh\ncase \"$1\" in\nsubscription) cat <<'JSON'\n{{\"id\":\"{SUBSCRIPTION}\",\"status\":\"active\",\"current_period_end\":1790000000,\"customer\":\"cus_example\"}}\nJSON\n;;\nsession) cat <<'JSON'\n{{\"id\":\"cs_example\",\"subscription\":\"{SUBSCRIPTION}\",\"client_reference_id\":\"{reference}\"}}\nJSON\n;;\n*) exit 1 ;;\nesac\n"
            ),
        );
    }

    /// The same pair, with a session that names no account reference.
    pub fn stripe_session_without_reference(&self) {
        self.script(
            "stripe-api.sh",
            &format!(
                "#!/bin/sh\ncase \"$1\" in\nsubscription) cat <<'JSON'\n{{\"id\":\"{SUBSCRIPTION}\",\"status\":\"active\",\"current_period_end\":1790000000,\"customer\":\"cus_example\"}}\nJSON\n;;\nsession) cat <<'JSON'\n{{\"id\":\"cs_example\",\"subscription\":\"{SUBSCRIPTION}\"}}\nJSON\n;;\n*) exit 1 ;;\nesac\n"
            ),
        );
    }

    /// An API the drain cannot reach, which must leave the event for the next
    /// pass rather than extend the date on trust.
    pub fn stripe_unreachable(&self) {
        self.script(
            "stripe-api.sh",
            "#!/bin/sh\necho 'cannot reach Stripe' >&2\nexit 1\n",
        );
    }

    /// Deliver one event the way the handler stored it: the raw body and a
    /// `Stripe-Signature` header over `t.` and that body, dated now.
    pub fn webhook(&self, id: &str, kind: &str, object: Value) {
        let event = json!({
            "id": id,
            "type": kind,
            "created": OffsetDateTime::now_utc().unix_timestamp(),
            "data": {"object": object},
        });
        let body = serde_json::to_vec(&event).unwrap();
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();
        let mut payload = timestamp.to_string().into_bytes();
        payload.push(b'.');
        payload.extend_from_slice(&body);
        let sig = sign::sign_bytes(WEBHOOK_SECRET, &payload).unwrap();
        self.webhook_raw(id, &body, &format!("t={timestamp},v1={sig}"));
    }

    /// Deliver bytes and a signature header verbatim, for the refusals a valid
    /// delivery cannot produce.
    pub fn webhook_raw(&self, id: &str, body: &[u8], header: &str) {
        let dir = self.dir.join("store/webhooks");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{id}.body")), body).unwrap();
        std::fs::write(dir.join(format!("{id}.sig")), header).unwrap();
    }

    /// The undecided deliveries left in `webhooks/`, which is the body and
    /// signature pairs rather than the append-only processed record.
    pub fn webhooks(&self) -> Vec<String> {
        self.names("webhooks")
            .into_iter()
            .filter(|n| n.ends_with(".body") || n.ends_with(".sig"))
            .collect()
    }

    /// A card account as an approval leaves it, with the subscription already
    /// attached, for a test whose event is an invoice.
    pub fn card_account(&self, username: &str, paid_until: Option<&str>) {
        let dir = self.dir.join("store/accounts").join(username);
        std::fs::create_dir_all(&dir).unwrap();
        let token = "KYR-AAAA-BBBB-CCCC";
        let token_dir = self.dir.join("store/tokens");
        std::fs::create_dir_all(&token_dir).unwrap();
        std::fs::write(
            token_dir.join(format!("{token}.json")),
            serde_json::to_vec_pretty(&json!({
                "token": token,
                "username": username,
                "issued_at": "2026-10-02T09:00:00Z",
                "window_closes_at": "2099-01-01T00:00:00Z",
                "state": "issued",
            }))
            .unwrap(),
        )
        .unwrap();
        let account = json!({
            "version": 1,
            "username": username,
            "state": "active",
            "decision": "approve",
            "decided_at": "2026-10-02T09:00:00Z",
            "rail": "card",
            "no_charge": false,
            "created_at": "2026-10-02T09:00:00Z",
            "payment": {
                "token_ref": "KYR-AAAA-BBBB-CCCC",
                "token_issued_at": "2026-10-02T09:00:00Z",
                "paid_until": paid_until,
                "window": {
                    "opened_at": "2026-10-02T09:00:00Z",
                    "closes_at": "2099-01-01T00:00:00Z",
                    "state": "open",
                    "extensions": 0
                },
                "stripe": {
                    "subscription": SUBSCRIPTION,
                    "customer": "cus_example",
                    "status": "active"
                }
            }
        });
        std::fs::write(
            dir.join("account.json"),
            serde_json::to_vec_pretty(&account).unwrap(),
        )
        .unwrap();
    }

    /// Write the application record the handler would have written.
    pub fn filed(&self, username: &str, rail: &str, answers: &[(&str, &str)]) -> Value {
        self.filed_with(username, rail, answers, None, Some((UPLOAD_KEY, "works")))
    }

    pub fn filed_with(
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
        // Relative, so a fixture filed today is inside ADR 0005's window
        // whenever the suite runs; a fixed date would be purged after it.
        let filed_at = kyriakon_control_core::util::after_days(-40);
        let record = json!({
            "username": username,
            "status_token": TOKEN,
            "filed_at": filed_at,
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

    /// One call to a page action's route as the handler files it: the account,
    /// a real page session opened for it, and the action's own fields. The
    /// session is real because the drain re-proves it, so a fixture that
    /// hand-wrote an id would only be testing itself.
    pub fn file_page_action(&self, kind: &str, username: &str, fields: Value) -> String {
        let cookie = self.open_session(username);
        let session = Self::session_id(&cookie);
        let id = ulid();
        let mut intent = fields;
        intent["id"] = json!(id);
        intent["kind"] = json!(kind);
        intent["filed_at"] = json!("2026-10-02T09:00:00Z");
        intent["username"] = json!(username);
        intent["session"] = json!(session);
        self.write_intent(&id, &intent);
        id
    }

    /// A plain active account with no payment block and no hosting flags, for a
    /// test whose subject is one of the page's actions. Fields the test names
    /// are set beside the required ones.
    pub fn page_account(&self, username: &str, fields: Value) -> Value {
        let mut account = json!({
            "version": 1,
            "username": username,
            "state": "active",
            "decision": "approve",
            "decided_at": "2026-10-02T09:00:00Z",
            "rail": "no_charge",
            "no_charge": true,
            "created_at": "2026-10-02T09:00:00Z",
        });
        if let (Some(base), Value::Object(extra)) = (account.as_object_mut(), fields) {
            base.extend(extra);
        }
        self.write_account(username, &account);
        account
    }

    /// Write one account record verbatim, as the drain would.
    pub fn write_account(&self, username: &str, account: &Value) {
        let dir = self.dir.join("store/accounts").join(username);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("account.json"),
            serde_json::to_vec_pretty(account).unwrap(),
        )
        .unwrap();
    }

    /// Change one field of an account the fixture already wrote.
    pub fn amend_account(&self, username: &str, amend: impl FnOnce(&mut Value)) {
        let mut account = self.account(username);
        amend(&mut account);
        self.write_account(username, &account);
    }

    /// Write one `provision-group` intent under `id`, as an approval files it.
    pub fn write_group(
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
        let mut intent = json!({
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
            "sig": "",
        });
        // Signed as the approval signs it, over the same fields the drain reads:
        // a fixture that filed an unsigned intent would exercise the refusal,
        // not the transition.
        let parsed: kyriakon_control_core::store::GroupIntent =
            serde_json::from_value(intent.clone()).unwrap();
        intent["sig"] =
            json!(
                sign::sign(b"the approval key", &sign::group_provision_payload(&parsed)).unwrap()
            );
        self.write_intent(id, &intent);
    }

    /// File one `provision-group` intent and hand back its id.
    pub fn file_group(
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
    pub fn file_address(
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

    /// Write one `remove-group` intent under `id`, signed the way the console
    /// signs it.
    pub fn write_remove_group(&self, id: &str, domain: &str) {
        let sig = sign::sign(b"the approval key", &sign::group_remove_payload(domain)).unwrap();
        self.write_intent(
            id,
            &json!({
                "id": id,
                "kind": "remove-group",
                "filed_at": "2026-10-02T09:00:00Z",
                "domain": domain,
                "sig": sig,
            }),
        );
    }

    /// File one `remove-group` intent and hand back its id.
    pub fn file_remove_group(&self, domain: &str) -> String {
        let id = ulid();
        self.write_remove_group(&id, domain);
        id
    }

    /// One token index entry, as a paid approval writes it.
    pub fn write_token(&self, name: &str, username: &str) {
        std::fs::create_dir_all(self.dir.join("store/tokens")).unwrap();
        let record = json!({
            "token": name,
            "username": username,
            "issued_at": "2026-10-02T09:00:00Z",
            "window_closes_at": "2099-01-01T00:00:00Z",
            "state": "open",
        });
        std::fs::write(
            self.dir.join("store/tokens").join(format!("{name}.json")),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
    }

    /// The fixture's stand-in for the box's host tree: the generated blocks,
    /// the certificate material and the queue entry.
    pub fn host(&self, rel: &str) -> PathBuf {
        self.dir.join("host").join(rel)
    }

    /// A virtual table beside the store, as the drain left it.
    pub fn table(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.join(name)).unwrap_or_default()
    }

    /// A body's application record, as the community block files it: two
    /// addresses sharing one mailbox, one mail key for it, and the block's
    /// upload key.
    pub fn filed_body(&self, applicant: &str) -> Value {
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
        let filed_at = kyriakon_control_core::util::after_days(-40);
        let record = json!({
            "username": applicant,
            "status_token": TOKEN,
            "filed_at": filed_at,
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
    pub fn rewrite_record(&self, record: &Value) {
        std::fs::write(
            self.dir
                .join("store/applications")
                .join(format!("{TOKEN}.json")),
            serde_json::to_vec_pretty(record).unwrap(),
        )
        .unwrap();
    }

    /// File an application intent, as the handler does.
    pub fn file_application(&self, record: &Value) -> String {
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

    pub fn write_intent(&self, id: &str, intent: &Value) {
        std::fs::write(
            self.dir.join("store/intents").join(format!("{id}.json")),
            serde_json::to_vec_pretty(intent).unwrap(),
        )
        .unwrap();
    }

    pub fn decide(&self, kind: &str, username: &str) -> String {
        let action = action_for(kind);
        let sig = self.sign_action(action);
        self.write_decision(kind, action, &sig, username)
    }

    /// A decision intent with whatever action and signature the caller gives, so
    /// a test can try one the drain must refuse.
    pub fn write_decision(&self, kind: &str, action: &str, sig: &str, username: &str) -> String {
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
    /// fixture's kyriakon-admin reads.
    pub fn sign_action(&self, action: &str) -> String {
        sign::sign(b"the approval key", &sign::decide_payload(TOKEN, action)).unwrap()
    }

    /// A provision-member.sh that refuses when the upload key file is not there,
    /// the shape the real script has, so an approval that fails to write it
    /// fails the way it would on the box.
    pub fn provision_requires_key(&self) {
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
    pub fn provision_fails(&self) {
        self.script(
            "provision-member.sh",
            "#!/bin/sh\necho 'builder refused' >&2\nexit 1\n",
        );
    }

    /// An enqueuer that refuses: the box's mail path is broken, which is when the
    /// fallback a printed alert relies on is the only channel left.
    pub fn enqueuer_fails(&self) {
        self.script("enqueuer.sh", "#!/bin/sh\ncat >/dev/null\nexit 1\n");
    }

    /// The working enqueuer back, for a test that broke the mail path and then
    /// wants the retry to go through.
    pub fn enqueuer_works(&self) {
        let sent = self.path("sent");
        self.script("enqueuer.sh", &format!("#!/bin/sh\ncat >> '{sent}'\n"));
    }

    /// The space-used sweep's `repquota -u`. `None` is the empty report a
    /// filesystem with quotas off prints; a test that wants usage passes the
    /// lines to print.
    pub fn repquota(&self, body: Option<&str>) {
        self.script(
            "repquota",
            &format!("#!/bin/sh\n{}\n", body.unwrap_or("exit 0")),
        );
    }

    /// A publish-mail-key.sh that refuses, in the shape the real one has when the
    /// forge will not take the change: the member and the key named on stderr,
    /// and a non-zero exit.
    pub fn publish_fails(&self) {
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

    /// One drain pass, in this process. It is the same `drain::run` the
    /// binary calls; the process boundary is only under test where a test asks
    /// for `drain_binary`.
    pub fn drain(&self) -> Output {
        match self.drain_in_process() {
            Ok(()) => drain_output(0, ""),
            Err(e) => drain_output(1, &format!("kyriakon-control-drain: {e}")),
        }
    }

    /// The installed binary, for the tests whose subject is the process itself:
    /// its printed alerts, its exit status and its pass lock.
    pub fn drain_binary(&self) -> Output {
        std::process::Command::new(drain_binary())
            .arg("--config")
            .arg(self.config())
            .output()
            .unwrap()
    }

    fn drain_in_process(&self) -> Result<(), kyriakon_control_drain::transitions::Error> {
        let cfg = DrainConfig::load(Path::new(&self.config()))?;
        let store = Store::new_for_test(&cfg.store_root);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| kyriakon_control_core::Error::context("cannot build the runtime", e))?;
        runtime.block_on(kyriakon_control_drain::run(&cfg, &store))
    }

    pub fn ctl(&self, args: &[&str]) -> Output {
        std::process::Command::new(ctl_binary())
            .arg("--config")
            .arg(self.config())
            .args(args)
            .output()
            .unwrap()
    }

    /// Write one root-side login proof, as `kyriakon-authcheck` does: a token
    /// as 64 hex characters, the account and an expiry. Returns the token.
    pub fn mint_proof(&self, username: &str, expires: i64) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let token = format!(
            "{:016x}{:048x}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        std::fs::write(
            self.dir.join("proofs").join(&token),
            serde_json::to_vec(&json!({"username": username, "expires": expires})).unwrap(),
        )
        .unwrap();
        token
    }

    /// Open a page session for a fixture account and return the cookie value.
    pub fn open_session(&self, username: &str) -> String {
        let cfg = DrainConfig::load(Path::new(&self.config())).unwrap();
        let store = Store::new_for_test(&cfg.store_root);
        let now = OffsetDateTime::now_utc();
        let proof = self.mint_proof(username, now.unix_timestamp() + 3600);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(kyriakon_control_core::account::session::open(
                &store, username, &proof, now,
            ))
            .unwrap()
    }

    /// The session id inside a cookie value, which is what a close intent carries.
    pub fn session_id(cookie: &str) -> &str {
        cookie.split_once('.').map(|(id, _)| id).unwrap_or("")
    }

    /// File the page's close intent through the handler's own writer, using a
    /// live session it opens, so a test exercises the production shape.
    pub fn file_close(&self, username: &str) -> String {
        let cookie = self.open_session(username);
        self.file_close_with_session(username, Self::session_id(&cookie))
    }

    /// File a close intent carrying a session id the caller chose, for the
    /// refusal paths.
    pub fn file_close_with_session(&self, username: &str, session_id: &str) -> String {
        let cfg = DrainConfig::load(Path::new(&self.config())).unwrap();
        let store = Store::new_for_test(&cfg.store_root);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(
                kyriakon_control_core::intent::Intent::Close(
                    kyriakon_control_core::intent::CloseIntent {
                        username: username.to_string(),
                        session: session_id.to_string(),
                        ..Default::default()
                    },
                )
                .file(&store),
            )
            .unwrap()
    }

    /// Move the root-written proof behind a session into the past, as twelve
    /// hours passing would. The session record's own expiry is the handler's
    /// copy and proves nothing to the drain.
    pub fn expire_session(&self, cookie: &str) {
        let id = Self::session_id(cookie);
        let path = self.dir.join("store/sessions").join(format!("{id}.json"));
        let record: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let proof = record["proof"].as_str().unwrap_or("");
        let username = record["username"].as_str().unwrap_or("");
        assert!(!proof.is_empty(), "the fixture session carries no proof");
        std::fs::write(
            self.dir.join("proofs").join(proof),
            serde_json::to_vec(&json!({"username": username, "expires": 0})).unwrap(),
        )
        .unwrap();
    }

    pub fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.dir.join("store").join(rel)).unwrap_or_default()
    }

    /// The names in one store directory, sorted.
    pub fn names(&self, rel: &str) -> Vec<String> {
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

    pub fn sent(&self) -> String {
        std::fs::read_to_string(self.dir.join("sent")).unwrap_or_default()
    }

    /// A draft on disk, as the capsule leaves it before a key page.
    pub fn write_draft(&self, token: &str, answers: &[(&str, &str)]) {
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
    pub fn mail(&self, name: &str, from: &str, subject: &str, body: &str) {
        std::fs::write(
            self.dir.join("store/mail/new").join(name),
            format!("From: {from}\nSubject: {subject}\n\n{body}\n"),
        )
        .unwrap();
    }

    pub fn scripts_log(&self) -> String {
        std::fs::read_to_string(self.dir.join("scripts.log")).unwrap_or_default()
    }

    pub fn journal(&self) -> String {
        self.read("journal.jsonl")
    }

    /// Move every failed attempt in the journal into the past, so a test can
    /// reach the retry a backoff is holding back without waiting out the minute.
    pub fn age_failures(&self) {
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

    pub fn account(&self, username: &str) -> Value {
        serde_json::from_str(&self.read(&format!("accounts/{username}/account.json"))).unwrap()
    }

    /// Every file under the store, by relative path, for an equality check
    /// across two runs.
    pub fn snapshot(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        walk(&self.dir.join("store"), &self.dir.join("store"), &mut out);
        out
    }

    pub fn intents(&self) -> Vec<String> {
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

pub fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
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

pub fn ulid() -> String {
    ulid::Ulid::new().to_string()
}

/// The signed action each decision kind carries: the free outcome is the
/// `provision` kind and the `approve-free` action.
pub fn action_for(kind: &str) -> &'static str {
    match kind {
        "approve" => "approve",
        "provision" => "approve-free",
        "decline" => "decline",
        other => panic!("no action for kind {other}"),
    }
}

/// The shape `Command::output` returns, for an in-process pass: a status and
/// whatever the binary would have written to stderr.
fn drain_output(code: i32, stderr: &str) -> Output {
    Output {
        status: std::process::ExitStatus::from_raw(code),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

pub fn body(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The account record as the service reads it.
pub fn stored_account(fix: &Fix, username: &str) -> store::Account {
    serde_json::from_str(&fix.read(&format!("accounts/{username}/account.json"))).unwrap()
}

/// A paid account approved through the real drain, and the token it holds.
pub fn approved_paid(fix: &Fix, username: &str, rail: &str) -> String {
    let record = fix.filed(username, rail, &[("rail", rail)]);
    fix.file_application(&record);
    assert!(fix.drain().status.success());
    fix.decide("approve", username);
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    fix.account(username)["payment"]["token_ref"]
        .as_str()
        .expect("a paid approval writes a token")
        .to_string()
}

/// The ledger's parsed lines.
pub fn ledger_lines(fix: &Fix) -> Vec<Value> {
    fix.read("ledger/payments.jsonl")
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// Only the credit lines, which is what a payment appends; the approval's own
/// line has kind `window_open`.
pub fn payment_lines(fix: &Fix) -> Vec<Value> {
    ledger_lines(fix)
        .into_iter()
        .filter(|line| line["kind"] == json!("payment"))
        .collect()
}

/// The unattributed queue's parsed lines.
pub fn held_lines(fix: &Fix) -> Vec<Value> {
    fix.read("ledger/unattributed.jsonl")
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// Only the refund lines, the negative record a refund appends.
pub fn refund_lines(fix: &Fix) -> Vec<Value> {
    ledger_lines(fix)
        .into_iter()
        .filter(|line| line["kind"] == json!("refund"))
        .collect()
}

/// Put an existing paid-until date on an account, as an earlier year's credit
/// would have left it.
pub fn set_paid_until(fix: &Fix, username: &str, paid: &str) {
    let mut account = fix.account(username);
    account["payment"]["paid_until"] = json!(paid);
    std::fs::write(
        fix.dir
            .join(format!("store/accounts/{username}/account.json")),
        serde_json::to_vec_pretty(&account).unwrap(),
    )
    .unwrap();
}

/// Whether a page puts the token in a link, which is the only way a page can put
/// it in a URL for relayd to log. The status page's own address is the status
/// token's and never the payment token's.
pub fn token_is_a_link(page: &str, token: &str) -> bool {
    page.lines().any(|line| {
        (line.contains("href=") || line.trim_start().starts_with("=> ")) && line.contains(token)
    })
}

/// The export's keyed header, in the order the accountant's sheet takes.
pub const EXPORT_HEADER: &str = "seq,token,kind,rail,received_on,amount_gbp,applied_gbp,\
paid_until_after,amount_xmr,txid,refund_of,settled_on,rate_quoted,rate_source,rate_at";

/// An add-user.sh that logs whether the confirmation had already reached the
/// enqueuer when the first provisioning script ran. `sent` is the enqueuer's
/// own output file, so this is the order the envelope saw, not a guess.
pub fn add_user_asks_whether_the_confirmation_left(fix: &Fix) {
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

// --- refunds ---------------------------------------------------------------

/// One cash credit on a paid account, applied, returning its ledger line.
pub fn cash_credit(fix: &Fix, token: &str) -> Value {
    let out = fix.ctl(&[
        "credit",
        "--token",
        token,
        "--rail",
        "cash",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    payment_lines(fix).remove(0)
}

/// One Monero credit on a paid account, applied, returning its ledger line.
pub fn monero_credit(fix: &Fix, token: &str) -> Value {
    let out = fix.ctl(&[
        "credit",
        "--token",
        token,
        "--rail",
        "monero",
        "--amount",
        "20.00",
        "--received",
        "2026-10-04",
        "--txid",
        TXID,
        "--xmr",
        "0.048847",
    ]);
    assert!(out.status.success(), "{}", body(&out));
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    payment_lines(fix).remove(0)
}

// --- the card rail's webhooks ------------------------------------------------

/// One invoice event's object, naming the fixture subscription. The amount is
/// in pence and the paid timestamp is 2026-09-21, so a ledger line that used
/// the configured price or the drain's clock would not match.
pub fn invoice(id: &str) -> Value {
    invoice_with(id, 2000, 1_790_000_000)
}

pub fn invoice_with(id: &str, amount_paid: i64, paid_at: i64) -> Value {
    json!({
        "id": id,
        "subscription": SUBSCRIPTION,
        "customer": "cus_example",
        "attempt_count": 1,
        "amount_paid": amount_paid,
        "status_transitions": {"paid_at": paid_at},
        "created": paid_at,
    })
}

/// The date a paid card account holds, as the account record has it.
pub fn paid_until(fix: &Fix, username: &str) -> Option<String> {
    fix.account(username)["payment"]["paid_until"]
        .as_str()
        .map(str::to_string)
}
