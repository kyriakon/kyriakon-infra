//! The handler's own configuration, read once at startup from the TOML the unit
//! names. It holds no secret: the store root, the files the front-ends share, the
//! three sockets this responder answers on and the release the acceptances
//! record.

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The store root. The handler reads the shared files below it and the
    /// application records it renders, and writes `intents/` and
    /// `applications/`. `drafts/` and `webhooks/` are the capsule's draft store
    /// and the payment webhooks, neither of which has a writer yet; both are
    /// later tickets.
    pub store_root: String,
    /// The shared reserved-names file, 0644 at the top of the store.
    pub reserved: String,
    /// The shared service catalogue, 0644 at the top of the store. Named here
    /// because a later layout moves the file rather than the handler reading an
    /// empty one and rendering no services. The question list has no key here:
    /// the crate carries it, so the store holds no copy to move.
    pub catalogue: String,
    /// The directory of mirrored capsule pages, 0644 at the top of the store:
    /// the terms, the acceptable use policy, the privacy notice and the key
    /// walkthrough, rendered to gemtext by `scripts/render-docs.sh --gemini` and
    /// staged by the deploy. Named here for the catalogue's reason: a later
    /// layout moves the directory rather than the handler serving 51 for every
    /// page and looking like a route that was never added.
    pub pages: String,
    /// The unix socket httpd's signup vhost reaches this responder on. Both
    /// front-ends resolve a FastCGI socket path inside their own chroot, which is
    /// the same directory for the two of them, so the path here is the one on
    /// disk and the two configs name it relative to that chroot.
    ///
    /// One socket each rather than one shared: the connecting daemon is `www` for
    /// httpd and `_gmid` for gmid, and a socket file may carry one group, so a
    /// socket both may open would have to be one any local user may open. A local
    /// user who can connect can forge the whole environment, `REMOTE_ADDR`
    /// included, which is the key the limits and the audit rest on.
    pub httpd_socket: String,
    /// The unix socket gmid's signup block reaches it on. See `httpd_socket`.
    pub gemini_socket: String,
    /// The unix socket the ssh portal reaches it on. The portal runs as `hello`,
    /// not chrooted, and asks one thing here: the stage of a filed application.
    /// Its directory is set-group-id to that account's group for the same reason
    /// the other two carry their daemon's group.
    pub portal_socket: String,
    /// The TCP address the Titan upload listener binds. It is loopback-only and
    /// relayd is the only thing off the box that can reach it: the relay
    /// terminates TLS with the capsule's certificate and forwards with PROXY
    /// protocol v1, which is how this listener still sees the client's address.
    /// The address is the forward target in the commented relayd block.
    pub titan_listener: String,
    /// The deployed commit and date, e.g. "2026-10-10 1a2b3c4". The acceptance
    /// records carry it as the version of each document accepted, and it is the
    /// version of the question list an application was answered against. It is
    /// the deployed release, not a hash of anything: see the answer record's
    /// comment.
    pub release: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("cannot parse {}: {e}", path.display()))
    }
}

/// The drain's own configuration, read once per run from
/// `/etc/kyriakon/onboard/drain.toml`. Root-only, unlike the handler's, because
/// it names the secret files and the scripts the drain runs as root.
///
/// Every value a test must redirect is here: the store root, the script
/// directory, the enqueuer and the secret files. That is what lets the
/// acceptance tests run with no root and no live store, pointing the whole
/// service at fixtures under a temporary directory, the way
/// `scripts/provision-member-capsule.sh --self-test` rebinds its own paths.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainConfig {
    /// The store root the drain owns: everything but the four directories the
    /// handler writes.
    pub store_root: String,
    /// The names the platform holds back, 0644 at the top of the store. The
    /// handler refuses them when an application is filed and this half checks
    /// the same file, because it is the half that creates the account as root.
    pub reserved: String,
    /// The directory the privileged scripts are installed in. `/root/bin` on the
    /// box, where `scripts/deploy-mail.sh` puts them; a fixtures directory in a
    /// test, which is why it is a value and not a literal.
    pub scripts: String,
    /// The local enqueuer, `/usr/sbin/sendmail`. Every notice leaves through it
    /// and is DKIM-signed by the smtpd that owns it.
    pub sendmail: String,
    /// The box's own account list, `/etc/passwd`. The drain reads it, rather
    /// than running `id(1)`, to decide whether a username is already in use:
    /// an account made any other way, by the operator or by a script run by
    /// hand, has no record under the store, and the drain must neither adopt it
    /// nor release its name. A configuration value so a test can drive it.
    pub passwd: String,
    /// The virtual table's two files, which smtpd reads at start:
    /// `/etc/mail/mail_domains` holds one body domain per line and
    /// `/etc/mail/virtuals` the full-address entries that point at an account.
    /// scripts/deploy-mail.sh seeds both and owns the platform's own lines; the
    /// drain adds a body's on approval. Configuration values for the reason
    /// `passwd` is one.
    pub mail_domains: String,
    pub virtuals: String,
    /// The DKIM filter's domain list, one domain per line. A body's domain is
    /// appended here when its group is provisioned, so the next deploy's splice
    /// of the filter's `-d` arguments signs it; the splice itself is the batched
    /// configuration pass, not this write.
    pub dkim_domains: String,
    /// The root-only HMAC key the review and password links are signed with.
    pub approval_key: String,
    /// The box keyring the encrypting LMTP reads: one `<localpart>.asc` per
    /// account. `scripts/deploy-mail.sh` seeds it from the tracked `keys/`, and
    /// the drain writes an approved member's mail key here before anything can
    /// deliver to the account. A configuration value so a test can drive it.
    pub keyring_dir: String,
    /// Stripe's signing secret and the keyring publish token. The drain reads
    /// the token and hands its path to scripts/publish-mail-key.sh, which is
    /// what opens an approved member's key against the public repository. The
    /// card rail is a later ticket and still reads nothing from its own file,
    /// so the two stay named together in the one root-only home.
    pub stripe_webhook_secret: String,
    pub keyring_publish_token: String,
    /// The one reviewer the whole application is mailed to.
    pub reviewer: String,

    /// The address every notice leaves as, display name included. The local
    /// enqueuer fills a From header from the account that ran it, and the drain
    /// runs as root, so without this a member's approval mail arrived from
    /// "Charlie Root <root@mail.kyriakon.net>". The drain owns these messages, so
    /// this is the one place the sender can be decided.
    pub from: String,
    /// The service's own base URL, which the signed links point at.
    pub base_url: String,
    /// The yearly price, as the ledger records it. A configuration value because
    /// the Stripe Price and the prepaid price have to agree.
    pub price_gbp: String,
    /// The postal address a cash-by-post member is given. `REPLACE_ME` in the
    /// repository, because it is the operator's own address. `prepaid-rails.md`
    /// leaves it to the deployment.
    pub postal_address: String,
    /// The `mail/new` directory `smtpd` delivers `apply@kyriakon.net` to. It is
    /// a plaintext Maildir, deliberately outside the encrypting LMTP path: the
    /// drain reads the key to file it. `scripts/onboard-store.sh` owns the
    /// directory and its `_onboard` ownership.
    pub mail_dir: String,
    /// The deployed commit and date, e.g. "2026-10-10 1a2b3c4". The drain records
    /// it on a journal line so a transition can be traced to the release that
    /// carried it out, and it is the confirmation email's document version.
    pub release: String,
}

impl DrainConfig {
    pub fn load(path: &Path) -> Result<DrainConfig, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("cannot parse {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, DrainConfig};

    #[test]
    fn parses_the_shipped_shape() {
        let c: Config = toml::from_str(
            "store_root = \"/var/db/onboard\"\n\
             reserved = \"/var/db/onboard/reserved-usernames.txt\"\n\
             catalogue = \"/var/db/onboard/catalogue.toml\"\n\
             pages = \"/var/db/onboard/pages\"\n\
             httpd_socket = \"/home/www/run/onboard-httpd/httpd.sock\"\n\
             gemini_socket = \"/home/www/run/onboard/onboard.sock\"\n\
             portal_socket = \"/home/www/run/onboard-portal/portal.sock\"\n\
             titan_listener = \"127.0.0.1:7081\"\n\
             release = \"REPLACE_ME\"\n",
        )
        .unwrap();
        assert_eq!(c.pages, "/var/db/onboard/pages");
        assert_eq!(c.httpd_socket, "/home/www/run/onboard-httpd/httpd.sock");
        assert_eq!(c.gemini_socket, "/home/www/run/onboard/onboard.sock");
        assert_eq!(c.portal_socket, "/home/www/run/onboard-portal/portal.sock");
        assert_eq!(c.titan_listener, "127.0.0.1:7081");
    }

    /// The handler config the deploy installs, not a fixture that can agree with a
    /// broken struct: a required field missing from the tracked file is a handler
    /// that will not start. The drain's own file is checked by
    /// `the_shipped_drain_config_parses`.
    #[test]
    fn the_tracked_handler_config_loads() {
        let handler: Config =
            toml::from_str(include_str!("../../openbsd/etc/onboard/onboard.toml"))
                .expect("the tracked handler config parses");
        assert_eq!(
            handler.portal_socket,
            "/home/www/run/onboard-portal/portal.sock"
        );
        assert_eq!(handler.titan_listener, "127.0.0.1:7081");
        assert_eq!(handler.pages, "/var/db/onboard/pages");
    }

    #[test]
    fn a_typo_is_refused_rather_than_ignored() {
        let r: Result<Config, _> = toml::from_str(
            "store_rooot = \"/x\"\n\
             reserved=\"r\"\ncatalogue=\"c\"\npages=\"p\"\n\
             httpd_socket=\"/a\"\ngemini_socket=\"/b\"\n\
             portal_socket=\"/c\"\ntitan_listener=\"127.0.0.1:7081\"\nrelease=\"r\"\n",
        );
        assert!(r.is_err());
    }

    /// The question list's key and the listener are gone rather than accepted and
    /// ignored: a config that still names a store copy of the questions is a
    /// config for a service that no longer reads one.
    #[test]
    fn the_question_key_and_the_loopback_listener_are_unknown() {
        for extra in [
            "questions = \"/var/db/onboard/questions.toml\"\n",
            "listen = \"127.0.0.1\"\n",
            "port = 7080\n",
        ] {
            let text = format!(
                "store_root = \"/var/db/onboard\"\n\
                 reserved = \"r\"\n\
                 catalogue = \"c\"\n\
                 pages = \"p\"\n\
                 httpd_socket = \"/a\"\n\
                 gemini_socket = \"/b\"\n\
                 portal_socket = \"/c\"\n\
                 titan_listener = \"127.0.0.1:7081\"\n\
                 release = \"r\"\n{extra}"
            );
            let r: Result<Config, _> = toml::from_str(&text);
            assert!(r.is_err(), "{extra:?} should be refused");
        }
    }

    #[test]
    fn the_drain_config_reads_the_shipped_shape_and_refuses_a_typo() {
        let text = "store_root = \"/var/db/onboard\"\n\
             reserved = \"/var/db/onboard/reserved-usernames.txt\"\n\
             scripts = \"/root/bin\"\n\
             sendmail = \"/usr/sbin/sendmail\"\n\
             passwd = \"/etc/passwd\"\n\
             mail_domains = \"/etc/mail/mail_domains\"\n\
             virtuals = \"/etc/mail/virtuals\"\n\
             dkim_domains = \"/etc/mail/dkim_domains\"\n\
             approval_key = \"/etc/kyriakon/onboard/approval-signing-key\"\n\
             keyring_dir = \"/etc/kyriakon/keys\"\n\
             stripe_webhook_secret = \"/etc/kyriakon/onboard/stripe-webhook-secret\"\n\
             keyring_publish_token = \"/etc/kyriakon/onboard/keyring-publish-token\"\n\
             reviewer = \"admin@kyriakon.net\"\n\
             from = \"kyriakon <hello@kyriakon.net>\"\n\
             base_url = \"https://signup.kyriakon.net\"\n\
             price_gbp = \"20.00\"\n\
             postal_address = \"REPLACE_ME\"\n\
             mail_dir = \"/var/db/onboard/mail/new\"\n\
             release = \"REPLACE_ME\"\n";
        let c: DrainConfig = toml::from_str(text).unwrap();
        assert_eq!(c.price_gbp, "20.00");
        assert_eq!(c.scripts, "/root/bin");
        let bad: Result<DrainConfig, _> = toml::from_str(&text.replace("sendmail", "sendmaill"));
        assert!(bad.is_err());
    }

    /// The tracked file, read at compile time, so a template that drifts from
    /// the struct fails the build rather than the first cron minute.
    #[test]
    fn the_shipped_drain_config_parses() {
        let c: DrainConfig =
            toml::from_str(include_str!("../../openbsd/etc/onboard/drain.toml")).unwrap();
        assert_eq!(c.store_root, "/var/db/onboard");
        assert_eq!(c.reserved, "/var/db/onboard/reserved-usernames.txt");
        assert_eq!(c.scripts, "/usr/local/libexec/kyriakon/scripts");
        assert_eq!(c.sendmail, "/usr/sbin/sendmail");
        assert_eq!(c.passwd, "/etc/passwd");
        assert_eq!(c.mail_domains, "/etc/mail/mail_domains");
        assert_eq!(c.virtuals, "/etc/mail/virtuals");
        assert_eq!(c.dkim_domains, "/etc/mail/dkim_domains");
        assert_eq!(c.approval_key, "/etc/kyriakon/onboard/approval-signing-key");
        assert_eq!(c.keyring_dir, "/etc/kyriakon/keys");
        assert_eq!(c.reviewer, "admin@kyriakon.net");
        assert_eq!(c.base_url, "https://signup.kyriakon.net");
        assert_eq!(c.price_gbp, "20.00");
        // The two the deploy leaves for the operator to fill.
        assert_eq!(c.release, "REPLACE_ME");
        assert_eq!(c.postal_address, "REPLACE_ME");
    }
}
