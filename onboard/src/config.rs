//! The handler's own configuration, read once at startup from the TOML the unit
//! names. It holds no secret: the store root, the two files the front-ends share,
//! the two sockets this responder answers on and the release the acceptances
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
    /// The service's own base URL, which the signed links point at.
    pub base_url: String,
    /// The yearly price, as the ledger records it. A configuration value because
    /// the Stripe Price and the prepaid price have to agree.
    pub price_gbp: String,
    /// The postal address a cash-by-post member is given. `REPLACE_ME` in the
    /// repository, because it is the operator's own address. `prepaid-rails.md`
    /// leaves it to the deployment.
    pub postal_address: String,
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
             httpd_socket = \"/home/www/run/onboard-httpd/httpd.sock\"\n\
             gemini_socket = \"/home/www/run/onboard/onboard.sock\"\n\
             release = \"REPLACE_ME\"\n",
        )
        .unwrap();
        assert_eq!(c.httpd_socket, "/home/www/run/onboard-httpd/httpd.sock");
        assert_eq!(c.gemini_socket, "/home/www/run/onboard/onboard.sock");
    }

    #[test]
    fn a_typo_is_refused_rather_than_ignored() {
        let r: Result<Config, _> = toml::from_str(
            "store_rooot = \"/x\"\n\
             reserved=\"r\"\ncatalogue=\"c\"\n\
             httpd_socket=\"/a\"\ngemini_socket=\"/b\"\nrelease=\"r\"\n",
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
                 httpd_socket = \"/a\"\n\
                 gemini_socket = \"/b\"\n\
                 release = \"r\"\n{extra}"
            );
            let r: Result<Config, _> = toml::from_str(&text);
            assert!(r.is_err(), "{extra:?} should be refused");
        }
    }

    #[test]
    fn the_drain_config_reads_the_shipped_shape_and_refuses_a_typo() {
        let text = "store_root = \"/var/db/onboard\"\n\
             scripts = \"/root/bin\"\n\
             sendmail = \"/usr/sbin/sendmail\"\n\
             passwd = \"/etc/passwd\"\n\
             approval_key = \"/etc/kyriakon/onboard/approval-signing-key\"\n\
             keyring_dir = \"/etc/kyriakon/keys\"\n\
             stripe_webhook_secret = \"/etc/kyriakon/onboard/stripe-webhook-secret\"\n\
             keyring_publish_token = \"/etc/kyriakon/onboard/keyring-publish-token\"\n\
             reviewer = \"admin@kyriakon.net\"\n\
             base_url = \"https://signup.kyriakon.net\"\n\
             price_gbp = \"20.00\"\n\
             postal_address = \"REPLACE_ME\"\n\
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
        assert_eq!(c.scripts, "/usr/local/libexec/kyriakon/scripts");
        assert_eq!(c.sendmail, "/usr/sbin/sendmail");
        assert_eq!(c.passwd, "/etc/passwd");
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
