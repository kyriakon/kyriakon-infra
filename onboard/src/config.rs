//! The handler's own configuration, read once at startup from the TOML the unit
//! names. It holds no secret: the store root, the two shared files, the loopback
//! address and the release the acceptances record.

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The store root. The handler reads the two shared files below it and the
    /// application records it renders, and writes `intents/` and
    /// `applications/`. `drafts/` and `webhooks/` are the capsule's draft store
    /// and the payment webhooks, neither of which has a writer yet; both are
    /// later tickets.
    pub store_root: String,
    /// The shared question list, 0644 at the top of the store.
    pub questions: String,
    /// The shared reserved-names file, 0644 at the top of the store.
    pub reserved: String,
    /// Loopback only, with relayd in front: the handler must never listen on a
    /// public interface.
    pub listen: String,
    pub port: u16,
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
    /// Stripe's signing secret and the keyring publish token. This build reads
    /// neither, because the card rail and the keyring pull request are later
    /// tickets, but the config names them now so their paths are fixed in one
    /// place rather than invented per ticket.
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
             questions = \"/var/db/onboard/questions.toml\"\n\
             reserved = \"/var/db/onboard/reserved-usernames.txt\"\n\
             listen = \"127.0.0.1\"\n\
             port = 7080\n\
             release = \"REPLACE_ME\"\n",
        )
        .unwrap();
        assert_eq!(c.port, 7080);
        assert_eq!(c.listen, "127.0.0.1");
    }

    #[test]
    fn a_typo_is_refused_rather_than_ignored() {
        let r: Result<Config, _> = toml::from_str("store_rooot = \"/x\"\nlisten=\"127.0.0.1\"\nport=1\nrelease=\"r\"\nquestions=\"q\"\nreserved=\"r\"\n");
        assert!(r.is_err());
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
