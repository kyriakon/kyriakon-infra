//! The handler's own configuration, read once at startup from the TOML the unit
//! names. It holds no secret: the store root, the files the front-ends share, the
//! three sockets this responder answers on and the release the acceptances
//! record.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// A configuration file that could not be read or parsed. The path is the
/// fact a startup message needs; the source is the parser's own error.
#[derive(Debug)]
pub enum Error {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Read { path, source } => write!(f, "cannot read {}: {source}", path.display()),
            Error::Parse { path, source } => {
                write!(f, "cannot parse {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Read { source, .. } => Some(source),
            Error::Parse { source, .. } => Some(source),
        }
    }
}

/// The fixed hostname for the form and the account page, used as itself. It is
/// public because the terminal front-end hands a reader the same host's status
/// route, so the address a session gives out cannot name a different service than
/// the one that answers it.
pub const HOST: &str = "signup.kyriakon.net";

/// Where the root-side login check writes its proofs: one file per admitted
/// login, named by a random token, holding the username and the expiry. Root
/// owns it 0700, so the unprivileged handler can neither read a proof it did
/// not mint nor write one the drain would trust. `scripts/deploy-control.sh`
/// creates it.
pub const PROOF_DIR: &str = "/var/db/kyriakon/logins";

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
    /// The platform's published mail host, IP addresses and DKIM key, which the
    /// DNS recipe shows a body. The handler holds no secret and these values are
    /// public, but they are still substituted at deploy from the box's own
    /// values and zone rather than restated here, so the recipe cannot name an
    /// address or key the box is not using. `dns::Values::check` refuses a
    /// placeholder.
    pub mail_host: String,
    pub ipv4: String,
    pub ipv6: String,
    pub dkim_selector: String,
    pub dkim_public_key: String,
    pub dmarc_rua: String,
    /// The deployed commit and date, e.g. "2026-10-10 1a2b3c4". The acceptance
    /// records carry it as the version of each document accepted, and it is the
    /// version of the question list an application was answered against. It is
    /// the deployed release, not a hash of anything: see the answer record's
    /// comment.
    pub release: String,
    /// The yearly price and the postal address a cash-by-post member is given,
    /// which the account page shows beside the token. The drain's config names
    /// the same two values, and both are substituted at deploy from the box's
    /// own environment: the price because the Stripe Price and the prepaid price
    /// have to agree, the address because it is the operator's own and this
    /// repository is public.
    pub price_gbp: String,
    pub postal_address: String,
    /// The card rail's Payment Link. It is public (a member is sent it), so the
    /// handler may hold it to render the same link the approval email carries.
    /// `REPLACE_ME` in the repository and substituted at deploy with the rest.
    pub stripe_payment_link: String,
    /// Where the login check writes one proof per admitted login, and the drain
    /// reads it back. Root-owned 0700, created by `scripts/deploy-control.sh`;
    /// the handler may pass the path to the checker but cannot write there
    /// itself. A value so a test points it at a temporary directory.
    #[serde(default = "proof_dir")]
    pub proof_dir: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, Error> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| Error::Parse {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// The directory the root-side login check writes its proofs in, and the drain
/// reads them from. Named once, so the handler and the drain cannot be pointed
/// at different ones by a default that drifts.
fn proof_dir() -> String {
    PROOF_DIR.to_string()
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
    /// webhook pass reads the signing secret from the first file and the
    /// restricted API key from the next, both root-only.
    pub stripe_webhook_secret: String,
    /// The root-only restricted Stripe key the drain reads to retrieve one
    /// subscription. The webhook path makes no Stripe writes, and the key is
    /// passed to `scripts/stripe-api.sh` by path rather than read here.
    pub stripe_api_key: String,
    /// The Payment Link the card decision email carries, with
    /// `client_reference_id` appended per application. A configuration value,
    /// not a literal: the live link and a sandbox link differ, and the file is
    /// deployed from the box's own environment.
    pub stripe_payment_link: String,
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
    /// The yearly price of an own-domain group. It is per domain rather than per
    /// address, and it is not a person's price with a multiple applied: the spec
    /// sells the tier at its own figure.
    pub group_price_gbp: String,
    /// The postal address a cash-by-post member is given. `REPLACE_ME` in the
    /// repository, because it is the operator's own address. `prepaid-rails.md`
    /// leaves it to the deployment.
    pub postal_address: String,
    /// The `mail/new` directory `smtpd` delivers `apply@kyriakon.net` to. It is
    /// a plaintext Maildir, deliberately outside the encrypting LMTP path: the
    /// drain reads the key to file it. `scripts/control-store.sh` owns the
    /// directory and its `_onboard` ownership.
    pub mail_dir: String,
    /// The deployed commit and date, e.g. "2026-10-10 1a2b3c4". The drain records
    /// it on a journal line so a transition can be traced to the release that
    /// carried it out, and it is the confirmation email's document version.
    pub release: String,
    /// The platform's published mail host, IP addresses and DKIM key, which the
    /// DNS recipe shows a body, and the DMARC reporting address. Substituted at
    /// deploy from the box's values and its tracked zone: the IPs and the DKIM
    /// key are placeholders here so the repository holds no second copy that can
    /// drift from what the box publishes.
    pub mail_host: String,
    pub ipv4: String,
    pub ipv6: String,
    pub dkim_selector: String,
    pub dkim_public_key: String,
    pub dmarc_rua: String,
    /// The resolver the broken-DNS sweep runs: `dig`, by path, with its
    /// `+short` and timeout options. A value
    /// so the acceptance test can point it at a stub and never touch the
    /// network.
    pub resolver: String,
    /// The quota report the space-used sweep runs: `/usr/sbin/repquota` on the
    /// box, by path so the test can point it at a fixture. Reads the per-uid
    /// block counts the platform's 5 GB allowance is written against; the
    /// handler cannot, because repquota needs root.
    pub repquota: String,
    /// The filesystem carrying member homes, `/home`. `repquota -u` takes it as
    /// its argument; a value rather than a literal so a fixture controls it.
    pub quota_mount: String,
    /// The cached XMR/GBP rate, `rates/xmr-gbp.json` under the store. The drain
    /// writes it at most once every twenty-four hours and reads it at a window's
    /// opening; the handler renders the quote the drain recorded and never asks
    /// the source anything. A path rather than a literal so a test can point it
    /// at a fixture.
    pub rates: String,
    /// The rate source's endpoint, CoinGecko's public price endpoint. Named here
    /// rather than compiled in because it is the one address this box fetches
    /// from, and an operator changing or retiring it must not need a rebuild.
    pub rate_endpoint: String,
    /// The HTTPS client used for the one rate fetch: `curl`, by path. A value so
    /// a test stubs it and never touches the network, and because cron's PATH is
    /// not where a package's binary lives.
    pub rates_fetch: String,
    /// Where the login check writes one proof per admitted login, and the drain
    /// reads it back. Root-owned 0700, created by `scripts/deploy-control.sh`:
    /// the handler writes session records in the store, so the proof has to be
    /// in a directory the handler cannot write. A value so the tests point it at
    /// a temporary directory, and absent from a config written before it, which
    /// reads the deployed path.
    #[serde(default = "proof_dir")]
    pub proof_dir: String,
    /// The OpenPGP implementation the export encrypts a written part to a
    /// member's key with: `gpg`, by path. The same binary `kyriakon-encrypt`
    /// runs, named here because cron's PATH is not where a package's binary
    /// lives and a test needs to point at it rather than inherit one.
    pub gpg: String,
    /// Where the members' public trees live: `/home/www` on the box, where
    /// `scripts/provision-member.sh` builds `<username>.kyriakon.net`. The
    /// export writes its bundle under that chroot, so the destination is a
    /// value a test can point at a fixture tree. Absent from a config written
    /// before the export existed, which reads the deployed path.
    #[serde(default = "public_root")]
    pub public_root: String,
}

fn public_root() -> String {
    "/home/www".to_string()
}

impl DrainConfig {
    pub fn load(path: &Path) -> Result<DrainConfig, Error> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| Error::Parse {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, DrainConfig, Error};

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
             mail_host = \"mail.kyriakon.net\"\n\
             ipv4 = \"192.0.2.10\"\n\
             ipv6 = \"2001:db8::10\"\n\
             dkim_selector = \"mail\"\n\
             dkim_public_key = \"v=DKIM1; k=rsa; p=example\"\n\
             dmarc_rua = \"mailto:dmarc@kyriakon.net\"\n\
             release = \"REPLACE_ME\"\n\
             price_gbp = \"20.00\"\n\
             postal_address = \"REPLACE_ME\"\n\
             stripe_payment_link = \"REPLACE_ME\"\n",
        )
        .unwrap();
        assert_eq!(c.pages, "/var/db/onboard/pages");
        assert_eq!(c.price_gbp, "20.00");
        assert_eq!(c.postal_address, "REPLACE_ME");
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
            toml::from_str(include_str!("../../../../openbsd/etc/onboard/onboard.toml"))
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
             stripe_api_key = \"/etc/kyriakon/onboard/stripe-api-key\"\n\
             stripe_payment_link = \"REPLACE_ME\"\n\
             keyring_publish_token = \"/etc/kyriakon/onboard/keyring-publish-token\"\n\
             reviewer = \"admin@kyriakon.net\"\n\
             from = \"kyriakon <hello@kyriakon.net>\"\n\
             base_url = \"https://signup.kyriakon.net\"\n\
             price_gbp = \"20.00\"\n\
             group_price_gbp = \"40.00\"\n\
             postal_address = \"REPLACE_ME\"\n\
             mail_dir = \"/var/db/onboard/mail/new\"\n\
             release = \"REPLACE_ME\"\n\
             mail_host = \"mail.kyriakon.net\"\n\
             ipv4 = \"192.0.2.10\"\n\
             ipv6 = \"2001:db8::10\"\n\
             dkim_selector = \"mail\"\n\
             dkim_public_key = \"v=DKIM1; k=rsa; p=example\"\n\
             dmarc_rua = \"mailto:dmarc@kyriakon.net\"\n\
             resolver = \"/usr/bin/dig\"\n\
             repquota = \"/usr/sbin/repquota\"\n\
             quota_mount = \"/home\"\n\
             rates = \"/var/db/onboard/rates/xmr-gbp.json\"\n\
             rate_endpoint = \"https://api.coingecko.com/api/v3/simple/price?ids=monero&vs_currencies=gbp&include_last_updated_at=true\"\n\
             rates_fetch = \"/usr/local/bin/curl\"\n\
             gpg = \"/usr/local/bin/gpg\"\n";
        let c: DrainConfig = toml::from_str(text).unwrap();
        assert_eq!(c.price_gbp, "20.00");
        assert_eq!(c.group_price_gbp, "40.00");
        assert_eq!(c.scripts, "/root/bin");
        let bad: Result<DrainConfig, _> = toml::from_str(&text.replace("sendmail", "sendmaill"));
        assert!(bad.is_err());
    }

    /// The tracked file, read at compile time, so a template that drifts from
    /// the struct fails the build rather than the first cron minute.
    #[test]
    fn the_shipped_drain_config_parses() {
        let c: DrainConfig =
            toml::from_str(include_str!("../../../../openbsd/etc/onboard/drain.toml")).unwrap();
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
        assert_eq!(c.group_price_gbp, "40.00");
        // The two the deploy leaves for the operator to fill.
        assert_eq!(c.release, "REPLACE_ME");
        assert_eq!(c.postal_address, "REPLACE_ME");
        // The three the deploy substitutes from the box's values and zone. The
        // recipe refuses them until it has, so a shipped file that gained a real
        // address here would be a second copy that can drift.
        assert_eq!(c.ipv4, "REPLACE_ME_IPV4");
        assert_eq!(c.ipv6, "REPLACE_ME_IPV6");
        assert_eq!(c.dkim_selector, "REPLACE_ME");
        assert_eq!(c.dkim_public_key, "REPLACE_ME");
        assert_eq!(c.resolver, "/usr/bin/dig");
        assert!(crate::account::dns::Values::from(&c).check().is_err());
    }

    /// The handler's tracked config is substituted by the same deploy, and the
    /// recipe refuses its placeholders too.
    #[test]
    fn the_tracked_handler_config_names_its_placeholders() {
        let c: Config =
            toml::from_str(include_str!("../../../../openbsd/etc/onboard/onboard.toml")).unwrap();
        assert_eq!(c.ipv4, "REPLACE_ME_IPV4");
        assert_eq!(c.ipv6, "REPLACE_ME_IPV6");
        assert_eq!(c.dkim_selector, "REPLACE_ME");
        assert_eq!(c.dkim_public_key, "REPLACE_ME");
        assert_eq!(c.stripe_payment_link, "REPLACE_ME");
        assert!(crate::account::dns::Values::from(&c).check().is_err());
    }

    /// A config that is not there and one that does not parse are the two
    /// failures the loaders can report, and both keep their source.
    #[test]
    fn a_missing_config_is_a_read_error() {
        let path =
            std::env::temp_dir().join(format!("onboard-config-missing-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let handler = Config::load(&path).expect_err("a missing handler config is an error");
        assert!(matches!(&handler, Error::Read { path: p, .. } if p == &path));
        assert!(std::error::Error::source(&handler).is_some());

        let drain = DrainConfig::load(&path).expect_err("a missing drain config is an error");
        assert!(matches!(&drain, Error::Read { path: p, .. } if p == &path));
        assert!(std::error::Error::source(&drain).is_some());
    }

    #[test]
    fn an_unparsable_config_is_a_parse_error() {
        let path =
            std::env::temp_dir().join(format!("onboard-config-parse-{}", std::process::id()));
        std::fs::write(&path, "this is not toml = [").unwrap();

        let handler = Config::load(&path).expect_err("an unparsable handler config is an error");
        assert!(matches!(&handler, Error::Parse { path: p, .. } if p == &path));
        assert!(std::error::Error::source(&handler).is_some());

        let drain = DrainConfig::load(&path).expect_err("an unparsable drain config is an error");
        assert!(matches!(&drain, Error::Parse { path: p, .. } if p == &path));
        assert!(std::error::Error::source(&drain).is_some());
        let _ = std::fs::remove_file(&path);
    }
}
