//! The handler's own configuration, read once at startup from the TOML the unit
//! names. It holds no secret: the store root, the two shared files, the loopback
//! address and the release the acceptances record.

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The store root. The handler writes `intents/`, `drafts/`, `applications/`
    /// and `webhooks/` under it and reads the two shared files and the
    /// application records it renders.
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

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn parses_the_shipped_shape() {
        let c: Config = toml::from_str(
            "store_root = \"/var/db/onboard\"\n\
             questions = \"/var/db/onboard/questions.tsv\"\n\
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
}
