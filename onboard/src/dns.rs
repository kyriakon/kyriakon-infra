//! The DNS recipe a body applies to its own zone.
//!
//! The platform does not host a body's zone, so the records are published by the
//! body and this module is one description of them. The approval email, the web
//! account page and the capsule all render this one [`Recipe`], which is what
//! keeps the three from disagreeing about a value only the body can publish.

use crate::config::{Config, DrainConfig};

/// One row of the recipe: what the record is for, the name it is published at,
/// its type and its value.
pub struct Row {
    pub what: &'static str,
    pub name: String,
    pub record_type: &'static str,
    pub value: String,
}

/// The recipe for one body's domain. The opening says what the platform will and
/// will not do; the rows are the records the body publishes; the closing repeats
/// the three things the platform cannot do, plainly.
pub struct Recipe {
    pub opening: String,
    pub rows: Vec<Row>,
    pub closing: Vec<String>,
}

/// The platform-owned values every body's recipe is generated from. Read from
/// the deploy's substitution of IPs and the tracked zone's DKIM key, never from
/// a literal in this crate: a hardcoded address or key is one that can drift
/// from the box without anything failing.
pub struct Values {
    pub mail_host: String,
    pub ipv4: String,
    pub ipv6: String,
    pub dkim_selector: String,
    pub dkim_public_key: String,
    pub dmarc_rua: String,
}

impl From<&Config> for Values {
    fn from(cfg: &Config) -> Values {
        Values {
            mail_host: cfg.mail_host.clone(),
            ipv4: cfg.ipv4.clone(),
            ipv6: cfg.ipv6.clone(),
            dkim_selector: cfg.dkim_selector.clone(),
            dkim_public_key: cfg.dkim_public_key.clone(),
            dmarc_rua: cfg.dmarc_rua.clone(),
        }
    }
}

impl From<&DrainConfig> for Values {
    fn from(cfg: &DrainConfig) -> Values {
        Values {
            mail_host: cfg.mail_host.clone(),
            ipv4: cfg.ipv4.clone(),
            ipv6: cfg.ipv6.clone(),
            dkim_selector: cfg.dkim_selector.clone(),
            dkim_public_key: cfg.dkim_public_key.clone(),
            dmarc_rua: cfg.dmarc_rua.clone(),
        }
    }
}

impl Values {
    /// Refuse a value the deploy should have substituted. The tracked configs
    /// carry `REPLACE_ME` placeholders, so a box that was never substituted is
    /// announced rather than sent a recipe naming an address that answers
    /// nothing.
    pub fn check(&self) -> Result<(), String> {
        for (name, value) in [
            ("mail_host", &self.mail_host),
            ("ipv4", &self.ipv4),
            ("ipv6", &self.ipv6),
            ("dkim_selector", &self.dkim_selector),
            ("dkim_public_key", &self.dkim_public_key),
            ("dmarc_rua", &self.dmarc_rua),
        ] {
            if value.trim().is_empty() {
                return Err(format!("the DNS recipe's {name} is empty"));
            }
            if value.contains("REPLACE_ME") {
                return Err(format!(
                    "the DNS recipe's {name} is still the placeholder {value:?}"
                ));
            }
        }
        Ok(())
    }
}

/// The recipe for `domain`, generated from the platform's own published values.
pub fn recipe(domain: &str, values: &Values) -> Recipe {
    Recipe {
        opening: format!(
            "You keep {domain}. The platform never touches its zone: you create \
             these records at your own registrar or DNS provider, and mail and the \
             website start working only once they are live."
        ),
        rows: vec![
            Row {
                what: "Mail arrives",
                name: "@".to_string(),
                record_type: "MX",
                value: format!("10 {}.", values.mail_host),
            },
            Row {
                what: "The website and the certificate reach the box",
                name: "@ and www".to_string(),
                record_type: "A",
                value: values.ipv4.clone(),
            },
            Row {
                what: "The website and the certificate reach the box",
                name: "@ and www".to_string(),
                record_type: "AAAA",
                value: values.ipv6.clone(),
            },
            Row {
                what: "Outbound mail is authorised",
                name: "@".to_string(),
                record_type: "TXT",
                // `mx` covers only the mail host's A record: it deliberately
                // has no AAAA, so a message the box sends over IPv6 matches
                // nothing unless the literal is here. The platform's own zone
                // carries the same pair for the same reason.
                value: format!("v=spf1 mx ip6:{} -all", values.ipv6),
            },
            Row {
                what: "Outbound mail is signed",
                name: format!("{}._domainkey", values.dkim_selector),
                record_type: "TXT",
                value: values.dkim_public_key.clone(),
            },
            Row {
                what: "Mail that fails is reported",
                name: "_dmarc".to_string(),
                record_type: "TXT",
                value: format!("v=DMARC1; p=none; rua={}", values.dmarc_rua),
            },
        ],
        closing: vec![
            "The platform does not host your zone.".to_string(),
            format!(
                "It cannot set a reverse DNS record for {domain}: the MX names the \
                 platform's mail host, whose reverse record is fixed at the hosting \
                 provider and cannot be varied per body."
            ),
            "It can only observe your records. If they stop resolving, mail to you \
             stops arriving and the certificate cannot renew; the platform will \
             write to the contact you gave, and nothing else."
                .to_string(),
        ],
    }
}

impl Recipe {
    /// The plain-text rendering shared by the approval email and the capsule.
    /// The web page renders the same `rows` as a table, so a value is written
    /// once and the three front-ends cannot disagree.
    pub fn text(&self) -> String {
        let mut out = format!("{}\n\n", self.opening);
        out.push_str("| What it is for | Name | Type | Value |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for row in &self.rows {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                row.what, row.name, row.record_type, row.value
            ));
        }
        out.push('\n');
        for line in &self.closing {
            out.push_str(line);
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use askama::Template;

    fn values() -> Values {
        Values {
            mail_host: "mail.kyriakon.net".into(),
            ipv4: "192.0.2.10".into(),
            ipv6: "2001:db8::10".into(),
            dkim_selector: "mail".into(),
            dkim_public_key: "v=DKIM1; k=rsa; p=examplepublickey".into(),
            dmarc_rua: "mailto:dmarc@kyriakon.net".into(),
        }
    }

    fn row<'a>(recipe: &'a Recipe, record_type: &str, name: &str) -> &'a Row {
        recipe
            .rows
            .iter()
            .find(|r| r.record_type == record_type && r.name == name)
            .unwrap_or_else(|| panic!("no {record_type} row at {name}: {}", recipe.text()))
    }

    #[test]
    fn every_row_is_generated_from_the_body_domain() {
        let built = recipe("parish.example", &values());
        assert!(built.opening.contains("parish.example"), "{}", built.text());
        assert_eq!(row(&built, "MX", "@").value, "10 mail.kyriakon.net.");
        assert_eq!(row(&built, "A", "@ and www").value, "192.0.2.10");
        assert_eq!(row(&built, "AAAA", "@ and www").value, "2001:db8::10");
        assert_eq!(
            row(&built, "TXT", "@").value,
            "v=spf1 mx ip6:2001:db8::10 -all"
        );
        assert_eq!(
            row(&built, "TXT", "mail._domainkey").value,
            "v=DKIM1; k=rsa; p=examplepublickey"
        );
        assert_eq!(
            row(&built, "TXT", "_dmarc").value,
            "v=DMARC1; p=none; rua=mailto:dmarc@kyriakon.net"
        );
        // The DKIM name is the selector's, so a rotation changes one value and
        // not a literal in three front-ends.
        let mut rotated = values();
        rotated.dkim_selector = "mail-2027".into();
        let rotated = recipe("parish.example", &rotated);
        assert!(row(&rotated, "TXT", "mail-2027._domainkey")
            .value
            .contains("p="));
        assert!(
            !rotated.text().contains("mail._domainkey"),
            "{}",
            rotated.text()
        );
    }

    #[test]
    fn the_opening_and_closing_state_what_the_platform_cannot_do() {
        let text = recipe("other.example", &values()).text();
        assert!(text.contains("You keep other.example"), "{text}");
        assert!(text.contains("never touches its zone"), "{text}");
        assert!(
            text.contains("only once they are live"),
            "mail and web wait for the records: {text}"
        );
        assert!(text.contains("does not host your zone"), "{text}");
        assert!(
            text.contains("cannot set a reverse DNS record for other.example"),
            "{text}"
        );
        assert!(text.contains("can only observe your records"), "{text}");
    }

    #[test]
    fn a_placeholder_is_refused_rather_than_published() {
        for field in [
            "mail_host",
            "ipv4",
            "ipv6",
            "dkim_selector",
            "dkim_public_key",
            "dmarc_rua",
        ] {
            let mut bad = values();
            match field {
                "mail_host" => bad.mail_host = "REPLACE_ME".into(),
                "ipv4" => bad.ipv4 = "REPLACE_ME_IPV4".into(),
                "ipv6" => bad.ipv6 = "REPLACE_ME_IPV6".into(),
                "dkim_selector" => bad.dkim_selector = "REPLACE_ME".into(),
                "dkim_public_key" => bad.dkim_public_key = "REPLACE_ME".into(),
                "dmarc_rua" => bad.dmarc_rua = "REPLACE_ME".into(),
                _ => unreachable!(),
            }
            assert!(bad.check().is_err(), "{field} was accepted");
        }
        assert!(values().check().is_ok());
    }

    #[test]
    fn the_text_carries_every_row_and_no_placeholder() {
        let recipe = recipe("parish.example", &values());
        let text = recipe.text();
        for row in &recipe.rows {
            assert!(
                text.contains(&format!(
                    "| {} | {} | {} | {} |",
                    row.what, row.name, row.record_type, row.value
                )),
                "row missing: {text}"
            );
        }
        assert!(!text.contains("REPLACE_ME"), "{text}");
    }

    /// The two account pages and the approval email are one recipe: the web page
    /// renders the rows as a table and the capsule renders `text()`, and both
    /// carry every value the approval email carries.
    #[test]
    fn the_web_page_and_the_capsule_carry_the_same_table() {
        let web_recipe = recipe("parish.example", &values());
        let web =
            crate::page::account(&[], Some("parish-secretary"), Some(web_recipe), None, false)
                .render()
                .unwrap();
        let capsule_recipe = recipe("parish.example", &values());
        let account: crate::store::Account = serde_json::from_value(serde_json::json!({
            "version": 1,
            "username": "parish-secretary",
            "state": "active",
            "decision": "approve",
            "decided_at": "2026-10-01T09:00:00Z",
            "rail": "cash",
            "no_charge": false,
            "created_at": "2026-10-01T09:00:00Z",
            "paid_until": null,
            "group": "parish.example"
        }))
        .unwrap();
        let capsule = crate::capsule::account(&account, &[], Some(&capsule_recipe), None);
        let email = capsule_recipe.text();
        for row in &capsule_recipe.rows {
            assert!(web.contains(&row.value), "web misses {}: {web}", row.value);
            assert!(
                capsule.contains(&row.value),
                "capsule misses {}: {capsule}",
                row.value
            );
            assert!(
                email.contains(&row.value),
                "email misses {}: {email}",
                row.value
            );
            assert!(
                web.contains(row.name.as_str()),
                "web misses the name: {web}"
            );
        }
    }
}
