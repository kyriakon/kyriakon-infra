//! Shared fixtures for the transition unit tests.

use kyriakon_control_core::config::DrainConfig;

pub(crate) fn quota_config(dir: &std::path::Path) -> DrainConfig {
    DrainConfig {
        store_root: dir.join("store").to_str().unwrap().to_string(),
        reserved: dir.join("reserved").to_str().unwrap().to_string(),
        scripts: dir.join("bin").to_str().unwrap().to_string(),
        sendmail: dir.join("bin/enqueuer.sh").to_str().unwrap().to_string(),
        passwd: dir.join("passwd").to_str().unwrap().to_string(),
        mail_domains: dir.join("mail_domains").to_str().unwrap().to_string(),
        virtuals: dir.join("virtuals").to_str().unwrap().to_string(),
        mail_from: dir.join("mail_from").to_str().unwrap().to_string(),
        dkim_domains: dir.join("dkim_domains").to_str().unwrap().to_string(),
        spamd_alloweddomains: dir
            .join("spamd.alloweddomains")
            .to_str()
            .unwrap()
            .to_string(),
        approval_key: dir.join("key").to_str().unwrap().to_string(),
        keyring_dir: dir.join("keyring").to_str().unwrap().to_string(),
        stripe_webhook_secret: String::new(),
        stripe_api_key: String::new(),
        stripe_payment_link: String::new(),
        stripe_group_payment_link: String::new(),
        keyring_publish_token: String::new(),
        reviewer: "reviewer@example.invalid".to_string(),
        from: "kyriakon <hello@example.invalid>".to_string(),
        base_url: "https://signup.kyriakon.net".to_string(),
        price_gbp: "20.00".to_string(),
        group_price_gbp: "40.00".to_string(),
        postal_address: "1 Example Street".to_string(),
        mail_dir: dir.join("mail").to_str().unwrap().to_string(),
        bounce_dir: dir.join("bounce/new").to_str().unwrap().to_string(),
        release: "2026-10-10 abc1234".to_string(),
        mail_host: "mail.kyriakon.net".to_string(),
        ipv4: "192.0.2.10".to_string(),
        ipv6: "2001:db8::10".to_string(),
        dkim_selector: "mail".to_string(),
        dkim_public_key: "v=DKIM1; k=rsa; p=example".to_string(),
        dmarc_rua: "mailto:dmarc@kyriakon.net".to_string(),
        resolver: dir.join("bin/dig").to_str().unwrap().to_string(),
        repquota: dir.join("bin/repquota").to_str().unwrap().to_string(),
        quota_mount: "/home".to_string(),
        rates: dir
            .join("store/rates/xmr-gbp.json")
            .to_str()
            .unwrap()
            .to_string(),
        rate_endpoint: "https://rates.example.invalid/simple/price".to_string(),
        rates_fetch: dir.join("bin/curl").to_str().unwrap().to_string(),
        gpg: "gpg".to_string(),
        proof_dir: dir.join("logins").to_str().unwrap().to_string(),
        public_root: dir.join("home/www").to_str().unwrap().to_string(),
    }
}
