//! One job of the operator console.

use crate::Error;
use crate::*;

/// File one address change in a group. The signature is the console's, over
/// every field the drain acts on: an address intent creates a root account or
/// removes one, and `intents/` is writable by the unprivileged handler.
///
/// `--key-file` is the new mailbox's armored public key, read here and carried
/// in the intent so the drain installs it in the keyring and publishes it.
pub(crate) async fn address(
    cfg: &DrainConfig,
    store: &Store,
    args: &[String],
) -> Result<(), Error> {
    let flags = flags(
        args,
        &[
            "domain",
            "action",
            "address",
            "mailbox",
            "key-file",
            "site-owner",
        ],
    )?;
    let domain = need(&flags, "domain")?;
    if let Some(why) = validate::domain(domain) {
        return Err(Error::Failed(format!("the domain {domain:?}: {why}")));
    }
    let action = need(&flags, "action")?;
    if !intent::ADDRESS_ACTIONS.contains(&action) {
        return Err(Error::Failed(format!(
            "--action {action:?} is not one of {:?}\n{}",
            intent::ADDRESS_ACTIONS,
            usage()
        )));
    }
    let mailbox = need(&flags, "mailbox")?;
    if let Some(why) = validate::username_shape(mailbox) {
        return Err(Error::Failed(format!("the mailbox {mailbox:?}: {why}")));
    }
    let address = flags.get("address").map(String::as_str).unwrap_or("");
    if action != "remove" {
        if address.is_empty() {
            return Err(Error::Failed(
                "--address is needed for this change".to_string(),
            ));
        }
        if let Some(why) = validate::address_localpart_shape(address) {
            return Err(Error::Failed(format!("the address {address:?}: {why}")));
        }
    }
    let site_owner = flags.get("site-owner").map(String::as_str);
    if let Some(owner) = site_owner {
        if let Some(why) = validate::username_shape(owner) {
            return Err(Error::Failed(format!("the site owner {owner:?}: {why}")));
        }
    }
    let mail_key = match flags.get("key-file") {
        Some(path) => {
            let material = std::fs::read_to_string(path)
                .map_err(|e| Error::context(format!("cannot read the mail key {path}"), e))?;
            if material.trim().is_empty() {
                return Err(Error::Failed(format!("the mail key {path} is empty")));
            }
            // The same check the responder and the portal run, so a console
            // submission cannot file a mailbox the pages would have refused:
            // the refusal and the verdict are the check's, never "unchecked"
            // for something that is not a key.
            let checked = keycheck::pgp_public_key(&material)
                .map_err(|why| Error::Failed(format!("the mail key {path}: {why}")))?;
            if let Some(why) = checked.refusal() {
                return Err(Error::Failed(format!(
                    "the mail key for {mailbox} cannot be used: {why}"
                )));
            }
            let address = format!("{mailbox}@kyriakon.net");
            let record = keycheck::mail_key(mailbox.to_string(), &address, &material);
            if record.fingerprint.is_empty() {
                return Err(Error::Failed(format!(
                    "the mail key {path}: it carries no key packet"
                )));
            }
            Some(record)
        }
        None => None,
    };
    if matches!(action, "add-mailbox" | "upgrade") && mail_key.is_none() {
        return Err(Error::Failed(
            "--key-file is needed for a new mailbox".to_string(),
        ));
    }
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(
        &key,
        &sign::address_payload(
            domain,
            action,
            address,
            mailbox,
            site_owner.unwrap_or(""),
            mail_key.as_ref().map(|k| k.material.as_str()).unwrap_or(""),
        ),
    )?;
    let id = intent::Intent::GroupAddress(store::GroupAddressIntent {
        domain: domain.to_string(),
        action: action.to_string(),
        address: address.to_string(),
        mailbox: mailbox.to_string(),
        mail_key: mail_key.clone(),
        site_owner: site_owner.map(str::to_string),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!("filed {action} for {domain} as intent {id}");
    if matches!(action, "add-mailbox" | "upgrade") {
        println!(
            "the drain writes a one-time password link onto {mailbox} when the intent applies; \
             deliver one with: kyriakon-admin password reset {mailbox}"
        );
    }
    Ok(())
}
