//! One job of the operator console.

use crate::Error;
use crate::*;

/// The flags one address change takes, after every check that needs no key and
/// no store. A removal names its mailbox and nothing else, so an `--address`
/// beside it is refused rather than silently discarded.
#[derive(Debug)]
pub(crate) struct AddressArgs {
    pub domain: String,
    pub action: String,
    pub address: String,
    pub mailbox: String,
    pub site_owner: Option<String>,
    pub key_file: Option<String>,
}

/// Parse and check the flags for [`address`]. `--confirm-remove` is a bare
/// switch, which the pair reader does not take, so it is lifted out first.
pub(crate) fn address_args(args: &[String]) -> Result<AddressArgs, Error> {
    let confirm_remove = args.iter().any(|a| a == "--confirm-remove");
    let paired: Vec<String> = args
        .iter()
        .filter(|a| a.as_str() != "--confirm-remove")
        .cloned()
        .collect();
    let flags = flags(
        &paired,
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
        return Err(Error::InvalidDomain {
            domain: domain.to_string(),
            why,
        });
    }
    let action = need(&flags, "action")?;
    if !intent::ADDRESS_ACTIONS.contains(&action) {
        return Err(Error::UnknownAction {
            action: action.to_string(),
        });
    }
    let mailbox = need(&flags, "mailbox")?;
    if let Some(why) = validate::username_shape(mailbox) {
        return Err(Error::InvalidMailbox {
            mailbox: mailbox.to_string(),
            why,
        });
    }
    let address = flags.get("address").map(String::as_str).unwrap_or("");
    if action == "remove" {
        if !address.is_empty() {
            return Err(Error::AddressOnRemoval {
                address: address.to_string(),
                mailbox: mailbox.to_string(),
                domain: domain.to_string(),
            });
        }
        if !confirm_remove {
            return Err(Error::ConfirmRequired {
                mailbox: mailbox.to_string(),
                domain: domain.to_string(),
            });
        }
    } else {
        if confirm_remove {
            return Err(Error::ConfirmOnlyForRemove);
        }
        if address.is_empty() {
            return Err(Error::AddressMissing);
        }
        if let Some(why) = validate::address_localpart_shape(address) {
            return Err(Error::InvalidAddress {
                address: address.to_string(),
                why,
            });
        }
    }
    let site_owner = flags.get("site-owner").cloned();
    if let Some(owner) = &site_owner {
        if let Some(why) = validate::username_shape(owner) {
            return Err(Error::InvalidSiteOwner {
                owner: owner.clone(),
                why,
            });
        }
    }
    Ok(AddressArgs {
        domain: domain.to_string(),
        action: action.to_string(),
        address: address.to_string(),
        mailbox: mailbox.to_string(),
        site_owner,
        key_file: flags.get("key-file").cloned(),
    })
}

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
    let parsed = address_args(args)?;
    let domain = parsed.domain.as_str();
    let action = parsed.action.as_str();
    let address = parsed.address.as_str();
    let mailbox = parsed.mailbox.as_str();
    let site_owner = parsed.site_owner.as_deref();
    let mail_key = match parsed.key_file {
        Some(path) => {
            let material =
                std::fs::read_to_string(&path).map_err(|source| Error::MailKeyUnreadable {
                    path: path.clone().into(),
                    source,
                })?;
            if material.trim().is_empty() {
                return Err(Error::MailKeyEmpty { path: path.into() });
            }
            // The same check the responder and the portal run, so a console
            // submission cannot file a mailbox the pages would have refused:
            // the refusal and the verdict are the check's, never "unchecked"
            // for something that is not a key.
            let checked = pgp::public_key(&material).map_err(|source| Error::MailKeyInvalid {
                path: path.clone().into(),
                source,
            })?;
            if let Some(why) = checked.refusal() {
                return Err(Error::MailKeyRefused {
                    mailbox: mailbox.to_string(),
                    why: why.to_string(),
                });
            }
            let address = format!("{mailbox}@kyriakon.net");
            let record = keycheck::mail_key(mailbox.to_string(), &address, &material);
            if record.fingerprint.is_empty() {
                return Err(Error::MailKeyNoPacket { path: path.into() });
            }
            Some(record)
        }
        None => None,
    };
    if matches!(action, "add-mailbox" | "upgrade") && mail_key.is_none() {
        return Err(Error::MailKeyMissing);
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
    if action == "remove" {
        println!(
            "filed remove of {mailbox}@{domain} as intent {id}: it deletes the account, home \
             and Maildir, quota record, git repositories, published tree and store record"
        );
    } else {
        println!("filed {action} for {domain} as intent {id}");
    }
    if matches!(action, "add-mailbox" | "upgrade") {
        println!(
            "the drain writes a one-time password link onto {mailbox} when the intent applies \
             and mails it to the group's contact"
        );
    }
    Ok(())
}
