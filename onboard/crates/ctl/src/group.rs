//! One job of the operator console.

use crate::Error;
use crate::*;

/// `group remove <domain>`: take a body's domain down and close every account
/// in it. Signed here, because the transition deletes accounts, and the drain
/// refuses a domain that has no group record.
pub(crate) async fn group(cfg: &DrainConfig, store: &Store, args: &[String]) -> Result<(), Error> {
    let [verb, domain] = args else {
        return Err(Error::from(usage()));
    };
    if verb != "remove" {
        return Err(Error::from(usage()));
    }
    if let Some(why) = validate::domain(domain) {
        return Err(Error::from(format!("the domain {domain:?}: {why}")));
    }
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    let sig = sign::sign(&key, &sign::group_remove_payload(domain))?;
    let id = intent::Intent::RemoveGroup(store::GroupRemoveIntent {
        domain: domain.to_string(),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!("filed group remove for {domain} as intent {id}");
    Ok(())
}
