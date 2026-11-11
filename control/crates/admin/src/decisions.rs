//! One job of the operator console.

use crate::account::find_application;
use crate::Error;
use crate::*;

/// Sign one decision and file it as an intent. The application it names is
/// looked up by username now, at the terminal, so the intent carries the token
/// the drain keys on and not a name a second application could share. The action
/// and its signature go with it, so the drain carries the decision out only if it
/// was signed under the approval key.
pub(crate) async fn sign_and_file(
    store: &Store,
    key: &[u8],
    decision: &Decision,
    username: &str,
) -> Result<(), Error> {
    let (token, _record) = find_application(store, username).await?;
    let sig = sign::sign(key, &sign::decide_payload(&token, decision.action))?;
    let id = intent::Intent::Decision(intent::DecisionIntent {
        kind: decision.kind.to_string(),
        application: store::ApplicationRef::application(username.to_string(), token.clone()),
        action: decision.action.to_string(),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!("filed {} for {username} as intent {id}", decision.kind);
    Ok(())
}
