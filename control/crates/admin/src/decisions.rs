//! One job of the operator console.

use crate::Error;
use crate::*;

/// Sign one decision and file it as an intent. The application is the one the
/// review mail names by its token, and the lookup refuses unless that record is
/// the named username's: resolving by username here would sign whichever
/// application was filed last, and anyone can file a second one between the mail
/// and the terminal. The action and its signature go with the token, so the drain
/// carries the decision out only if it was signed under the approval key.
pub(crate) async fn sign_and_file(
    store: &Store,
    key: &[u8],
    decision: &Decision,
    username: &str,
    token: &str,
) -> Result<(), Error> {
    if !store::is_status_token(token) {
        return Err(Error::Failed(format!(
            "the token {token:?} is not a status token (26 Crockford characters)"
        )));
    }
    let Some(record) = store.application(token).await? else {
        return Err(Error::Failed(format!("no application at token {token}")));
    };
    if record.username != username {
        return Err(Error::Failed(format!(
            "the application at token {token} is for {}, not {username}",
            record.username
        )));
    }
    let sig = sign::sign(key, &sign::decide_payload(token, decision.action))?;
    let id = intent::Intent::Decision(intent::DecisionIntent {
        kind: decision.kind.to_string(),
        application: store::ApplicationRef::application(username.to_string(), token.to_string()),
        action: decision.action.to_string(),
        sig,
        ..Default::default()
    })
    .file(store)
    .await?;
    println!(
        "filed {} for {username} (application {token}) as intent {id}",
        decision.kind
    );
    Ok(())
}
