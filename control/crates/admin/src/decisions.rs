//! One job of the operator console.

use crate::Error;
use crate::*;

/// Sign one decision and file it as an intent. The application is the one the
/// review mail names by its token, and the lookup refuses unless that record is
/// the named username's: resolving by username here would sign whichever
/// application was filed last, and anyone can file a second one between the mail
/// and the terminal. The action and its signature go with the token, so the drain
/// carries the decision out only if it was signed under the approval key.
///
/// The review mail described one record and the operator approves that one. The
/// fields the signature covers are printed, and the journal's `review-sent` line
/// holds them as the mail saw them: `applications/` belongs to the handler, so a
/// record rewritten between the mail and this command is refused and the field
/// it changed is named, rather than signed under the operator's key.
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
    // What this command is about to sign, printed before it signs. Every field
    // here is the handler's to write and the signature's to cover.
    let now = sign::review_fields(&record);
    println!("{} {username} (application {token})", decision.kind);
    println!("  no_charge        {}", now.no_charge);
    println!("  rail             {}", or_none(&now.rail));
    println!("  domain           {}", or_none(&now.domain));
    println!("  outside_address  {}", or_none(&now.outside_address));
    println!("  answers          {}", now.answers);
    println!("  keys             {}", now.keys);

    match Journal::load(store).await?.reviewed(token) {
        Some(reviewed) => {
            if let Some(changed) = reviewed.changed(&now) {
                return Err(Error::Failed(format!(
                    "the application record changed after the review mail: {changed}. \
                     Nothing was signed; read the application again and check it \
                     against the mail before deciding"
                )));
            }
        }
        // A review line from a release before this one carries no fields to
        // compare; the operator still sees above what will be signed.
        None => println!(
            "  review           no recorded review for this application: \
             check the fields above against the mail"
        ),
    }

    let sig = sign::sign(key, &sign::decide_payload(&record, decision.action))?;
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

/// A covered field with no value, as the review mail says it: `none`.
fn or_none(text: &str) -> String {
    if text.is_empty() {
        "none".to_string()
    } else {
        safe(text)
    }
}
