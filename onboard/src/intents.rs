//! The intent loop: what makes a filed application move.
//!
//! Every pass reads `intents/*.json` in ULID order, which is the order they
//! were filed, revalidates each one, appends the journal line before carrying
//! the transition out, and deletes the intent file once it is done. An intent
//! whose kind this build does not implement is refused by name and left in
//! place, never silently dropped: a kind added by a later ticket waits here
//! until the ticket that understands it lands.

use serde_json::Value;

use crate::config::DrainConfig;
use crate::sign;
use crate::store::Store;
use crate::transitions::{self, DecisionIntent};

/// One pass: every intent, then the sweeps. The drain is a single short-lived
/// process with no listener, so there is no loop inside it; cron runs it again
/// a minute later.
pub async fn run(cfg: &DrainConfig, store: &Store) -> Result<(), String> {
    // Read once, before anything is done: the review email's links are signed
    // with it, and a box whose key is missing should fail on the first minute
    // rather than after it has half-carried a transition out.
    let key = sign::read_key(std::path::Path::new(&cfg.approval_key))?;
    // The filenames are ULIDs, so a lexical sort is an age sort.
    for name in store.list("intents").await? {
        if !name.ends_with(".json") {
            continue;
        }
        if let Err(e) = one(cfg, store, &key, &name).await {
            // One bad intent must not stop the others, and the error names the
            // intent file. The intent is left in place for the next pass.
            eprintln!("kyriakon-onboard-drain: {name}: {e}");
        }
    }
    transitions::purge_declined(cfg, store).await
}

/// One intent, dispatched by kind.
async fn one(cfg: &DrainConfig, store: &Store, key: &[u8], file: &str) -> Result<(), String> {
    let text = store
        .read_record("intents", file)
        .await
        .ok_or("the intent vanished between the listing and the read")?;
    let value: Value =
        serde_json::from_str(&text).map_err(|e| format!("the intent does not parse: {e}"))?;
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    match kind.as_str() {
        "application" => transitions::filed_application(cfg, store, key, &text, file).await,
        "approve" | "provision" | "decline" => {
            let intent: DecisionIntent = serde_json::from_value(value)
                .map_err(|e| format!("the decision intent does not parse: {e}"))?;
            transitions::decision(cfg, store, key, intent, file).await
        }
        _ => transitions::refuse(cfg, store, file, &value).await,
    }
}
