//! The intent seam: one enum, proved before it is applied.
//!
//! The other areas file raw JSON and let the pass parse it, because the point
//! there is the handler's input. These cases construct the variants and call
//! the seam directly, because the point here is that a verb cannot be applied
//! without saying what proves it.

use crate::common::*;

use kyriakon_onboard::config::DrainConfig;
use kyriakon_onboard::intents::Intent;
use kyriakon_onboard::store::{self as st, Store};
use kyriakon_onboard::transitions as tr;

/// The fixture's config and store, as the drain builds them.
fn seam(fix: &Fix) -> (DrainConfig, Store) {
    let cfg = DrainConfig::load(Path::new(&fix.config())).unwrap();
    let store = Store::new_for_test(&cfg.store_root);
    (cfg, store)
}

fn driver() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A filed close intent is proved by its page session. Only a proved intent
/// puts the account into its closing window.
#[test]
fn a_variant_proves_itself_before_it_is_applied() {
    let fix = Fix::new("intent-seam-close");
    fix.page_account("secretary", json!({}));
    let cookie = fix.open_session("secretary");
    let session = Fix::session_id(&cookie);
    let (cfg, store) = seam(&fix);
    let runtime = driver();

    let id = runtime
        .block_on(
            Intent::Close(tr::CloseIntent {
                username: "secretary".to_string(),
                session: session.to_string(),
                ..Default::default()
            })
            .file(&store),
        )
        .unwrap();
    let file = format!("{id}.json");
    let value: Value = serde_json::from_str(&fix.read(&format!("intents/{id}.json"))).unwrap();

    // The intent the writer filed is the variant the drain parses.
    let intent = Intent::parse(&value).unwrap();
    assert!(
        matches!(intent, Intent::Close(_)),
        "the writer's kind is the dispatcher's"
    );
    assert!(
        runtime
            .block_on(intent.verify(&cfg, &store, KEY, &file, &value))
            .unwrap(),
        "a live session proves the close"
    );
    assert_eq!(fix.account("secretary")["state"], "active");
    runtime
        .block_on(intent.apply(&cfg, &store, KEY, &file, &value))
        .unwrap();

    assert_eq!(fix.account("secretary")["state"], "closing");
    assert!(
        !fix.dir.join("store/intents").join(&file).exists(),
        "an applied intent removes its own file"
    );
    assert!(fix.journal().contains("\"outcome\":\"applied\""));
}

/// A signed verb with no valid signature is refused by the seam, and nothing it
/// covers moves.
#[test]
fn a_variant_that_cannot_prove_itself_is_refused() {
    let fix = Fix::new("intent-seam-unsigned");
    fix.page_account("secretary", json!({}));
    let account_before = fix.account("secretary");
    let (cfg, store) = seam(&fix);
    let runtime = driver();

    let intent = Intent::Resend(tr::ResendIntent {
        username: "secretary".to_string(),
        token: "KYR-0123456789ABCD".to_string(),
        sig: String::new(),
        ..Default::default()
    });
    let value = serde_json::to_value(&intent).unwrap();
    let refused = runtime
        .block_on(intent.verify(&cfg, &store, KEY, "unsigned.json", &value))
        .unwrap_err();
    assert_eq!(
        refused, "the token resend's signature does not verify",
        "{refused}"
    );
    assert_eq!(
        fix.account("secretary"),
        account_before,
        "a refused intent writes nothing"
    );

    // A kind this build does not implement cannot say how it is authenticated
    // either, so the seam refuses it by name and leaves it for a later release.
    let raw = json!({"id": "01H", "kind": "not-a-verb"});
    let unknown = Intent::parse(&raw).unwrap();
    assert!(matches!(unknown, Intent::Unknown { .. }));
    assert!(
        !runtime
            .block_on(unknown.verify(&cfg, &store, KEY, "unknown.json", &raw))
            .unwrap(),
        "an unimplemented kind is settled, not applied"
    );
    let journal = fix.journal();
    assert!(
        journal.contains("\"kind\":\"not-a-verb\""),
        "no refused line for the unknown kind: {journal:?}"
    );
    assert!(fix.journal().contains("does not implement this kind"));
    assert!(
        runtime
            .block_on(Intent::parse(&raw).unwrap().file(&store))
            .is_err(),
        "the writer files no kind this build cannot read back"
    );
}

/// One writer for every verb: the file it writes is the wire the drain reads
/// back into the same variant, with the envelope the handler's builders wrote.
#[test]
fn the_one_writer_keeps_the_wire_the_drain_reads() {
    let fix = Fix::new("intent-seam-wire");
    let (_cfg, store) = seam(&fix);
    let runtime = driver();
    let id = runtime
        .block_on(
            Intent::Credit(tr::CreditIntent {
                token: "KYR-0123456789ABCD".to_string(),
                rail: "cash".to_string(),
                amount_gbp: "20.00".to_string(),
                received: "2026-10-04".to_string(),
                note: Some("the operator's note".to_string()),
                ..Default::default()
            })
            .file(&store),
        )
        .unwrap();

    let filed: Value = serde_json::from_str(&fix.read(&format!("intents/{id}.json"))).unwrap();
    assert_eq!(filed["id"], id.as_str());
    assert_eq!(filed["kind"], "credit");
    assert!(filed["filed_at"].is_string(), "{filed}");
    assert_eq!(filed["token"], "KYR-0123456789ABCD");
    assert_eq!(filed["amount_gbp"], "20.00");
    assert_eq!(filed["note"], "the operator's note");

    let parsed = Intent::parse(&filed).unwrap();
    match parsed {
        Intent::Credit(intent) => {
            assert_eq!(intent.id, id);
            assert_eq!(intent.amount_gbp, "20.00");
            assert_eq!(intent.received, "2026-10-04");
        }
        _ => panic!("the writer's kind parsed as another variant"),
    }
}

/// One instance of every implemented variant, for the round trip below. The
/// exhaustive match makes a new variant a compile error here, so it cannot be
/// added to the enum and quietly skipped by the dispatcher.
fn every_variant() -> Vec<Intent> {
    let all = vec![
        Intent::Application(st::Intent::default()),
        // The three decisions share one variant and three kinds.
        Intent::Decision(tr::DecisionIntent {
            kind: "approve".to_string(),
            ..Default::default()
        }),
        Intent::Password(tr::PasswordIntent::default()),
        Intent::ProvisionGroup(Box::default()),
        Intent::GroupAddress(st::GroupAddressIntent::default()),
        Intent::RemoveGroup(st::GroupRemoveIntent::default()),
        Intent::Close(tr::CloseIntent::default()),
        Intent::Resend(tr::ResendIntent::default()),
        Intent::Credit(tr::CreditIntent::default()),
        Intent::WindowExtend(tr::WindowExtendIntent::default()),
        Intent::ReconcileAttribute(tr::AttributeIntent::default()),
        Intent::ReconcileReturn(tr::ReturnIntent::default()),
        Intent::Refund(tr::RefundIntent::default()),
        Intent::Export(tr::ExportIntent::default()),
        Intent::ChangePassword(tr::ChangePasswordIntent::default()),
        Intent::UploadKey(tr::UploadKeyIntent::default()),
        Intent::OutsideAddress(tr::OutsideAddressIntent::default()),
        Intent::Serving(tr::ServingIntent::default()),
        Intent::CancelRenewal(tr::CancelRenewalIntent::default()),
        Intent::MailKey(tr::MailKeyIntent::default()),
    ];
    for intent in &all {
        match intent {
            Intent::Application(_)
            | Intent::Decision(_)
            | Intent::Password(_)
            | Intent::ProvisionGroup(_)
            | Intent::GroupAddress(_)
            | Intent::RemoveGroup(_)
            | Intent::Close(_)
            | Intent::Resend(_)
            | Intent::Credit(_)
            | Intent::WindowExtend(_)
            | Intent::ReconcileAttribute(_)
            | Intent::ReconcileReturn(_)
            | Intent::Refund(_)
            | Intent::Export(_)
            | Intent::ChangePassword(_)
            | Intent::UploadKey(_)
            | Intent::OutsideAddress(_)
            | Intent::Serving(_)
            | Intent::CancelRenewal(_)
            | Intent::MailKey(_) => {}
            Intent::Unknown { .. } => panic!("the round trip covers implemented kinds only"),
        }
    }
    all
}

/// Every implemented kind, written by the one writer and read back, is the
/// variant it was filed as. A kind whose parse arm is forgotten comes back as
/// `Unknown`, which is what the drain would refuse.
#[test]
fn every_kind_parses_back_to_its_variant() {
    let fix = Fix::new("intent-seam-round-trip");
    let (_cfg, store) = seam(&fix);
    let runtime = driver();
    let mut kinds = Vec::new();
    for intent in every_variant() {
        let kind = intent.kind().to_string();
        let id = runtime.block_on(intent.file(&store)).unwrap();
        let filed: Value = serde_json::from_str(&fix.read(&format!("intents/{id}.json"))).unwrap();
        assert_eq!(filed["kind"], kind.as_str(), "{filed}");
        match Intent::parse(&filed).unwrap() {
            Intent::Unknown { kind, .. } => panic!("{kind:?} has no parse arm"),
            parsed => assert_eq!(parsed.kind(), kind, "{filed}"),
        }
        kinds.push(kind);
    }
    kinds.sort();
    kinds.dedup();
    assert_eq!(kinds.len(), every_variant().len(), "{kinds:?}");
}
