//! The intent seam: one enum, proved before it is applied.
//!
//! The other areas file raw JSON and let the pass parse it, because the point
//! there is the handler's input. These cases construct the variants and call
//! the seam directly, because the point here is that a verb cannot be applied
//! without saying what proves it.

use crate::common::*;

use kyriakon_control_core::account::sign;
use kyriakon_control_core::config::DrainConfig;
use kyriakon_control_core::intent::{self, Intent};
use kyriakon_control_core::store::journal::Journal;
use kyriakon_control_core::store::{self as st, Store};

/// The fixture's config and store, as the drain builds them.
fn seam(fix: &Fix) -> (DrainConfig, Store, Journal) {
    let cfg = DrainConfig::load(Path::new(&fix.config())).unwrap();
    let store = Store::new_for_test(&cfg.store_root);
    let journal = driver().block_on(Journal::load(&store)).unwrap();
    (cfg, store, journal)
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
    let (cfg, store, journal) = seam(&fix);
    let runtime = driver();

    let id = runtime
        .block_on(
            Intent::Close(intent::CloseIntent {
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
            .block_on(kyriakon_control_drain::verify(
                &intent, &cfg, &store, KEY, &file, &value
            ))
            .unwrap()
            .is_none(),
        "a live session proves the close"
    );
    assert_eq!(fix.account("secretary")["state"], "active");
    runtime
        .block_on(kyriakon_control_drain::apply(
            intent, &cfg, &store, &journal, KEY, &file, &value,
        ))
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
    let (cfg, store, journal) = seam(&fix);
    let runtime = driver();

    let intent = Intent::Resend(intent::ResendIntent {
        username: "secretary".to_string(),
        token: "KYR-0123456789ABCD".to_string(),
        sig: String::new(),
        ..Default::default()
    });
    let value = serde_json::to_value(&intent).unwrap();
    let refused = runtime
        .block_on(kyriakon_control_drain::verify(
            &intent,
            &cfg,
            &store,
            KEY,
            "unsigned.json",
            &value,
        ))
        .unwrap_err();
    assert!(
        matches!(
            &refused,
            kyriakon_control_drain::transitions::Error::Failed(message)
                if message == "the token resend's signature does not verify"
        ),
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
        runtime
            .block_on(kyriakon_control_drain::verify(
                &unknown,
                &cfg,
                &store,
                KEY,
                "unknown.json",
                &raw
            ))
            .unwrap()
            .is_some(),
        "an unimplemented kind is settled, not applied"
    );
    // The refusal is journalled by `settle`, which is the only writer: the
    // verify side hands it the settlement and does not write anything itself.
    runtime
        .block_on(kyriakon_control_drain::run_intent(
            Intent::parse(&raw).unwrap(),
            &cfg,
            &store,
            &journal,
            KEY,
            "unknown.json",
            &raw,
        ))
        .unwrap();
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
    let (_cfg, store, _journal) = seam(&fix);
    let runtime = driver();
    let id = runtime
        .block_on(
            Intent::Credit(intent::CreditIntent {
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
        Intent::Decision(intent::DecisionIntent {
            kind: "approve".to_string(),
            ..Default::default()
        }),
        Intent::Password(intent::PasswordIntent::default()),
        Intent::ProvisionGroup(Box::default()),
        Intent::GroupAddress(st::GroupAddressIntent::default()),
        Intent::RemoveGroup(st::GroupRemoveIntent::default()),
        Intent::Close(intent::CloseIntent::default()),
        Intent::Resend(intent::ResendIntent::default()),
        Intent::Credit(intent::CreditIntent::default()),
        Intent::WindowExtend(intent::WindowExtendIntent::default()),
        Intent::ReconcileAttribute(intent::AttributeIntent::default()),
        Intent::ReconcileReturn(intent::ReturnIntent::default()),
        Intent::Refund(intent::RefundIntent::default()),
        Intent::Export(intent::ExportIntent::default()),
        Intent::ChangePassword(intent::ChangePasswordIntent::default()),
        Intent::UploadKey(intent::UploadKeyIntent::default()),
        Intent::OutsideAddress(intent::OutsideAddressIntent::default()),
        Intent::Serving(intent::ServingIntent::default()),
        Intent::CancelRenewal(intent::CancelRenewalIntent::default()),
        Intent::MailKey(intent::MailKeyIntent::default()),
        Intent::TestMail(intent::TestMailIntent::default()),
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
            | Intent::MailKey(_)
            | Intent::TestMail(_) => {}
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
    let (_cfg, store, _journal) = seam(&fix);
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

/// An unreadable journal is the pass's error, not an empty journal: dedup that
/// read it as empty would fail open (#513).
#[test]
fn an_unreadable_journal_fails_the_pass() {
    let fix = Fix::new("intent-journal-unreadable");
    // A directory where the record should be: every read of it fails.
    std::fs::create_dir_all(fix.dir.join("store/journal.jsonl")).unwrap();
    let out = fix.drain();
    assert!(
        !out.status.success(),
        "the pass ran on an unreadable journal: {}",
        body(&out)
    );
    assert!(body(&out).contains("journal.jsonl"), "{}", body(&out));
}

/// A settled intent is not work again: the same file left behind by a crash
/// between the outcome line and the remove finishes with the remove and no
/// second line. The dedup is the combinator's, so every verb has it.
#[test]
fn a_settled_intent_is_not_applied_again() {
    let fix = Fix::new("intent-settled-twice");
    fix.page_account("secretary", json!({}));
    let cookie = fix.open_session("secretary");
    let session = Fix::session_id(&cookie);
    let (cfg, store, journal) = seam(&fix);
    let runtime = driver();

    let id = runtime
        .block_on(
            Intent::Close(intent::CloseIntent {
                username: "secretary".to_string(),
                session: session.to_string(),
                ..Default::default()
            })
            .file(&store),
        )
        .unwrap();
    let file = format!("{id}.json");
    let value: Value = serde_json::from_str(&fix.read(&format!("intents/{id}.json"))).unwrap();
    let intent = Intent::parse(&value).unwrap();
    assert!(runtime
        .block_on(kyriakon_control_drain::verify(
            &intent, &cfg, &store, KEY, &file, &value
        ))
        .unwrap()
        .is_none());
    runtime
        .block_on(kyriakon_control_drain::apply(
            intent, &cfg, &store, &journal, KEY, &file, &value,
        ))
        .unwrap();
    let lines = fix
        .journal()
        .matches(&format!("\"intent\":\"{id}\""))
        .count();
    assert_eq!(lines, 1, "{}", fix.journal());

    // The file back, as a crash between the line and the remove leaves it.
    std::fs::write(
        fix.path(&format!("store/intents/{file}")),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
    let intent = Intent::parse(&value).unwrap();
    runtime
        .block_on(kyriakon_control_drain::apply(
            intent, &cfg, &store, &journal, KEY, &file, &value,
        ))
        .unwrap();

    assert!(
        !fix.dir.join("store/intents").join(&file).exists(),
        "the applied intent was left in place"
    );
    assert_eq!(
        fix.journal()
            .matches(&format!("\"intent\":\"{id}\""))
            .count(),
        lines,
        "a second pass appended a line: {}",
        fix.journal()
    );
    assert_eq!(fix.account("secretary")["state"], "closing");
}

/// A page refusal is one line, and the file goes with it. A pass that finds the
/// line and the file a crash left behind removes the file and appends nothing:
/// the verify side hands `settle` the refusal, and `settle` owns the guard.
#[test]
fn a_page_refusal_is_journalled_once_and_its_file_removed() {
    let fix = Fix::new("intent-page-refusal-replay");
    fix.page_account("secretary", json!({}));
    let id = fix.file_page_action(
        "serving",
        "secretary",
        json!({"http": true, "gemini": false}),
    );
    let file = format!("intents/{id}.json");
    let value: Value = serde_json::from_str(&fix.read(&file)).unwrap();
    // The session record is gone, as expiry leaves it, so the proof refuses.
    let session = value["session"].as_str().unwrap().to_string();
    std::fs::remove_file(fix.path(&format!("store/sessions/{session}.json"))).unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !std::path::Path::new(&fix.path(&format!("store/{file}"))).exists(),
        "a page refusal removes its file"
    );
    let journal = fix.journal();
    assert_eq!(
        journal.matches(&format!("\"intent\":\"{id}\"")).count(),
        1,
        "{journal}"
    );
    assert_eq!(
        journal.matches("\"outcome\":\"refused\"").count(),
        1,
        "{journal}"
    );
    assert!(
        journal.contains("\"username\":\"secretary\""),
        "the refusal line names the account: {journal}"
    );
    assert!(
        !journal.contains("status_token"),
        "a page line wrote a token field: {journal}"
    );

    // The file back, as a crash between the line and the remove leaves it.
    std::fs::write(
        fix.path(&format!("store/{file}")),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !std::path::Path::new(&fix.path(&format!("store/{file}"))).exists(),
        "the replayed refusal left its file behind"
    );
    assert_eq!(
        fix.journal()
            .matches(&format!("\"intent\":\"{id}\""))
            .count(),
        1,
        "the replay appended a second refusal: {}",
        fix.journal()
    );
}

/// The two refusal shapes keep opposite files: a page verb's refusal is the
/// handler's input and goes, an operator's is a decision to read and stays.
#[test]
fn a_page_refusal_removes_its_file_and_an_operator_refusal_keeps_it() {
    let fix = Fix::new("intent-refusal-dispositions");
    fix.page_account("secretary", json!({}));
    // The body refuses a plaintext that cannot be a password, which is a page
    // verb's own refusal.
    let page = fix.file_page_action("change-password", "secretary", json!({"password": "short"}));

    // The body refuses a token that is not a payment token. The console's
    // signature is real, so verify passes and the refusal is the body's.
    let operator = ulid();
    let token = "not-a-token";
    let sig = sign::sign(
        b"the approval key",
        &sign::window_extend_payload(token, 14, "because the window lapsed"),
    )
    .unwrap();
    fix.write_intent(
        &operator,
        &json!({
            "id": operator,
            "kind": "window-extend",
            "filed_at": "2026-10-02T09:00:00Z",
            "token": token,
            "days": 14,
            "reason": "because the window lapsed",
            "sig": sig,
        }),
    );

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert!(
        !std::path::Path::new(&fix.path(&format!("store/intents/{page}.json"))).exists(),
        "a page refusal kept its file"
    );
    assert!(
        std::path::Path::new(&fix.path(&format!("store/intents/{operator}.json"))).exists(),
        "an operator refusal removed its file"
    );
    let journal = fix.journal();
    assert!(
        journal.contains(&format!("\"intent\":\"{page}\"")) && journal.contains("\"refused\""),
        "{journal}"
    );
    // The operator's intent is journalled under the id its signature names,
    // which is not the file name the console chose.
    let filed = kyriakon_control_core::intent::id_for(&sig);
    assert!(
        journal.contains(&format!("\"intent\":\"{filed}\"")),
        "{journal}"
    );
    // Both proofs passed and both bodies refused: the page verb's session was
    // live and the operator's signature was real.
    assert!(
        journal.contains("Use at least") && journal.contains("not a payment token"),
        "the refusals are not the bodies' own: {journal}"
    );
}

/// An old journal line wrote its subject's token as a plain string, and a group
/// line put a domain there. Both still load, and the refusal the line records
/// still dedups: the pass appends nothing.
#[test]
fn an_old_journal_line_still_loads_and_dedups() {
    let fix = Fix::new("intent-old-journal-line");
    let id = ulid();
    fix.write_intent(&id, &json!({"id": id, "kind": "not-a-verb"}));
    let old = format!(
        "{{\"version\":1,\"at\":\"2026-11-04T09:00:00Z\",\"intent\":\"{id}\",\"kind\":\"not-a-verb\",\"release\":\"old\",\"application\":{{\"username\":\"warden\",\"status_token\":\"parish.example\"}},\"outcome\":\"refused\",\"note\":\"this build does not implement this kind; the intent is left in place\"}}\n"
    );
    std::fs::write(fix.dir.join("store/journal.jsonl"), old).unwrap();

    let out = fix.drain();
    assert!(out.status.success(), "{}", body(&out));
    assert_eq!(
        fix.journal()
            .matches(&format!("\"intent\":\"{id}\""))
            .count(),
        1,
        "the old line was not read as the settlement it is: {}",
        fix.journal()
    );
    assert!(
        std::path::Path::new(&fix.path(&format!("store/intents/{id}.json"))).exists(),
        "a refused unknown kind is left for the operator"
    );
}
