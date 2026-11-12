//! Tests for the titan module.

use super::super::{App, MAX_TITAN_BODY};
use super::{proxy_address, titan_answer, titan_params};
use crate::responder::test_support::*;

/// One Titan exchange: the request line (and any PROXY line) and a body, put in
/// front of the handler together. The leftover count is what the handler did not
/// read, which is how a refusal proves it left the body alone.
async fn titan_exchange(app: &App, head: &str, body: &[u8]) -> (u16, String, usize) {
    let mut request = head.as_bytes().to_vec();
    request.extend_from_slice(body);
    let mut reader = &request[..];
    let (reply, _address) = titan_answer(&mut reader, app, Some("203.0.113.10"))
        .await
        .expect("the request is readable");
    (
        reply.code(),
        String::from_utf8_lossy(&reply.head()).into_owned(),
        reader.len(),
    )
}

#[tokio::test]
async fn a_titan_upload_naming_no_live_draft_is_refused_before_the_body() {
    let (app, _dir) = handler("titan-unknown-token").await;
    let body = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nnot read\n";
    let head = format!(
        "titan://signup.kyriakon.net:1966/key;size={};token={TOKEN}\r\n",
        body.len()
    );
    let (code, reply, leftover) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 51, "{reply}");
    assert_eq!(
        leftover,
        body.len(),
        "the body is left on the stream: {reply}"
    );
}

#[tokio::test]
async fn a_titan_upload_over_the_cap_is_refused_before_the_body() {
    let (app, _dir) = handler("titan-over-cap").await;
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "person".to_string());
    record
        .answers
        .insert("username".to_string(), "secretary".to_string());
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let body = b"not read";
    let head = format!(
        "titan://signup.kyriakon.net:1966/key;size={};token={TOKEN}\r\n",
        MAX_TITAN_BODY + 1
    );
    let (code, reply, leftover) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 59, "{reply}");
    assert_eq!(
        leftover,
        body.len(),
        "the body is left on the stream: {reply}"
    );
}

#[tokio::test]
async fn a_titan_upload_files_the_key_and_the_mail_verdict() {
    let (app, dir) = handler("titan-files").await;
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "person".to_string());
    record
        .answers
        .insert("username".to_string(), "secretary".to_string());
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let body = GOOD_KEY.as_bytes();
    let head = format!(
        "titan://signup.kyriakon.net:1966/key;size={};mime=application/pgp-keys;token={TOKEN}\r\n",
        body.len()
    );
    let (code, reply, leftover) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 20, "{reply}");
    assert_eq!(leftover, 0, "the whole body is read: {reply}");

    let draft = read_draft(&dir, TOKEN);
    assert_eq!(draft.mail_keys.len(), 1);
    let filed = &draft.mail_keys[0];
    let expected = kyriakon_control_core::mail::keycheck::mail_key(
        "secretary".to_string(),
        "secretary@kyriakon.net",
        GOOD_KEY,
    );
    assert_eq!(filed.mailbox, "secretary");
    assert_eq!(filed.material, expected.material);
    assert_eq!(filed.fingerprint, expected.fingerprint);
    assert_eq!(
        filed.verdict, expected.verdict,
        "the Titan route records the verdict the mail route records"
    );
}

#[tokio::test]
async fn a_titan_upload_of_an_undeliverable_key_is_refused() {
    let (app, dir) = handler("titan-refuses").await;
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "person".to_string());
    record
        .answers
        .insert("username".to_string(), "secretary".to_string());
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let body = std::fs::read_to_string(format!(
        "{}/../../../docs/planning/prototypes/keygen-spike/fixtures/gpg-aead.asc",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let head = format!(
        "titan://signup.kyriakon.net:1966/key;size={};mime=application/pgp-keys;token={TOKEN}\r\n",
        body.len()
    );
    let (code, reply, leftover) = titan_exchange(&app, &head, body.as_bytes()).await;
    assert_eq!(code, 59, "{reply}");
    assert_eq!(leftover, 0, "the whole body is read: {reply}");
    assert!(
        reply.contains("AEAD"),
        "the refusal names the fault: {reply}"
    );
    let draft = read_draft(&dir, TOKEN);
    assert!(
        draft.mail_keys.is_empty(),
        "an undeliverable key is not filed"
    );
}

#[tokio::test]
async fn a_second_titan_upload_is_refused_and_the_first_key_stays() {
    let (app, dir) = handler("titan-second").await;
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "person".to_string());
    record
        .answers
        .insert("username".to_string(), "secretary".to_string());
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let body = GOOD_KEY.as_bytes();
    let head = format!(
        "titan://signup.kyriakon.net:1966/key;size={};token={TOKEN}\r\n",
        body.len()
    );
    let (code, reply, _) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 20, "{reply}");
    let first = read_draft(&dir, TOKEN);
    assert_eq!(first.mail_keys.len(), 1);
    let fingerprint = first.mail_keys[0].fingerprint.clone();

    let (code, reply, leftover) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 59, "{reply}");
    assert_eq!(
        leftover,
        body.len(),
        "the second body is left on the stream: {reply}"
    );
    let after = read_draft(&dir, TOKEN);
    assert_eq!(
        after.mail_keys.len(),
        1,
        "the second upload does not add a key"
    );
    assert_eq!(after.mail_keys[0].fingerprint, fingerprint);
}

#[tokio::test]
async fn a_titan_request_reads_the_proxy_line_and_the_request_line() {
    let (app, _dir) = handler("titan-proxy").await;
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "person".to_string());
    record
        .answers
        .insert("username".to_string(), "secretary".to_string());
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let body = GOOD_KEY.as_bytes();
    let head = format!(
        "PROXY TCP4 198.51.100.7 192.0.2.1 34567 7081\r\n\
         titan://signup.kyriakon.net:1966/key;size={};token={TOKEN}\r\n",
        body.len()
    );
    let (code, reply, leftover) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 20, "{reply}");
    assert_eq!(leftover, 0);
    assert_eq!(
        proxy_address("PROXY TCP4 198.51.100.7 192.0.2.1 34567 7081"),
        Some("198.51.100.7".to_string())
    );
    assert_eq!(proxy_address("PROXY UNKNOWN\r"), None);
}

/// A body draft's flow has one key page per mailbox, and Titan fills the next
/// one each time: two mailboxes take two uploads, and the third has nothing left
/// to fill.
#[tokio::test]
async fn a_body_draft_takes_one_key_per_mailbox_over_titan() {
    let (app, dir) = handler("titan-body").await;
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    for (key, value) in [
        ("whose", "body"),
        ("body_addresses", "secretary: own\nhall: own"),
        ("body_account_names", "secretary\nhall"),
    ] {
        record.answers.insert(key.to_string(), value.to_string());
    }
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let body = GOOD_KEY.as_bytes();
    let head = format!(
        "titan://signup.kyriakon.net:1966/key;size={};token={TOKEN}\r\n",
        body.len()
    );
    let (code, reply, _) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 20, "{reply}");
    let (code, reply, _) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 20, "{reply}");
    let filed = read_draft(&dir, TOKEN);
    let mut boxes: Vec<&str> = filed.mail_keys.iter().map(|k| k.mailbox.as_str()).collect();
    boxes.sort_unstable();
    assert_eq!(boxes, vec!["hall", "secretary"], "{:?}", filed.mail_keys);

    let (code, reply, leftover) = titan_exchange(&app, &head, body).await;
    assert_eq!(code, 59, "{reply}");
    assert!(
        reply.contains("Every mailbox"),
        "the third upload is refused by the draft's state: {reply}"
    );
    assert_eq!(leftover, body.len(), "the refusal reads no body: {reply}");
    assert_eq!(read_draft(&dir, TOKEN).mail_keys.len(), 2);
}

/// A zero-byte upload is a link being opened, so it answers and files nothing.
#[tokio::test]
async fn a_zero_byte_titan_navigation_opens_without_filing() {
    let (app, dir) = handler("titan-zero").await;
    let mut record = kyriakon_control_core::store::draft::Draft::new(TOKEN.to_string());
    record
        .answers
        .insert("whose".to_string(), "person".to_string());
    record
        .answers
        .insert("username".to_string(), "secretary".to_string());
    kyriakon_control_core::store::draft::save(&app.store, &mut record)
        .await
        .unwrap();

    let head = format!("titan://signup.kyriakon.net:1966/key;size=0;token={TOKEN}\r\n");
    let (code, reply, leftover) = titan_exchange(&app, &head, b"").await;
    assert_eq!(code, 20, "{reply}");
    assert_eq!(leftover, 0, "{reply}");
    assert!(read_draft(&dir, TOKEN).mail_keys.is_empty());
}

#[test]
fn titan_parameters_are_read_or_refused() {
    let upload = titan_params("titan://signup.kyriakon.net/key;size=12;mime=text/plain;token=abc")
        .expect("a well-formed line parses");
    assert_eq!(upload.size, Some(12));
    assert_eq!(upload.token.as_deref(), Some("abc"));

    assert_eq!(
        titan_params("titan://signup.kyriakon.net/key;size=twelve").unwrap_err(),
        "Size is not a number"
    );
    assert_eq!(
        titan_params("titan://signup.kyriakon.net/key;size=1;mode=x").unwrap_err(),
        "Unknown titan parameter"
    );
    assert_eq!(
        titan_params("gemini://signup.kyriakon.net/key;size=1").unwrap_err(),
        "Not a titan request"
    );
}
