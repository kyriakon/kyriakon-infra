//! Tests for the apply module.

use crate::fastcgi::fixture;
use crate::responder::test_support::*;
use crate::responder::*;

/// A Stripe delivery is stored exactly as it arrived, raw body and signature
/// header, for the drain to verify. Nothing is parsed here and nothing is
/// refused for coming from Stripe rather than this form.
#[tokio::test]
async fn a_webhook_post_stores_the_raw_body_and_the_signature_header() {
    let (app, dir) = handler("webhook-intake").await;
    let body = b"{\"id\":\"evt_1\",\"type\":\"invoice.paid\",\"note\":\"a&b=c\"}";
    let header = "t=1760000000,v1=abcdef";
    let length = body.len().to_string();
    let request = fixture::httpd(
        &[
            ("REQUEST_METHOD", "POST"),
            ("REQUEST_URI", "/stripe/webhook"),
            ("CONTENT_TYPE", "application/json"),
            ("CONTENT_LENGTH", &length),
            ("HTTP_STRIPE_SIGNATURE", header),
            ("REMOTE_ADDR", "127.0.0.1"),
        ],
        body,
    );
    let (code, _) = ask(&app, &request).await;
    assert_eq!(code, 200, "a stored delivery is acknowledged at once");

    let mut bodies = Vec::new();
    let mut sigs = Vec::new();
    for entry in std::fs::read_dir(dir.join("webhooks")).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        let mode = entry.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{name} is readable by its owner only");
        if name.ends_with(".body") {
            bodies.push(entry.path());
        } else if name.ends_with(".sig") {
            sigs.push(entry.path());
        }
    }
    assert_eq!(bodies.len(), 1, "{bodies:?}");
    assert_eq!(sigs.len(), 1, "{sigs:?}");
    assert_eq!(std::fs::read(&bodies[0]).unwrap(), body);
    assert_eq!(std::fs::read(&sigs[0]).unwrap(), header.as_bytes());
}

/// A request that is not a signed POST is refused without writing: the handler
/// no longer answers a webhook's path with a page, and it never stores one it
/// could not verify later.
#[tokio::test]
async fn a_webhook_that_is_not_a_signed_post_writes_nothing() {
    let (app, dir) = handler("webhook-refused").await;
    let body = b"{}";

    let get = fixture::httpd(
        &[
            ("REQUEST_METHOD", "GET"),
            ("REQUEST_URI", "/stripe/webhook"),
            ("REMOTE_ADDR", "127.0.0.1"),
        ],
        b"",
    );
    let (code, _) = ask(&app, &get).await;
    assert_eq!(code, 405, "only a POST is a delivery");

    let unsigned = fixture::httpd(
        &[
            ("REQUEST_METHOD", "POST"),
            ("REQUEST_URI", "/stripe/webhook"),
            ("CONTENT_TYPE", "application/json"),
            ("CONTENT_LENGTH", "2"),
            ("REMOTE_ADDR", "127.0.0.1"),
        ],
        body,
    );
    let (code, _) = ask(&app, &unsigned).await;
    assert_eq!(code, 400, "a delivery with no signature is refused");

    let written = std::fs::read_dir(dir.join("webhooks"))
        .map(|rd| rd.count())
        .unwrap_or(0);
    assert_eq!(written, 0, "a refused delivery writes no file");
}
