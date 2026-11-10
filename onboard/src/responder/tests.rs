//! Tests for the responder's startup and front-end classification.

use crate::responder::test_support::*;
use crate::responder::*;

/// A staging run that missed a page stops the handler rather than leaving a
/// route that answers 51 for a document the capsule promises.
#[tokio::test]
async fn the_handler_refuses_to_start_without_a_staged_page() {
    let dir = fixture_dir("missing-page");
    for (route, file, _) in capsule::PAGES {
        if *route == "aup" {
            continue;
        }
        std::fs::write(dir.join("pages").join(file), "# ok\n").unwrap();
    }
    let Err(err) = App::load(handler_config(&dir)).await else {
        panic!("the handler started without a page");
    };
    assert!(err.contains("aup.gmi"), "{err}");
}

/// An empty staged file is the same failure as a missing one: the page exists
/// and says nothing, which a reader would take for the document.
#[tokio::test]
async fn the_handler_refuses_an_empty_staged_page() {
    let dir = fixture_dir("empty-page");
    for (route, file, _) in capsule::PAGES {
        let body = if *route == "privacy" {
            String::new()
        } else {
            "# ok\n".to_string()
        };
        std::fs::write(dir.join("pages").join(file), body).unwrap();
    }
    let Err(err) = App::load(handler_config(&dir)).await else {
        panic!("the handler started on an empty page");
    };
    assert!(err.contains("privacy.gmi"), "{err}");
}

#[test]
fn a_front_end_is_web_tui_or_capsule_and_nothing_else() {
    let mut form = BTreeMap::new();
    // The web form posts no such field, so its absence is the web form.
    assert_eq!(label(&form).unwrap(), "web");
    for v in ["web", "tui", "capsule"] {
        form.insert("front_end".to_string(), v.to_string());
        assert_eq!(label(&form).unwrap(), v);
    }
    for v in ["", "Capsule", "capsule ", "ssh", "http"] {
        form.insert("front_end".to_string(), v.to_string());
        assert!(label(&form).is_err(), "{v:?} should be refused");
    }
}
