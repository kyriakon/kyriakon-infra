//! The payment webhook and the application submission.

use super::*;

use super::connection::fields;
use super::flow::{application_problems, build_record, file_application, render_applicant};
use super::gemini::capsule_new;
use super::reply::{capability, page_html, refused, server_error, too_many, Which};
use super::route::Call;
use kyriakon_onboard_core::flow::applicant::{label, reading, Reading};

use crate::fastcgi::{Reply, Request};
use crate::page;
use crate::page::ReceivedPage;
use kyriakon_onboard_core::config::HOST;
use kyriakon_onboard_core::store;

/// Store one Stripe delivery for the drain: the raw body and the
/// `Stripe-Signature` header, under `webhooks/`, named by a ULID so the
/// directory sorts by age. Nothing is verified here and no store record is
/// written; the handler holds no secret. The row's method is POST and the table
/// is the half that refuses another one; a delivery with no signature header is
/// refused without writing, and a successful store answers 2xx at once so Stripe
/// does not retry a delivery the drain has not settled yet.
pub(super) async fn webhook(app: &App, request: &Request) -> Reply {
    let signature = request.get("HTTP_STRIPE_SIGNATURE").unwrap_or("");
    if signature.trim().is_empty() {
        return Reply::html(400, String::new());
    }
    if request.body_too_large {
        return Reply::html(413, String::new());
    }
    let id = ulid::Ulid::new().to_string();
    // The signature is written before the body. The drain iterates `.body`
    // files, so the other order leaves a body with no signature for a window,
    // which it would refuse and delete: a delivery Stripe will not send again.
    let placed = async {
        app.store.ensure_dir("webhooks").await?;
        app.store
            .write_record("webhooks", &format!("{id}.sig"), signature.as_bytes())
            .await?;
        app.store
            .write_record("webhooks", &format!("{id}.body"), &request.body)
            .await
    }
    .await;
    match placed {
        Ok(()) => Reply::html(200, String::new()),
        Err(e) => {
            // The front-end is mid-request, so the failure is answered rather
            // than the connection dropped; Stripe retries a non-2xx.
            eprintln!("kyriakon-onboard: cannot store a webhook: {e}");
            Reply::html(500, String::new())
        }
    }
}

/// The applicant flow's entry: the web form's submission, and the capsule's
/// first page. One row, because both front ends start the flow at the same path,
/// and each renders its own.
pub(super) async fn apply(app: &App, call: &Call<'_>) -> Reply {
    match call.front {
        FrontEnd::Httpd => apply_web(app, call.request, call.incoming).await,
        FrontEnd::Gemini => capsule_new(app, call.incoming).await,
    }
}

/// The web form's submission.
pub(super) async fn apply_web(app: &App, request: &Request, incoming: &Incoming) -> Reply {
    let form = fields(&String::from_utf8_lossy(&request.body));
    let Reading { body, shown } = reading(&form);

    // Read before anything else is done with the submission, and before the
    // request is charged as a draft: a front end that names itself wrongly gets
    // its refusal rather than an application recorded under a name nothing
    // recognises. The web form does not post this field at all, so its absence is
    // the web form.
    let label = match label(&form) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("kyriakon-onboard: {e}");
            return refused("A submission has to name its front end as web, tui or capsule.");
        }
    };

    // The answer names a branch the page did not carry, so its questions are ones
    // the applicant has not been shown and answers they have not been given the
    // chance to give. Refusing would list exactly those, which is the refusal the
    // ticket is about: the page is rendered again with the block open instead, and
    // the answers so far come back with it.
    if !shown {
        return render_applicant(app, body, &form, &[]);
    }
    let errors = application_problems(app, &form);
    if !errors.is_empty() {
        let mut page = page::applicant(
            &app.questions,
            &app.catalogue,
            body,
            &form,
            &app.cfg.release,
        );
        page.errors = errors;
        return Reply::html(422, page_html(&page));
    }

    // Charged here, once the submission is a draft and no longer merely an
    // attempt: a refusal spends the request budget, not the day's drafts, and a
    // third-party page cannot burn a visitor's day with junk posts.
    if !app.counter.allow_draft(incoming.key) {
        // The web front-end's own refusal: a draft is filed through this route,
        // which is the form's.
        return too_many(FrontEnd::Httpd, Which::Day);
    }

    let token = match store::status_token().await {
        Ok(t) => t,
        Err(e) => return server_error(&e),
    };
    let record = match build_record(app, &form, body, &token, label) {
        Ok(r) => r,
        Err(e) => return server_error(&e),
    };
    if let Err(e) = file_application(app, &record).await {
        return server_error(&e);
    }

    capability(&ReceivedPage {
        status_url: format!("https://{HOST}/status/{token}"),
    })
}

#[cfg(test)]
mod tests;
