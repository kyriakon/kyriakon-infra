//! The payment instructions and the card link the account pages, the approval
//! mail and the renewal note carry.
//!
//! The copy lives here, not in the drain, so a front end can say what a member
//! owes without depending on a transition verb.

use crate::payments::xmr;
use crate::store::Monero;
use crate::util;
use crate::Error;

/// The rail's own payment instructions, one line each, in the words the
/// approval email and both account pages carry. Monero has no subaddress until
/// the operator's wallet makes one, so the line says that rather than leaving an
/// empty field for the member to wonder at; and a window with no usable quote
/// falls back to cash by post, which is the one prepaid rail it does have.
pub fn rail_instructions(
    rail: &str,
    postal_address: &str,
    card_link: Option<&str>,
    monero: Option<&Monero>,
    amount_gbp: &str,
) -> Vec<String> {
    let cash = || {
        vec![
            "Post the money to:".to_string(),
            postal_address.to_string(),
            "Write the reference on the envelope, or on a slip inside it.".to_string(),
        ]
    };
    match rail {
        "cash" => cash(),
        "monero" => match monero.filter(|m| !m.stale && m.quote_xmr.is_some()) {
            Some(m) => {
                let mut out = Vec::new();
                match m.address.as_deref() {
                    Some(address) => out.push(format!("Your Monero subaddress is {address}.")),
                    None => out.push(
                        "Your Monero subaddress is not ready yet; it will follow in a second \
                         message."
                            .to_string(),
                    ),
                }
                if let Some(rate) = m.rate_gbp_per_xmr.as_deref() {
                    // The stored quote is for the full price. A held balance
                    // re-quotes what is still owed at the same rate, because
                    // otherwise the page asks for GBP 19.50 and the XMR amount
                    // for GBP 20.00 beside it. On a window with nothing held the
                    // recomputation is the stored quote.
                    let quote = util::pence(amount_gbp)
                        .ok()
                        .and_then(|pence| xmr::quote_xmr(pence, rate).ok())
                        .or_else(|| m.quote_xmr.clone());
                    if let Some(quote) = quote {
                        let on = m
                            .rate_at
                            .as_deref()
                            .and_then(|at| at.get(..10))
                            .unwrap_or("");
                        out.push(format!(
                            "Send {quote} XMR for GBP {amount_gbp}, quoted at GBP {rate} per XMR on {on}."
                        ));
                    }
                }
                out.push(
                    "The pound amount is what is owed; the quoted amount in Monero settles it."
                        .to_string(),
                );
                out.push(
                    "Send it to the subaddress: a payment to the wallet's main address cannot be \
                     joined to an account."
                        .to_string(),
                );
                out
            }
            None => {
                let mut out = vec![
                    "Monero is not quoted for this window, so cash by post is the only prepaid \
                     rail."
                        .to_string(),
                ];
                out.extend(cash());
                out
            }
        },
        "card" => match card_link {
            Some(link) => vec![
                "Pay by card at this link, which carries your reference:".to_string(),
                link.to_string(),
            ],
            None => vec!["A card payment link will follow in a second message.".to_string()],
        },
        other => vec![format!(
            "The rail you chose, {other}, will be quoted to you."
        )],
    }
}

/// The card rail's Payment Link, keyed to one payment token.
///
/// The reference is the account's `KYR-` token, which is what the token index
/// joins to the account: the same join `credit()` uses. `client_reference_id`
/// is the one Payment Link parameter that carries it, and it is what
/// `checkout.session.completed` names the account by. A placeholder that
/// reached the box is refused rather than mailed, because a member cannot pay
/// at REPLACE_ME.
pub fn card_link(payment_link: &str, token: &str) -> Result<Option<String>, Error> {
    if token.is_empty() {
        return Ok(None);
    }
    let link = payment_link.trim_end_matches(['&', '?']);
    if link.is_empty() || link.contains("REPLACE_ME") {
        return Err(Error::Failed(
            "stripe_payment_link is not configured, so a card approval has no link to send"
                .to_string(),
        ));
    }
    let joiner = if link.contains('?') { '&' } else { '?' };
    Ok(Some(format!("{link}{joiner}client_reference_id={token}")))
}
