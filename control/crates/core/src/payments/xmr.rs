//! The XMR/GBP rate the Monero rail quotes from, and the shape a Monero
//! credit's transaction id and amount must have.
//!
//! One named source, cached in `rates/xmr-gbp.json` for twenty-four hours. The
//! drain is the only writer and the only caller: a quote is computed when a
//! window opens, and the account and its application copy carry the number the
//! member was shown, so nothing a member's page renders can reach the endpoint.
//!
//! Two cases are deliberate. A source that cannot be reached while a cache
//! exists yields the cached rate marked stale, which the page hides rather than
//! re-quoting a member mid-window. No cache at all yields no rate, and the
//! window opens with cash as the only prepaid rail.
//!
//! Fetching is `curl` by configured path, the way the DNS sweep runs `dig`:
//! the release's dependency list is frozen and one HTTPS GET does not earn a
//! client crate.

use std::path::Path;

use crate::config::DrainConfig;
use crate::store::Monero;
use crate::Error;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

/// The one named source a quote records. CoinGecko's public price endpoint
/// needs no key, and its response is the only thing read.
pub const SOURCE: &str = "coingecko";

/// How long a cache is used without asking the source again. It is also the
/// most often the drain writes the file.
const FRESH: Duration = Duration::hours(24);

/// How long after a failed fetch the next one waits. The cache cannot record a
/// failure without pretending the old rate is fresh, so the attempt is stamped
/// beside it.
const RETRY: Duration = Duration::hours(1);

/// `rates/xmr-gbp.json`: the fetched rate, its source and when it was fetched.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cached {
    pub version: u32,
    /// GBP per XMR as a decimal string, never a float: the quote is arithmetic
    /// over this and money is not a float in this service.
    pub rate_gbp_per_xmr: String,
    pub source: String,
    pub fetched_at: String,
}

/// The cache as it stands, or `None` when nothing has ever been fetched or the
/// file cannot be read as a rate. A corrupt cache is no rate rather than a
/// guessed one.
pub fn cached(cfg: &DrainConfig) -> Option<Cached> {
    let text = std::fs::read_to_string(&cfg.rates).ok()?;
    let cached: Cached = serde_json::from_str(&text).ok()?;
    valid_rate(&cached.rate_gbp_per_xmr).then_some(cached)
}

/// Whether the cache may be used without asking the source again.
pub fn fresh(cached: &Cached, now: OffsetDateTime) -> bool {
    parse_stamp(&cached.fetched_at).is_some_and(|fetched| now - fetched < FRESH)
}

/// The rate a quote is computed from, and whether it is stale. `None` when no
/// rate has ever been fetched and the source cannot be reached.
///
/// This is the one place the endpoint is called, and the fresh-cache check is
/// what keeps the egress to a handful of requests a day: a cache inside its
/// twenty-four hours is returned without a fetch, and a failed fetch waits an
/// hour before the next attempt.
pub async fn current(cfg: &DrainConfig, now: OffsetDateTime) -> Option<(Cached, bool)> {
    let cached = cached(cfg);
    if let Some(cached) = &cached {
        if fresh(cached, now) {
            return Some((cached.clone(), false));
        }
    }
    if attempted_recently(cfg, now) {
        return cached.map(|cached| (cached, true));
    }
    match fetch(cfg).await {
        Some(rate_gbp_per_xmr) => {
            let refreshed = Cached {
                version: 1,
                rate_gbp_per_xmr,
                source: SOURCE.to_string(),
                fetched_at: crate::util::stamp(now),
            };
            if let Err(e) = write(cfg, &refreshed) {
                e.report("writing the rate cache");
            }
            Some((refreshed, false))
        }
        None => {
            if let Err(e) = stamp_attempt(cfg, now) {
                e.report("writing the rate attempt");
            }
            cached.map(|cached| (cached, true))
        }
    }
}

/// The Monero block a window opens with: the quote for this price, from the
/// rate, or `None` when no rate has ever been fetched. The subaddress is the
/// wallet pass's, so it is written separately and never guessed here.
pub async fn quote(cfg: &DrainConfig, now: OffsetDateTime, price_gbp: &str) -> Option<Monero> {
    let price = crate::util::pence(price_gbp).ok().filter(|p| *p > 0)?;
    let (rate, stale) = match current(cfg, now).await {
        Some(found) => found,
        None => return None,
    };
    let quote_xmr = quote_xmr(price, &rate.rate_gbp_per_xmr).ok()?;
    Some(Monero {
        address: None,
        quote_xmr: Some(quote_xmr),
        rate_gbp_per_xmr: Some(rate.rate_gbp_per_xmr),
        rate_source: Some(rate.source),
        rate_at: Some(rate.fetched_at),
        stale,
    })
}

/// `price ÷ rate`, rounded up to six decimal places, as a decimal string. A
/// quote that rounded down would leave the member a fraction short of the
/// amount owed, which is the one defect the spec names for the conversion.
///
/// Integer arithmetic throughout: `xmr = pence × 10^(4+d) / R` where the rate is
/// `R / 10^d`, and the ceiling is taken on that quotient.
pub fn quote_xmr(price_pence: i64, rate: &str) -> Result<String, Error> {
    let (value, places) = parse_rate(rate).ok_or_else(|| {
        Error::Failed(format!(
            "the rate {rate:?} is not a positive decimal amount"
        ))
    })?;
    // `xmr × 1e6`, in millionths of a coin.
    let numerator = (price_pence as u128)
        .checked_mul(
            10u128
                .checked_pow(places + 4)
                .ok_or_else(|| Error::Failed("the rate has too many decimals".to_string()))?,
        )
        .ok_or_else(|| Error::Failed("the price and rate overflow the quote".to_string()))?;
    let millionths = numerator.div_ceil(value);
    let whole = millionths / 1_000_000;
    let fraction = millionths % 1_000_000;
    Ok(format!("{whole}.{fraction:06}"))
}

/// A positive decimal with at most twelve decimal places, the coin's atomic
/// unit. It is the shape the cache and the endpoint both have to produce before
/// either is used.
pub fn valid_rate(rate: &str) -> bool {
    parse_rate(rate).is_some()
}

/// A Monero transaction id is a 32-byte hash written as 64 hexadecimal
/// characters. Absent is valid: only a Monero credit carries one.
pub fn valid_txid(txid: Option<&str>) -> bool {
    match txid {
        None => true,
        Some(t) => t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()),
    }
}

/// An XMR amount is written as a decimal, never a float, with at most the
/// twelve decimal places the coin's atomic unit carries. Absent is valid.
pub fn valid_xmr(amount: Option<&str>) -> bool {
    let Some(amount) = amount else {
        return true;
    };
    let (whole, fraction) = amount.split_once('.').unwrap_or((amount, ""));
    !whole.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && fraction.len() <= 12
        && fraction.bytes().all(|b| b.is_ascii_digit())
}

/// `(R, d)` for a decimal `R / 10^d` with `R > 0`.
fn parse_rate(rate: &str) -> Option<(u128, u32)> {
    let (whole, fraction) = rate.split_once('.').unwrap_or((rate, ""));
    let places = fraction.len() as u32;
    if whole.is_empty()
        || places > 12
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let value: u128 = format!("{whole}{fraction}").parse().ok()?;
    (value > 0).then_some((value, places))
}

/// One HTTPS GET, with the response body on stdout. `-f` makes a non-2xx exit
/// non-zero rather than print an error page that would not parse anyway, and
/// `-m` bounds a source that answers and then stalls.
///
/// The child is run on a blocking thread with `std::process` rather than
/// through tokio's process driver: this is one short-lived command, and it runs
/// at the very start of every pass, where the driver's signal bookkeeping is the
/// one thing on the path that can strand a completed child.
async fn fetch(cfg: &DrainConfig) -> Option<String> {
    let program = cfg.rates_fetch.clone();
    let endpoint = cfg.rate_endpoint.clone();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(program)
            .args(["-fsS", "-m", "15", &endpoint])
            .output()
    })
    .await;
    let out = match out {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            Error::Io {
                what: "run the rate fetch",
                path: Some(cfg.rates_fetch.clone().into()),
                source: e,
            }
            .report("the rate fetch");
            return None;
        }
        Err(e) => {
            Error::Failed(format!("the rate fetch did not finish: {e}")).report("the rate fetch");
            return None;
        }
    };
    if !out.status.success() {
        let reason = String::from_utf8_lossy(&out.stderr);
        Error::Failed(format!(
            "{} {} exited {}: {}",
            cfg.rates_fetch,
            cfg.rate_endpoint,
            out.status,
            reason.trim()
        ))
        .report("the rate fetch");
        return None;
    }
    let body: serde_json::Value = match serde_json::from_slice(&out.stdout) {
        Ok(body) => body,
        Err(e) => {
            Error::Json {
                what: "parse the rate answer",
                source: e,
            }
            .report(&cfg.rate_endpoint);
            return None;
        }
    };
    // `{"monero":{"gbp":409.44,"last_updated_at":1790857880}}`. The number's
    // own text is kept, so no float ever reaches the quote's arithmetic.
    let Some(rate) = body.get("monero").and_then(|m| m.get("gbp")) else {
        Error::Refused(format!(
            "{} answered no monero.gbp price",
            cfg.rate_endpoint
        ))
        .report("the rate fetch");
        return None;
    };
    let rate = rate.to_string();
    if !valid_rate(&rate) {
        Error::Refused(format!(
            "{} answered a rate that is not a decimal: {rate}",
            cfg.rate_endpoint
        ))
        .report("the rate fetch");
        return None;
    }
    Some(rate)
}

/// Write the cache. The temporary file and the rename are what keeps a reader
/// from seeing half a file if the drain dies mid-write.
fn write(cfg: &DrainConfig, cached: &Cached) -> Result<(), Error> {
    if let Some(dir) = Path::new(&cfg.rates).parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::context(format!("cannot make {}", dir.display()), e))?;
    }
    let bytes = serde_json::to_vec_pretty(cached)
        .map_err(|e| Error::context("cannot encode the rate", e))?;
    let temp = format!("{}.new", cfg.rates);
    std::fs::write(&temp, &bytes).map_err(|e| Error::context(format!("cannot write {temp}"), e))?;
    std::fs::rename(&temp, &cfg.rates)
        .map_err(|e| Error::context(format!("cannot rename {temp}"), e))
}

fn attempt_path(cfg: &DrainConfig) -> String {
    format!("{}.attempt", cfg.rates)
}

/// Whether a fetch was tried inside the retry window, so an unreachable source
/// is not asked every minute.
fn attempted_recently(cfg: &DrainConfig, now: OffsetDateTime) -> bool {
    std::fs::read_to_string(attempt_path(cfg))
        .ok()
        .and_then(|text| parse_stamp(text.trim()))
        .is_some_and(|at| now - at < RETRY)
}

fn stamp_attempt(cfg: &DrainConfig, now: OffsetDateTime) -> Result<(), Error> {
    let path = attempt_path(cfg);
    if let Some(dir) = Path::new(&path).parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::context(format!("cannot make {}", dir.display()), e))?;
    }
    std::fs::write(&path, crate::util::stamp(now))
        .map_err(|e| Error::context(format!("cannot write {path}"), e))
}

fn parse_stamp(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_quote_rounds_up_to_six_places() {
        // 20.00 / 409.44 = 0.04884720..., so the quote is the next millionth up.
        assert_eq!(quote_xmr(2000, "409.44").unwrap(), "0.048848");
        // An exact division is not pushed up a unit.
        assert_eq!(quote_xmr(2000, "400.00").unwrap(), "0.050000");
        assert_eq!(quote_xmr(2000, "200").unwrap(), "0.100000");
        // A rate with more places is still exact arithmetic.
        assert_eq!(quote_xmr(2000, "409.4412").unwrap(), "0.048848");
    }

    #[test]
    fn a_rate_that_is_not_a_positive_decimal_is_refused() {
        for bad in ["", "0", "0.00", "-409.44", "409.44.0", "1e3", "409,44"] {
            assert!(quote_xmr(2000, bad).is_err(), "{bad:?} was accepted");
        }
        assert!(valid_rate("0.000000000001"));
        assert!(
            !valid_rate("0.0000000000001"),
            "thirteen places is not a rate"
        );
    }

    #[test]
    fn a_credit_fields_validator_accepts_only_the_coin_shape() {
        let txid = "a".repeat(64);
        let short = "a".repeat(63);
        let non_hex = format!("{}g", "a".repeat(63));
        assert!(valid_txid(None));
        assert!(valid_txid(Some(txid.as_str())));
        assert!(!valid_txid(Some("not-a-txid")));
        assert!(!valid_txid(Some(short.as_str())), "short");
        assert!(!valid_txid(Some(non_hex.as_str())), "non-hex");
        assert!(valid_xmr(None));
        assert!(valid_xmr(Some("0.048847")));
        assert!(valid_xmr(Some("20")));
        assert!(!valid_xmr(Some("0.1.2")));
        assert!(!valid_xmr(Some("")));
        assert!(!valid_xmr(Some(".5")));
        assert!(!valid_xmr(Some("0.0000000000001")), "thirteen places");
    }

    #[test]
    fn freshness_is_the_twenty_four_hour_window() {
        let now = OffsetDateTime::parse("2026-10-02T09:00:00Z", &Rfc3339).unwrap();
        let mut cached = Cached {
            version: 1,
            rate_gbp_per_xmr: "409.44".to_string(),
            source: SOURCE.to_string(),
            fetched_at: "2026-10-01T09:00:01Z".to_string(),
        };
        assert!(fresh(&cached, now));
        cached.fetched_at = "2026-10-01T09:00:00Z".to_string();
        assert!(!fresh(&cached, now), "exactly 24 hours is due");
        cached.fetched_at = "not a stamp".to_string();
        assert!(!fresh(&cached, now), "an unreadable timestamp is not fresh");
    }
}
