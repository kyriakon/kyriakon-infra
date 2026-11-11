//! The payment ledger: one typed line, one append that allocates the next
//! `seq` under the ledger's own lock, and the queries the money transitions ask.
//!
//! `ledger/payments.jsonl` is append-only and root-owned. A line is a payment, a
//! refund, the window an approval opens or a card invoice; the shape is one
//! struct rather than a `json!` per writer, so a renamed field is a compile
//! error in every caller. The on-disk field set is unchanged: a payment omits
//! the four refund-only fields, and a refund carries them, null included, so a
//! line written before this module still reads and a line written after it is
//! the shape the accountant's export expects.
//!
//! [`Ledger::append`] is the only writer. It holds [`Log::lock`] across the read
//! of the highest `seq` and the append, so a credit and a refund cannot claim
//! the same number. A settlement is the one rewrite, through
//! [`Ledger::settle_refund`], under the same lock.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::store::{Log, Store};
use crate::util;
use crate::Error;

/// The one ledger of money movements.
pub const PAYMENTS: &str = "ledger/payments.jsonl";

/// One line of the payment ledger as recorded.
#[derive(Clone, Debug, Serialize)]
pub struct LedgerLine {
    pub version: u64,
    pub seq: u64,
    pub token: String,
    pub kind: String,
    pub rail: String,
    pub received_on: Option<String>,
    pub amount_gbp: Option<String>,
    pub applied_gbp: Option<String>,
    pub paid_until_after: Option<String>,
    pub amount_xmr: Option<String>,
    pub rate_quoted: Option<String>,
    pub rate_source: Option<String>,
    pub rate_at: Option<String>,
    /// The XMR/GBP rate in force on `received_on`, and its source and the day
    /// it is struck. A Monero payment records it beside the window's quote,
    /// because the income is valued at the receipt date. Absent on every other
    /// rail and on a Monero row whose receipt-date rate is not known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_received: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_received_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_received_at: Option<String>,
    pub txid: Option<String>,
    pub intent: Option<String>,
    pub note: Option<String>,
    /// The settlement a refund line carries after it is paid out. Absent on
    /// every other line, which is why it is skipped rather than written as null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settled_intent: Option<String>,
    /// The refund-only fields, absent on a payment or a window's line.
    #[serde(flatten)]
    pub refund: Option<RefundTail>,
}

/// The four fields a refund line carries and a payment line does not. The whole
/// block is present on a refund even when a field is null, which is the shape
/// the refund writer has always recorded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefundTail {
    #[serde(default)]
    pub refund_of: Option<u64>,
    #[serde(default)]
    pub settled_on: Option<String>,
    #[serde(default)]
    pub refund_basis: Option<String>,
    #[serde(default)]
    pub rate_refund: Option<String>,
}

/// The fields as they sit on disk. Deserialising through this type is what lets
/// a payment's absent refund block stay absent: a flattened `Option` would give
/// every parsed payment an empty tail, and re-serialising it would invent four
/// null refund keys.
#[derive(Deserialize)]
struct LedgerLineRecord {
    version: u64,
    seq: u64,
    token: String,
    kind: String,
    rail: String,
    #[serde(default)]
    received_on: Option<String>,
    #[serde(default)]
    amount_gbp: Option<String>,
    #[serde(default)]
    applied_gbp: Option<String>,
    #[serde(default)]
    paid_until_after: Option<String>,
    #[serde(default)]
    amount_xmr: Option<String>,
    #[serde(default)]
    rate_quoted: Option<String>,
    #[serde(default)]
    rate_source: Option<String>,
    #[serde(default)]
    rate_at: Option<String>,
    #[serde(default)]
    rate_received: Option<String>,
    #[serde(default)]
    rate_received_source: Option<String>,
    #[serde(default)]
    rate_received_at: Option<String>,
    #[serde(default)]
    txid: Option<String>,
    #[serde(default)]
    intent: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    settled_intent: Option<String>,
    #[serde(default)]
    refund_of: Option<u64>,
    #[serde(default)]
    settled_on: Option<String>,
    #[serde(default)]
    refund_basis: Option<String>,
    #[serde(default)]
    rate_refund: Option<String>,
}

impl<'de> Deserialize<'de> for LedgerLine {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = LedgerLineRecord::deserialize(deserializer)?;
        let refund = if raw.refund_of.is_some()
            || raw.settled_on.is_some()
            || raw.refund_basis.is_some()
            || raw.rate_refund.is_some()
        {
            Some(RefundTail {
                refund_of: raw.refund_of,
                settled_on: raw.settled_on,
                refund_basis: raw.refund_basis,
                rate_refund: raw.rate_refund,
            })
        } else {
            None
        };
        Ok(LedgerLine {
            version: raw.version,
            seq: raw.seq,
            token: raw.token,
            kind: raw.kind,
            rail: raw.rail,
            received_on: raw.received_on,
            amount_gbp: raw.amount_gbp,
            applied_gbp: raw.applied_gbp,
            paid_until_after: raw.paid_until_after,
            amount_xmr: raw.amount_xmr,
            rate_quoted: raw.rate_quoted,
            rate_source: raw.rate_source,
            rate_at: raw.rate_at,
            rate_received: raw.rate_received,
            rate_received_source: raw.rate_received_source,
            rate_received_at: raw.rate_received_at,
            txid: raw.txid,
            intent: raw.intent,
            note: raw.note,
            settled_intent: raw.settled_intent,
            refund,
        })
    }
}

impl LedgerLine {
    /// The fields every kind shares, with the optional ones empty. A caller
    /// fills the named fields it records; one it forgets writes as null, the
    /// same shape its hand-built line had.
    pub fn empty(token: &str, kind: &str, rail: &str) -> LedgerLine {
        LedgerLine {
            version: 1,
            seq: 0,
            token: token.to_string(),
            kind: kind.to_string(),
            rail: rail.to_string(),
            received_on: None,
            amount_gbp: None,
            applied_gbp: None,
            paid_until_after: None,
            amount_xmr: None,
            rate_quoted: None,
            rate_source: None,
            rate_at: None,
            rate_received: None,
            rate_received_source: None,
            rate_received_at: None,
            txid: None,
            intent: None,
            note: None,
            settled_intent: None,
            refund: None,
        }
    }

    /// The payment `seq` a refund reverses, when this is a refund line.
    pub fn refund_of(&self) -> Option<u64> {
        self.refund.as_ref().and_then(|refund| refund.refund_of)
    }

    /// The day a refund was paid out, when it has been settled.
    pub fn settled_on(&self) -> Option<&str> {
        self.refund
            .as_ref()
            .and_then(|refund| refund.settled_on.as_deref())
    }

    /// What a refund gives back: the recorded XMR or the sterling price.
    pub fn refund_basis(&self) -> Option<&str> {
        self.refund
            .as_ref()
            .and_then(|refund| refund.refund_basis.as_deref())
    }

    /// The refund-date rate, when the refund was paid in sterling.
    pub fn rate_refund(&self) -> Option<&str> {
        self.refund
            .as_ref()
            .and_then(|refund| refund.rate_refund.as_deref())
    }
}

/// The refunds that reverse one payment, and their total in pence. One read
/// answers both the identical-refund check and the cap, so the file is parsed
/// once.
pub struct RefundSum {
    pub total: i64,
    pub lines: Vec<LedgerLine>,
}

/// The ledger's handle: the one append, the one settlement and the typed
/// queries. Built from [`Store::log`], so it takes the same lock as every other
/// writer of the same record.
pub struct Ledger<'a> {
    store: &'a Store,
    log: Log<'a>,
}

impl<'a> Ledger<'a> {
    pub fn open(store: &'a Store) -> Ledger<'a> {
        Ledger {
            store,
            log: store.log(PAYMENTS),
        }
    }

    /// Append one line, allocating its `seq` as one past the highest already
    /// recorded, inside the ledger's lock. Returns the number it wrote.
    pub async fn append(&self, mut line: LedgerLine) -> Result<u64, Error> {
        let guard = self.log.lock().await?;
        let mut last = 0u64;
        self.log
            .jsonl_each(|_, seen: &LedgerLine| last = last.max(seen.seq))
            .await?;
        line.seq = last + 1;
        // Every line on disk was written from a `json!` value, whose object is
        // sorted. Going through `Value` keeps the key order identical; a struct
        // serialised directly would write declaration order.
        let value = serde_json::to_value(&line)
            .map_err(|e| Error::context("cannot encode the ledger", e))?;
        let encoded = serde_json::to_string(&value)
            .map_err(|e| Error::context("cannot encode the ledger", e))?;
        self.log
            .append_while_locked(&guard, encoded.as_bytes())
            .await?;
        drop(guard);
        Ok(line.seq)
    }

    /// Every line, typed. A line that does not parse is an error.
    pub async fn lines(&self) -> Result<Vec<LedgerLine>, Error> {
        self.log.jsonl().await.map_err(Error::from)
    }

    /// The token's most recent payment line: what a refund reverses. Every
    /// payment line for the token must carry an amount, because a refund cannot
    /// reverse one it cannot read.
    pub async fn last_payment(&self, token: &str) -> Result<Option<LedgerLine>, Error> {
        let mut found = None;
        for line in self.lines().await? {
            if line.token == token && line.kind == "payment" {
                if line.amount_gbp.is_none() {
                    return Err(Error::Failed(
                        "a payment line carries no amount".to_string(),
                    ));
                }
                found = Some(line);
            }
        }
        Ok(found)
    }

    /// The token's refund lines, oldest first.
    pub async fn refunds(&self, token: &str) -> Result<Vec<LedgerLine>, Error> {
        let mut found = Vec::new();
        self.log
            .jsonl_each(|_, line: &LedgerLine| {
                if line.token == token && line.kind == "refund" {
                    found.push(line.clone());
                }
            })
            .await?;
        Ok(found)
    }

    /// The token's refunds that reverse `original`, with their total in pence.
    /// An amount this cannot read is an error, never zero: counting it as zero
    /// would let this refund and the unreadable one together exceed the payment.
    pub async fn refunded_total(&self, token: &str, original: u64) -> Result<RefundSum, Error> {
        let mut total = 0i64;
        let mut lines = Vec::new();
        for line in self.refunds(token).await? {
            if line.refund_of() != Some(original) {
                continue;
            }
            let text = line.amount_gbp.as_deref().ok_or_else(|| {
                Error::Failed(format!(
                    "the refund at ledger seq {} has no amount",
                    line.seq
                ))
            })?;
            let pence = util::pence(text.strip_prefix('-').unwrap_or(text)).map_err(|e| {
                Error::context(
                    format!("the refund at ledger seq {} cannot be read", line.seq),
                    e,
                )
            })?;
            total += pence;
            lines.push(line);
        }
        Ok(RefundSum { total, lines })
    }

    /// Whether a refund line has already recorded this settlement intent.
    pub async fn settled_by(&self, intent: &str) -> Result<bool, Error> {
        self.log
            .jsonl_any(|line: &LedgerLine| line.settled_intent.as_deref() == Some(intent))
            .await
            .map_err(Error::from)
    }

    /// Whether the ledger already holds this intent's line.
    pub async fn has_intent(&self, intent: &str) -> Result<bool, Error> {
        self.log
            .jsonl_any(|line: &LedgerLine| line.intent.as_deref() == Some(intent))
            .await
            .map_err(Error::from)
    }

    /// Whether the approval already opened this token's window. Its dedup is
    /// the token and the kind, not an intent id.
    pub async fn has_window_open(&self, token: &str) -> Result<bool, Error> {
        self.log
            .jsonl_any(|line: &LedgerLine| line.token == token && line.kind == "window_open")
            .await
            .map_err(Error::from)
    }

    /// The first line carrying this transaction id.
    pub async fn by_txid(&self, txid: &str) -> Result<Option<LedgerLine>, Error> {
        let mut found = None;
        self.log
            .jsonl_each(|_, line: &LedgerLine| {
                if found.is_none() && line.txid.as_deref() == Some(txid) {
                    found = Some(line.clone());
                }
            })
            .await?;
        Ok(found)
    }

    /// The token's lines as recorded, for the export, which copies them rather
    /// than re-encoding the fields this build models. A line written by an
    /// earlier release that this build cannot model is not the member's line, so
    /// it is skipped rather than failing their whole export.
    pub async fn raw_lines_for(&self, token: &str) -> Result<Vec<String>, Error> {
        let mut out = Vec::new();
        for raw in self.log.raw_lines().await? {
            let Ok(value) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            if value.get("token").and_then(Value::as_str) == Some(token) {
                out.push(raw);
            }
        }
        Ok(out)
    }

    /// The token's lines typed, skipping a line this build cannot model. For the
    /// display readers, which must not lose a member's whole answer to one
    /// legacy line; the money readers use [`Self::lines`] and fail instead.
    pub async fn lines_for(&self, token: &str) -> Result<Vec<LedgerLine>, Error> {
        let mut out = Vec::new();
        for raw in self.log.raw_lines().await? {
            let Ok(value) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            if value.get("token").and_then(Value::as_str) != Some(token) {
                continue;
            }
            if let Ok(line) = serde_json::from_value::<LedgerLine>(value) {
                out.push(line);
            }
        }
        Ok(out)
    }

    /// Complete the newest unsettled refund line under the lock, and nothing
    /// else on it. This is the ledger's one non-append write: `--settled` names
    /// a line already recorded, and appending a second line would leave two
    /// records of one refund. The returned `seq` is the line that was settled.
    pub async fn settle_refund(
        &self,
        token: &str,
        intent: &str,
        on: &str,
    ) -> Result<Option<u64>, Error> {
        let guard = self.log.lock().await?;
        let mut lines = self.log.raw_lines().await?;
        let Some((index, settled)) = unsettled_index(&lines, token)? else {
            return Ok(None);
        };
        // Only the settled line is re-encoded, through a `Value`, so fields this
        // build does not model survive the rewrite. Its key order is what the
        // value held, not the order this struct would declare.
        let mut line: Value = serde_json::from_str(&lines[index])
            .map_err(|e| Error::context("the refund line does not parse", e))?;
        line["settled_on"] = serde_json::json!(on);
        line["settled_intent"] = serde_json::json!(intent);
        lines[index] = serde_json::to_string(&line)
            .map_err(|e| Error::context("cannot encode the ledger", e))?;
        let mut text = lines.join("\n");
        text.push('\n');
        self.store.rewrite_log(PAYMENTS, text.as_bytes()).await?;
        drop(guard);
        Ok(Some(settled.seq))
    }
}

/// The index and line of the newest refund for `token` without `settled_on`. A
/// line that does not parse is an error: a settlement must not skip a line it
/// cannot read and settle an older one in its place.
fn unsettled_index(lines: &[String], token: &str) -> Result<Option<(usize, LedgerLine)>, Error> {
    let mut found = None;
    for (index, raw) in lines.iter().enumerate() {
        let line: LedgerLine = serde_json::from_str(raw).map_err(|source| Error::ParseLine {
            path: PAYMENTS,
            line: index + 1,
            source,
        })?;
        if line.token == token && line.kind == "refund" && line.settled_on().is_none() {
            found = Some((index, line));
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("onboard-ledger-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn credit(intent: &str) -> LedgerLine {
        let mut line = LedgerLine::empty("KYR-AAAA-BBBB-CCCC", "payment", "cash");
        line.received_on = Some("2026-10-04".to_string());
        line.amount_gbp = Some("20.00".to_string());
        line.applied_gbp = Some("20.00".to_string());
        line.intent = Some(intent.to_string());
        line
    }

    fn refund(intent: &str) -> LedgerLine {
        let mut line = LedgerLine::empty("KYR-AAAA-BBBB-CCCC", "refund", "cash");
        line.received_on = Some("2026-10-04".to_string());
        line.amount_gbp = Some("-5.00".to_string());
        line.applied_gbp = Some("-5.00".to_string());
        line.intent = Some(intent.to_string());
        line.note = Some("overpaid".to_string());
        line.refund = Some(RefundTail {
            refund_of: Some(3),
            settled_on: None,
            refund_basis: None,
            rate_refund: None,
        });
        line
    }

    /// The bytes a new line puts on disk are the bytes the `json!` writers put
    /// there: the same sorted key order and the same nulls. A payment has no
    /// refund block; a refund has all four of its fields.
    #[tokio::test]
    async fn an_appended_line_keeps_the_recorded_key_order_and_nulls() {
        let dir = temp("bytes");
        let store = Store::new_for_test(dir.to_str().unwrap());
        let ledger = Ledger::open(&store);
        ledger.append(credit("in_credit")).await.unwrap();
        ledger.append(refund("in_refund")).await.unwrap();
        let lines = store.log(PAYMENTS).raw_lines().await.unwrap();
        assert_eq!(
            lines[0],
            r#"{"amount_gbp":"20.00","amount_xmr":null,"applied_gbp":"20.00","intent":"in_credit","kind":"payment","note":null,"paid_until_after":null,"rail":"cash","rate_at":null,"rate_quoted":null,"rate_source":null,"received_on":"2026-10-04","seq":1,"token":"KYR-AAAA-BBBB-CCCC","txid":null,"version":1}"#
        );
        assert_eq!(
            lines[1],
            r#"{"amount_gbp":"-5.00","amount_xmr":null,"applied_gbp":"-5.00","intent":"in_refund","kind":"refund","note":"overpaid","paid_until_after":null,"rail":"cash","rate_at":null,"rate_quoted":null,"rate_refund":null,"rate_source":null,"received_on":"2026-10-04","refund_basis":null,"refund_of":3,"seq":2,"settled_on":null,"token":"KYR-AAAA-BBBB-CCCC","txid":null,"version":1}"#
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A Monero row records the receipt-date rate beside the window quote, and
    /// a line written before those fields existed still parses with them absent.
    #[test]
    fn a_receipt_rate_round_trips_and_an_old_line_parses_without_it() {
        let raw = r#"{"amount_gbp":"20.00","applied_gbp":"20.00","intent":"in_credit","kind":"payment","rail":"monero","seq":1,"token":"KYR-AAAA-BBBB-CCCC","version":1}"#;
        let old: LedgerLine = serde_json::from_str(raw).unwrap();
        assert!(old.rate_received.is_none());
        let value = serde_json::to_value(&old).unwrap();
        assert!(value.get("rate_received").is_none(), "{value}");

        let mut line = credit("in_credit");
        line.rail = "monero".to_string();
        line.rate_received = Some("409.44".to_string());
        line.rate_received_source = Some("coingecko".to_string());
        line.rate_received_at = Some("2026-10-01T09:00:00Z".to_string());
        let parsed: LedgerLine =
            serde_json::from_str(&serde_json::to_string(&line).unwrap()).unwrap();
        assert_eq!(parsed.rate_received.as_deref(), Some("409.44"));
        assert_eq!(parsed.rate_received_source.as_deref(), Some("coingecko"));
        assert_eq!(
            parsed.rate_received_at.as_deref(),
            Some("2026-10-01T09:00:00Z")
        );
    }

    /// Parsing a payment and writing it again must not invent the refund block.
    #[test]
    fn parsing_a_payment_does_not_add_a_refund_block() {
        let raw = r#"{"amount_gbp":"20.00","applied_gbp":"20.00","intent":"in_credit","kind":"payment","rail":"cash","seq":1,"token":"KYR-AAAA-BBBB-CCCC","version":1}"#;
        let line: LedgerLine = serde_json::from_str(raw).unwrap();
        assert!(line.refund.is_none());
        let value = serde_json::to_value(&line).unwrap();
        assert!(value.get("refund_of").is_none(), "{value}");
        assert!(value.get("settled_on").is_none(), "{value}");
    }

    /// A partial line for another token is skipped by the export reader, while
    /// the settlement still refuses to read past it.
    #[tokio::test]
    async fn a_partial_line_for_another_token_does_not_break_the_export() {
        let dir = temp("partial");
        let store = Store::new_for_test(dir.to_str().unwrap());
        let ledger = Ledger::open(&store);
        ledger.append(credit("in_credit")).await.unwrap();
        store
            .log(PAYMENTS)
            .append(br#"{"token":"KYR-ZZZZ-ZZZZ-ZZZZ","amount_gbp":"5.00"}"#)
            .await
            .unwrap();

        let exported = ledger.raw_lines_for("KYR-AAAA-BBBB-CCCC").await.unwrap();
        assert_eq!(exported.len(), 1, "{exported:?}");
        let error = ledger
            .settle_refund("KYR-ZZZZ-ZZZZ-ZZZZ", "in_settle", "2026-11-05")
            .await
            .expect_err("a settlement must not skip a line it cannot read");
        assert!(
            matches!(&error, Error::ParseLine { line: 2, .. }),
            "{error}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The number is allocated inside the lock every append takes: an append
    /// waits for the record's lock, then numbers after the highest line already
    /// written.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_append_waits_for_the_lock_and_numbers_after_the_highest_seq() {
        let dir = temp("seq");
        let store = Store::new_for_test(dir.to_str().unwrap());
        let mut first = serde_json::to_value(credit("in_first")).unwrap();
        first["seq"] = 41.into();
        store
            .log(PAYMENTS)
            .append(serde_json::to_string(&first).unwrap().as_bytes())
            .await
            .unwrap();

        let held = store.log(PAYMENTS).lock().await.unwrap();
        let root = dir.to_str().unwrap().to_string();
        let append = std::thread::spawn(move || {
            let store = Store::new_for_test(&root);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(Ledger::open(&store).append(credit("in_second")))
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(
            store.log(PAYMENTS).raw_lines().await.unwrap().len(),
            1,
            "the append wrote without the ledger's lock"
        );
        drop(held);
        assert_eq!(append.join().unwrap().unwrap(), 42);

        let lines = Ledger::open(&store).lines().await.unwrap();
        assert_eq!(
            lines.iter().map(|line| line.seq).collect::<Vec<_>>(),
            [41, 42]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two appends in sequence get distinct, increasing numbers. The lock is
    /// what keeps them distinct when two processes append at once.
    #[tokio::test]
    async fn two_appends_get_distinct_increasing_seqs() {
        let dir = temp("distinct");
        let store = Store::new_for_test(dir.to_str().unwrap());
        let ledger = Ledger::open(&store);
        assert_eq!(ledger.append(credit("in_one")).await.unwrap(), 1);
        assert_eq!(ledger.append(credit("in_two")).await.unwrap(), 2);
        let lines = ledger.lines().await.unwrap();
        assert_eq!(
            lines.iter().map(|line| line.seq).collect::<Vec<_>>(),
            [1, 2]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
