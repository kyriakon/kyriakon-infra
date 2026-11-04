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

use crate::store::{Log, Monero, Store};
use crate::util;

/// The one ledger of money movements.
pub const PAYMENTS: &str = "ledger/payments.jsonl";

/// One line of the payment ledger as recorded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerLine {
    pub version: u64,
    pub seq: u64,
    pub token: String,
    pub kind: String,
    pub rail: String,
    #[serde(default)]
    pub received_on: Option<String>,
    #[serde(default)]
    pub amount_gbp: Option<String>,
    #[serde(default)]
    pub applied_gbp: Option<String>,
    #[serde(default)]
    pub paid_until_after: Option<String>,
    #[serde(default)]
    pub amount_xmr: Option<String>,
    #[serde(default)]
    pub rate_quoted: Option<String>,
    #[serde(default)]
    pub rate_source: Option<String>,
    #[serde(default)]
    pub rate_at: Option<String>,
    #[serde(default)]
    pub txid: Option<String>,
    #[serde(default)]
    pub intent: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    /// The settlement a refund line carries after it is paid out. Absent on
    /// every other line, which is why it is skipped rather than written as null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

impl LedgerLine {
    /// The fields every kind shares, with the optional ones empty. A caller
    /// fills what it records; a field it forgets writes as null, the same shape
    /// its hand-built line had.
    fn empty(token: &str, kind: &str, rail: &str) -> LedgerLine {
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
            txid: None,
            intent: None,
            note: None,
            settled_intent: None,
            refund: None,
        }
    }

    /// A payment line: a prepaid credit or a paid card invoice. Only a Monero
    /// credit carries the quote that produced its window.
    #[allow(clippy::too_many_arguments)]
    pub fn payment(
        token: &str,
        rail: &str,
        received_on: &str,
        amount_gbp: &str,
        applied_gbp: &str,
        paid_until_after: Option<&str>,
        amount_xmr: Option<&str>,
        quoted: Option<&Monero>,
        txid: Option<&str>,
        intent: &str,
    ) -> LedgerLine {
        let mut line = LedgerLine::empty(token, "payment", rail);
        line.received_on = Some(received_on.to_string());
        line.amount_gbp = Some(amount_gbp.to_string());
        line.applied_gbp = Some(applied_gbp.to_string());
        line.paid_until_after = paid_until_after.map(str::to_string);
        line.amount_xmr = amount_xmr.map(str::to_string);
        line.rate_quoted = quoted.and_then(|m| m.rate_gbp_per_xmr.clone());
        line.rate_source = quoted.and_then(|m| m.rate_source.clone());
        line.rate_at = quoted.and_then(|m| m.rate_at.clone());
        line.txid = txid.map(str::to_string);
        line.intent = Some(intent.to_string());
        line
    }

    /// A refund's negative line. The amount is negative in both money fields so
    /// a sum over the ledger is the year's takings.
    #[allow(clippy::too_many_arguments)]
    pub fn refund(
        token: &str,
        rail: &str,
        received_on: &str,
        amount_gbp: &str,
        paid_until_after: Option<&str>,
        amount_xmr: Option<&str>,
        intent: &str,
        note: &str,
        refund_of: u64,
        refund_basis: Option<&str>,
        rate_refund: Option<&str>,
    ) -> LedgerLine {
        let mut line = LedgerLine::empty(token, "refund", rail);
        line.received_on = Some(received_on.to_string());
        line.amount_gbp = Some(amount_gbp.to_string());
        line.applied_gbp = Some(amount_gbp.to_string());
        line.paid_until_after = paid_until_after.map(str::to_string);
        line.amount_xmr = amount_xmr.map(str::to_string);
        line.intent = Some(intent.to_string());
        line.note = Some(note.to_string());
        line.refund = Some(RefundTail {
            refund_of: Some(refund_of),
            settled_on: None,
            refund_basis: refund_basis.map(str::to_string),
            rate_refund: rate_refund.map(str::to_string),
        });
        line
    }

    /// The window a paid approval opens: the amount owed and the day it falls
    /// due, before any money has arrived.
    pub fn window_open(
        token: &str,
        rail: &str,
        amount_gbp: &str,
        rate_at: &str,
        intent: &str,
    ) -> LedgerLine {
        let mut line = LedgerLine::empty(token, "window_open", rail);
        line.amount_gbp = Some(amount_gbp.to_string());
        line.applied_gbp = Some("0.00".to_string());
        line.rate_at = Some(rate_at.to_string());
        line.intent = Some(intent.to_string());
        line.note = Some("the window opened at approval; no money has arrived yet".to_string());
        line
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
    pub async fn append(&self, mut line: LedgerLine) -> Result<u64, String> {
        let guard = self.log.lock().await?;
        let mut last = 0u64;
        self.log
            .jsonl_each(|_, seen: &LedgerLine| last = last.max(seen.seq))
            .await?;
        line.seq = last + 1;
        let encoded =
            serde_json::to_string(&line).map_err(|e| format!("cannot encode the ledger: {e}"))?;
        self.log.append_while_locked(encoded.as_bytes()).await?;
        drop(guard);
        Ok(line.seq)
    }

    /// Every line, typed. A line that does not parse is an error.
    pub async fn lines(&self) -> Result<Vec<LedgerLine>, String> {
        self.log.jsonl().await
    }

    /// The token's most recent payment line: what a refund reverses. Every
    /// payment line for the token must carry an amount, because a refund cannot
    /// reverse one it cannot read.
    pub async fn last_payment(&self, token: &str) -> Result<Option<LedgerLine>, String> {
        let mut found = None;
        for line in self.lines().await? {
            if line.token == token && line.kind == "payment" {
                if line.amount_gbp.is_none() {
                    return Err("a payment line carries no amount".to_string());
                }
                found = Some(line);
            }
        }
        Ok(found)
    }

    /// The token's refund lines, oldest first.
    pub async fn refunds(&self, token: &str) -> Result<Vec<LedgerLine>, String> {
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

    /// The token's refunds that reverse `original`: the one filter the refund
    /// cap asks, rather than a copy of it in the caller.
    pub async fn refunds_of(&self, token: &str, original: u64) -> Result<Vec<LedgerLine>, String> {
        Ok(self
            .refunds(token)
            .await?
            .into_iter()
            .filter(|line| line.refund_of() == Some(original))
            .collect())
    }

    /// What the token's refunds of `original` total, in pence. An amount this
    /// cannot read is an error, never zero: counting it as zero would let this
    /// refund and the unreadable one together exceed the payment.
    pub async fn refunded_total(&self, token: &str, original: u64) -> Result<i64, String> {
        let mut total = 0i64;
        for line in self.refunds_of(token, original).await? {
            let text = line
                .amount_gbp
                .as_deref()
                .ok_or_else(|| format!("the refund at ledger seq {} has no amount", line.seq))?;
            let pence = util::pence(text.strip_prefix('-').unwrap_or(text)).map_err(|e| {
                format!("the refund at ledger seq {} cannot be read: {e}", line.seq)
            })?;
            total += pence;
        }
        Ok(total)
    }

    /// The newest refund line for the token with no `settled_on`.
    pub async fn unsettled_refund(&self, token: &str) -> Result<Option<LedgerLine>, String> {
        let lines = self.log.raw_lines().await?;
        Ok(unsettled_index(&lines, token)?.map(|(_, line)| line))
    }

    /// Whether a refund line has already recorded this settlement intent.
    pub async fn settled_by(&self, intent: &str) -> Result<bool, String> {
        self.log
            .jsonl_any(|line: &LedgerLine| line.settled_intent.as_deref() == Some(intent))
            .await
    }

    /// Whether the ledger already holds this intent's line.
    pub async fn has_intent(&self, intent: &str) -> Result<bool, String> {
        self.log
            .jsonl_any(|line: &LedgerLine| line.intent.as_deref() == Some(intent))
            .await
    }

    /// Whether the token already has a line of this kind, for the one dedup that
    /// is not keyed by an intent id.
    pub async fn has_token_kind(&self, token: &str, kind: &str) -> Result<bool, String> {
        self.log
            .jsonl_any(|line: &LedgerLine| line.token == token && line.kind == kind)
            .await
    }

    /// The first line carrying this transaction id.
    pub async fn by_txid(&self, txid: &str) -> Result<Option<LedgerLine>, String> {
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
    /// than re-encoding the fields this build models.
    pub async fn raw_lines_for(&self, token: &str) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for (index, raw) in self.log.raw_lines().await?.iter().enumerate() {
            let line: LedgerLine = serde_json::from_str(raw)
                .map_err(|e| format!("{PAYMENTS}: line {} does not parse: {e}", index + 1))?;
            if line.token == token {
                out.push(raw.clone());
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
    ) -> Result<Option<u64>, String> {
        let guard = self.log.lock().await?;
        let mut lines = self.log.raw_lines().await?;
        let Some((index, settled)) = unsettled_index(&lines, token)? else {
            return Ok(None);
        };
        // The lines stay as recorded: only the settled one is re-encoded, so a
        // line an earlier release wrote keeps its bytes and its unknown fields.
        let mut line: Value = serde_json::from_str(&lines[index])
            .map_err(|e| format!("the refund line does not parse: {e}"))?;
        line["settled_on"] = serde_json::json!(on);
        line["settled_intent"] = serde_json::json!(intent);
        lines[index] =
            serde_json::to_string(&line).map_err(|e| format!("cannot encode the ledger: {e}"))?;
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
fn unsettled_index(lines: &[String], token: &str) -> Result<Option<(usize, LedgerLine)>, String> {
    let mut found = None;
    for (index, raw) in lines.iter().enumerate() {
        let line: LedgerLine = serde_json::from_str(raw)
            .map_err(|e| format!("{PAYMENTS}: line {} does not parse: {e}", index + 1))?;
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
        LedgerLine::payment(
            "KYR-AAAA-BBBB-CCCC",
            "cash",
            "2026-10-04",
            "20.00",
            "20.00",
            None,
            None,
            None,
            None,
            intent,
        )
    }

    /// The printed key order is not part of the shape, but the key set and the
    /// nulls are: a payment omits the refund block, and a refund carries all
    /// four of its fields, null included.
    #[test]
    fn a_credit_and_a_refund_serialise_the_current_key_shape() {
        let credit = serde_json::to_value(credit("in_credit")).unwrap();
        assert_eq!(
            credit
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            [
                "amount_gbp",
                "amount_xmr",
                "applied_gbp",
                "intent",
                "kind",
                "note",
                "paid_until_after",
                "rail",
                "rate_at",
                "rate_quoted",
                "rate_source",
                "received_on",
                "seq",
                "token",
                "txid",
                "version",
            ]
        );
        for field in [
            "amount_xmr",
            "paid_until_after",
            "note",
            "rate_quoted",
            "rate_source",
            "rate_at",
            "txid",
        ] {
            assert!(credit[field].is_null(), "{field} is not null: {credit}");
        }
        assert_eq!(credit["amount_gbp"], "20.00");
        assert!(credit.get("refund_of").is_none(), "{credit}");

        let refund = serde_json::to_value(LedgerLine::refund(
            "KYR-AAAA-BBBB-CCCC",
            "cash",
            "2026-10-04",
            "-5.00",
            None,
            None,
            "in_refund",
            "overpaid",
            3,
            None,
            None,
        ))
        .unwrap();
        assert_eq!(
            refund
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            [
                "amount_gbp",
                "amount_xmr",
                "applied_gbp",
                "intent",
                "kind",
                "note",
                "paid_until_after",
                "rail",
                "rate_at",
                "rate_quoted",
                "rate_refund",
                "rate_source",
                "received_on",
                "refund_basis",
                "refund_of",
                "seq",
                "settled_on",
                "token",
                "txid",
                "version",
            ]
        );
        for field in [
            "amount_xmr",
            "paid_until_after",
            "rate_quoted",
            "rate_source",
            "rate_at",
            "txid",
            "settled_on",
            "refund_basis",
            "rate_refund",
        ] {
            assert!(refund[field].is_null(), "{field} is not null: {refund}");
        }
        assert_eq!(refund["refund_of"], 3);
        assert_eq!(refund["amount_gbp"], "-5.00");
        assert_eq!(refund["applied_gbp"], "-5.00");
        assert!(refund.get("settled_intent").is_none(), "{refund}");
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
