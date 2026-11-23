//! The two per-address counters the spec fixes: sixty requests a minute and five
//! drafts a day. No CAPTCHA and no challenge, because a person reads every
//! application and that is the gate.
//!
//! The counters are process state, so a restart clears them. That is the
//! accepted ceiling: a restart is rare and the gate does not depend on them.
//!
//! Both maps are bounded. The request map drops a batch of its oldest entries at
//! `MAX_KEYS`, so an attacker cannot grow memory without bound and the scan that
//! finds the batch happens once per batch of new addresses rather than on every
//! request. The draft map holds a day, so it makes room by dropping a bucket that
//! is below its cap and refuses a new source only when every bucket is at its cap.
//! A capped bucket is never dropped: that would hand a rotating source a fresh
//! daily cap.
//!
//! A std mutex, not parking_lot: the release's dependency list is frozen and a
//! counter held for a few instructions does not earn a new crate. The lock is
//! taken with `into_inner` on a poison rather than unwrapping, because a counter
//! poisoned by a panic elsewhere should still count rather than take the handler
//! down.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const REQUESTS_PER_MINUTE: usize = 60;
pub const DRAFTS_PER_DAY: usize = 5;

const MINUTE: Duration = Duration::from_secs(60);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// The most keys either map holds. The request map drops a batch past it; the
/// draft map makes room for one source and refuses when every bucket is at its
/// cap.
pub const MAX_KEYS: usize = 4096;
/// The bits of an IPv6 address a bucket keeps: one site delegation. A /56 or /48
/// holder can rotate the /64s inside it, so a /64 bucket would mint a fresh cap
/// per address it owns.
const V6_PREFIX_MASK: u64 = 0xffff_ffff_ffff_0000;
/// How many of the oldest to drop when the cap is reached. Draining a batch
/// leaves the next `EVICT_BATCH` new addresses free of eviction work, which is
/// what makes the cost amortised rather than a scan per request.
const EVICT_BATCH: usize = MAX_KEYS / 8;

/// What a counter is keyed on.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Key {
    /// An IPv4 address, whole.
    V4(Ipv4Addr),
    /// An IPv6 address's /48 prefix, as the top 64 bits with the bits below the
    /// prefix zeroed. A smaller prefix lets a delegated /56 or /48 mint a bucket
    /// per /64 inside it.
    V6(u64),
    /// An `X-Forwarded-For` that is present but does not parse. It gets its own
    /// single key rather than collapsing onto the peer, which would let a caller
    /// escape the peer's bucket, and rather than minting a key per string, which
    /// would be unbounded.
    UnknownForward,
}

/// The client's key, from what the front-end observed about the request.
///
/// The web front-end arrives through relayd, which `match header set
/// "X-Forwarded-For" value "$REMOTE_ADDR"`s the header rather than appending to
/// it, so the last element is the address the terminator accepted the connection
/// from and a value a client prepended is not there to be read. httpd passes the
/// header on to a responder as `HTTP_X_FORWARDED_FOR`, and that is the only
/// place in this service where a forwarded value is read.
///
/// The gemini front-end has no forwarded header of any kind: gmid sends none, so
/// its `REMOTE_ADDR` is the socket peer as the kernel saw it and a header read
/// there would be one the applicant wrote. `forwarded` is passed by the caller
/// that knows which front-end it is answering, rather than by sniffing the
/// environment here, because the two are different questions.
///
/// `peer` is that `REMOTE_ADDR`. It is arbitrary text from the environment, so an
/// address that does not parse shares one key rather than falling back to
/// something a caller could choose.
pub fn key(forwarded: Option<&str>, peer: Option<&str>) -> Key {
    let observed = match forwarded {
        Some(value) => value.rsplit(',').next().map(str::trim),
        None => peer,
    };
    match observed.and_then(|v| v.parse::<IpAddr>().ok()) {
        Some(ip) => bucket(ip),
        None => Key::UnknownForward,
    }
}

fn bucket(ip: IpAddr) -> Key {
    // `to_canonical` turns `::ffff:a.b.c.d` into the IPv4 address, so a
    // dual-stack front-end that reports the mapped form counts against the same
    // bucket as the plain one instead of collapsing every client onto `::`.
    match ip.to_canonical() {
        IpAddr::V4(v4) => Key::V4(v4),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            Key::V6(
                u64::from_be_bytes([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
                    & V6_PREFIX_MASK,
            )
        }
    }
}

/// The key as one field: what the login checker's failed-attempt record keys on,
/// so a source is the same address in both counters. A `Key::V6` is the /48 as a
/// prefix, because a delegated prefix of that size or smaller otherwise rotates
/// /64s to mint unlimited sources and unlimited guesses.
impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Key::V4(addr) => write!(f, "{addr}"),
            Key::V6(prefix) => write!(f, "{}/48", Ipv6Addr::from(u128::from(*prefix) << 64)),
            Key::UnknownForward => f.write_str("-"),
        }
    }
}

pub struct Counter {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    requests: HashMap<Key, Vec<Instant>>,
    drafts: Drafts,
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

impl Counter {
    pub fn new() -> Counter {
        Counter {
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Count one request. `false` once the key has made sixty in the last
    /// minute, so the sixty-first is the one refused.
    pub fn allow_request(&self, key: Key) -> bool {
        allow_request(&mut self.lock().requests, key)
    }

    /// Count one draft. The answer tells the front-end whether this source is
    /// at its cap or whether the map has no room for a source it has not seen.
    pub fn allow_draft(&self, key: Key) -> Admission {
        self.lock().drafts.allow(key, Instant::now())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The answer to one draft attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Admission {
    /// Counted.
    Allowed,
    /// This source has started its five in the day.
    Denied,
    /// Every bucket in the map is at its cap, so this source cannot be counted
    /// without dropping a live cap. The front-end answers a temporary failure
    /// rather than the per-source message.
    Unavailable,
}

fn allow_request(map: &mut HashMap<Key, Vec<Instant>>, key: Key) -> bool {
    let now = Instant::now();
    if map.len() >= MAX_KEYS && !map.contains_key(&key) {
        evict(map, now, MINUTE);
        if map.len() >= MAX_KEYS {
            drop_oldest(map, now);
        }
    }
    let times = map.entry(key).or_default();
    times.retain(|t| now.duration_since(*t) < MINUTE);
    if times.len() >= REQUESTS_PER_MINUTE {
        return false;
    }
    times.push(now);
    true
}

/// The draft map. It holds a day of starts, so the batch eviction a request map
/// can afford would erase a live cap. It makes room from a bucket below its cap,
/// and says `Unavailable` only when every bucket is at its cap.
#[derive(Default)]
struct Drafts {
    entries: HashMap<Key, Window>,
    /// Buckets at `DRAFTS_PER_DAY`. Kept here so the unavailable answer does not
    /// walk 4096 buckets to find out that there is no room.
    capped: usize,
    /// The earliest moment a capped bucket can fall below the cap. It is a
    /// lower bound: once it has passed, the map is read again.
    next_uncap: Option<Instant>,
}

#[derive(Default)]
struct Window {
    times: Vec<Instant>,
    capped: bool,
}

impl Drafts {
    fn allow(&mut self, key: Key, now: Instant) -> Admission {
        if self.entries.contains_key(&key) {
            self.prune(&key, now);
            if self.entries[&key].times.len() >= DRAFTS_PER_DAY {
                return Admission::Denied;
            }
        } else if self.entries.len() >= MAX_KEYS && !self.make_room(now) {
            return Admission::Unavailable;
        }
        {
            let window = self.entries.entry(key).or_default();
            window.times.push(now);
        }
        self.settle(&key);
        Admission::Allowed
    }

    /// Drop the starts outside the day and keep the capped count in step.
    fn prune(&mut self, key: &Key, now: Instant) {
        if let Some(window) = self.entries.get_mut(key) {
            window.times.retain(|t| now.duration_since(*t) < DAY);
        }
        self.settle(key);
    }

    /// Record whether the bucket is at its cap, and the moment it could next
    /// fall below it.
    fn settle(&mut self, key: &Key) {
        let (was, capped, expiry) = {
            let Some(window) = self.entries.get_mut(key) else {
                return;
            };
            let was = window.capped;
            window.capped = window.times.len() >= DRAFTS_PER_DAY;
            (
                was,
                window.capped,
                window.times.first().copied().map(|t| t + DAY),
            )
        };
        match (was, capped) {
            (false, true) => self.capped += 1,
            (true, false) => self.capped -= 1,
            _ => {}
        }
        if let (true, Some(expiry)) = (capped, expiry) {
            self.next_uncap = Some(self.next_uncap.map_or(expiry, |t| t.min(expiry)));
        }
    }

    /// Make room for one new source. This reads the map only when a bucket can
    /// actually be dropped: a full map whose every bucket is capped and whose
    /// earliest cap has not aged yet answers from the counters. A capped bucket
    /// is never the one dropped.
    fn make_room(&mut self, now: Instant) -> bool {
        if self.capped == self.entries.len() && self.next_uncap.is_some_and(|t| now < t) {
            return false;
        }
        let mut victim: Option<(Instant, Key)> = None;
        let mut capped = 0;
        let mut next_uncap: Option<Instant> = None;
        self.entries.retain(|key, window| {
            window.times.retain(|t| now.duration_since(*t) < DAY);
            if window.times.is_empty() {
                window.capped = false;
                return false;
            }
            window.capped = window.times.len() >= DRAFTS_PER_DAY;
            if window.capped {
                capped += 1;
                if let Some(expiry) = window.times.first().map(|t| *t + DAY) {
                    next_uncap = Some(next_uncap.map_or(expiry, |t| t.min(expiry)));
                }
            } else {
                let seen = window.times.last().copied().unwrap_or(now);
                if victim.is_none_or(|(v, _)| seen < v) {
                    victim = Some((seen, *key));
                }
            }
            true
        });
        self.capped = capped;
        self.next_uncap = next_uncap;
        if self.entries.len() < MAX_KEYS {
            return true;
        }
        match victim {
            Some((_, key)) => {
                self.entries.remove(&key);
                true
            }
            None => false,
        }
    }
}

/// Empty the windows that have run out before the request map drops a batch.
fn evict(map: &mut HashMap<Key, Vec<Instant>>, now: Instant, window: Duration) {
    map.retain(|_, times| {
        times.retain(|t| now.duration_since(*t) < window);
        !times.is_empty()
    });
}

/// Drop the oldest batch when `evict` left the request map at its cap. The oldest
/// entry is the one seen least recently, so a flood loses the buckets it filled
/// first rather than the ones still counting.
fn drop_oldest(map: &mut HashMap<Key, Vec<Instant>>, now: Instant) {
    let mut ages: Vec<(Instant, Key)> = map
        .iter()
        .map(|(k, times)| (times.last().copied().unwrap_or(now), *k))
        .collect();
    ages.sort_by_key(|(seen, _)| *seen);
    for (_, k) in ages.into_iter().take(EVICT_BATCH) {
        map.remove(&k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn v4(n: u8) -> Key {
        Key::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    #[test]
    fn the_sixty_first_request_in_a_minute_is_refused() {
        let c = Counter::new();
        for i in 0..REQUESTS_PER_MINUTE {
            assert!(c.allow_request(v4(1)), "request {i} was refused");
        }
        assert!(!c.allow_request(v4(1)));
        assert!(c.allow_request(v4(2)));
    }

    #[test]
    fn the_sixth_draft_in_a_day_is_refused() {
        let c = Counter::new();
        for i in 0..DRAFTS_PER_DAY {
            assert_eq!(c.allow_draft(v4(1)), Admission::Allowed, "draft {i}");
        }
        assert_eq!(c.allow_draft(v4(1)), Admission::Denied);
        assert_eq!(c.allow_draft(v4(2)), Admission::Allowed);
    }

    #[test]
    fn requests_and_drafts_are_counted_separately() {
        let c = Counter::new();
        for _ in 0..DRAFTS_PER_DAY {
            c.allow_draft(v4(1));
        }
        assert_eq!(c.allow_draft(v4(1)), Admission::Denied);
        assert!(c.allow_request(v4(1)));
    }

    #[test]
    fn an_ipv6_delegation_is_one_bucket_and_two_delegations_are_two() {
        // The /64s inside one /48 are what a /56 or /48 holder rotates, so they
        // must count as one bucket.
        let a: Ipv6Addr = "2001:db8:1:2::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8:1:99::ffff".parse().unwrap();
        let c: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
        assert_eq!(bucket(IpAddr::V6(a)), bucket(IpAddr::V6(b)));
        assert_ne!(bucket(IpAddr::V6(a)), bucket(IpAddr::V6(c)));
        // These share the first six bytes and differ in the seventh, which is
        // the /56 boundary. The bucket must stop at the /48.
        let lower: Ipv6Addr = "2001:db8:aa:0100::1".parse().unwrap();
        let upper: Ipv6Addr = "2001:db8:aa:0200::1".parse().unwrap();
        assert_eq!(
            bucket(IpAddr::V6(lower)),
            bucket(IpAddr::V6(upper)),
            "the bucket must stop at the /48 boundary"
        );
    }

    #[test]
    fn a_mapped_ipv4_address_buckets_with_its_ipv4_client() {
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        let plain: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(bucket(mapped), bucket(plain));
        assert_eq!(bucket(mapped), Key::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_ne!(
            bucket(mapped),
            bucket("::ffff:198.51.100.1".parse().unwrap())
        );
        // The login checker keys its failed attempts on `Display`, so the mapped
        // and plain forms must print the same source too.
        assert_eq!(bucket(mapped).to_string(), plain.to_string());
    }

    #[test]
    fn a_56_rotation_does_not_reset_the_draft_cap() {
        let c = Counter::new();
        let fourth = |n: u16| format!("2001:db8:aa:{:x}::1", 0xbb00 | n);
        // Every /64 in the one /56 is a different address for the front-end and
        // the same source for the cap.
        for i in 0..DRAFTS_PER_DAY {
            let addr = fourth(0);
            assert_eq!(
                c.allow_draft(key(None, Some(addr.as_str()))),
                Admission::Allowed,
                "draft {i}"
            );
        }
        for n in 1..=255u16 {
            let addr = fourth(n);
            assert_eq!(
                c.allow_draft(key(None, Some(addr.as_str()))),
                Admission::Denied,
                "{addr} inside the /56 reset the cap"
            );
        }
    }

    #[test]
    fn a_draft_flood_cannot_evict_a_live_cap() {
        let c = Counter::new();
        let offender = key(None, Some("198.51.100.7"));
        for _ in 0..DRAFTS_PER_DAY {
            assert_eq!(c.allow_draft(offender), Admission::Allowed);
        }
        // Each flood bucket is below its cap, so the map makes room from one of
        // them rather than closing the form.
        for i in 0..MAX_KEYS + EVICT_BATCH {
            let a = (i >> 8) as u8;
            let b = (i & 0xff) as u8;
            assert_eq!(
                c.allow_draft(key(None, Some(&format!("10.2.{a}.{b}")))),
                Admission::Allowed
            );
        }
        assert_eq!(c.lock().drafts.entries.len(), MAX_KEYS);
        assert_eq!(
            c.allow_draft(offender),
            Admission::Denied,
            "the flood evicted the bucket that was already capped"
        );
        // A new applicant still gets in, because a below-cap bucket makes room.
        assert_eq!(
            c.allow_draft(key(None, Some("192.0.2.52"))),
            Admission::Allowed
        );
    }

    #[test]
    fn a_full_map_of_capped_sources_is_unavailable() {
        let c = Counter::new();
        for i in 0..MAX_KEYS {
            let a = (i >> 8) as u8;
            let b = (i & 0xff) as u8;
            let k = key(None, Some(&format!("10.9.{a}.{b}")));
            for _ in 0..DRAFTS_PER_DAY {
                assert_eq!(c.allow_draft(k), Admission::Allowed);
            }
        }
        assert_eq!(
            c.allow_draft(key(None, Some("192.0.2.50"))),
            Admission::Unavailable,
            "a map with no below-cap bucket has no room"
        );
        // The answer does not reset a capped source.
        assert_eq!(
            c.allow_draft(key(None, Some("10.9.0.0"))),
            Admission::Denied
        );
    }

    #[test]
    fn a_full_map_makes_room_from_a_source_below_its_cap() {
        let c = Counter::new();
        for i in 0..MAX_KEYS {
            let a = (i >> 8) as u8;
            let b = (i & 0xff) as u8;
            let k = key(None, Some(&format!("10.8.{a}.{b}")));
            assert_eq!(c.allow_draft(k), Admission::Allowed);
        }
        assert_eq!(
            c.allow_draft(key(None, Some("192.0.2.51"))),
            Admission::Allowed,
            "a below-cap bucket must make room for a new source"
        );
        assert_eq!(c.lock().drafts.entries.len(), MAX_KEYS);
    }

    #[test]
    fn a_request_flood_evicts_the_oldest_and_stays_bounded() {
        let c = Counter::new();
        let first = key(None, Some("10.0.0.1"));
        assert!(c.allow_request(first));
        for i in 0..MAX_KEYS + EVICT_BATCH {
            let a = (i >> 8) as u8;
            let b = (i & 0xff) as u8;
            assert!(c.allow_request(key(None, Some(&format!("10.1.{a}.{b}")))));
        }
        assert!(c.lock().requests.len() <= MAX_KEYS);
        assert!(
            !c.lock().requests.contains_key(&first),
            "the oldest bucket survived the eviction batch"
        );
    }

    #[test]
    fn the_last_forwarded_address_is_the_key_and_a_garbled_one_has_its_own() {
        // The web front-end: relayd's value is the whole header, so the peer is
        // read only when the relay sent none.
        assert_eq!(key(None, Some("127.0.0.1")), v4(1));
        // A client that prepends a lie cannot change the bucket: the proxy's
        // value is the last one.
        assert_eq!(
            key(Some("192.0.2.9, 203.0.113.10"), Some("127.0.0.1")),
            bucket("203.0.113.10".parse().unwrap())
        );
        assert_ne!(
            key(Some("192.0.2.9, 203.0.113.10"), Some("127.0.0.1")),
            bucket("192.0.2.9".parse().unwrap())
        );
        assert_eq!(
            key(Some("not an address"), Some("127.0.0.1")),
            Key::UnknownForward
        );

        // The gemini front-end: no forwarded header exists, and the peer is what
        // it keys on.
        assert_eq!(
            key(None, Some("2001:db8:1:2::9")),
            bucket("2001:db8:1:2::9".parse().unwrap())
        );
        // Anything that is not an address shares one bucket rather than being
        // read as whatever the environment put there.
        assert_eq!(key(None, Some("UNKNOWN")), Key::UnknownForward);
        assert_eq!(key(None, None), Key::UnknownForward);
    }
}
