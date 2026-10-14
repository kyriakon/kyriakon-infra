//! The two per-address counters the spec fixes: sixty requests a minute and five
//! drafts a day. No CAPTCHA and no challenge, because a person reads every
//! application and that is the gate.
//!
//! The counters are process state, so a restart clears them. That is the
//! accepted ceiling: a restart is rare and the gate does not depend on them.
//!
//! Both maps are bounded. When a map is at `MAX_KEYS` a batch of its oldest
//! entries is evicted, so an attacker cannot grow memory without bound and the
//! scan that finds the batch happens once per batch of new addresses rather than
//! on every request.
//!
//! A std mutex, not parking_lot: the release's dependency list is frozen and a
//! counter held for a few instructions does not earn a new crate. The lock is
//! taken with `into_inner` on a poison rather than unwrapping, because a counter
//! poisoned by a panic elsewhere should still count rather than take the handler
//! down.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const REQUESTS_PER_MINUTE: usize = 60;
pub const DRAFTS_PER_DAY: usize = 5;

const MINUTE: Duration = Duration::from_secs(60);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// The most keys either map holds before a batch is evicted.
const MAX_KEYS: usize = 4096;
/// How many of the oldest to drop when the cap is reached. Draining a batch
/// leaves the next `EVICT_BATCH` new addresses free of eviction work, which is
/// what makes the cost amortised rather than a scan per request.
const EVICT_BATCH: usize = MAX_KEYS / 8;

/// What a counter is keyed on.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Key {
    /// An IPv4 address, whole.
    V4(Ipv4Addr),
    /// An IPv6 address's /64 prefix, as its top 64 bits. One delegated prefix
    /// otherwise mints unlimited buckets.
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
    match ip {
        IpAddr::V4(v4) => Key::V4(v4),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            Key::V6(u64::from_be_bytes([
                o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7],
            ]))
        }
    }
}

pub struct Counter {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    requests: HashMap<Key, Vec<Instant>>,
    drafts: HashMap<Key, Vec<Instant>>,
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
        allow(&mut self.lock().requests, key, MINUTE, REQUESTS_PER_MINUTE)
    }

    /// Count one draft. `false` once the key has started five in the last day.
    pub fn allow_draft(&self, key: Key) -> bool {
        allow(&mut self.lock().drafts, key, DAY, DRAFTS_PER_DAY)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn allow(map: &mut HashMap<Key, Vec<Instant>>, key: Key, window: Duration, limit: usize) -> bool {
    let now = Instant::now();
    if map.len() >= MAX_KEYS && !map.contains_key(&key) {
        evict(map, now, window);
    }
    let times = map.entry(key).or_default();
    times.retain(|t| now.duration_since(*t) < window);
    if times.len() >= limit {
        return false;
    }
    times.push(now);
    true
}

/// Empty the windows that have run out, and if the map is still at the cap drop
/// the oldest batch. This is the only scan in the module, so it runs once per
/// batch of new keys rather than on every request.
fn evict(map: &mut HashMap<Key, Vec<Instant>>, now: Instant, window: Duration) {
    map.retain(|_, times| {
        times.retain(|t| now.duration_since(*t) < window);
        !times.is_empty()
    });
    if map.len() < MAX_KEYS {
        return;
    }
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
            assert!(c.allow_draft(v4(1)), "draft {i} was refused");
        }
        assert!(!c.allow_draft(v4(1)));
        assert!(c.allow_draft(v4(2)));
    }

    #[test]
    fn requests_and_drafts_are_counted_separately() {
        let c = Counter::new();
        for _ in 0..DRAFTS_PER_DAY {
            c.allow_draft(v4(1));
        }
        assert!(!c.allow_draft(v4(1)));
        assert!(c.allow_request(v4(1)));
    }

    #[test]
    fn an_ipv6_prefix_is_one_bucket_and_two_prefixes_are_two() {
        let a: Ipv6Addr = "2001:db8:1:2::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8:1:2::ffff".parse().unwrap();
        let c: Ipv6Addr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(bucket(IpAddr::V6(a)), bucket(IpAddr::V6(b)));
        assert_ne!(bucket(IpAddr::V6(a)), bucket(IpAddr::V6(c)));
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
        assert_eq!(key(None, Some("2001:db8:1:2::9")), bucket("2001:db8:1:2::9".parse().unwrap()));
        // Anything that is not an address shares one bucket rather than being
        // read as whatever the environment put there.
        assert_eq!(key(None, Some("UNKNOWN")), Key::UnknownForward);
        assert_eq!(key(None, None), Key::UnknownForward);
    }

    #[test]
    fn the_map_is_bounded() {
        let c = Counter::new();
        for i in 0..MAX_KEYS + EVICT_BATCH {
            let n = (i & 0xff) as u8;
            let last = (i >> 8) as u8;
            c.allow_request(Key::V4(Ipv4Addr::new(10, last, 0, n)));
        }
        assert!(c.lock().requests.len() <= MAX_KEYS);
    }
}
