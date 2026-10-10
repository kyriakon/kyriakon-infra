//! The two per-address counters the spec fixes: sixty requests a minute and five
//! drafts a day. No CAPTCHA and no challenge, because a person reads every
//! application and that is the gate.
//!
//! The counters are process state, so a restart clears them. That is the
//! accepted ceiling: a restart is rare and the gate does not depend on them. The
//! maps are pruned once they hold many addresses, so a flood from many addresses
//! cannot grow memory without bound.
//!
//! A std mutex, not parking_lot: the release's dependency list is frozen and a
//! counter that is only ever locked for a few instructions does not earn a new
//! crate. The lock is taken with `into_inner` on a poison rather than unwrapping,
//! because a counter that was poisoned by a panic elsewhere should still count
//! rather than take the handler down.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const REQUESTS_PER_MINUTE: usize = 60;
pub const DRAFTS_PER_DAY: usize = 5;

const MINUTE: Duration = Duration::from_secs(60);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Above this many addresses the map is pruned of entries whose window has
/// emptied, so a flood cannot grow it without bound.
const PRUNE_AT: usize = 1024;

pub struct Counter {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    requests: HashMap<IpAddr, Vec<Instant>>,
    drafts: HashMap<IpAddr, Vec<Instant>>,
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

    /// Count one request. `false` once the address has made sixty in the last
    /// minute, so the sixty-first is the one refused.
    pub fn allow_request(&self, ip: IpAddr) -> bool {
        allow(&mut self.lock().requests, ip, MINUTE, REQUESTS_PER_MINUTE)
    }

    /// Count one draft. `false` once the address has started five in the last
    /// day.
    pub fn allow_draft(&self, ip: IpAddr) -> bool {
        allow(&mut self.lock().drafts, ip, DAY, DRAFTS_PER_DAY)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn allow(
    map: &mut HashMap<IpAddr, Vec<Instant>>,
    ip: IpAddr,
    window: Duration,
    limit: usize,
) -> bool {
    let now = Instant::now();
    if map.len() > PRUNE_AT {
        map.retain(|_, times| {
            times.retain(|t| now.duration_since(*t) < window);
            !times.is_empty()
        });
    }
    let times = map.entry(ip).or_default();
    times.retain(|t| now.duration_since(*t) < window);
    if times.len() >= limit {
        return false;
    }
    times.push(now);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    #[test]
    fn the_sixty_first_request_in_a_minute_is_refused() {
        let c = Counter::new();
        for i in 0..REQUESTS_PER_MINUTE {
            assert!(c.allow_request(ip(1)), "request {i} was refused");
        }
        assert!(!c.allow_request(ip(1)));
        // Another address is unaffected.
        assert!(c.allow_request(ip(2)));
    }

    #[test]
    fn the_sixth_draft_in_a_day_is_refused() {
        let c = Counter::new();
        for i in 0..DRAFTS_PER_DAY {
            assert!(c.allow_draft(ip(1)), "draft {i} was refused");
        }
        assert!(!c.allow_draft(ip(1)));
        assert!(c.allow_draft(ip(2)));
    }

    #[test]
    fn requests_and_drafts_are_counted_separately() {
        let c = Counter::new();
        for _ in 0..DRAFTS_PER_DAY {
            c.allow_draft(ip(1));
        }
        assert!(!c.allow_draft(ip(1)));
        assert!(c.allow_request(ip(1)));
    }
}
