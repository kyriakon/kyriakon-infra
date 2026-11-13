//! Six addresses opening sessions as fast as they can, checking after every open
//! that the file the session just created and flocked is still named in the
//! directory. Before the prune moved inside the count lock this reported live
//! files unlinked and a third session admitted over a cap of two; it is the
//! reproducer for [#701] and not a gate, because it is a race rather than an
//! ordered interleaving. The ordered case is `a_prune_waits_for_the_count_lock`
//! in the crate's own tests.
//!
//! Run by hand: `cargo test -p kyriakon-control-tui --test concurrent_sessions
//! -- --ignored --nocapture`. `RACE_SECS` sets how long it runs.
//!
//! [#701]: https://github.com/kyriakon/kyriakon-infra/issues/701

use kyriakon_control_tui::{Admission, Sessions};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn held_by(dir: &Path, prefix: &str) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
        .count()
}

#[test]
#[ignore]
fn concurrent_opens_do_not_lose_a_live_session() {
    let dir = std::env::temp_dir().join(format!("concurrent-sessions-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let stop = Arc::new(AtomicBool::new(false));
    let rounds = Arc::new(AtomicUsize::new(0));
    let first_lost = Arc::new(AtomicUsize::new(0));
    let second_lost = Arc::new(AtomicUsize::new(0));
    let over_cap = Arc::new(AtomicUsize::new(0));

    let mut threads = Vec::new();
    for t in 0..6 {
        let dir = dir.clone();
        let stop = Arc::clone(&stop);
        let rounds = Arc::clone(&rounds);
        let first_lost = Arc::clone(&first_lost);
        let second_lost = Arc::clone(&second_lost);
        let over_cap = Arc::clone(&over_cap);
        threads.push(std::thread::spawn(move || {
            let address = format!("198.51.100.{}", t + 1);
            let addr: IpAddr = address.parse().unwrap();
            let prefix = format!("{address}@");
            while !stop.load(Ordering::Relaxed) {
                let Ok(Admission::Open(a)) = Sessions::open(&dir, Some(addr)) else {
                    continue;
                };
                // The file was created and flocked before open returned, so only
                // a concurrent prune can have removed it.
                if held_by(&dir, &prefix) == 0 {
                    first_lost.fetch_add(1, Ordering::Relaxed);
                }
                let Ok(Admission::Open(b)) = Sessions::open(&dir, Some(addr)) else {
                    continue;
                };
                if held_by(&dir, &prefix) != 2 {
                    second_lost.fetch_add(1, Ordering::Relaxed);
                }
                // Two live sessions, and the cap is 2: a third must be refused.
                if let Ok(Admission::Open(c)) = Sessions::open(&dir, Some(addr)) {
                    over_cap.fetch_add(1, Ordering::Relaxed);
                    drop(c);
                }
                rounds.fetch_add(1, Ordering::Relaxed);
                drop(a);
                drop(b);
            }
        }));
    }

    let secs: u64 = std::env::var("RACE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);
    std::thread::sleep(Duration::from_secs(secs));
    stop.store(true, Ordering::Relaxed);
    for t in threads {
        t.join().unwrap();
    }
    println!(
        "rounds: {}, unlinked while the first was held: {}, held count wrong: {}, \
         third session admitted over the cap: {}",
        rounds.load(Ordering::Relaxed),
        first_lost.load(Ordering::Relaxed),
        second_lost.load(Ordering::Relaxed),
        over_cap.load(Ordering::Relaxed)
    );
    // A refused or failed open is skipped above, so counters of zero mean
    // nothing happened unless at least one round ran.
    assert!(
        rounds.load(Ordering::Relaxed) > 0,
        "no round ran, so the counters prove nothing"
    );
    assert_eq!(
        first_lost.load(Ordering::Relaxed)
            + second_lost.load(Ordering::Relaxed)
            + over_cap.load(Ordering::Relaxed),
        0,
        "a live session was unlinked and the cap under-counted it"
    );
}
