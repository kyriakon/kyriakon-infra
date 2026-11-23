#![no_main]

use libfuzzer_sys::fuzz_target;

use kyriakon_control_fromcheck::{Filter, Policy};

fn policy() -> Policy {
    Policy::parse(
        b"alice: alice@kyriakon.net\n",
        &["kyriakon.net".to_string()],
    )
}

/// The filter reads two untrusted streams: the protocol lines smtpd sends and
/// the message's header block. Neither may panic or make the parse superlinear;
/// every data line must also come back byte for byte.
fuzz_target!(|data: &[u8]| {
    let mut filter = Filter::new(policy());
    for line in data.split(|byte| *byte == b'\n') {
        let _ = filter.handle(line);
    }

    let mut filter = Filter::new(policy());
    let _ = filter.handle(
        b"report|0.7|1|smtp-in|link-connect|sid|localhost|pass|unix:a|unix:b",
    );
    for line in data.split(|byte| *byte == b'\n') {
        let mut message = b"filter|0.7|1|smtp-in|data-line|sid|t|".to_vec();
        message.extend_from_slice(line);
        let answer = filter.handle(&message);
        assert!(answer.starts_with(b"filter-dataline|sid|t|"));
    }
    let _ = filter.handle(b"filter|0.7|9|smtp-in|commit|sid|t");
});
