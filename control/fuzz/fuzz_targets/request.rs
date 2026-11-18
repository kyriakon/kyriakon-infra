#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use tokio::runtime::Runtime;

use kyriakon_control_handler::fastcgi;

/// One runtime for every input: `read_request` is async, but a socket slice
/// needs no reactor, so a current-thread runtime built once is enough.
static RT: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime")
});

/// The whole FastCGI read path: the record header, the begin record, the
/// parameter pairs and the body. A panic here is a 500 on the public form.
fuzz_target!(|data: &[u8]| {
    let mut cursor: &[u8] = data;
    let _ = RT.block_on(fastcgi::read_request(&mut cursor, 64 * 1024));
});
