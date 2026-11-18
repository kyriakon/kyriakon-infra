#![no_main]

use libfuzzer_sys::fuzz_target;

/// Whatever the message, the wrapper the crate builds must read back as the
/// ciphertext it wraps. A message that breaks the round trip would be encrypted
/// twice on a re-upload.
fuzz_target!(|data: &[u8]| {
    kyriakon_encrypt::fuzz::envelope(data);
});
