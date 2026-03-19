#![no_main]

use git_sshripped_encryption::decrypt;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = [1_u8; 32];
    let _ = decrypt(&key, "secrets/fuzz.env", data);
});
