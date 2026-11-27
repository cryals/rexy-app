#![no_main]
use libfuzzer_sys::fuzz_target;
use r3x_security::Redactor;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Redactor::redact_str(text);
    }
});
