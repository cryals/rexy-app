#![no_main]
use libfuzzer_sys::fuzz_target;
use r3x_domain::ProfileSource;
use r3x_profiles::parse_import_payload;

fuzz_target!(|data: &[u8]| {
    let _ = parse_import_payload(data, ProfileSource::Manual);
});
