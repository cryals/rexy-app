#![no_main]
use libfuzzer_sys::fuzz_target;
use r3x_domain::ProfileSource;
use r3x_profiles::parse_profile_uri;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_profile_uri(text, ProfileSource::Manual);
    }
});
