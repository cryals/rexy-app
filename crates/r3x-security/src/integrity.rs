use r3x_domain::R3xError;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use subtle::ConstantTimeEq;

#[must_use]
pub fn compute_sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn compute_sha256_file(path: &Path) -> Result<String, R3xError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn verify_sha256_file(path: &Path, expected_hex: &str) -> Result<(), R3xError> {
    let expected_bytes = hex::decode(expected_hex.trim())
        .map_err(|_| R3xError::Validation("expected checksum is not valid hex".to_owned()))?;
    if expected_bytes.len() != 32 {
        return Err(R3xError::Validation(
            "expected SHA-256 checksum must be 32 bytes".to_owned(),
        ));
    }
    let actual_hex = compute_sha256_file(path)?;
    let actual_bytes = hex::decode(&actual_hex)
        .map_err(|e| R3xError::Storage(format!("internal hex decode error: {e}")))?;

    if actual_bytes.ct_eq(&expected_bytes).into() {
        Ok(())
    } else {
        Err(R3xError::SecurityViolation(format!(
            "SHA-256 mismatch for {}: expected {}, got {}",
            path.display(),
            expected_hex.trim(),
            actual_hex
        )))
    }
}
