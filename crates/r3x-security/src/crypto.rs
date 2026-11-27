use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use r3x_domain::R3xError;
use rand::Rng;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub version: u8,
    pub kdf: String,
    pub cipher: String,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

pub fn encrypt_backup(plaintext: &[u8], passphrase: &str) -> Result<EncryptedEnvelope, R3xError> {
    if passphrase.len() < 8 {
        return Err(R3xError::Validation(
            "backup passphrase must be at least 8 characters".to_owned(),
        ));
    }

    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 24];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| R3xError::SecurityViolation(format!("key derivation failed: {e}")))?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| R3xError::SecurityViolation(format!("cipher init failed: {e}")))?;
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| R3xError::SecurityViolation(format!("backup encryption failed: {e}")))?;

    key.zeroize();

    Ok(EncryptedEnvelope {
        version: 1,
        kdf: "argon2id".to_owned(),
        cipher: "xchacha20poly1305".to_owned(),
        salt_b64: B64.encode(salt),
        nonce_b64: B64.encode(nonce_bytes),
        ciphertext_b64: B64.encode(ciphertext),
    })
}

pub fn decrypt_backup(envelope: &EncryptedEnvelope, passphrase: &str) -> Result<Vec<u8>, R3xError> {
    if envelope.version != 1 {
        return Err(R3xError::Validation(format!(
            "unsupported backup envelope version {}",
            envelope.version
        )));
    }
    let salt = B64
        .decode(&envelope.salt_b64)
        .map_err(|_| R3xError::Validation("invalid base64 salt".to_owned()))?;
    let nonce_bytes = B64
        .decode(&envelope.nonce_b64)
        .map_err(|_| R3xError::Validation("invalid base64 nonce".to_owned()))?;
    let ciphertext = B64
        .decode(&envelope.ciphertext_b64)
        .map_err(|_| R3xError::Validation("invalid base64 ciphertext".to_owned()))?;

    let nonce_arr: [u8; 24] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| R3xError::Validation("invalid nonce length".to_owned()))?;

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| R3xError::SecurityViolation(format!("key derivation failed: {e}")))?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| R3xError::SecurityViolation(format!("cipher init failed: {e}")))?;
    let nonce = XNonce::from(nonce_arr);
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).map_err(|_| {
        R3xError::SecurityViolation(
            "backup decryption failed (wrong passphrase or tampered data)".to_owned(),
        )
    });

    key.zeroize();
    plaintext
}

#[must_use]
pub fn generate_ipc_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    bytes.zeroize();
    token
}

#[must_use]
pub fn verify_ipc_token(expected: &str, provided: &str) -> bool {
    if expected.is_empty() || expected.len() != provided.len() {
        return false;
    }
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}
