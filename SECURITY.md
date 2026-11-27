# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in R3X (such as secret leakage, IPC authorization bypass, path traversal during subscription/core import, TLS verification bypass, or privilege escalation), please report it privately to the repository maintainers rather than opening a public issue.

## Security Architecture Highlights

- **Centralized Redaction (`r3x-security::Redactor`):** Strips proxy URI userinfo, JSON/YAML/INI secret keys, Bearer tokens, and sensitive query parameters from logs and diagnostic exports.
- **No Plaintext Secret Fallback:** When platform credential storage (`Windows Credential Manager`, `Linux Secret Service`, `Android Keystore`) is unavailable, R3X refuses plaintext disk persistence (`R3xError::SecretStoreUnavailable`).
- **Safe Archive Extraction (`r3x-security::archive`):** Rejects `..`, absolute paths, Windows drive/UNC prefixes, symlinks/hardlinks, and enforces decompression size/count limits.
- **Encrypted Backups:** Argon2id KDF + XChaCha20-Poly1305 AEAD (`r3x-security::crypto`) with `zeroize` on sensitive key material.
- **Authenticated Local IPC:** Versioned framing (`MAX_IPC_FRAME_BYTES = 4 MiB`) and constant-time 256-bit token authentication.
- **Telemetry:** Disabled by default. No background analytics or third-party trackers.
