# Persistence & Secret Storage (`r3x-storage`)

`crates/r3x-storage/` provides ACID SQLite persistence, corruption self-healing, encrypted backups, and OS-native secret isolation.

## 1. SQLite Schema & Recovery (`repository.rs`, `migrations.rs`)

- **Configuration:** Embedded SQLite (`rusqlite` with `bundled` SQLite 3), `PRAGMA journal_mode = WAL`, `PRAGMA foreign_keys = ON`, synchronous mode balanced for durability without blocking UI frames.
- **Migrations:** Forward-only versioned SQL migrations recorded in `schema_migrations`.
- **Corruption Recovery:** `R3xDatabase::open` executes `PRAGMA quick_check`. If corruption is detected (for example after sudden power loss), the damaged database is atomically quarantined to `r3x.db.corrupt.<timestamp>`, and a clean database is initialized while surfacing a recoverable warning.
- **Entities Persisted:** `subscriptions`, `profiles` (preserving `is_favorite` and user labels across refreshes), `routing_rules`, `rule_sets`, `connection_history`, `app_settings`, and `window_state`.

## 2. Encrypted `.r3xbak` Backups (`r3x-security::crypto`)

- Export/Import uses `ExportBundle` encrypted with **Argon2id** key derivation + **XChaCha20-Poly1305** AEAD.
- Temporary passphrase/key material buffers are cleared via `zeroize`.
- Wrong passwords or tampered ciphertexts fail AEAD authentication cleanly (`R3xError::Crypto`).

## 3. Platform Secret Stores (`secrets.rs`)

| Platform | Backend | Fallback Policy |
|---|---|---|
| Windows | Windows Credential Manager (`keyring` `windows-native-keyring-store`) | Refuses plaintext file fallback (`E_SECRET_STORE`) |
| Linux | D-Bus Secret Service (`zbus-secret-service-keyring-store`) | Refuses plaintext file fallback (`E_SECRET_STORE`) |
| Android | AndroidKeyStore AES-256-GCM wrapped store (`R3xKeystoreStore.kt` via `JniAndroidKeystoreBridge` registered by `android_jni.rs`) | Hardware/OS Keystore required; errors surface explicitly |
| Unit Tests | In-memory `MemorySecretStore` (strictly test-only) | Never enabled silently in production builds |
