# R3X Test & Verification Results

## Wave 1 Verification (2026-11-28, Windows x86_64 MSVC, Rust 1.100.0)

| Check / Suite | Command | Result | Details |
|---|---|---|---|
| Formatting | `cargo fmt --all -- --check` | Passed | Clean |
| Lints | `cargo clippy --workspace --all-targets -- -D warnings` | Passed | Zero Rust warnings |
| UI Smoke (`r3x-app`) | `cargo test --workspace` (`tests/ui_smoke.rs`) | 1 passed, 0 failed | Headless `i-slint-backend-testing`: instantiation, navigation, Light/AMOLED switch, SQLite persistence |
| Domain (`r3x-domain`) | `cargo test --workspace` (`tests/domain_tests.rs`) | 5 passed, 0 failed | FSM transitions, `RingBuffer`, `RedactedSecret` Debug redaction, quota math, serde |
| Security (`r3x-security`) | `cargo test --workspace` (`tests/security_tests.rs`) | 5 passed, 0 failed | Redactor, zip traversal & size-bomb guard, SHA-256, Argon2id+XChaCha20 AEAD, URL validation, `proptest` |
| Storage (`r3x-storage`) | `cargo test --workspace` (`tests/storage_tests.rs`) | 3 passed, 0 failed | SQLite migrations & CRUD, corruption quarantine recovery, encrypted backup & `SecretStore` guarantees |
| IPC (`r3x-ipc`) | `cargo test --workspace` (`tests/ipc_tests.rs`) | 2 passed, 0 failed | Live local socket handshake, invalid token rejection, version mismatch error, frame limit |
| Engine (`r3x-engine`) | `cargo test --workspace` (`tests/engine_tests.rs`) | 4 passed, 0 failed | Connect/disconnect lifecycle, health-check gate, cancellation cleanup, `CoreSelector` priority, redacted `LogHub` |
| Docs Dual-Portal Build | `D:\Rexy\rexy-docs\.\scripts\build-all.ps1` | Passed | `mkdocs build --strict` on `user-portal` (6.38s) and `dev-portal` (1.63s) + `landing/index.html` |
