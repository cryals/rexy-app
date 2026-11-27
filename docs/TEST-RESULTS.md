# R3X Test & Verification Results

## Wave 3 Verification (2026-11-28, Windows x86_64 MSVC, Rust 1.100.0)

**Workspace test total:** 38 passed, 0 failed across 11 crates. `D:` free space after full test build: 6.03 GB.

| Check / Suite | Command | Result | Details |
|---|---|---|---|
| Formatting | `cargo fmt --all -- --check` | Passed | Clean formatting across entire workspace |
| Lints | `cargo clippy --workspace --all-targets -- -D warnings` | Passed | Zero Rust warnings; zero R3X Slint binding-loop warnings (`material-1.1.0` drop-shadow warning left intact) |
| Supply Chain & Licenses | `cargo deny check licenses bans sources` | Passed | `bans ok, licenses ok, sources ok` |
| UI Smoke (`r3x-app`) | `cargo test --workspace` (`tests/ui_smoke.rs`) | 1 passed, 0 failed | Headless `i-slint-backend-testing`: onboarding gate + persistence, all 8 nav views, 14 cores, Light/AMOLED themes, EN/RU toggle, Reduced Motion, VLESS import into SQLite, routing presets, raw Xray config preview, encrypted `.r3xbak` backup, redacted logs |
| CLI (`r3x-cli`) | `cargo test --workspace` (`tests/cli_tests.rs`) | 1 passed, 0 failed | `--json version`, `cores list` (14 manifests), `cores info xray`, `profiles validate/import/list` |
| Cores (`r3x-cores`) | `cargo test --workspace` (`tests/cores_tests.rs`) | 5 passed, 0 failed | All 14 manifests parse; Xray/sing-box/Mihomo + all extended adapters (Hysteria2, WG, AmneziaWG, NaiveProxy, Mieru, OpenVPN, shadowsocks-rust, V2Fly, Juicity, Brook, Tor, External VPNs); zip install/verify/rollback/uninstall; real TCP subprocess |
| Diagnostics (`r3x-diagnostics`) | `cargo test --workspace` (`tests/diagnostics_tests.rs`) | 4 passed, 0 failed | Routing CRUD/sorting/core previews; DNS validation, probe & leak check; 16-check Network Doctor + secret redaction; TelemetryHub pause, `sysinfo` RSS, TCP RTT probe & SVG path builders |
| Domain (`r3x-domain`) | `cargo test --workspace` (`tests/domain_tests.rs`) | 5 passed, 0 failed | FSM transitions, `RingBuffer`, `RedactedSecret` Debug redaction, quota math, serde roundtrips |
| Engine (`r3x-engine`) | `cargo test --workspace` (`tests/engine_tests.rs`) | 4 passed, 0 failed | Connect/disconnect lifecycle, health-check gate, cancellation cleanup, `CoreSelector` priority, redacted `LogHub` |
| IPC (`r3x-ipc`) | `cargo test --workspace` (`tests/ipc_tests.rs`) | 2 passed, 0 failed | Live local socket handshake, invalid token rejection, version mismatch error, frame limit |
| Network (`r3x-network`) | `cargo test --workspace` (`tests/network_tests.rs`) | 2 passed, 0 failed | Transactional proxy snapshot restore & crash recovery, kill-switch recovery, free port discovery, TUN/interface checks |
| Profiles (`r3x-profiles`) | `cargo test --workspace` (`tests/profiles_tests.rs`) | 6 passed, 0 failed | URI parsing/export, Base64/YAML/JSON/WG/AWG/OpenVPN parsing, untrusted subscription headers, QR SVG encode + PNG decode, HTTP refresh preservation on failure, `proptest` |
| Security (`r3x-security`) | `cargo test --workspace` (`tests/security_tests.rs`) | 5 passed, 0 failed | Redactor, zip traversal & size-bomb guard, SHA-256, Argon2id+XChaCha20 AEAD, URL validation, `proptest` |
| Storage (`r3x-storage`) | `cargo test --workspace` (`tests/storage_tests.rs`) | 3 passed, 0 failed | SQLite migrations & CRUD, corruption quarantine recovery, encrypted backup & `SecretStore` |
| Docs Dual-Portal Build | `D:\Rexy\rexy-docs\.\scripts\build-all.ps1` | Passed (Wave 1 baseline) | Re-sync and rebuild scheduled for Wave 4 |
