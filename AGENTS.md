# R3X (Rexy) — Agent & Engineering Guide

**Product:** R3X (*Rust-powered Expressive Proxy*) — *"Many cores. One experience."*
**License:** GNU General Public License v3.0 (`GPL-3.0-only`)

## Workspace Layout

```text
rexy-app/
├── Cargo.toml                 # Cargo workspace root + r3x-app GUI binary/cdylib
├── rust-toolchain.toml        # Pinned Rust 1.100.0 + rustfmt + clippy
├── deny.toml                  # cargo-deny license/ban/advisory policy
├── material-1.1.0/            # Read-only Slint Material 3 kit (import via @material; do NOT edit)
├── crates/
│   ├── r3x-domain/            # Pure domain models, 10-state FSM, protocol enums, ring buffers
│   ├── r3x-security/          # Secret redaction, safe archive extraction, SHA-256, AEAD backups
│   ├── r3x-storage/           # SQLite migrations, corruption recovery, platform SecretStore
│   ├── r3x-ipc/               # Versioned token-authenticated local IPC (Named Pipe / Unix socket)
│   └── r3x-engine/            # Central async engine, CoreAdapter trait, CoreSelector, LogHub
├── ui/
│   ├── main.slint             # MainWindow entry + theme init
│   ├── layouts/app_shell.slint# Adaptive desktop drawer/rail & mobile bottom bar
│   ├── state/app_state.slint  # Global Slint state & Rust callbacks
│   ├── tokens/                # R3xPalette, R3xMetrics, R3xTypography, R3xIcons, R3xFlags
│   ├── themes/                # System / Light / Dark / AMOLED theme switcher
│   ├── components/            # Material 3 Expressive custom widgets
│   ├── screens/               # Screen implementations
│   └── assets/                # Generated SVG Material Symbols icons & country flags
├── src/                       # Desktop & Android Slint bootstrap (android_main entry)
├── tests/                     # Headless UI tests (i-slint-backend-testing)
└── docs/                      # Architecture, ADRs, status tracking, test & build reports
```

## Mandatory Engineering Rules

1. **No fake functionality:** Never return dummy success, simulated speeds, or stub latencies in production paths. Unavailable metrics must render `N/A` or `Idle`.
2. **Error safety:** No `unwrap()` or `expect()` in library/production crates (`r3x-*`, `src/`). Use typed `R3xError`.
3. **Security:** Never bypass TLS verification by default, never fall back silently to plaintext secret storage, and route every log/diagnostic export through `r3x_security::Redactor`.
4. **Read-only reference assets:** Never modify `material-1.1.0/` or `D:\Rexy\stitch_r3x_multi_core_vpn_client/`.
5. **Rust Edition 2024:** Always use `#[unsafe(no_mangle)]` on FFI/JNI/Android exports and avoid `gen` as an identifier.

## Build & Verification Commands

```powershell
cargo fmt --all -- --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check licenses bans sources
```

## Session Continuity

Before resuming multi-wave development, read this file (`AGENTS.md`) alongside `docs/IMPLEMENTATION-STATUS.md` and `docs/DEVELOPMENT-PLAN.md` to continue from the last verified wave.
