# Contributing to R3X (Rexy)

Thank you for contributing to **R3X** (*Rust-powered Expressive Proxy*, licensed `GPL-3.0-only`).

## 1. Repository Layout

- `D:\Rexy\rexy-app` — Primary Rust + Slint Cargo workspace:
  - `src/`, `ui/`, `build.rs` — `r3x-app` (`r3x_app_lib`) native Material 3 Expressive GUI and controller
  - `crates/` — Domain, Security, Storage, IPC, Engine, Profiles, Cores, Network, Diagnostics crates
  - `apps/` — `r3x-daemon` privileged/background daemon and `r3x` CLI (`r3x-cli`)
  - `platform/android/` — Native Android Gradle/Kotlin shell (`dev.rexy.r3x`) with `R3xVpnService` and AndroidKeyStore JNI bridge
  - `packaging/` — Windows, Linux, Android packaging and CycloneDX SBOM scripts
  - `fuzz/` — `cargo-fuzz` harnesses (excluded from workspace builds so MSVC/stable builds stay fast)
  - `material-1.1.0/` — Upstream Slint Material Components kit (**read-only, do not edit**)
- External companion folder `rexy-docs/` — Dual-portal MkDocs Material documentation (`user-portal/`, `dev-portal/`).

## 2. Hard Contribution Rules

1. **Zero UI Kit / Reference Mutations:** Never modify `material-1.1.0/` or external reference exports (`stitch_r3x_multi_core_vpn_client`).
2. **Honesty Policy:** Never claim a feature, protocol, or platform is verified unless automated checks ran after your final edit. Mark static config/adapter work `Supported` or `Implemented`, reserving `Verified` strictly for passing tests/checks.
3. **Supply Chain & License Hygiene:** Keep `deny.toml` green (`cargo deny check licenses bans sources`). Do not re-introduce banned crates (`serde_yaml`, `serde_yml`, `openssl`, `openssl-sys`), and never link `GPL-2.0-only` code (`OpenVPN` stays strictly out-of-process CLI).
4. **Security Boundaries:**
   - Route all user-visible logs and exported diagnostics through `r3x_security::Redactor`.
   - Never fall back to plaintext credential files when the OS secret store fails.
   - Treat remote subscription inputs, QR payloads, headers, and archive entries as untrusted.

## 3. Mandatory Verification Gate

Run before opening any PR or finalizing edits:

```powershell
cargo fmt --all -- --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check licenses bans sources
```

## 4. Reporting Vulnerabilities

Please follow [SECURITY.md](SECURITY.md) instead of opening public issues for security-sensitive bugs.
