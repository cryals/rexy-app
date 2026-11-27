# R3X (Rexy) — Rust-powered Expressive Proxy

> **Many cores. One experience.**

**R3X** (`dev.rexy.r3x`, `GPL-3.0-only`) is a cross-platform multi-core VPN and proxy client built natively in **Rust** (`2024` Edition, `rustc 1.100.0`) and **Slint `1.19`** (`Material 3 Expressive`), without WebView or JavaScript wrappers.

## Highlights

- **Universal Multi-Core Architecture (`crates/r3x-cores`):** 19 registered `CoreAdapter` implementations + 14 embedded machine-readable JSON core manifests (`Xray-core`, `sing-box`, `Mihomo`, `Hysteria 2`, `WireGuard`, `AmneziaWG`, `NaiveProxy`, `Mieru`, `OpenVPN`, `shadowsocks-rust`, `V2Fly`, `Juicity`, `Brook`, `Tor`, plus external CLI bridges for `OpenConnect`, `IKEv2`, `SSTP`, `SoftEther`, and `OpenSSH TUN`).
- **45 Modeled Protocols (`crates/r3x-domain`):** Strict separation of protocol, transport (`RawTCP`, `WebSocket`, `gRPC`, `HTTPUpgrade`, `XHTTP`/`SplitHTTP`, `HTTP/2`, `mKCP`, `QUIC`, `HTTP/3`), TLS/REALITY/VLESS Encryption/Noise obfuscation, and flow (`XTLS Vision`, `Mux`, `Salamander`). Intentionally blocks broken `PPTP` and cleartext `L2TP`.
- **Material 3 Expressive Native UI (`ui/`, `src/`):** Graphite Dark, Warm Light, and pure `#000000` AMOLED surfaces, custom accent hex support, EN/RU localization, `reduced_motion` support, adaptive navigation (`>= 1024 px` desktop rail/drawer vs mobile bottom bar), animated `ConnectionHeroButton` scalloped SVG morph, live `sysinfo` telemetry charts, and encrypted `.r3xbak` backups.
- **Security by Design (`crates/r3x-security`, `crates/r3x-storage`, `crates/r3x-ipc`):**
  - Centralized `Redactor` across all log categories & Network Doctor exports.
  - Refuses silent plaintext secret storage when OS keyring (`Windows Credential Manager`, `Linux D-Bus Secret Service`, `AndroidKeyStore`) is unavailable.
  - Argon2id + XChaCha20-Poly1305 encrypted `.r3xbak` backups.
  - SHA-256 verification & path-traversal/symlink/size-bomb archive guards for core binaries.
  - Authenticated local IPC (`<= 4 MiB` frames, 256-bit constant-time tokens, `0600` Unix sockets / Named Pipes).
  - SQLite WAL storage with `PRAGMA quick_check` corruption quarantine recovery.
- **Zero Telemetry & Zero Commercial Lock-In:** No ads, no mandatory accounts, no bundled paid subscriptions.
- **CLI & Background Daemon (`apps/r3x-cli`, `apps/r3x-daemon`):** Headless JSON-capable automation (`r3x --json version`, `cores list`, `profiles`, `diagnostics run`, `connect`, `disconnect`, `recover-network`).
- **Android Native Shell (`platform/android/`):** Kotlin + `R3xVpnService` foreground tunnel (`minSdk 29`, `targetSdk 36`), self-exclusion (`dev.rexy.r3x`), `R3xKeystoreStore`, and Rust JNI bindings (`src/android_jni.rs`).

## Quick Start

### Desktop Source Build & Tests

```powershell
git clone https://github.com/cryals/rexy-app.git
cd rexy-app
cargo test --workspace --locked
cargo run --release -p r3x-app
```

### Windows Portable Release Package

```powershell
.\packaging\windows\package-portable.ps1 -DistDir dist
```

Produces `r3x-app.exe`, `r3x-daemon.exe`, `r3x.exe`, `r3x-0.1.0-windows-x86_64-portable.zip`, `r3x-sbom.cdx.json` (CycloneDX 1.5), and `SHA256SUMS.txt`.

### Documentation Portals

Companion **MkDocs Material** dual-portal documentation (`User Portal` + `Developer Portal`) lives in `D:\Rexy\rexy-docs`. Further technical architecture and verification reports reside under [docs/](docs/):

- [Core Architecture](docs/CORE-ARCHITECTURE.md)
- [Core Adapters](docs/CORE-ADAPTERS.md) & [Protocol Matrix](docs/PROTOCOL-SUPPORT.md)
- [Security Architecture](docs/SECURITY-ARCHITECTURE.md) & [Threat Model](docs/THREAT-MODEL.md)
- [Build Guides (Windows / Linux / Android)](docs/BUILD-WINDOWS.md)
- [Performance](docs/PERFORMANCE.md), [Testing](docs/TESTING.md) & [Final Development Report](docs/FINAL-DEVELOPMENT-REPORT.md)

## License

GNU General Public License v3.0 only (`GPL-3.0-only`). See [LICENSE.txt](LICENSE.txt) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
