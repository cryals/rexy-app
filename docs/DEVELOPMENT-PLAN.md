# R3X Development Plan (Phases 00–12 across 4 Waves)

## Wave 1 — Foundation, Engine Core, Expressive Shell & Docs Portals (Phases 00–03)
- **Phase 00 (Audit):** Toolchain pinning (`rust-toolchain.toml`), Material 1.1.0 audit, Stitch 14-screen design audit, crate/license compatibility audit (`GPL-3.0-only`, `deny.toml`).
- **Phase 01 (Foundation):** Cargo Workspace (`r3x-domain`, `r3x-security`, `r3x-storage`, `r3x-ipc`, `r3x-engine`), SQLite schema v1 + corruption recovery, Argon2id + XChaCha20-Poly1305 encrypted backups, platform secret store, versioned token-authenticated IPC, central redacted `LogHub`.
- **Phase 02 (Design System):** Native Slint R3X Material 3 Expressive UI kit (`R3xPalette`, `R3xMetrics`, `R3xTypography`, `R3xIcons`, `R3xFlags`, `R3xThemeController` with System/Light/Dark/AMOLED, `ConnectionHeroButton` 12-lobe morph, `ConnectedSegmentedGroup`, `StackedListItem`, `TrafficAreaChart`), adaptive desktop/mobile shell, EN/RU localization, headless UI tests.
- **Phase 03 (Engine):** 10-state typed connection FSM, single-flight concurrency lock, `CancellationToken`, mandatory `health_check()` gate before `Connected`, `CoreAdapter` contract, `CoreSelector` priority hierarchy.
- **Docs (`D:\Rexy\rexy-docs`):** Dual-portal MkDocs Material site (`user-portal/` + `dev-portal/` + `landing/`) and GitHub Actions deployment workflows.

## Wave 2 — Subscriptions, Primary Cores, Desktop Networking, Daemon & CLI (Phases 04–06)
- `r3x-subscriptions` & `r3x-profiles`: URI parsers (`vless://`, `vmess://`, `trojan://`, `ss://`, `hy2://`, `tuic://`, `wg://`, `amnezia://`, etc.), Base64, Clash/Mihomo YAML (`serde_yaml_ng`), sing-box/Xray JSON, metadata headers, deduplication, QR decode/encode.
- Primary Core Adapters (`adapters/xray`, `adapters/sing-box`, `adapters/mihomo`) + `r3x-core-manager` (machine-readable manifests, SHA-256 verified installs/updates/rollbacks).
- Desktop Networking (`r3x-network`, `platform/windows`, `platform/linux`), System Proxy with transactional rollback, TUN lifecycle, background `r3x-daemon`, System Tray, and `r3x` CLI.

## Wave 3 — Full UI Completion, Advanced Networking & Extended Cores (Phases 07–09)
- Complete all 60 screens/states natively in Slint (Onboarding, Server Selector, Subscription Details, Routing Rule Editor, DNS Manager, Connection Inspector, Network Doctor 16-check suite, Live Monitoring charts, Log Viewer, Core Manager, Settings & Backup/Restore).
- Implement `r3x-routing`, `r3x-dns`, `r3x-diagnostics`, `r3x-monitoring`.
- Implement Extended Core Adapters (`Hysteria 2`, `WireGuard`, `AmneziaWG`, `NaiveProxy`, `Mieru`, `OpenVPN`, `shadowsocks-rust`, `Tor`, `Juicity`, `Brook`, `OpenConnect`, etc.) and complete `docs/PROTOCOL-SUPPORT.md`.

## Wave 4 — Android Native Integration, Quality/Fuzzing, Packaging & Release (Phases 10–12)
- Android Gradle project + `R3xVpnService` (Kotlin `VpnService` + `ForegroundService` + Android Keystore JNI bridge + `NotificationChannel` + `android_main`).
- Fuzz targets (`cargo-fuzz`), property tests, real local loopback integration tests, benchmarks (`criterion`), RAM/CPU/FPS profiling.
- Windows installer (WiX/NSIS + portable ZIP), Linux packages (DEB/RPM/AppImage/tarball), Android APK/AAB, release CI/CD workflows, `SHA256SUMS`, SBOM, and `docs/FINAL-DEVELOPMENT-REPORT.md`.
