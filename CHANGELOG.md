# Changelog

All notable engineering milestones in **R3X (Rexy)** (`dev.rexy.r3x`) are documented below.

## [0.1.0-rc.1] — 2026-11-28 (Waves 1–4 Complete)

### Wave 4 — Android Integration, Benchmarks, Fuzzing, Packaging, CI/CD & Documentation
- **Android Native & VPN Layer:** Added `platform/android/` (`dev.rexy.r3x`, `minSdk = 29`, `targetSdk = 36`, AGP `8.9.1`, Kotlin `2.1.20`), `R3xVpnService` foreground TUN service with self-exclusion (`addDisallowedApplication("dev.rexy.r3x")`), `R3xKeystoreStore` AES-GCM secret persistence, `R3xBootReceiver`, and `src/android_jni.rs` JNI entrypoints (`setDataDir`, `initKeystoreBridge`, `onVpnTunnelEstablished`, `onVpnTunnelRevoked`, `onNetworkChanged`). Verified ARM64 NDK (`27.2.12479018`) `cdylib` build + Gradle `assembleDebug` APK creation locally (`app-debug.apk`, `137,714,711` bytes).
- **Performance Benchmarks:** Added Criterion benchmark suite in `crates/r3x-diagnostics/benches/r3x_benchmarks.rs` covering 1k VLESS URI parsing (`5.7116 ms` median), dense secret redaction (`90.921 us`), 3,600-point SVG path rendering (`1.7879 ms`), and 100-rule multi-core translation (`425.94 us`).
- **Fuzz Harnesses:** Added 4 `libfuzzer-sys` targets under `fuzz/fuzz_targets/` (`fuzz_uri_parser`, `fuzz_import_payload`, `fuzz_redactor`, `fuzz_ipc_frame`); verified standalone compilation (`cargo check --manifest-path fuzz/Cargo.toml`).
- **Packaging & SBOM:** Implemented `packaging/windows/{package-portable.ps1,r3x-installer.iss}`, `packaging/linux/{build-deb.sh,build-appimage.sh,r3x.spec,dev.rexy.r3x.desktop,dev.rexy.r3x.metainfo.xml}`, `packaging/android/build-android.{ps1,sh}`, and CycloneDX 1.5 generator `packaging/generate-sbom.ps1` (`752` packages). Packaged Windows x86_64 release portable archive + `SHA256SUMS.txt`.
- **CI/CD & Documentation:** Added `.github/workflows/{windows,linux,android,integration,security,benchmarks,release}.yml`, enhanced `ci.yml` with `cargo deny`, added `dependabot.yml` + issue templates, authored complete `docs/` suite + `FINAL-DEVELOPMENT-REPORT.md`, and synchronized `D:\Rexy\rexy-docs` dual portals.

### Wave 3 — Full UI Kit Completion, Diagnostics, All 19 Core Adapters (`f262c24`)
- Implemented `r3x-diagnostics` (`RoutingManager`, `DnsManager` + leak/probe checks, 16-check `NetworkDoctor`, `TelemetryHub` with `sysinfo` + SVG path builders).
- Expanded `r3x-cores` to all 19 `CoreAdapter` implementations and wired them into `apps/r3x-daemon`.
- Completed native Slint Material 3 Expressive screens (Onboarding, Home, Subscriptions, Servers, Routing & DNS, Connections, Diagnostics, Core Manager, 8-category Settings) + `src/{controller,tray}.rs` + `ui_smoke`.

### Waves 1 & 2 — Core Workspace, Security, Storage, IPC, Profiles & Primary Cores (`8d8ec54`)
- Established 11-crate Rust 2024 workspace (`LICENSE.txt` `GPL-3.0-only`, `deny.toml`, `rust-toolchain.toml` pinned `1.100.0`).
- Implemented `r3x-domain`, `r3x-security`, `r3x-storage`, `r3x-ipc`, `r3x-engine`, `r3x-profiles`, `r3x-cores` (14 embedded core manifests, Xray/sing-box/Mihomo adapters, `CoreManager`, `SupervisedProcess`), `r3x-network`, `apps/{r3x-daemon,r3x-cli}`, and dual-portal MkDocs site (`D:\Rexy\rexy-docs`).
