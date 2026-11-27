# R3X (Rexy) — Final Development Report

**Product:** R3X (*Rust-powered Expressive Proxy* — *"Many cores. One experience."*)
**Version:** `0.1.0`
**License:** `GPL-3.0-only`
**Date:** 2026-11-28
**Final Release Assessment:** **`Release Candidate`**

---

## 1. Executive Summary

Across Waves 1–4, **R3X (Rexy)** was designed, implemented, audited, benchmarked, packaged, and documented across two local Git repositories:

1. **`D:\Rexy\rexy-app`** — 11-crate Rust `2024` Edition (`rustc 1.100.0`) workspace paired with a native **Slint `1.19`** (`Material 3 Expressive`) frontend (`r3x-app`), background IPC daemon (`r3x-daemon`), headless JSON CLI (`r3x`), Android Kotlin/`VpnService`/JNI host (`platform/android/`), packaging scripts (`packaging/`), fuzz targets (`fuzz/`), Criterion benchmarks, 8 GitHub Actions workflows (`.github/workflows/`), and full technical documentation (`docs/`).
2. **`D:\Rexy\rexy-docs`** — Dual-portal **MkDocs Material** documentation site (`public/users/`, `public/developers/`, `landing/index.html`) with strict CI (`docs-ci.yml`) and GitHub Pages deployment (`deploy-docs.yml`).

No WebView, Electron, Tauri, HTML shell, ads, trackers, forced accounts, or telemetry opt-in traps exist anywhere in the codebase.

---

## 2. Implemented & Verified Architecture Inventory

### 2.1 Rust Workspace Crates (`11` Members + `4` Standalone Fuzz Targets)

| Crate / Target | Status | Summary |
|---|---|---|
| `r3x-domain` | **Verified** (`5/5`) | Typed domain entities (`Profile`, 45 `ProtocolType`s decoupled from `TransportConfig`/`SecurityConfig`/`FlowType`, `Subscription`, `CoreManifest`, 10-state `ConnectionState` FSM, `RoutingRule`, `DnsConfig`, `AppSettings`, `RingBuffer`, `RedactedSecret`, `R3xError`) |
| `r3x-security` | **Verified** (`5/5`) | `Redactor`, `extract_zip_safely` & `extract_targz_safely`, SHA-256 verification, Argon2id + XChaCha20-Poly1305 encrypted backups, 256-bit constant-time IPC tokens, URL/filename/bounds validation |
| `r3x-storage` | **Verified** (`3/3`) | Bundled SQLite WAL DB (`rusqlite`), forward-only migrations, startup `PRAGMA quick_check` quarantine recovery (`r3x.db.corrupt.<ts>`), fail-closed OS secret store (`Credential Manager`, `Secret Service`, `AndroidKeystoreBridge`) |
| `r3x-ipc` | **Verified** (`2/2`) | Versioned length-prefixed JSON protocol (`<= 4 MiB`), Windows Named Pipes & Linux `0600` Unix Domain Sockets |
| `r3x-engine` | **Verified** (`4/4`) | Async `tokio::sync::Mutex` single-flight engine, health-check readiness gate, `CancellationToken` cleanup, deterministic `CoreSelector`, bounded `LogHub` |
| `r3x-profiles` | **Verified** (`6/6`) | Multi-format parser/exporter (`vless://`, `vmess://`, `trojan://`, `ss://`, `ssr://`, `hy2://`, `tuic://`, `anytls://`, `naive+*://`, `mieru://`, `juicity://`, `socks*://`, `http*://`, `ssh://`, `brook://`, Base64, Clash YAML via `serde-saphyr`, JSON, WG/AWG INI, `.ovpn`), untrusted header sanitization, QR SVG/PNG |
| `r3x-cores` | **Verified** (`5/5`) | `CoreManager` (14 embedded manifests, SHA-256 verification & rollback), `SupervisedProcess` lifecycle, all 19 `CoreAdapter` implementations (`Xray-core`, `sing-box`, `Mihomo`, `Hysteria2`, `WireGuard`, `AmneziaWG`, `NaiveProxy`, `Mieru`, strictly out-of-process `OpenVPN`, `shadowsocks-rust`, `V2Fly`, `Juicity`, `Brook`, `Tor`, `OpenConnect`, `IKEv2`, `SSTP`, `SoftEther`, `OpenSSH TUN`) |
| `r3x-network` | **Verified** (`2/2`) | Transactional OS proxy snapshot/restore, crash-recovery marker, `KillSwitchManager`, TUN & interface/port probes |
| `r3x-diagnostics` | **Verified** (`4/4`) + **4 Benches** | `RoutingManager` + Xray/sing-box/Mihomo rule previews, `DnsManager` probes/leak check, 16-check `NetworkDoctor`, `TelemetryHub` (`sysinfo` CPU/RSS + SVG path builders) |
| `r3x-daemon` & `r3x-cli` | **Verified** (`1/1` CLI + Release Smoke) | Full IPC server wired to all 19 adapters + JSON CLI (`version`, `cores`, `profiles`, `subscriptions`, `connect`, `disconnect`, `diagnostics`, `logs`, `recover-network`) |
| `r3x-app` (`src/` + `ui/`) | **Verified** (`1/1` Headless UI + Release + Android) | Complete native Slint `1.19` + Material 3 Expressive screens, Graphite/Warm Light/AMOLED themes, EN/RU localization, `Reduced Motion`, `ConnectionHeroButton` scalloped SVG morph, onboarding gate, encrypted backup/restore, `DesktopTrayHandle`, `android_jni.rs` |
| `fuzz/` (`r3x-fuzz`) | **Typechecked** (`FUZZ_CHECK_EXIT=0`) | `fuzz_uri_parser`, `fuzz_import_payload`, `fuzz_redactor`, `fuzz_ipc_frame` (`cargo check --manifest-path fuzz/Cargo.toml`) |

---

## 3. Exact Verified Metrics & Build Artifacts

### 3.1 Final Workspace Test & Compliance Suite (`2026-11-28`)

- **`cargo fmt --all -- --check`:** Passed (`exit=0`).
- **`cargo clippy --workspace --all-targets -- -D warnings`:** Passed (`exit=0`, zero Rust warnings, zero R3X Slint warnings).
- **`cargo test --workspace`:** **38 passed, 0 failed, 0 ignored** across 11 crates.
- **`cargo deny check licenses bans sources`:** **`bans ok, licenses ok, sources ok`**.
- **`cargo audit`:** `1,571` advisories checked across `752` lockfile dependencies -> **`0` security vulnerabilities** (`8` allowed upstream `unmaintained` warnings: `bincode 2.0.1`, `chrono 0.4.45`, `pin-utils 0.1.1`, `ttf-parser 0.25.1`, `unsafe-libyaml 0.2.11`, `zbus_names 4.3.5`, `zvariant 5.15.1`, `zvariant_derive 5.15.1`).
- **`fuzz/` check:** `cargo check --manifest-path fuzz/Cargo.toml` -> **`FUZZ_CHECK_EXIT=0`** (`52.18s`).
- **`rexy-docs` build:** `.\scripts\build-all.ps1` (`mkdocs build --strict`) -> **`MKDOCS_EXIT=0`** (User Portal `1.87s`, Developer Portal `1.22s`), committed locally at `846a5db`.

### 3.2 Criterion Microbenchmarks (`r3x-diagnostics`)

| Benchmark | Lower Bound | Median Estimate | Upper Bound |
|---|---|---|---|
| `parse_1000_vless_uris` | `5.4576 ms` | **`5.7116 ms`** | `6.0048 ms` |
| `redact_dense_secrets` | `87.837 us` | **`90.921 us`** | `94.986 us` |
| `build_area_path_3600` | `1.6210 ms` | **`1.7879 ms`** | `1.9453 ms` |
| `preview_routing_100_rules` | `405.62 us` | **`425.94 us`** | `453.13 us` |

### 3.3 Packaged Release Artifacts & Checksums (`D:\Rexy\rexy-app\dist\`)

| File | Exact Size (Bytes) | SHA-256 (`dist/SHA256SUMS.txt`) |
|---|---|---|
| `r3x-app.exe` | `32,522,240` | `e883e809251452cd061b927d6dc01404445a91c65f6048b93184660fdfba0f02` |
| `r3x-daemon.exe` | `10,594,816` | `1377da70e5500b772dbaeba34f33d976d84e9e0d410037ac6f3e5d5d7f828632` |
| `r3x.exe` | `10,246,656` | `5e7b6bca6c13c45735e89b16cff79a691772ae8f33be15e48d1c9682d4777fc9` |
| `r3x-0.1.0-windows-x86_64-portable.zip` | `22,233,141` | `8d9e5b74d1f3e00ecbdca9841d490500f8711d74f8e74a9bef2f610cdcde5f73` |
| `r3x-0.1.0-android-arm64-debug.apk` | `137,714,711` | `8e53b997749fa3881428a7f8e39bde72b6928d8e37016fa537a4a0aceeb59b23` |
| `r3x-sbom.cdx.json` (752 packages) | `204,789` | `8599d1f3e2bfdaa388c1a27aa55833fb7c2120aa9df2c644ffa4b61c86c5d8a7` |

### 3.4 Observed Release CLI Latency & Android NDK Output

- **`dist/r3x.exe --json version`:** `22.85 ms` (`exit=0`)
- **`dist/r3x.exe --json cores list`:** `23.76 ms` (`exit=0`)
- **`dist/r3x.exe --json diagnostics run`:** `73.47 ms` (`exit=0`)
- **Android NDK + Gradle (`build-android.ps1`):** Rust `1.100.0` `aarch64-linux-android` built `libr3x_app_lib.so` (`129,296,464` bytes unstripped debug) via NDK `27.2.12479018` in `4m 28s`; Gradle `9.6.0` / AGP `8.9.1` assembled `app-debug.apk` (`137,714,711` bytes) in `3m 45s` (`BUILD_SCRIPT_EXIT=0`). Note: CI (`.github/workflows/android.yml`) pins Gradle `8.13` to avoid Gradle 10 deprecation warnings cleanly.

---

## 4. Explicit Scope Gaps & Why Verdict Is `Release Candidate` (Not Live-Production Sign-Off)

1. **Unexecuted Hardware / OS Desktop Environments:** Live interactive GUI verification on Linux Wayland/X11 compositors, physical Android `R3xVpnService` tunnel packet-forwarding, and local Windows Inno Setup (`ISCC.exe`) execution have not yet run outside CI definitions.
2. **External Core Binary Soak Testing:** Upstream proxy binaries are declared via 14 SHA-256 manifests and verified across 19 adapter config generators + deterministic local TCP subprocess probes; multi-hour (`8h–24h`) continuous high-load tunnel endurance against live remote servers remains outside automated local test runs.
3. **Missing Initial Catalog File:** `PROXY-PROTOCOLS-AND-CORES.md` was absent from `D:\Rexy` during audit; protocol/adapter coverage follows Section 10 of the engineering prompt (`docs/PROTOCOL-SUPPORT.md`).
4. **Remote Repositories Untouched by Design:** All work in `D:\Rexy\rexy-app` and `D:\Rexy\rexy-docs` is committed cleanly to local `main` branches without pushing (`git push`) or publishing unreviewed GitHub Releases.

---

## 5. Sign-Off Summary

R3X `v0.1.0` compiles cleanly across desktop `x86_64` and `aarch64-linux-android`, passes `38/38` workspace unit/integration/UI/CLI tests, passes `cargo clippy --all-targets -D warnings`, passes `cargo deny` (`bans/licenses/sources`), reports `0` known dependency vulnerabilities in `cargo audit`, packages reproducible Windows release archives + CycloneDX SBOM + `SHA256SUMS.txt` + Android debug APK, and builds dual-portal MkDocs Material sites strictly. Recommended verdict: **`Release Candidate`** ready for live hardware device testing and release signing when maintainers push tags.
