# R3X Test & Verification Results

## Wave 4 Final Verification (2026-11-28, Windows `x86_64` MSVC, Rust `1.100.0`)

- **Workspace Test Total:** **38 passed, 0 failed, 0 ignored** across all 11 workspace crates.
- **`D:` Drive Free Space After Final Build & Verification:** `2.68 GB` (large temporary `CARGO_TARGET_DIR` builds offloaded to `E:` and deleted after artifact capture).

### 1. Automated Quality, Security & Compliance Gates

| Check / Suite | Command Executed | Outcome | Details |
|---|---|---|---|
| Formatting | `cargo fmt --all -- --check` | **Passed** (`exit=0`) | Clean across workspace after final edits |
| Lints | `cargo clippy --workspace --all-targets -- -D warnings` | **Passed** (`exit=0`) | Zero Rust warnings; zero R3X Slint warnings (`material-1.1.0` drop-shadow warning untouched) |
| Supply Chain & Licenses | `cargo deny check licenses bans sources` | **Passed** (`exit=0`) | `bans ok, licenses ok, sources ok` |
| Vulnerability Audit | `cargo audit` | **Passed** (`AUDIT_EXIT=0`) | Scanned `752` deps against `1,571` advisories: **`0` vulnerabilities**, `8` allowed upstream `unmaintained` warnings (`bincode 2.0.1`, `chrono 0.4.45`, `pin-utils 0.1.1`, `ttf-parser 0.25.1`, `unsafe-libyaml 0.2.11`, `zbus_names 4.3.5`, `zvariant 5.15.1`, `zvariant_derive 5.15.1`) |
| Fuzz Harnesses | `cargo check --manifest-path fuzz/Cargo.toml` | **Passed** (`FUZZ_CHECK_EXIT=0`, `52.18s`) | Checked `fuzz_uri_parser`, `fuzz_import_payload`, `fuzz_redactor`, `fuzz_ipc_frame` (`E:\r3x-fuzz-target`, cleaned) |
| Criterion Benchmarks | `cargo bench -p r3x-diagnostics --bench r3x_benchmarks --locked -- --sample-size 10 --measurement-time 1` | **Passed** (`BENCH_EXIT=0`, `3m 04s`) | `parse_1000_vless_uris`: `5.7116 ms`; `redact_dense_secrets`: `90.921 us`; `build_area_path_3600`: `1.7879 ms`; `preview_routing_100_rules`: `425.94 us` (`E:\r3x-bench-target`, cleaned) |
| Dual-Portal MkDocs | `D:\Rexy\rexy-docs\.\scripts\build-all.ps1` | **Passed** (`MKDOCS_EXIT=0`) | Built `public/users` (`1.87s`) and `public/developers` (`1.22s`) under `--strict`; committed `846a5db` |

### 2. Per-Crate Test Breakdown (`cargo test --workspace`)

| Crate | Test Binary | Passed / Failed / Ignored | Duration | Key Covered Behaviors |
|---|---|---|---|---|
| `r3x-app` | `tests/ui_smoke.rs` | `1 / 0 / 0` | `0.89s` | Headless `i-slint-backend-testing`: onboarding persistence, 8 nav views, Light/AMOLED themes, EN/RU toggle, Reduced Motion, VLESS SQLite import, routing presets, raw Xray config preview, encrypted `.r3xbak` backup, redacted logs |
| `r3x-cli` | `tests/cli_tests.rs` | `1 / 0 / 0` | `1.15s` | `--json` `version`, `cores list` (14 manifests), `cores info xray`, `profiles validate/import/list` |
| `r3x-cores` | `tests/cores_tests.rs` | `5 / 0 / 0` | `0.64s` | All 14 manifests parse; Xray/sing-box/Mihomo + extended & external adapters; archive install/verify/rollback/uninstall; real TCP subprocess + logs |
| `r3x-diagnostics` | `tests/diagnostics_tests.rs` | `4 / 0 / 0` | `0.10s` | Routing CRUD/sorting/core previews; DNS validation, probe & leak check; all 16 Network Doctor checks + redacted report; TelemetryHub pause, `sysinfo` RSS, TCP RTT, SVG paths |
| `r3x-domain` | `tests/domain_tests.rs` | `5 / 0 / 0` | `0.00s` | 10-state FSM transitions, `RingBuffer`, unlimited quota behavior, `RedactedSecret` Debug redaction, serde roundtrips |
| `r3x-engine` | `tests/engine_tests.rs` | `4 / 0 / 0` | `0.06s` | Connect/disconnect lifecycle, health-check gate, mid-start cancellation cleanup, `CoreSelector` hierarchy, redacted `LogHub` |
| `r3x-ipc` | `tests/ipc_tests.rs` | `2 / 0 / 0` | `0.00s` | Live Named Pipe / local socket handshake, 256-bit token auth, `E_IPC_VERSION_MISMATCH`, 4 MiB frame rejection |
| `r3x-network` | `tests/network_tests.rs` | `2 / 0 / 0` | `0.02s` | Transactional proxy snapshot restore & crash recovery, kill-switch recovery, free port discovery, interface enumeration |
| `r3x-profiles` | `tests/profiles_tests.rs` | `6 / 0 / 0` | `0.22s` | URI parse/export, Base64/YAML/JSON/WG/AWG/OpenVPN parse, untrusted headers, QR SVG+PNG roundtrip, HTTP failure preservation, `proptest` |
| `r3x-security` | `tests/security_tests.rs` | `5 / 0 / 0` | `2.01s` | Redactor, zip-slip & size-bomb guard, SHA-256, Argon2id+XChaCha20 AEAD, URL validation, `proptest` |
| `r3x-storage` | `tests/storage_tests.rs` | `3 / 0 / 0` | `1.96s` | SQLite WAL migrations & CRUD, `PRAGMA quick_check` corruption quarantine recovery, `.r3xbak` backup & fail-closed secret store guarantees |

### 3. Release Packaging, CLI Cold-Start & Android Verification

| Target | Artifact / Check | Exact Result |
|---|---|---|
| Windows Release Portable | `packaging/windows/package-portable.ps1` (`--release`, LTO thin) | Compiled in `11m 47s`; `r3x-app.exe` (`32,522,240 B`), `r3x-daemon.exe` (`10,594,816 B`), `r3x.exe` (`10,246,656 B`), `r3x-0.1.0-windows-x86_64-portable.zip` (`22,233,141 B`), `r3x-sbom.cdx.json` (`204,789 B`, `752` deps) |
| Release CLI Cold-Start | `dist/r3x.exe --json version` / `cores list` / `diagnostics run` | `exit=0` in `22.85 ms`, `23.76 ms`, and `73.47 ms` (with temp `R3X_DATA_DIR`) |
| Android ARM64 NDK + APK | `packaging/android/build-android.ps1` | `BUILD_SCRIPT_EXIT=0`: NDK `27.2.12479018` `libr3x_app_lib.so` (`129,296,464 B` debug, `4m 28s`), Gradle `9.6.0` / AGP `8.9.1` `app-debug.apk` (`137,714,711 B`, `3m 45s`) |

### 4. Explicitly Unexecuted Checks

The following remain unexecuted in this offline Windows build environment and are reflected honestly in the **`Release Candidate`** status:
- Live interactive Slint GUI test on physical Linux Wayland/X11 compositors
- Physical Android device / emulator `R3xVpnService` traffic routing & boot-receiver verification
- Live Inno Setup (`ISCC.exe`) installer build locally (automated in `.github/workflows/windows.yml`)
- Multi-hour (`8h–24h`) continuous proxy/TUN throughput and battery endurance soak tests against live external endpoints
