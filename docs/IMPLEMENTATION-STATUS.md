# R3X Implementation Status

> **Status Definitions:** `Not started` | `In progress` | `Implemented` | `Tested` | `Verified` | `Blocked` | `Unsupported`
> Note: `Implemented` does not mean `Verified`. `Verified` is assigned strictly after automated checks/tests pass on real behavior.
> Note on protocol catalog: `PROXY-PROTOCOLS-AND-CORES.md` was not present in `D:\Rexy` on initial audit; Section 10 of the specification was used as the canonical baseline.

| Feature | Module | Platform | Implementation Status | Test / Build Status | Remaining / Hardware Caveats |
|---|---|---|---|---|---|
| Cargo Workspace & Toolchain Pinning | Root (`Cargo.toml`, `rust-toolchain.toml`, `.cargo/config.toml`) | All | Verified | Passed (`fmt`, `check`, `clippy --all-targets -D warnings`, `[profile.release]`) | None |
| License Audit, `cargo-deny` & `cargo-audit` | `LICENSE.txt`, `deny.toml` | All | Verified | `cargo deny` passed (`bans/licenses/sources ok`); `cargo audit` 0 vulns across 752 deps | 8 `unmaintained` upstream transitive advisories monitored via Dependabot |
| Domain Models & 10-State FSM | `crates/r3x-domain` | All | Verified | `5/5` passed (`domain_tests`) | None |
| Security (Redaction, Archives, AEAD, SHA-256) | `crates/r3x-security` | All | Verified | `5/5` passed incl. `proptest` (`security_tests`) + `fuzz_redactor` typechecked | Nightly `libFuzzer` fuzz runtime scheduled in Linux CI |
| SQLite Storage, Migrations & Recovery | `crates/r3x-storage` | All | Verified | `3/3` passed (`storage_tests`) | Live AndroidKeyStore hardware test pending device bench |
| Versioned Authenticated IPC | `crates/r3x-ipc` | Windows / Linux | Verified | `2/2` passed (`ipc_tests`) + `fuzz_ipc_frame` typechecked | None |
| Central Engine, Core Contract & LogHub | `crates/r3x-engine` | All | Verified | `4/4` passed (`engine_tests`) | None |
| Subscription Parsers, QR & HTTP Refresh | `crates/r3x-profiles` | All | Verified | `6/6` passed incl. `proptest` & HTTP (`profiles_tests`) + URI/import fuzzers checked | None |
| Core Manager, Manifests & All 19 Adapters | `crates/r3x-cores`, `resources/core-manifests/` | All | Verified (Configs & Subprocess) | `5/5` passed (`cores_tests`: 14 manifests + all 19 adapters + real TCP subprocess) | External live multi-hour VPN soak not executed |
| Desktop Networking (Proxy, Recovery, Kill Switch, Ports) | `crates/r3x-network` | Windows / Linux | Verified | `2/2` passed (`network_tests`) | Live Linux Wayland/X11 desktop run unexecuted |
| Diagnostics, Routing, DNS & Criterion Benchmarks | `crates/r3x-diagnostics` | All | Verified | `4/4` passed (`diagnostics_tests`, 16 Doctor checks + SVG + `sysinfo`) + `4/4` Criterion benchmarks (`BENCH_EXIT=0`) | None |
| Background Daemon (`r3x-daemon`) & CLI (`r3x`) | `apps/r3x-daemon`, `apps/r3x-cli` | Windows / Linux | Verified | `1/1` CLI test (`cli_tests`) + live `--release` `r3x.exe --json` smoke (`22.85–73.47 ms`, `exit=0`) | None |
| Full Material 3 Expressive UI Kit & All Screens | `ui/` & `src/` | All | Verified (Headless) | `1/1` (`ui_smoke`) + Windows release EXE (`32,522,240 B`) | Interactive Linux GUI & physical Android display test pending |
| Desktop Window State & Tray Abstraction | `src/tray.rs` | Windows / Linux | Implemented | Compiled across dev/release/Clippy targets (`WindowState` persisted) | Optional native OS tray shell icon bindings |
| Android Gradle + `R3xVpnService` + JNI + Keystore | `platform/android/`, `src/android_jni.rs` | Android | Verified (Cross-Compile & APK) | `aarch64-linux-android` NDK `27.2.12479018` + Gradle `assembleDebug` passed (`BUILD_SCRIPT_EXIT=0`, `137,714,711 B` APK) | Live `VpnService` packet routing on physical Android hardware unexecuted |
| Fuzz Harnesses, Packaging, SBOM & CI/CD | `.github/`, `packaging/`, `fuzz/` | All | Verified (Windows/Android/SBOM/Fuzz-Check) | Portable `.zip` + CycloneDX SBOM (`752` deps) + `SHA256SUMS.txt` + `fuzz` check (`exit=0`) + 8 CI workflows | Live Linux `.deb`/AppImage & Inno Setup `.exe` run in GitHub Actions |
| Dual-Portal MkDocs & Actions | `D:\Rexy\rexy-docs` | Web / GitHub Pages | Verified | `mkdocs build --strict` passed (`MKDOCS_EXIT=0`), committed (`846a5db`) | Pages deployment awaits push when user chooses |
