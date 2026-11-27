# R3X Multi-Platform Build Status (`v0.1.0`)

| Target Platform | Artifact / Output | Verified Locally? | CI Workflow | Exact Evidence / Caveats |
|---|---|---|---|---|
| **Windows `x86_64` MSVC** | `r3x-app.exe`, `r3x-daemon.exe`, `r3x.exe`, portable `.zip`, CycloneDX SBOM, `SHA256SUMS.txt` | **Yes (Verified)** | `.github/workflows/windows.yml` | Compiled in `11m 47s` (`--release`); CLI smoke (`version` 22.85ms, `cores list` 23.76ms, `diagnostics run` 73.47ms) exited `0`; Inno Setup `.iss` defined for CI |
| **Windows `aarch64` MSVC** | Cross-check target | Config only (CI) | `.github/workflows/windows.yml` | Dedicated `windows-arm64-check` job in CI |
| **Android `arm64-v8a` (`aarch64-linux-android`)** | `libr3x_app_lib.so` + `app-debug.apk` | **Yes (Verified Build)** | `.github/workflows/android.yml` | NDK `27.2.12479018` (`4m 28s`) + Gradle `9.6.0` / AGP `8.9.1` (`3m 45s`, `BUILD_SCRIPT_EXIT=0`); APK `137,714,711` bytes; CI pins Gradle `8.13`; physical device/emulator run unexecuted |
| **Android `x86_64`** | Secondary ABI in `build.gradle.kts` | Config only | `.github/workflows/android.yml` | Installed in CI workflow targets; local debug script built `arm64-v8a` |
| **Linux `x86_64` (Wayland / X11)** | `.deb`, `AppImage` / portable tarball, `.rpm` spec | Config + CI | `.github/workflows/linux.yml` | `build-deb.sh`, `build-appimage.sh`, `.desktop`, `metainfo.xml`, `r3x.spec` written; Linux build runs on `ubuntu-24.04` runner (not executed locally on Windows host) |
| **Fuzz Suite (`fuzz/`)** | 4 `libfuzzer-sys` binaries (`fuzz_uri_parser`, `fuzz_import_payload`, `fuzz_redactor`, `fuzz_ipc_frame`) | **Typechecked Locally** | `.github/workflows/security.yml` | `cargo check --manifest-path fuzz/Cargo.toml` passed (`FUZZ_CHECK_EXIT=0` in `52.18s`); nightly fuzz execution configured on Linux CI |
| **Criterion Benchmarks** | `crates/r3x-diagnostics/benches/r3x_benchmarks.rs` | **Yes (Verified)** | `.github/workflows/benchmarks.yml` | All 4 benchmarks passed (`BENCH_EXIT=0`): 5.71ms, 90.92us, 1.79ms, 425.94us |
| **Docs Portals (`rexy-docs`)** | `public/users/`, `public/developers/`, `public/index.html` | **Yes (Verified)** | `rexy-docs/.github/workflows/` | `.\scripts\build-all.ps1` (`mkdocs build --strict`) exited `0` (committed `846a5db`) |
