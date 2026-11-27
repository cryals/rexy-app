# R3X Release Candidate Checklist (`v0.1.0`)

| Check | Status | Measured Result / Evidence |
|---|---|---|
| `cargo fmt --all -- --check` | **Passed** | Exited `0` after final Rust edits |
| `cargo clippy --workspace --all-targets -- -D warnings` | **Passed** | Exited `0`; zero Rust warnings across all 11 crates (expected `material-1.1.0` drop-shadow warning untouched) |
| `cargo test --workspace` | **Passed** | `38 passed, 0 failed, 0 ignored` across 11 crates (`ui_smoke`: 1, `cli_tests`: 1, `cores_tests`: 5, `diagnostics_tests`: 4, `domain_tests`: 5, `engine_tests`: 4, `ipc_tests`: 2, `network_tests`: 2, `profiles_tests`: 6, `security_tests`: 5, `storage_tests`: 3) |
| `cargo deny check licenses bans sources` | **Passed** | `bans ok, licenses ok, sources ok` |
| `cargo audit` | **Passed (0 Vulns)** | 752 dependencies scanned against 1,571 advisories; `0` vulnerabilities, `8` allowed upstream `unmaintained` warnings (`AUDIT_EXIT=0`) |
| Fuzz Targets (`cargo check --manifest-path fuzz/Cargo.toml`) | **Passed** | All 4 libFuzzer targets (`fuzz_uri_parser`, `fuzz_import_payload`, `fuzz_redactor`, `fuzz_ipc_frame`) checked cleanly (`FUZZ_CHECK_EXIT=0` in `52.18s`) |
| Criterion Microbenchmarks (`r3x-diagnostics`) | **Passed** | `BENCH_EXIT=0`: `parse_1000_vless_uris` `5.7116 ms`, `redact_dense_secrets` `90.921 us`, `build_area_path_3600` `1.7879 ms`, `preview_routing_100_rules` `425.94 us` |
| CycloneDX 1.5 SBOM (`dist/r3x-sbom.cdx.json`) | **Passed** | `SBOM_EXIT=0`; `752` packages, `204,789` bytes |
| Windows `x86_64` Release Portable + CLI Smoke | **Passed** | `r3x-app.exe` (`32,522,240 B`), `r3x-daemon.exe` (`10,594,816 B`), `r3x.exe` (`10,246,656 B`), portable `.zip` (`22,233,141 B`), 6-entry `SHA256SUMS.txt`; CLI smoke exited `0` (`version` `22.85 ms`, `cores list` `23.76 ms`, `diagnostics run` `73.47 ms`) |
| Android `arm64-v8a` NDK + Gradle APK Build | **Passed** | `BUILD_SCRIPT_EXIT=0`; `libr3x_app_lib.so` (`129,296,464 B` debug) + `app-debug.apk` (`137,714,711 B`, `dist/r3x-0.1.0-android-arm64-debug.apk`) |
| Dual-Portal MkDocs Strict Build (`D:\Rexy\rexy-docs`) | **Passed** | `.\scripts\build-all.ps1` (`mkdocs build --strict`) exited `0`; committed locally (`846a5db`) |
| Linux Compositor GUI, Physical Android Device & 8–24h Soak | **Not Executed** | Outside local Windows CI bounds; documented explicitly in `docs/KNOWN-LIMITATIONS.md` -> Final Verdict: **`Release Candidate`** |
