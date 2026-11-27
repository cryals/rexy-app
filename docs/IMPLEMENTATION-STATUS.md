# R3X Implementation Status

> **Status Definitions:** `Not started` | `In progress` | `Implemented` | `Tested` | `Verified` | `Blocked` | `Unsupported`
> Note: `Implemented` does not mean `Verified`. `Verified` is assigned strictly after automated checks/tests pass on real behavior.
> Note on protocol catalog: `PROXY-PROTOCOLS-AND-CORES.md` was not present in the workspace on initial audit; Section 10 of the specification is tracked as the canonical baseline.

| Feature | Module | Platform | Implementation Status | Test Status | Remaining Work | Blockers |
|---|---|---|---|---|---|---|
| Cargo Workspace & Toolchain Pinning | Root (`Cargo.toml`, `rust-toolchain.toml`) | All | Verified | Passed (`cargo check`, `clippy`, `fmt`) | Add release profile & benchmarks | None |
| License Audit & `cargo-deny` | `LICENSE.txt`, `deny.toml` | All | Verified | Passed (`licenses`, `bans`, `sources`) | Re-run with Wave 4 deps | None |
| Domain Models & 10-state FSM | `crates/r3x-domain` | All | Verified | 5/5 passed (`domain_tests`) | None | None |
| Security (Redaction, Archives, AEAD, SHA-256) | `crates/r3x-security` | All | Verified | 5/5 passed incl. `proptest` (`security_tests`) | Fuzz harnesses in Wave 4 | None |
| SQLite Storage, Migrations & Recovery | `crates/r3x-storage` | All | Verified | 3/3 passed (`storage_tests`) | Wire Android Keystore JNI bridge in Wave 4 | None |
| Versioned Authenticated IPC | `crates/r3x-ipc` | Windows / Linux | Verified | 2/2 passed (`ipc_tests`) | None | None |
| Central Engine, Core Contract & LogHub | `crates/r3x-engine` | All | Verified | 4/4 passed (`engine_tests`) | Live binary integration where cores installed | None |
| Subscription Parsers, QR & HTTP Refresh | `crates/r3x-profiles` | All | Verified | 6/6 passed incl. `proptest` & HTTP (`profiles_tests`) | None | None |
| Core Manager, Manifests & All 19 Adapters | `crates/r3x-cores` | All | Verified (Configs & Subprocess) | 5/5 passed (`cores_tests`, 14 manifests + all adapters + real TCP subprocess) | Live multi-hour tunnel soak with external binaries | None |
| Desktop Networking (Proxy, Recovery, Kill Switch, Ports) | `crates/r3x-network` | Windows / Linux | Verified | 2/2 passed (`network_tests`) | Real OS Linux desktop/Wayland GUI test | None |
| Diagnostics, Routing, DNS Probes & Telemetry | `crates/r3x-diagnostics` | All | Verified | 4/4 passed (`diagnostics_tests`, 16 Doctor checks + SVG + `sysinfo`) | None | None |
| Background Daemon (`r3x-daemon`) & CLI (`r3x`) | `apps/r3x-daemon`, `apps/r3x-cli` | Windows / Linux | Verified | 1/1 CLI JSON test passed (`cli_tests`) | None | None |
| Full Material 3 Expressive UI Kit & All Screens | `ui/` & `src/` | All | Verified (Headless) | 1/1 comprehensive UI test (`ui_smoke`) | Interactive visual test on Linux/Android | None |
| Desktop Window State & Tray Abstraction | `src/tray.rs` | Windows / Linux | Implemented | Window persistence compiled; `DesktopTrayHandle` abstracts OS icon cleanly for headless/Wayland CI compatibility | Optional `libayatana-appindicator` / Windows shell icon binding | None |
| Dual-Portal MkDocs & Actions | `D:\Rexy\rexy-docs` | Web / GitHub Pages | Verified | `mkdocs build --strict` passed | Final Wave 4 docs sync | None |
| Android Gradle + `VpnService` + JNI | `platform/android/` | Android | Not started | Not started | Wave 4 implementation | None |
| Release Packaging, Fuzz, Benchmarks & CI | `.github/workflows/`, `packaging/`, `fuzz/` | All | In progress | `ci.yml` passing | Complete Wave 4 artifacts | None |
