# R3X Implementation Status

> **Status Definitions:** `Not started` | `In progress` | `Implemented` | `Tested` | `Verified` | `Blocked` | `Unsupported`
> Note: `Implemented` does not mean `Verified`. `Verified` is assigned strictly after automated checks/tests pass on real behavior.
> Note on protocol catalog: `PROXY-PROTOCOLS-AND-CORES.md` was not present in the workspace on initial audit; Section 10 of the specification is tracked as the canonical baseline.

| Feature | Module | Platform | Implementation Status | Test Status | Remaining Work | Blockers |
|---|---|---|---|---|---|---|
| Cargo Workspace & Toolchain Pinning | Root (`Cargo.toml`, `rust-toolchain.toml`) | All | Verified | Passed (`cargo check`, `clippy`, `fmt`) | Add Wave 3 crates (`r3x-diagnostics`) | None |
| License Audit & `cargo-deny` | `LICENSE.txt`, `deny.toml` | All | Verified | Passed (`licenses`, `bans`, `sources`) | Re-run as Wave 3–4 deps added | None |
| Domain Models & 10-state FSM | `crates/r3x-domain` | All | Verified | 5/5 passed (`domain_tests`) | None | None |
| Security (Redaction, Archives, AEAD, SHA-256) | `crates/r3x-security` | All | Verified | 5/5 passed incl. `proptest` (`security_tests`) | Fuzz targets in Wave 4 | None |
| SQLite Storage, Migrations & Recovery | `crates/r3x-storage` | All | Verified | 3/3 passed (`storage_tests`) | Wire Android Keystore JNI bridge in Wave 4 | None |
| Versioned Authenticated IPC | `crates/r3x-ipc` | Windows / Linux | Verified | 2/2 passed (`ipc_tests`) | Attach tray/extended handlers | None |
| Central Engine, Core Contract & LogHub | `crates/r3x-engine` | All | Verified | 4/4 passed (`engine_tests`) | Wire extended adapters (Wave 3) | None |
| Subscription Parsers, QR & HTTP Refresh | `crates/r3x-profiles` | All | Verified | 6/6 passed incl. `proptest` & HTTP (`profiles_tests`) | None | None |
| Core Manager, Manifests & Primary Adapters | `crates/r3x-cores` | All | Verified | 4/4 passed (`cores_tests`, all 14 manifests + real subprocess) | Extended adapters in Wave 3 | None |
| Desktop Networking (Proxy, Recovery, Kill Switch, Ports) | `crates/r3x-network` | Windows / Linux | Verified | 2/2 passed (`network_tests`) | Desktop tray integration in Wave 3 | None |
| Background Daemon (`r3x-daemon`) & CLI (`r3x`) | `apps/r3x-daemon`, `apps/r3x-cli` | Windows / Linux | Verified | 1/1 CLI JSON test passed (`cli_tests`) | Live daemon end-to-end tests with real cores where installed | None |
| M3 Expressive UI Kit & Adaptive Shell | `ui/` & `src/` | All | Verified (Headless) | 1/1 passed (`ui_smoke`) | Complete remaining 60 screens/states in Wave 3 | None |
| Dual-Portal MkDocs & Actions | `D:\Rexy\rexy-docs` | Web / GitHub Pages | Verified | `mkdocs build --strict` passed for both portals | Sync with Wave 3/4 docs before release | None |
| Routing, DNS, Network Doctor, Monitoring | `crates/r3x-diagnostics` | All | Not started | Not started | Wave 3 implementation | None |
| Extended Cores (WG, AWG, Hysteria, Mieru, etc.) | `crates/r3x-cores` | All | Manifests parsed | Pending adapter tests | Wave 3 adapters | None |
| Android Gradle + `VpnService` + JNI | `platform/android/` | Android | Not started | Not started | Wave 4 implementation | None |
| Release Packaging & Multi-OS CI Workflows | `.github/workflows/`, `packaging/` | All | In progress | `ci.yml` created | Platform packaging & release workflows in Wave 4 | None |
