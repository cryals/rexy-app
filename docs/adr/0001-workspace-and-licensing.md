# ADR 0001: Cargo Workspace Layout and Project Licensing

- **Status:** Accepted
- **Date:** 2026-11-28

## Context
R3X requires cross-platform builds across Windows, Linux, and Android, strict separation between UI/platform code and core networking/domain logic, and legal compatibility across Slint and multi-core proxy engines.

## Decision
1. Structure `rexy-app` as a Cargo Workspace (`resolver = "3"`, Rust Edition `2024`, pinned `rustc 1.100.0` via `rust-toolchain.toml`) with focused crates (`r3x-domain`, `r3x-security`, `r3x-storage`, `r3x-ipc`, `r3x-engine`, and subsequent Wave 2/3 crates) plus the root `r3x-app` UI package (`lib` + `cdylib` + `bin`).
2. License R3X under `GPL-3.0-only`, matching Slint's open-source license and GPL-3.0 proxy engines (`sing-box`, `mihomo`, `mieru`) while maintaining compatibility with MPL-2.0 (`Xray-core`) and permissive crates. GPL-2.0-only tools (`OpenVPN`) remain strictly external CLI subprocesses.
3. Enforce dependency/license hygiene via `deny.toml` (`cargo-deny`).

## Consequences
- Pure-Rust crates (`r3x-domain`, `r3x-security`, `r3x-engine`) stay 100% portable to `aarch64-linux-android`.
- Desktop-only credential backends (`keyring`) are strictly target-gated out of Android builds.
