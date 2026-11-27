# R3X Security Architecture

## 1. Defense-in-Depth Layers

1. **TLS & Cryptography:** Workspace HTTP/DoH clients use `rustls` with WebPKI roots (`ring` backend) — `openssl` and `openssl-sys` are explicitly banned in `deny.toml`.
2. **YAML/Parser Safety:** Clash/Mihomo YAML imports use pure-Rust `serde-saphyr`; deprecated `serde_yaml` / `serde_yml` crates are banned in `deny.toml`.
3. **Archive Extraction Guard (`r3x-security::archive`):** Core archive unpacking enforces relative-only canonical paths, denies symlinks/hardlinks, and caps maximum file counts and decompressed byte totals.
4. **Binary Integrity (`CoreManager`):** Downloaded cores must match their manifest SHA-256 digest before replacing an active installation; verification failures roll back automatically.
5. **Local IPC Authentication (`r3x-ipc`):** `r3x-daemon` enforces `0600` POSIX permissions on Unix sockets, per-session Named Pipes on Windows, `4 MiB` frame pre-allocation limits, protocol version checks, and constant-time comparison (`subtle::ConstantTimeEq`) of 256-bit runtime tokens.
6. **Crash-Safe Network Hygiene (`r3x-network`):** Pre-connection OS proxy snapshots and kill-switch markers persist in the runtime journal so `recover_network_state()` restores clean internet access on restart after unexpected termination.
7. **License & Dependency Governance:** `deny.toml` enforces `GPL-3.0-only` compatibility across crates (`cargo deny check licenses bans sources`); `OpenVPN` (`GPL-2.0-only`) is strictly invoked as an unlinked external binary via `OpenVpnAdapter`.

## 2. Automated Security Checks

- **`cargo deny check licenses bans sources`:** Verified passing (`bans ok, licenses ok, sources ok`).
- **`cargo audit` (RustSec):** Scanned 752 dependencies with **0 known security vulnerabilities** (8 non-vulnerability `unmaintained` upstream transitive advisories logged in `crates`/`Cargo.lock` tracking: `bincode`, `chrono`, `pin-utils`, `ttf-parser`, `unsafe-libyaml`, `zbus_names`, `zvariant`, `zvariant_derive`).
- **Fuzz Harnesses (`fuzz/`):** 4 libFuzzer targets (`fuzz_uri_parser`, `fuzz_import_payload`, `fuzz_redactor`, `fuzz_ipc_frame`) wired into `.github/workflows/security.yml`.
