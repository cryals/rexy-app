# R3X License Compatibility Analysis

## Selected Project License
**GNU General Public License v3.0 only (`GPL-3.0-only`)** — recorded in `LICENSE.txt` and `Cargo.toml`.

## Why `GPL-3.0-only`
1. **Slint GUI Toolkit (`slint` 1.19.1):** Distributed under `GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0`. Licensing R3X under `GPL-3.0-only` keeps open-source distribution cleanly compliant without requiring proprietary license restrictions.
2. **Universal Proxy Cores (`sing-box`, `Mihomo`, `Mieru`):** Licensed under `GPL-3.0`. Even when invoked out-of-process or bundled, `GPL-3.0-only` ensures unambiguous license alignment for a unified distribution.
3. **Permissive & Weak-Copyleft Ecosystem Compatibility:**
   - **MIT / Apache-2.0 / BSD-2-Clause / BSD-3-Clause / ISC / Zlib / 0BSD / Unicode-3.0:** Compatible with `GPL-3.0-only`.
   - **MPL-2.0 (`Xray-core`):** Compatible with `GPL-3.0` (Section 3.3 MPL-2.0).
   - **GPL-2.0-only (`OpenVPN`):** Incompatible for static/dynamic linking with `GPL-3.0`. Therefore `OpenVPN` is strictly treated as an optional out-of-process system/external binary invoked via its CLI interface, never linked into the Rust binary.

## Banned Dependencies (`deny.toml`)
- `serde_yaml` and `serde_yml` are explicitly banned (deprecated/unmaintained); `serde_yaml_ng` is used instead.
- `openssl` and `openssl-sys` are banned in Rust crates to ensure pure-Rust cryptography (`rustls`, `chacha20poly1305`, `argon2`, `sha2`) and consistent cross-compilation to Android.
