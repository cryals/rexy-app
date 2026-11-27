# Third-Party Notices

R3X (`GPL-3.0-only`) builds on the following open-source projects and templates. Full machine-readable license verification is enforced via `deny.toml` (`cargo deny check licenses`).

## Bundled UI Kit & Template
- **Slint & Material Components for Slint (`material-1.1.0/`)** — Copyright © SixtyFPS GmbH. Dual-licensed under `GPL-3.0-only` / Slint Commercial / Material kit `MIT`.

## Rust Crates (Direct Dependencies)
- `tokio`, `tokio-util`, `tracing`, `tracing-subscriber`, `tracing-appender`, `parking_lot` — MIT / Apache-2.0
- `serde`, `serde_json`, `thiserror`, `anyhow`, `url`, `uuid`, `chrono`, `ipnet`, `regex`, `base64`, `hex`, `sha2`, `rand`, `argon2`, `chacha20poly1305`, `zeroize`, `secrecy` — MIT OR Apache-2.0
- `subtle` — BSD-3-Clause
- `rusqlite` (bundled SQLite 3) — MIT (SQLite is Public Domain)
- `interprocess` — 0BSD OR Apache-2.0
- `directories`, `zip`, `flate2`, `tar`, `keyring` — MIT / Apache-2.0

## External Network Cores (Planned Integration & Manifests)
- **Xray-core** (`XTLS/Xray-core`) — MPL-2.0
- **sing-box** (`SagerNet/sing-box`) — GPL-3.0 (plus upstream naming notice)
- **Mihomo** (`MetaCubeX/mihomo`) — GPL-3.0 (plus upstream trademark notice)
- **Hysteria 2** (`apernet/hysteria`) — MIT
- **AmneziaWG** (`amnezia-vpn`) — MIT
- **NaiveProxy** (`klzgrad/naiveproxy`) — BSD-3-Clause
- **Mieru** (`enfein/mieru`) — GPL-3.0
