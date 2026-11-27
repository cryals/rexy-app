# R3X Multi-Core Adapters (`r3x-cores`)

Every network core integrates behind the async `r3x_engine::CoreAdapter` contract and is registered via `create_all_adapters(&CoreManager)` (`crates/r3x-cores/src/adapters/mod.rs`).

## 1. Registered Adapters (19 Total)

| Adapter Struct | `CoreId` / Binary Role | Config Format | Source File |
|---|---|---|---|
| `XrayAdapter` | `xray` (`Xray-core`) | JSON (`inbounds`/`outbounds`/`routing`) | `adapters/xray.rs` |
| `SingBoxAdapter` | `sing-box` | JSON (`log`/`dns`/`inbounds`/`outbounds`/`route`) | `adapters/sing_box.rs` |
| `MihomoAdapter` | `mihomo` | YAML (`proxies`/`proxy-groups`/`rules`/`tun`) | `adapters/mihomo.rs` |
| `Hysteria2Adapter` | `hysteria2` | YAML/JSON (`server`/`auth`/`socks5`/`http`) | `adapters/hysteria2.rs` |
| `WireGuardAdapter` | `wireguard` | INI `[Interface]` + `[Peer]` (`0600`) | `adapters/wireguard.rs` |
| `AmneziaWgAdapter` | `amneziawg` | INI + `Jc`/`Jmin`/`Jmax`/`S1..S4`/`H1..H4`/`I1..I5` | `adapters/wireguard.rs` |
| `NaiveProxyAdapter` | `naive` | JSON (`listen` SOCKS/HTTP + `proxy` Chromium TLS/QUIC) | `adapters/naive.rs` |
| `MieruAdapter` | `mieru` | JSON client profile | `adapters/mieru.rs` |
| `OpenVpnAdapter` | `openvpn` | `.ovpn` + separate `0600` credentials + `--script-security 1` | `adapters/openvpn.rs` |
| `ShadowsocksRustAdapter` | `shadowsocks-rust` | SIP003/SIP022 JSON (`sslocal`) | `adapters/specialized.rs` |
| `V2FlyAdapter` | `v2fly` | V2Ray v5 JSON config | `adapters/specialized.rs` |
| `JuicityAdapter` | `juicity` | Juicity QUIC client JSON | `adapters/specialized.rs` |
| `BrookAdapter` | `brook` | Brook CLI client flags/config | `adapters/specialized.rs` |
| `TorAdapter` | `tor` | `torrc` + pluggable transports (`obfs4`/`webtunnel`/`snowflake`) | `adapters/specialized.rs` |
| `ExternalCliVpnAdapter::openconnect` | `openconnect` | External CLI invocation args | `adapters/specialized.rs` |
| `ExternalCliVpnAdapter::ikev2` | `ikev2` | OS/strongSwan external CLI bridge | `adapters/specialized.rs` |
| `ExternalCliVpnAdapter::sstp` | `sstp` | `sstp-client` / RAS external CLI | `adapters/specialized.rs` |
| `ExternalCliVpnAdapter::softether` | `softether` | `vpncmd` / external SoftEther CLI | `adapters/specialized.rs` |
| `ExternalCliVpnAdapter::openssh_tun` | `openssh-tun` | `ssh -N -w` external tunnel args | `adapters/specialized.rs` |

## 2. Smart Core Selection Priority

`CoreSelector::select` in `crates/r3x-engine/src/selector.rs` applies deterministic precedence:

1. Profile-level `CorePreference::Preferred(CoreId)`
2. Subscription-level `CorePreference::Preferred(CoreId)`
3. Global `AppSettings::global_core_preference`
4. Automatic ranking by `(SupportStatus, universal_core_priority)` where `Verified > Supported > Experimental > Legacy`, preferring universal multi-protocol cores (`xray`, `sing-box`, `mihomo`) on equal capability rank.

## 3. Manifest & Binary Integrity (`CoreManager`)

- Machine-readable manifests live under `resources/core-manifests/*.json` (14 embedded default manifests loaded via `include_str!` in `crates/r3x-cores/src/manifests.rs`).
- Archives installed via `CoreManager` pass through `extract_zip_safely` or `extract_targz_safely` (no path traversal, no symlinks, bounded extracted bytes) and SHA-256 verification before activating (`CoreInstallState::Installed` / rollback to previous binary on failure).
- **GPL-2.0-only Compliance:** `OpenVpnAdapter` never embeds or links `libopenvpn`; it launches user-installed `openvpn` strictly as a subprocess.
