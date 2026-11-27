# R3X Protocol, Transport & Core Support Matrix

> **Honesty Rule:** Every entry below strictly reflects actual parser, adapter, and platform verification status in this repository.
> - `Supported` = URI/config parser, `CoreAdapter` config generation, validation, and unit tests pass; runtime execution uses an official client binary verified by SHA-256 via `CoreManager` (or user-installed OS binary for external VPN tools).
> - `Verified` = End-to-end verified against a live tunnel binary/endpoint in CI or interactive testing (reserved until binary integration passes).
> - `Experimental` = Adapter/config generation implemented, requires external CLI tool or protocol extensions under validation.
> - `Legacy` = Deprecated/compatibility protocol kept strictly opt-in or external.
> - `ImportOnly` = Profile parsed into `r3x-domain` models cleanly, requires manual/external client outside R3X's primary adapters.
> - `Blocked` = Intentionally blocked for cryptographic or security hazards (never implemented).

## 1. Proxy Protocols

| Protocol | Primary / Dedicated Core(s) | Status | URI / Format Support | Platforms | Notes |
|---|---|---|---|---|---|
| VLESS (XTLS Vision, REALITY, VLESS Encryption) | Xray-core, sing-box, Mihomo | `Supported` | `vless://`, Clash YAML, sing-box/Xray JSON | Windows, Linux, Android | Primary flagship protocol; flow/security/transport strictly separated |
| VMess | Xray-core, sing-box, Mihomo, V2Fly | `Supported` | `vmess://`, Clash YAML, JSON | Windows, Linux, Android | Legacy JSON VMess QR & AEAD supported |
| Trojan | Xray-core, sing-box, Mihomo, V2Fly | `Supported` | `trojan://`, Clash YAML, JSON | Windows, Linux, Android | TLS / REALITY / WS / gRPC |
| Shadowsocks (AEAD) | Xray-core, sing-box, Mihomo, shadowsocks-rust | `Supported` | `ss://`, SIP008/YAML/JSON | Windows, Linux, Android | Legacy RC4/stream ciphers deprecated (`Legacy`) |
| Shadowsocks 2022 | Xray-core, sing-box, Mihomo, shadowsocks-rust | `Supported` | `ss://`, JSON/YAML | Windows, Linux, Android | `2022-blake3-*` PSKs |
| Hysteria 2 (Brutal + Salamander) | Hysteria 2, sing-box, Mihomo | `Supported` | `hy2://`, `hysteria2://`, YAML/JSON | Windows, Linux, Android | Dedicated `Hysteria2Adapter` + universal cores |
| Hysteria 1 | sing-box, Mihomo | `Legacy` | `hysteria://`, YAML/JSON | Windows, Linux, Android | Superseded by Hysteria 2 |
| TUIC v5 | sing-box, Mihomo | `Supported` | `tuic://`, YAML/JSON | Windows, Linux, Android | ALPN/congestion control supported |
| TUIC v4 | sing-box | `Legacy` | YAML/JSON | Windows, Linux, Android | Superseded by TUIC v5 |
| AnyTLS | sing-box, Mihomo | `Supported` | `anytls://`, JSON/YAML | Windows, Linux, Android | Session-multiplexed TLS anti-probe |
| ShadowTLS v3 | sing-box | `Supported` | Clash YAML, sing-box JSON | Windows, Linux, Android | Chained detour support in sing-box |
| ShadowTLS v1/v2 | sing-box | `Legacy` | JSON/YAML | Windows, Linux, Android | Prefer v3 |
| NaiveProxy (Chromium stack) | NaiveProxy | `Supported` | `naive+https://`, `naive+quic://`, JSON | Windows, Linux, Android | Standalone local SOCKS/HTTP core |
| Mieru | Mieru, Mihomo | `Supported` | `mieru://`, YAML/JSON | Windows, Linux, Android | Non-TLS high-entropy TCP/UDP obfuscation |
| Snell (v3/v4) | Mihomo | `Supported` | Clash YAML | Windows, Linux, Android | Via Mihomo outbound |
| Juicity | Juicity | `Supported` | `juicity://`, JSON | Windows, Linux, Android | Dedicated QUIC adapter |
| HTTP / HTTPS Proxy | Xray-core, sing-box, Mihomo | `Supported` | `http://`, `https://`, JSON/YAML | Windows, Linux, Android | Outbound + inbound |
| SOCKS5 / SOCKS4 / SOCKS4a | Xray-core, sing-box, Mihomo, Tor | `Supported` | `socks5://`, `socks://`, `socks4://`, `socks4a://` | Windows, Linux, Android | Basic auth supported |
| SSH Tunnel / Forwarding | sing-box, Mihomo, OpenSSH | `Supported` | `ssh://`, JSON/YAML | Windows, Linux, Android | Outbound SSH proxy |
| ShadowsocksR (SSR) | Mihomo | `Legacy` | `ssr://`, Clash YAML | Windows, Linux, Android | Legacy compatibility only |
| Brook | Brook | `Supported` | `brook://`, JSON | Windows, Linux | Desktop standalone adapter |
| MASQUE | External / Cloudflare Warp+ | `ImportOnly` | JSON / manual | Windows, Linux, Android | Model tracked; awaits upstream stable client CLI adapter |
| TrustTunnel / Sudoku / MTProto | Dedicated upstream binaries | `ImportOnly` | `tg://` / `mtproto://` / JSON | Windows, Linux | Parsed/validated; dedicated adapter optional |

## 2. VPN Protocols & Mesh Overlays

| Protocol / Overlay | Core / Driver | Status | Config Generation | Notes |
|---|---|---|---|---|
| WireGuard | `wireguard`, sing-box, Xray-core | `Supported` | `[Interface]` + `[Peer]` INI (`0600`) | Uses `wireguard-go` / OS Wintun / kernel netlink / universal cores |
| AmneziaWG (1.0 / 1.5 / 2.0 / 3.1) | `amneziawg-go` (`AmneziaWgAdapter`) | `Supported` | `[Interface]` INI + `Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5` | DPI obfuscation parameters validated & persisted |
| OpenVPN (UDP / TCP) | External `openvpn` CLI (`OpenVpnAdapter`) | `Supported` | `.ovpn` + restricted `auth.txt`, `--script-security 1` | **GPL-2.0-only isolation:** invoked strictly out-of-process, never statically/dynamically linked |
| OpenVPN + Cloak | External `openvpn` + `ck-client` | `Experimental` | `.ovpn` + `ck-client` flags | Requires both external binaries |
| OpenConnect (AnyConnect / ocserv) | External `openconnect` CLI | `Experimental` | CLI target generation | Requires system OpenConnect install |
| IKEv2 / IPsec | strongSwan / Windows RAS | `Experimental` | External CLI adapter | Requires OS IPsec service |
| IKEv1 / IPsec | Legacy IPsec | `Legacy` | Import only | Superseded by IKEv2/WireGuard |
| L2TP / IPsec | OS L2TP+IPsec | `Legacy` | Import only | Must always use IPsec; unencrypted L2TP blocked |
| SSTP | `sstp-client` / Windows SSTP | `Legacy` | External CLI adapter | Windows native / Linux `sstp-client` |
| SoftEther VPN | SoftEther Client CLI | `Experimental` | External CLI adapter | External system client |
| OpenSSH TUN (`ssh -w`) | OpenSSH | `Experimental` | External CLI (`-N -w 0:0`) | Linux privileged TUN |
| Tailscale / Headscale / ZeroTier / Nebula | Official mesh daemons | `ImportOnly` | Recognized in `ProtocolType` | Managed alongside R3X; conflict checks in Network Doctor |
| **PPTP & Unencrypted L2TP** | — | **`Blocked`** | **Rejected by validation** | MS-CHAPv2 / MPPE and cleartext L2TP are cryptographically broken |

## 3. Transports, Security & Obfuscation Layers

R3X strictly decouples **Protocol** from **Transport**, **Security**, and **Flow** (`crates/r3x-domain/src/profile.rs`):
- **Transports:** `RawTcp` (none / HTTP header masquerade), `WebSocket` (path, Host header, early data), `gRPC` (serviceName, multi-mode), `HTTPUpgrade`, `XHTTP` / `SplitHTTP` (mode/path/host), `Http2`, `mKCP` (header/seed), `Quic`, `Http3`, `UdpRaw`.
- **Security:** `None`, `Tls` (SNI, ALPN, uTLS fingerprint, ECH config, opt-in explicit `allow_insecure` warning), `Reality` (SNI, publicKey, shortId, spiderX, fingerprint), `VlessEncryption`, `NoiseWg`, `AmneziaWg`.
- **Flow / Multiplexing:** `xtls-rprx-vision`, `xtls-rprx-vision-udp443`, Mux concurrency, XUDP, UDP-over-TCP, Salamander obfs (`Hysteria2`), WebTunnel / obfs4 / Snowflake bridge parameters (`TorAdapter`).
