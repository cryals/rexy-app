# Subscriptions & Multi-Format Parsing (`r3x-profiles`)

R3X parses subscriptions, local configs, clipboard imports, and QR images defensively in `crates/r3x-profiles/`.

## 1. Supported Import Formats

- **Individual & multi-line URIs (`uri.rs`):** `vless://`, `vmess://` (base64 JSON & AEAD), `trojan://`, `ss://` (SIP002 & legacy base64), `ssr://`, `hy2://` / `hysteria2://`, `hysteria://`, `tuic://`, `anytls://`, `naive+https://` / `naive+quic://`, `mieru://`, `juicity://`, `socks5://` / `socks://` / `socks4://` / `socks4a://`, `http://` / `https://`, `ssh://`, `brook://`.
- **Base64 Subscription Payloads (`formats.rs`):** Standard & URL-safe base64 decoding up to bounded limits.
- **Clash / Mihomo YAML (`formats.rs`):** Parsed safely via `serde-saphyr` (not deprecated `serde_yaml`).
- **sing-box & Xray JSON (`formats.rs`):** Inbound/outbound JSON extraction.
- **WireGuard & AmneziaWG INI (`formats.rs`):** `[Interface]` + `[Peer]` including `Jc`, `Jmin`, `Jmax`, `S1..S4`, `H1..H4`, `I1..I5`.
- **OpenVPN (`.ovpn`):** Remote host, port, proto, cipher/auth extraction into `ProtocolType::OpenVpn`.
- **QR Codes (`qr.rs`):** `encode_profile_qr_svg` (rendered crisply without bitmap blurring) and `decode_qr_image_bytes` (PNG/image decoding).

## 2. Safety & Reliability Guarantees

- **Bounds (`r3x-security::validation`):**
  - `MAX_SUBSCRIPTION_BYTES = 10 MiB`
  - `MAX_PROFILES_PER_SUBSCRIPTION` enforced during import
  - Remote URL validation blocks malformed/non-HTTP(S) schemes before fetching
- **Untrusted Headers (`headers.rs`):** `parse_subscription_headers` tolerates absent, negative, malformed, or overflowing `Subscription-Userinfo` values (`upload`, `download`, `total`, `expire`) and MIME `Profile-Title` headers; `total == 0` renders as **Unlimited** rather than dividing by zero.
- **Atomic Preservation (`subscription_manager.rs`):** Failed HTTP refreshes return typed `R3xError` diagnostics and **never overwrite** the previously saved SQLite profile set, custom user renames, or `is_favorite` flags.
