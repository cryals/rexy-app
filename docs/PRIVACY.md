# R3X Privacy Policy & Guarantees

R3X (*Rust-powered Expressive Proxy*) is built with strict privacy-by-default engineering.

## 1. Zero Commercial Tracking & Zero Forced Accounts

- **No Telemetry:** R3X disables analytics, telemetry, crash reporting uploads, and advertising identifiers completely.
- **No Mandatory Registration:** R3X operates entirely locally and independently of any SaaS account or commercial VPN provider.

## 2. Sensitive Data Handling

- **Credential Isolation (`r3x-storage`):** Passwords, proxy secrets, subscription credentials, and private keys are stored in the platform secure store (Windows Credential Manager, Linux D-Bus Secret Service, Android Keystore) rather than unencrypted JSON/SQLite rows.
- **Log & Export Scrubbing (`r3x-security::Redactor`):** Every Application, Core, Subscription, Network, Platform, and Connection log line — as well as exported diagnostic bundles from **Network Doctor** — passes through automated redaction before being buffered, written to disk, or copied.
- **Encrypted Backups:** Local export archives (`.r3xbak`) require explicit user passphrases and are sealed with **Argon2id** + **XChaCha20-Poly1305**.

## 3. Local Network Exposure

- Loopback HTTP/SOCKS5 listeners bind to `127.0.0.1` by default.
- LAN sharing (`0.0.0.0`) is disabled by default and requires explicit user opt-in in **Settings -> Connection & Network Ports**.
