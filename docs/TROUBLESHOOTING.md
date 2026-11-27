# R3X Troubleshooting Guide

## 1. Error Code Reference

| Code | Category | Typical Cause & Resolution |
|---|---|---|
| `E_VALIDATION` / `E_PROFILE_PARSE` | Input / Profile | Malformed URI, unsupported scheme, blocked insecure protocol (`PPTP` / cleartext `L2TP`), or payload over `10 MiB`. Inspect URI/YAML syntax in Import preview. |
| `E_SECRET_STORE` | Security / Storage | Platform secret backend unavailable (most common on minimal Linux WMs without `gnome-keyring` / `kwallet` D-Bus Secret Service). Start a Secret Service provider; R3X intentionally refuses plaintext secret storage. |
| `E_IPC_VERSION_MISMATCH` | IPC | Stale `r3x-daemon` protocol version. Restart `r3x-daemon` to match the installed `r3x` / `r3x-app` version (`IPC_PROTOCOL_VERSION = 1`). |
| `E_CORE_NOT_INSTALLED` | Cores | Selected core manifest exists, but binary archive has not been downloaded/installed into `CoreManager`. Open **Core Manager** to install/verify or switch back to Auto selection. |
| `E_TUN_PERMISSION` | Network / Privileges | TUN mode requested without elevation (`r3x-daemon` / Wintun on Windows, `CAP_NET_ADMIN` + `/dev/net/tun` on Linux, or `VpnService` grant on Android). Switch to **Proxy** mode or grant TUN permission. |
| `E_HEALTH_CHECK` | Connection | Core started, but SOCKS/HTTP port or control probe failed readiness within timeout. Inspect **Diagnostics -> Core Logs** and run **Network Doctor**. |

## 2. Database Corruption Recovery (`r3x.db`)

On startup, `R3xDatabase::open` runs `PRAGMA quick_check`. If SQLite reports structural corruption (e.g., unsafe shutdown), R3X renames the broken file to `r3x.db.corrupt.<timestamp>` and provisions a fresh schema cleanly. Restore settings/profiles from an encrypted `.r3xbak` backup if needed.

## 3. Stale Proxy or Broken Internet After Crash

Run **Settings -> Advanced -> Recover Network State** (or `r3x-network::recover_network_state()`) to restore the pre-VPN system proxy snapshot and tear down lingering kill-switch rules.

## 4. Android Specifics

- Ensure VPN consent dialog is accepted (`VpnService.prepare()`) and battery optimization does not kill `R3xVpnService` foreground service.
- Note on Gradle versions: `platform/android/build.gradle.kts` specifies AGP `8.9.1`. Locally Gradle `9.6.0` succeeded (`assembleDebug` built cleanly with deprecation warnings for Gradle 10), while `.github/workflows/android.yml` pins Gradle `8.13` for warning-free CI builds.
