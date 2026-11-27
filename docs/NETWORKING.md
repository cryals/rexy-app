# Desktop & Mobile Networking (`r3x-network`, Android `VpnService`)

## 1. Transactional System Proxy (`r3x-network::proxy`)

Proxy settings changes on Windows (WinINet / `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`) and Linux (GNOME `gsettings` / environment snapshot) are wrapped in `SystemProxyManager`:

1. **Snapshot:** Prior proxy state (`enabled`, `server`, `bypass_list`) is persisted before mutation.
2. **Apply:** Sets loopback listener (`127.0.0.1:<port>` unless LAN sharing enabled) + private CIDR bypasses.
3. **Recovery Journal (`recovery.rs`):** Persists an active transaction marker so if the app or daemon terminates unexpectedly, startup `recover_network_state()` restores the pre-VPN system proxy and clears stale kill-switch rules cleanly.

## 2. TUN, Interfaces & Kill Switch (`tun.rs`, `monitor.rs`, `kill_switch.rs`)

- **Privilege-Aware TUN (`check_tun_capability`):** Reports whether creating a virtual adapter is permitted right now (elevated/`r3x-daemon` on Windows with Wintun, `CAP_NET_ADMIN` + `/dev/net/tun` on Linux, active `VpnService` permission on Android). Unsupported/unprivileged environments disable TUN cleanly with actionable remediation rather than hanging.
- **Port & Interface Probes:** Checks bind availability on SOCKS5/HTTP/control ports and enumerates `NetworkInterfaceInfo` (`up`, `mtu`, `addresses`).
- **Kill Switch (`KillSwitchManager`):** Coordinates strict route/firewall teardown and recovery journaling on Linux/Windows.

## 3. Android `VpnService` & JNI Tunnel Flow (`platform/android/` + `src/android_jni.rs`)

- `R3xVpnService` requests `VpnService.prepare()`, builds a foreground notification channel (`r3x_vpn_channel`), configures `VpnService.Builder` (`addAddress`, `addRoute`, `addDnsServer`, `setMtu`, `addDisallowedApplication("dev.rexy.r3x")` for self-exclusion), calls `builder.establish()`, detaches the file descriptor, and hands it via JNI (`onVpnTunnelEstablished(fd)`) into `R3xController` (`active_tun_fd()`).
- On revoke or disconnect, `onVpnTunnelRevoked()` notifies Rust immediately so the engine stops rather than reporting a false `Connected` state.
