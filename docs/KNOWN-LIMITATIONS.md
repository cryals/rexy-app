# Known Limitations & Deferred Scope

R3X maintains strict engineering honesty between implemented features and unexecuted external runtime environments:

1. **External Core Binaries Not Pre-Bundled in Source Repo:** R3X embeds 14 machine-readable core manifests (`resources/core-manifests/*.json`) and 19 `CoreAdapter` engines, plus full SHA-256 install/verify/rollback orchestration. Because upstream core binaries (`xray`, `sing-box`, `mihomo`, `hysteria2`, `wireguard`, `openvpn`, etc.) are distributed independently by their respective upstream projects, first-time users install cores via **Core Manager** (or system PATH for external VPN CLIs like `openvpn`).
2. **Unexecuted Live Environments in This Release Candidate:**
   - Interactive GUI visual walkthrough on live **Linux Wayland/X11** desktop compositors (verified via GitHub Actions `ubuntu-24.04` build/test definitions and headless `i-slint-backend-testing` only, not live physical Linux GPU compositors).
   - Live tunnel packet-forwarding on physical **Android 10–16** hardware / emulator (`R3xVpnService` + JNI tunnel FD handoff are implemented in Kotlin + Rust and compiled for `aarch64-linux-android`, pending physical device test bench).
   - 8–24h continuous high-load tunnel endurance / soak benchmark against external VPN servers (process/controller tests ran deterministic local TCP/subprocess probes).
   - Live Windows `ISCC.exe` Inno Setup compilation if Inno Setup 6 is not installed locally (CI workflow installs Inno Setup automatically; portable ZIP + unarchived EXEs are verified locally).
3. **Desktop System Tray Native Icon Hooks:** `src/tray.rs` provides `DesktopTrayHandle` and persisted close/minimize/autostart preferences (`WindowState` + tray status snapshots) cleanly decoupled from Wayland/Headless CI blockers; direct native shell status-icon binding (`Shell_NotifyIconW` / StatusNotifierItem) remains an optional post-1.0 enhancement.
4. **Protocol Scope:** `MASQUE`, `TrustTunnel`, `Sudoku`, `MTProto`, `Tailscale`, `Headscale`, `ZeroTier`, and `Nebula` are modeled and recognized as `ImportOnly` profiles (`docs/PROTOCOL-SUPPORT.md`); `PPTP` and unencrypted `L2TP` are intentionally blocked.
5. **macOS & iOS:** Architecture (`r3x-domain`, `r3x-engine`, `r3x-cores`, adaptive Slint UI) avoids platform lock-in, though Apple targets (`NetworkExtension` / notarization) are out of scope for v0.1.0.
