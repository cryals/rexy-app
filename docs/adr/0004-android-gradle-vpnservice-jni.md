# ADR 0004: Android Integration via Gradle + VpnService + JNI + Slint

- **Status:** Accepted
- **Date:** 2026-11-28

## Context
Desktop R3X manages TUN and external core binaries as child processes/daemon. On Android, VPN tunnels require `android.net.VpnService`, user VPN consent (`VpnService.prepare`), a `ForegroundService` notification, socket protection (`protect()`), and restricted binary execution rules on modern Android versions (`targetSdk >= 29`).

## Decision
1. Use Slint's `backend-android-activity-06` (`#[unsafe(no_mangle)] fn android_main`) inside `r3x_app_lib` (`cdylib`), packaged via a persistent Gradle project in `platform/android/` (rather than a toy `cargo-apk` manifest) in Wave 4.
2. Implement `R3xVpnService` in Kotlin extending `VpnService`, passing the established TUN file descriptor (`ParcelFileDescriptor.detachFd()` / `fd`) and Android Keystore secrets across JNI to `r3x-storage` and `r3x-engine`.
3. Target Android 10 (API 29) minimum SDK (`minSdk = 29`) with `aarch64-linux-android` and `x86_64-linux-android` ABIs, bundling cores via permitted native library/JNI integration rather than runtime binary downloads.

## Consequences
- Background VPN connections survive UI Activity recreation and screen rotation.
- Android Keystore protects credentials natively instead of desktop `keyring`.
