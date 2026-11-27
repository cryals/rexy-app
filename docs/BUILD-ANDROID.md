# Building R3X for Android

## 1. Prerequisites

- **Rust Toolchain:** `1.100.0` (pinned by `rust-toolchain.toml`) with Android targets installed:
  ```powershell
  rustup target add --toolchain 1.100.0 aarch64-linux-android x86_64-linux-android
  ```
- **Android SDK & NDK:**
  - `compileSdk = 36`, `minSdk = 29` (Android 10+), `targetSdk = 36`
  - Android NDK `27.2.12479018`
  - Android SDK Build-Tools `35.0.0` / `36.0.0`
- **JDK:** Java 17+ (tested locally with JDK `21.0.12.1`; CI uses Temurin JDK 17)
- **Gradle:** CI pins Gradle `8.13` (recommended for AGP `8.9.1` + Kotlin `2.1.20` without deprecation warnings); local verification also succeeded on system Gradle `9.6.0`.

## 2. Automated Build Scripts

=== "Windows (PowerShell)"

```powershell
# Cross-compile debug libr3x_app_lib.so on an external scratch drive & build APK:
.\packaging\android\build-android.ps1 -TargetDir "E:\r3x-android-target"

# Or release build (configure signing env vars first):
.\packaging\android\build-android.ps1 -TargetDir "E:\r3x-android-target" -Release
```

=== "Linux (Bash)"

```bash
./packaging/android/build-android.sh
```

## 3. Release Signing Environment Variables

Never commit `.keystore` or `.jks` secrets. `platform/android/app/build.gradle.kts` reads signing credentials strictly from environment variables when building `assembleRelease`:

- `R3X_KEYSTORE_PATH`
- `R3X_KEYSTORE_PASSWORD`
- `R3X_KEY_ALIAS`
- `R3X_KEY_PASSWORD`

## 4. Verified Local Build Output (2026-11-28)

- **Native library (`aarch64-linux-android`, debug `cdylib`):** Built cleanly via NDK `27.2.12479018` in `4m 28s` (`libr3x_app_lib.so`, `129,296,464` bytes unstripped debug).
- **Android APK (`gradle assembleDebug` on Gradle `9.6.0` / AGP `8.9.1`):** `BUILD SUCCESSFUL in 3m 45s` (`35 actionable tasks`), producing `app-debug.apk` (`137,714,711` bytes, archived at `dist/r3x-0.1.0-android-arm64-debug.apk`, SHA-256 `8e53b997749fa3881428a7f8e39bde72b6928d8e37016fa537a4a0aceeb59b23`).
- **Scope Caveat:** `arm64-v8a` native library compiled and bundled; `x86_64` APK ABI slice was empty when only `aarch64-linux-android` was built (`packaging/android/build-android.ps1` targets `aarch64-linux-android`). Physical Android device / emulator live `R3xVpnService` testing remains unexecuted locally.
