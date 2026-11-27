# Building & Packaging R3X for Windows

## 1. Supported Targets & Prerequisites

- **OS:** Windows 10 / Windows 11 (`x86_64-pc-windows-msvc` verified; `aarch64-pc-windows-msvc` CI cross-check configured).
- **Toolchain:** Rust `1.100.0` (`rust-toolchain.toml`), MSVC Build Tools / Windows SDK (linker stack configured to `/STACK:8000000` in `.cargo/config.toml`).
- **Optional:** Python 3 (used cleanly by `packaging/generate-sbom.ps1` to generate CycloneDX 1.5 JSON without PowerShell 5.1 case-insensitive key collisions), Inno Setup 6 (`ISCC.exe` for installer `.exe`).

## 2. Building Workspace Binaries

```powershell
cargo build --release --locked -p r3x-app -p r3x-daemon -p r3x-cli
```

Uses `[profile.release]` (`opt-level = 3`, `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, `debug = false`) + `rustls` (`ring`) so no OpenSSL or NASM installation is required.

## 3. Portable Archive, CycloneDX SBOM & SHA-256 Verification

```powershell
.\packaging\windows\package-portable.ps1 -DistDir dist
```

Verified local output (`2026-11-28`):

- `dist/r3x-app.exe` — `32,522,240` bytes (`31.02` MiB), SHA-256 `e883e809251452cd061b927d6dc01404445a91c65f6048b93184660fdfba0f02`
- `dist/r3x-daemon.exe` — `10,594,816` bytes (`10.10` MiB), SHA-256 `1377da70e5500b772dbaeba34f33d976d84e9e0d410037ac6f3e5d5d7f828632`
- `dist/r3x.exe` — `10,246,656` bytes (`9.77` MiB), SHA-256 `5e7b6bca6c13c45735e89b16cff79a691772ae8f33be15e48d1c9682d4777fc9`
- `dist/r3x-0.1.0-windows-x86_64-portable.zip` — `22,233,141` bytes (`21.20` MiB), SHA-256 `8d9e5b74d1f3e00ecbdca9841d490500f8711d74f8e74a9bef2f610cdcde5f73`
- `dist/r3x-sbom.cdx.json` — `204,789` bytes (`752` packages), SHA-256 `8599d1f3e2bfdaa388c1a27aa55833fb7c2120aa9df2c644ffa4b61c86c5d8a7`

## 4. Inno Setup Installer

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" packaging\windows\r3x-installer.iss
```

CI automation in `.github/workflows/windows.yml` installs Inno Setup via Chocolatey and compiles `r3x-0.1.0-windows-x86_64-setup.exe`.
