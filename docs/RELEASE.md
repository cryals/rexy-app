# R3X Release Engineering

## 1. Versioning & Licensing

- **Workspace Version:** `0.1.0` (`Cargo.toml`, `platform/android/app/build.gradle.kts`, `packaging/windows/r3x-installer.iss`, `packaging/linux/{build-deb.sh,build-appimage.sh,r3x.spec}`).
- **License:** `GPL-3.0-only` (`LICENSE.txt`, verified across crates with `cargo deny check licenses bans sources`).
- **Tag Format:** Annotated semantic version tags `vX.Y.Z` (or `vX.Y.Z-rc.N`).

## 2. Automated Release Pipeline (`.github/workflows/release.yml`)

1. Triggers on tag push `v*` or manual `workflow_dispatch`.
2. Gates on `verify` job (`cargo deny`, `cargo fmt --all -- --check`, `cargo test --workspace --locked` on `ubuntu-24.04`).
3. Builds platform packages in parallel:
   - `package-windows`: `.\packaging\windows\package-portable.ps1` -> portable ZIP, CycloneDX SBOM (`r3x-sbom.cdx.json`), `SHA256SUMS.txt`.
   - `package-linux`: `./packaging/linux/build-deb.sh`, `./packaging/linux/build-appimage.sh`, `SHA256SUMS-linux.txt`.
4. Uploads all outputs to a **draft**, prerelease GitHub Release via `softprops/action-gh-release@v2` for maintainer inspection before publishing.

## 3. Local Manual Packaging & Checksums

- **Windows Portable + SBOM + SHA-256:** `.\packaging\windows\package-portable.ps1`
- **Standalone SBOM Generation:** `.\packaging\generate-sbom.ps1 -OutPath dist\r3x-sbom.cdx.json`
- **Windows Installer (requires Inno Setup 6):** `ISCC.exe packaging\windows\r3x-installer.iss`
- **Android APK:** `.\packaging\android\build-android.ps1` (pass `-Release` with signing env vars for release APK)
