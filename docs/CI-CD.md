# CI/CD & Supply Chain Pipelines

All GitHub Actions workflows live under `D:\Rexy\rexy-app\.github\workflows\`.

## 1. Workflow Inventory

| Workflow File | Triggers | Responsibility |
|---|---|---|
| `.github/workflows/ci.yml` | `push` / `pull_request` on `main`, `workflow_dispatch` | Format check (`rustfmt`), `cargo deny check licenses bans sources`, `cargo check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace`, release check across `ubuntu-24.04` and `windows-2022` |
| `.github/workflows/windows.yml` | `push` / `pull_request` on code/packaging paths, `workflow_dispatch` | Builds `r3x-app.exe`, `r3x-daemon.exe`, `r3x.exe`, packages portable ZIP + SBOM + `SHA256SUMS.txt`, runs CLI smoke checks, compiles Inno Setup `.iss` when available, cross-checks `aarch64-pc-windows-msvc` |
| `.github/workflows/linux.yml` | `push` / `pull_request` on code/packaging paths, `workflow_dispatch` | Validates `.desktop` (`desktop-file-validate`) & `.metainfo.xml` (`appstreamcli validate`), builds `.deb` and AppDir/AppImage/portable tarball packages |
| `.github/workflows/android.yml` | `push` / `pull_request` on `src/` / `platform/android/`, `workflow_dispatch` | Sets up JDK 17, Android SDK 36, NDK `27.2.12479018`, Gradle `8.13`, cross-compiles `aarch64-linux-android`, runs `gradle assembleDebug`, uploads APK |
| `.github/workflows/integration.yml` | `push` / `pull_request` on `main`, `workflow_dispatch` | Runs integration & headless Slint UI suites (`cli_tests`, `ipc_tests`, `network_tests`, `cores_tests`, `diagnostics_tests`, `ui_smoke`) |
| `.github/workflows/security.yml` | `push` / `pull_request` on `main`, weekly cron, `workflow_dispatch` | Runs `cargo-deny`, `rustsec/audit-check`, and scheduled/manual nightly `cargo-fuzz` smoke runs |
| `.github/workflows/benchmarks.yml` | `push` on core/diag crates, `workflow_dispatch` | Executes `cargo bench -p r3x-diagnostics` Criterion microbenchmarks on Linux and Windows |
| `.github/workflows/release.yml` | Tags `v*`, `workflow_dispatch` | Gates on workspace tests + `cargo-deny`, builds Windows/Linux release packages & checksums, creates a **draft** GitHub Release |

## 2. Companion Documentation Pipelines (`D:\Rexy\rexy-docs`)

- `.github/workflows/docs-ci.yml`: Validates `mkdocs build --strict` for both `user-portal/` and `dev-portal/`.
- `.github/workflows/deploy-docs.yml`: Deploys unified GitHub Pages site (`/` landing hub, `/users/`, `/developers/`).

## 3. Dependency & Issue Governance

- `.github/dependabot.yml`: Weekly update PRs for `cargo` (`/`), `github-actions` (`/`), and `gradle` (`/platform/android`).
- `.github/ISSUE_TEMPLATE/`: Structured bug & feature templates instructing reporters to attach redacted Network Doctor diagnostics rather than raw credentials.
