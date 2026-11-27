# R3X Testing Strategy, Harnesses & Coverage

R3X enforces multi-layer automated verification without relying on unexecuted manual claims.

## 1. Test Pyramid (`cargo test --workspace`)

| Layer | Crates / Files | Scope Verified |
|---|---|---|
| Domain & Property Tests | `crates/r3x-domain/tests/domain_tests.rs`, `crates/r3x-security/tests/security_tests.rs`, `crates/r3x-profiles/tests/profiles_tests.rs` | 10-state Connection FSM transitions, bounded `RingBuffer` wraparound, `RedactedSecret` `Debug` masking, quota math, `proptest` filename sanitization, archive traversal/bomb guards, Argon2id+XChaCha20 AEAD, URI/YAML/JSON/WG/AWG/OpenVPN parsing, untrusted HTTP header handling |
| Storage & Keyring Recovery | `crates/r3x-storage/tests/storage_tests.rs` | SQLite WAL schema migrations, full repository CRUD, `PRAGMA quick_check` corruption quarantine & recovery, `.r3xbak` backup roundtrips, explicit fail-closed `SecretStoreUnavailable` behavior |
| IPC Security & Framing | `crates/r3x-ipc/tests/ipc_tests.rs` | Live Named Pipe / Unix Domain Socket handshake, 256-bit constant-time token rejection, `E_IPC_VERSION_MISMATCH`, 4 MiB frame oversize rejection |
| Engine, Cores & Adapters | `crates/r3x-engine/tests/engine_tests.rs`, `crates/r3x-cores/tests/cores_tests.rs` | Single-flight serialization, health-check readiness gate, cancellation cleanup, `CoreSelector` precedence, all 14 embedded manifests, all 19 `CoreAdapter` generators, SHA-256 install/verify/rollback, real local TCP subprocess handshake |
| Network Recovery & Probes | `crates/r3x-network/tests/network_tests.rs` | Transactional OS proxy snapshot restore & crash recovery, kill-switch recovery marker cleanup, free port discovery, TUN/interface inspection |
| Diagnostics, Routing & DNS | `crates/r3x-diagnostics/tests/diagnostics_tests.rs` | Routing rule CRUD/sorting/core config preview (`Xray`/`sing-box`/`Mihomo`), DNS validation/probes/leak checks, 16-check `NetworkDoctor` + redaction, `TelemetryHub` (`sysinfo` RSS, TCP RTT probe, SVG path builders) |
| Headless UI & CLI Suites | `tests/ui_smoke.rs`, `apps/r3x-cli/tests/cli_tests.rs` | `i-slint-backend-testing` full-shell walkthrough (onboarding gate, 8 navigation screens, Light/AMOLED themes, EN/RU switch, Reduced Motion, SQLite VLESS import, routing presets, raw Xray config preview, encrypted backup, redacted logs) + `--json` CLI commands |

## 2. Criterion Benchmarks (`crates/r3x-diagnostics/benches/r3x_benchmarks.rs`)

Executed against optimized `--bench` profile with `criterion = "0.5"`:

```powershell
cargo bench -p r3x-diagnostics --bench r3x_benchmarks --locked -- --sample-size 10 --measurement-time 1
```

Measured local results (Windows `x86_64`, Rust `1.100.0`, 2026-11-28):
- `parse_1000_vless_uris`: `[5.4576 ms, 5.7116 ms, 6.0048 ms]`
- `redact_dense_secrets`: `[87.837 us, 90.921 us, 94.986 us]`
- `build_area_path_3600`: `[1.6210 ms, 1.7879 ms, 1.9453 ms]`
- `preview_routing_100_rules`: `[405.62 us, 425.94 us, 453.13 us]`

## 3. Fuzz Harnesses (`fuzz/fuzz_targets/`)

Four independent `libfuzzer-sys` targets stress-test untrusted boundaries (scheduled/manual Linux nightly runs via `.github/workflows/security.yml`):
- `fuzz_uri_parser`: Random byte slices into `parse_profile_uri`
- `fuzz_import_payload`: Random byte payloads into `parse_import_payload`
- `fuzz_redactor`: Arbitrary strings into `Redactor::redact_str`
- `fuzz_ipc_frame`: Arbitrary framed bytes into `r3x_ipc::read_frame::<_, IpcRequest>`
