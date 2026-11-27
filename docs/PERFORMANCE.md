# R3X Performance Benchmarks & Binary Budget

All metrics below were measured directly on Windows `x86_64` (`Rust 1.100.0`, release/bench profile) on `2026-11-28`.

## 1. Criterion Microbenchmarks (`crates/r3x-diagnostics/benches/r3x_benchmarks.rs`)

Command executed:

```powershell
cargo bench -p r3x-diagnostics --bench r3x_benchmarks --locked -- --sample-size 10 --measurement-time 1
```

| Benchmark | Workload | Lower Bound | Median Estimate | Upper Bound | Notes |
|---|---|---|---|---|---|
| `parse_1000_vless_uris` | 1,000 VLESS WS/TLS URIs parsed into `Profile` models | `5.4576 ms` | **`5.7116 ms`** | `6.0048 ms` | ~5.7 us per VLESS profile |
| `redact_dense_secrets` | Repeated multi-secret URI + Bearer + key=value scrubbing via `Redactor::redact_str` | `87.837 us` | **`90.921 us`** | `94.986 us` | Zero UI thread blocking on log export |
| `build_area_path_3600` | 3,600 telemetry points (1-hour window @ 1s) converted to SVG `<path>` fill/stroke | `1.6210 ms` | **`1.7879 ms`** | `1.9453 ms` | Bounded ring-buffer SVG rendering |
| `preview_routing_100_rules` | 100 routing rules compiled to Xray + sing-box + Mihomo config previews simultaneously | `405.62 us` | **`425.94 us`** | `453.13 us` | Instant raw config preview refresh |

## 2. Release Artifact Sizes & CLI Cold-Start Latency (`[profile.release]`)

Release profile (`Cargo.toml`): `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, `debug = false`.

| Artifact / Executable | Exact Size (Bytes) | Size (MiB) | Platform / Role |
|---|---|---|---|
| `r3x-app.exe` | `32,522,240` | `31.02` MiB | Native Slint 1.19 GUI (`x86_64-pc-windows-msvc`) |
| `r3x-daemon.exe` | `10,594,816` | `10.10` MiB | Background IPC daemon + 19 core adapters |
| `r3x.exe` | `10,246,656` | `9.77` MiB | Headless CLI (`--json` automation) |
| `r3x-0.1.0-windows-x86_64-portable.zip` | `22,233,141` | `21.20` MiB | Portable ZIP bundle (EXEs + manifests + licenses) |
| `r3x-0.1.0-android-arm64-debug.apk` | `137,714,711` | `131.33` MiB | Unstripped debug ARM64 APK (`libr3x_app_lib.so` unstripped debug = `129,296,464` bytes) |

### CLI Cold-Start Timings (`dist/r3x.exe`)

Measured cleanly with an isolated temporary `R3X_DATA_DIR`:

- `r3x.exe --json version`: `22.85 ms` (`exit=0`)
- `r3x.exe --json cores list`: `23.76 ms` (`exit=0`)
- `r3x.exe --json diagnostics run` (real SQLite boot + OS probes): `73.47 ms` (`exit=0`)

## 3. UI & Telemetry Memory Discipline

- **Live Telemetry (`TelemetryHub`):** Tracks UI and active core child-process CPU% + RSS memory through `sysinfo` rather than synthetic metrics.
- **Reduced Motion (`R3xMetrics.reduced_motion`):** Collapses shape-morph and panel transition durations to `0ms` cleanly when enabled.
- **Deferred Measurement:** Multi-hour (`8h–24h`) continuous live proxy/TUN tunnel throughput and battery/soak profiling against external servers have not been executed in automated local CI and remain documented in `docs/KNOWN-LIMITATIONS.md`.
