use crate::manifests::find_manifest;
use crate::supervisor::{
    ProcessRegistry, SupervisedProcess, probe_tcp_ready, read_process_metrics,
};
use chrono::Utc;
use parking_lot::RwLock;
use r3x_domain::{
    CoreCapabilities, CoreId, CoreIntegrationType, CoreManifest, LogEntry, Profile, R3xError,
};
use r3x_engine::{CoreHealth, CoreStats, RunningCoreHandle};
use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub(crate) fn resolve_manifest(id: CoreId, default_name: &str, license: &str) -> CoreManifest {
    find_manifest(id).unwrap_or_else(|| CoreManifest {
        id,
        name: default_name.to_owned(),
        version: "0.1.0".to_owned(),
        release_source: "https://github.com/cryals/rexy-app".to_owned(),
        license: license.to_owned(),
        supported_platforms: Vec::new(),
        supported_archs: Vec::new(),
        checksums_sha256: BTreeMap::new(),
        signature_verification: "sha256".to_owned(),
        capabilities: CoreCapabilities {
            protocols: Vec::new(),
            transports: Vec::new(),
            supports_tls: false,
            supports_reality: false,
            supports_vision: false,
            supports_udp: false,
            supports_ipv6: false,
            supports_tun: false,
            supports_system_proxy: false,
            supports_routing: false,
            supports_stats: false,
            supports_dns: false,
        },
        limitations: Vec::new(),
        integration_type: CoreIntegrationType::ExternalBinary,
        changelog_summary: None,
    })
}

pub(crate) fn validate_basic_endpoint(profile: &Profile, core_label: &str) -> Result<(), R3xError> {
    if profile.endpoint.host.trim().is_empty() || profile.endpoint.port == 0 {
        return Err(R3xError::Validation(format!(
            "{core_label} profile '{}' missing valid server host or port",
            profile.effective_name()
        )));
    }
    Ok(())
}

pub(crate) fn spawn_process_with_args(
    core_id: CoreId,
    binary_slot: &RwLock<Option<PathBuf>>,
    processes: &ProcessRegistry,
    work_dir: PathBuf,
    args: Vec<String>,
    api_endpoint: Option<String>,
    log_tx: mpsc::Sender<LogEntry>,
) -> Result<RunningCoreHandle, R3xError> {
    let binary = binary_slot
        .read()
        .clone()
        .ok_or_else(|| R3xError::CoreNotInstalled(core_id.to_string()))?;
    if !binary.exists() {
        return Err(R3xError::CoreNotInstalled(format!(
            "{} binary not found at {}",
            core_id.display_name(),
            binary.display()
        )));
    }
    let proc_handle = Arc::new(SupervisedProcess::spawn(
        core_id, &binary, &args, &work_dir, log_tx,
    )?);
    let pid = proc_handle.pid;
    processes.insert(proc_handle);
    Ok(RunningCoreHandle {
        core_id,
        pid: Some(pid),
        work_dir,
        api_endpoint,
        started_at: Utc::now(),
    })
}

pub(crate) async fn check_health_with_optional_endpoint(
    core_label: &str,
    processes: &ProcessRegistry,
    handle: &RunningCoreHandle,
    require_endpoint: bool,
) -> CoreHealth {
    let alive = handle
        .pid
        .and_then(|p| processes.get(p))
        .is_some_and(|p| p.is_alive());
    let endpoint_ready = if !alive {
        false
    } else if !require_endpoint {
        true
    } else if let Some(ref ep) = handle.api_endpoint
        && let Ok(addr) = ep.parse::<SocketAddr>()
    {
        probe_tcp_ready(addr, Duration::from_millis(1200)).await
    } else {
        false
    };

    CoreHealth {
        process_alive: alive,
        control_api_reachable: endpoint_ready,
        tunnel_ready: alive && endpoint_ready,
        details: if alive && endpoint_ready {
            format!("{core_label} process active and accepting connections")
        } else if !alive {
            format!("{core_label} process terminated")
        } else {
            format!(
                "{core_label} inbound unreachable at {}",
                handle.api_endpoint.as_deref().unwrap_or("unknown")
            )
        },
    }
}

pub(crate) fn collect_pid_stats(handle: &RunningCoreHandle) -> CoreStats {
    let (cpu, rss) = handle.pid.map(read_process_metrics).unwrap_or((None, None));
    CoreStats {
        core_cpu_pct: cpu,
        core_rss_bytes: rss,
        ..CoreStats::default()
    }
}

pub(crate) fn stop_process_handle(
    processes: &ProcessRegistry,
    handle: RunningCoreHandle,
) -> Result<(), R3xError> {
    if let Some(pid) = handle.pid
        && let Some(proc_handle) = processes.remove(pid)
    {
        proc_handle.terminate()?;
    }
    Ok(())
}

pub(crate) fn cleanup_runtime_dir(work_dir: &Path) {
    if work_dir.exists() {
        let _ = fs::remove_dir_all(work_dir);
    }
}

#[cfg(unix)]
pub(crate) fn restrict_secret_file(path: &Path) -> Result<(), R3xError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn restrict_secret_file(_path: &Path) -> Result<(), R3xError> {
    Ok(())
}
