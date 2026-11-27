use crate::proxy::{SystemProxyBackend, SystemProxySnapshot};
use chrono::{DateTime, Utc};
use r3x_domain::R3xError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const RECOVERY_FILENAME: &str = "network_recovery.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRecoveryState {
    pub updated_at: Option<DateTime<Utc>>,
    pub proxy_modified: bool,
    pub previous_proxy: Option<SystemProxySnapshot>,
    pub active_tun_interface: Option<String>,
    pub kill_switch_active: bool,
}

impl NetworkRecoveryState {
    #[must_use]
    pub fn has_active_changes(&self) -> bool {
        self.proxy_modified || self.active_tun_interface.is_some() || self.kill_switch_active
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub had_pending_state: bool,
    pub restored_proxy: bool,
    pub cleared_kill_switch: bool,
    pub notes: Vec<String>,
}

fn state_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(RECOVERY_FILENAME)
}

pub fn load_recovery_state(cache_dir: &Path) -> Result<Option<NetworkRecoveryState>, R3xError> {
    let path = state_path(cache_dir);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)?;
    let state: NetworkRecoveryState = serde_json::from_str(&raw)
        .map_err(|e| R3xError::Storage(format!("corrupt recovery state JSON: {e}")))?;
    Ok(Some(state))
}

pub fn save_recovery_state(cache_dir: &Path, state: &NetworkRecoveryState) -> Result<(), R3xError> {
    fs::create_dir_all(cache_dir)?;
    let mut copy = state.clone();
    copy.updated_at = Some(Utc::now());
    let raw = serde_json::to_string_pretty(&copy)
        .map_err(|e| R3xError::Storage(format!("serialize recovery state: {e}")))?;
    fs::write(state_path(cache_dir), raw)?;
    Ok(())
}

pub fn clear_recovery_state(cache_dir: &Path) -> Result<(), R3xError> {
    let path = state_path(cache_dir);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn recover_network_state(
    cache_dir: &Path,
    proxy_backend: &dyn SystemProxyBackend,
) -> Result<RecoveryReport, R3xError> {
    let Some(state) = load_recovery_state(cache_dir)? else {
        return Ok(RecoveryReport {
            had_pending_state: false,
            restored_proxy: false,
            cleared_kill_switch: false,
            notes: vec!["No stale network recovery state found".to_owned()],
        });
    };

    let mut restored_proxy = false;
    let mut notes = Vec::new();
    if state.proxy_modified
        && let Some(prev) = state.previous_proxy
    {
        if proxy_backend.is_supported() {
            proxy_backend.apply_snapshot(&prev)?;
            restored_proxy = true;
            notes.push("Restored system proxy settings to pre-session state".to_owned());
        } else {
            notes.push("Skipped system proxy restore (backend unsupported)".to_owned());
        }
    }

    if let Some(tun) = state.active_tun_interface {
        notes.push(format!(
            "Cleared stale TUN record '{tun}' (kernel drops non-persistent TUN on process exit)"
        ));
    }

    let cleared_kill_switch = state.kill_switch_active;
    if cleared_kill_switch {
        notes.push("Cleared kill switch active marker".to_owned());
    }

    clear_recovery_state(cache_dir)?;
    Ok(RecoveryReport {
        had_pending_state: true,
        restored_proxy,
        cleared_kill_switch,
        notes,
    })
}
