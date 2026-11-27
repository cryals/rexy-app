use crate::recovery::{clear_recovery_state, load_recovery_state, save_recovery_state};
use r3x_domain::R3xError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::warn;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemProxySnapshot {
    pub enabled: bool,
    pub server: Option<String>,
    pub bypass: Option<String>,
    pub backend: String,
}

pub trait SystemProxyBackend: Send + Sync {
    fn backend_name(&self) -> &'static str;
    fn is_supported(&self) -> bool;
    fn read_snapshot(&self) -> Result<SystemProxySnapshot, R3xError>;
    fn apply_snapshot(&self, snapshot: &SystemProxySnapshot) -> Result<(), R3xError>;
}

pub struct UnsupportedProxyBackend;

impl SystemProxyBackend for UnsupportedProxyBackend {
    fn backend_name(&self) -> &'static str {
        "unsupported"
    }

    fn is_supported(&self) -> bool {
        false
    }

    fn read_snapshot(&self) -> Result<SystemProxySnapshot, R3xError> {
        Err(R3xError::UnsupportedPlatform(
            "system proxy is not supported on this platform/environment".to_owned(),
        ))
    }

    fn apply_snapshot(&self, _snapshot: &SystemProxySnapshot) -> Result<(), R3xError> {
        Err(R3xError::UnsupportedPlatform(
            "system proxy is not supported on this platform/environment".to_owned(),
        ))
    }
}

#[cfg(target_os = "windows")]
pub struct WindowsSystemProxyBackend;

#[cfg(target_os = "windows")]
impl SystemProxyBackend for WindowsSystemProxyBackend {
    fn backend_name(&self) -> &'static str {
        "windows_wininet_registry"
    }

    fn is_supported(&self) -> bool {
        true
    }

    fn read_snapshot(&self) -> Result<SystemProxySnapshot, R3xError> {
        use winreg::RegKey;
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu
            .open_subkey_with_flags(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                KEY_READ,
            )
            .map_err(|e| R3xError::Storage(format!("open WinINet registry key: {e}")))?;

        let enabled_val: u32 = key.get_value("ProxyEnable").unwrap_or(0);
        let server: Option<String> = key.get_value("ProxyServer").ok();
        let bypass: Option<String> = key.get_value("ProxyOverride").ok();

        Ok(SystemProxySnapshot {
            enabled: enabled_val != 0,
            server: server.filter(|s| !s.is_empty()),
            bypass: bypass.filter(|s| !s.is_empty()),
            backend: self.backend_name().to_owned(),
        })
    }

    fn apply_snapshot(&self, snapshot: &SystemProxySnapshot) -> Result<(), R3xError> {
        use windows_sys::Win32::Networking::WinInet::{
            INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
        };
        use winreg::RegKey;
        use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu
            .open_subkey_with_flags(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                KEY_WRITE,
            )
            .map_err(|e| R3xError::Storage(format!("open WinINet registry key for write: {e}")))?;

        key.set_value("ProxyEnable", &u32::from(snapshot.enabled))
            .map_err(|e| R3xError::Storage(format!("write ProxyEnable: {e}")))?;
        match &snapshot.server {
            Some(srv) => key
                .set_value("ProxyServer", srv)
                .map_err(|e| R3xError::Storage(format!("write ProxyServer: {e}")))?,
            None => {
                let _ = key.delete_value("ProxyServer");
            }
        }
        match &snapshot.bypass {
            Some(byp) => key
                .set_value("ProxyOverride", byp)
                .map_err(|e| R3xError::Storage(format!("write ProxyOverride: {e}")))?,
            None => {
                let _ = key.delete_value("ProxyOverride");
            }
        }

        // Notify WinINet so active desktop applications pick up proxy updates immediately.
        unsafe {
            let _ = InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null_mut(),
                0,
            );
            let _ = InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null_mut(),
                0,
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub struct LinuxSystemProxyBackend;

#[cfg(target_os = "linux")]
impl SystemProxyBackend for LinuxSystemProxyBackend {
    fn backend_name(&self) -> &'static str {
        "linux_gnome_gsettings"
    }

    fn is_supported(&self) -> bool {
        let desktop = std::env::var("XDG_CURRENT_DESKTOP")
            .unwrap_or_default()
            .to_ascii_lowercase();
        desktop.contains("gnome") || desktop.contains("ubuntu") || desktop.contains("cinnamon")
    }

    fn read_snapshot(&self) -> Result<SystemProxySnapshot, R3xError> {
        if !self.is_supported() {
            return Err(R3xError::UnsupportedPlatform(
                "No universal Linux system proxy mechanism detected for this desktop environment"
                    .to_owned(),
            ));
        }
        let out = std::process::Command::new("gsettings")
            .args(["get", "org.gnome.system.proxy", "mode"])
            .output()
            .map_err(|e| R3xError::UnsupportedPlatform(format!("gsettings unavailable: {e}")))?;
        let mode_str = String::from_utf8_lossy(&out.stdout);
        let enabled = mode_str.contains("manual");
        let host_out = std::process::Command::new("gsettings")
            .args(["get", "org.gnome.system.proxy.http", "host"])
            .output()
            .ok();
        let port_out = std::process::Command::new("gsettings")
            .args(["get", "org.gnome.system.proxy.http", "port"])
            .output()
            .ok();
        let server = match (host_out, port_out) {
            (Some(h), Some(p)) => {
                let host = String::from_utf8_lossy(&h.stdout)
                    .trim()
                    .trim_matches('\'')
                    .to_owned();
                let port = String::from_utf8_lossy(&p.stdout).trim().to_owned();
                if host.is_empty() {
                    None
                } else {
                    Some(format!("{host}:{port}"))
                }
            }
            _ => None,
        };
        Ok(SystemProxySnapshot {
            enabled,
            server,
            bypass: None,
            backend: self.backend_name().to_owned(),
        })
    }

    fn apply_snapshot(&self, snapshot: &SystemProxySnapshot) -> Result<(), R3xError> {
        if !self.is_supported() {
            return Err(R3xError::UnsupportedPlatform(
                "No universal Linux system proxy mechanism detected for this desktop environment"
                    .to_owned(),
            ));
        }
        if snapshot.enabled {
            let server = snapshot.server.as_deref().unwrap_or("127.0.0.1:10808");
            let (host, port) = server.rsplit_once(':').unwrap_or(("127.0.0.1", "10808"));
            run_gsettings(&["set", "org.gnome.system.proxy", "mode", "manual"])?;
            run_gsettings(&["set", "org.gnome.system.proxy.http", "host", host])?;
            run_gsettings(&["set", "org.gnome.system.proxy.http", "port", port])?;
            run_gsettings(&["set", "org.gnome.system.proxy.https", "host", host])?;
            run_gsettings(&["set", "org.gnome.system.proxy.https", "port", port])?;
        } else {
            run_gsettings(&["set", "org.gnome.system.proxy", "mode", "none"])?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn run_gsettings(args: &[&str]) -> Result<(), R3xError> {
    let status = std::process::Command::new("gsettings")
        .args(args)
        .status()
        .map_err(|e| R3xError::UnsupportedPlatform(format!("failed running gsettings: {e}")))?;
    if !status.success() {
        return Err(R3xError::Network(format!(
            "gsettings {:?} exited with {status}",
            args
        )));
    }
    Ok(())
}

#[must_use]
pub fn create_platform_proxy_backend() -> Arc<dyn SystemProxyBackend> {
    #[cfg(target_os = "windows")]
    {
        Arc::new(WindowsSystemProxyBackend)
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(LinuxSystemProxyBackend)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Arc::new(UnsupportedProxyBackend)
    }
}

pub struct SystemProxyManager {
    backend: Arc<dyn SystemProxyBackend>,
    cache_dir: PathBuf,
}

impl SystemProxyManager {
    #[must_use]
    pub fn new(backend: Arc<dyn SystemProxyBackend>, cache_dir: PathBuf) -> Self {
        Self { backend, cache_dir }
    }

    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.backend.is_supported()
    }

    pub fn enable_loopback(&self, port: u16) -> Result<(), R3xError> {
        let prev = self.backend.read_snapshot()?;
        let mut recovery = load_recovery_state(&self.cache_dir)?.unwrap_or_default();
        if recovery.previous_proxy.is_none() {
            recovery.previous_proxy = Some(prev.clone());
        }
        recovery.proxy_modified = true;
        save_recovery_state(&self.cache_dir, &recovery)?;

        let target = SystemProxySnapshot {
            enabled: true,
            server: Some(format!("127.0.0.1:{port}")),
            bypass: Some("localhost;127.*;10.*;172.16.*;192.168.*;<local>".to_owned()),
            backend: self.backend.backend_name().to_owned(),
        };

        if let Err(err) = self.backend.apply_snapshot(&target) {
            warn!(error = %err, "System proxy activation failed; rolling back to prior snapshot");
            let _ = self.backend.apply_snapshot(&prev);
            let _ = clear_recovery_state(&self.cache_dir);
            return Err(err);
        }
        Ok(())
    }

    pub fn disable_and_restore(&self) -> Result<(), R3xError> {
        let Some(mut recovery) = load_recovery_state(&self.cache_dir)? else {
            return Ok(());
        };
        if let Some(prev) = recovery.previous_proxy.take() {
            self.backend.apply_snapshot(&prev)?;
        }
        recovery.proxy_modified = false;
        if !recovery.has_active_changes() {
            clear_recovery_state(&self.cache_dir)?;
        } else {
            save_recovery_state(&self.cache_dir, &recovery)?;
        }
        Ok(())
    }
}
