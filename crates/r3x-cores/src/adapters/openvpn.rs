use super::common::{
    check_health_with_optional_endpoint, cleanup_runtime_dir, collect_pid_stats, resolve_manifest,
    restrict_secret_file, spawn_process_with_args, stop_process_handle, validate_basic_endpoint,
};
use crate::supervisor::ProcessRegistry;
use parking_lot::RwLock;
use r3x_domain::{
    CoreCapabilities, CoreId, CoreManifest, LogEntry, Profile, ProtocolType, R3xError,
    SupportStatus,
};
use r3x_engine::{
    BoxFuture, CoreAdapter, CoreConfigContext, CoreHealth, CoreStats, GeneratedCoreConfig,
    RunningCoreHandle,
};
use std::fs;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

/// Invokes user-installed `openvpn` CLI out-of-process (`GPL-2.0-only` isolation: zero linking).
pub struct OpenVpnAdapter {
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl OpenVpnAdapter {
    #[must_use]
    pub fn new(binary_path: Option<PathBuf>) -> Self {
        Self {
            manifest: resolve_manifest(CoreId::OpenVpn, "OpenVPN", "GPL-2.0-only"),
            binary_path: RwLock::new(binary_path),
            processes: ProcessRegistry::new(),
        }
    }

    pub fn set_binary_path(&self, path: Option<PathBuf>) {
        *self.binary_path.write() = path;
    }

    fn render_ovpn(ctx: &CoreConfigContext) -> Result<(String, Option<String>), R3xError> {
        let p = &ctx.profile;
        let auth_file_contents = match (&p.auth.username, &p.auth.inline_secret) {
            (Some(u), Some(s)) if !u.trim().is_empty() && !s.is_empty() => {
                Some(format!("{u}\n{}\n", s.expose()))
            }
            _ => None,
        };

        if let Some(raw_ovpn) = p.options.raw_extra.get("ovpn_raw")
            && !raw_ovpn.trim().is_empty()
        {
            return Ok((raw_ovpn.clone(), auth_file_contents));
        }

        let proto = match p.protocol.protocol_type {
            ProtocolType::OpenVpnTcp => "tcp-client",
            _ => "udp",
        };
        let cipher = p.protocol.cipher.as_deref().unwrap_or("AES-256-GCM");
        let mut lines = vec![
            "client".to_owned(),
            "dev tun".to_owned(),
            format!("proto {proto}"),
            format!("remote {} {}", p.endpoint.host, p.endpoint.port),
            "resolv-retry infinite".to_owned(),
            "nobind".to_owned(),
            "persist-key".to_owned(),
            "persist-tun".to_owned(),
            format!("data-ciphers {cipher}"),
            "verb 3".to_owned(),
        ];
        if auth_file_contents.is_some() {
            lines.push("auth-user-pass auth.txt".to_owned());
        }
        lines.push(String::new());
        Ok((lines.join("\n"), auth_file_contents))
    }
}

impl CoreAdapter for OpenVpnAdapter {
    fn id(&self) -> CoreId {
        CoreId::OpenVpn
    }

    fn version(&self) -> &str {
        &self.manifest.version
    }

    fn manifest(&self) -> CoreManifest {
        self.manifest.clone()
    }

    fn capabilities(&self) -> CoreCapabilities {
        self.manifest.capabilities.clone()
    }

    fn supports_profile(&self, profile: &Profile) -> SupportStatus {
        match profile.protocol.protocol_type {
            ProtocolType::OpenVpnUdp | ProtocolType::OpenVpnTcp => SupportStatus::Supported,
            ProtocolType::OpenVpnCloak => SupportStatus::Experimental,
            _ => SupportStatus::Unsupported,
        }
    }

    fn validate_profile(&self, profile: &Profile) -> Result<(), R3xError> {
        validate_basic_endpoint(profile, "OpenVPN")?;
        if !matches!(
            profile.protocol.protocol_type,
            ProtocolType::OpenVpnUdp | ProtocolType::OpenVpnTcp | ProtocolType::OpenVpnCloak
        ) {
            return Err(R3xError::Validation(
                "OpenVPN adapter supports only OpenVPN profiles".to_owned(),
            ));
        }
        Ok(())
    }

    fn generate_config<'a>(
        &'a self,
        ctx: &'a CoreConfigContext,
    ) -> BoxFuture<'a, Result<GeneratedCoreConfig, R3xError>> {
        Box::pin(async move {
            self.validate_profile(&ctx.profile)?;
            fs::create_dir_all(&ctx.work_dir)?;
            let (ovpn, auth_opt) = Self::render_ovpn(ctx)?;
            if let Some(auth_txt) = auth_opt {
                let auth_path = ctx.work_dir.join("auth.txt");
                fs::write(&auth_path, auth_txt)?;
                restrict_secret_file(&auth_path)?;
            }
            let config_path = ctx.work_dir.join("client.ovpn");
            fs::write(&config_path, &ovpn)?;
            Ok(GeneratedCoreConfig {
                core_id: CoreId::OpenVpn,
                config_path,
                config_contents: ovpn,
                local_http_port: None,
                local_socks_port: None,
                tun_interface_name: Some(ctx.tun_interface_name.clone()),
                api_endpoint: None,
            })
        })
    }

    fn start<'a>(
        &'a self,
        config: &'a GeneratedCoreConfig,
        log_tx: mpsc::Sender<LogEntry>,
    ) -> BoxFuture<'a, Result<RunningCoreHandle, R3xError>> {
        Box::pin(async move {
            let work_dir = config
                .config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            let args = vec![
                "--config".to_owned(),
                config.config_path.display().to_string(),
                "--script-security".to_owned(),
                "1".to_owned(),
                "--verb".to_owned(),
                "3".to_owned(),
            ];
            spawn_process_with_args(
                CoreId::OpenVpn,
                &self.binary_path,
                &self.processes,
                work_dir,
                args,
                None,
                log_tx,
            )
        })
    }

    fn health_check<'a>(
        &'a self,
        handle: &'a RunningCoreHandle,
    ) -> BoxFuture<'a, Result<CoreHealth, R3xError>> {
        Box::pin(async move {
            Ok(
                check_health_with_optional_endpoint("OpenVPN", &self.processes, handle, false)
                    .await,
            )
        })
    }

    fn collect_stats<'a>(
        &'a self,
        handle: &'a RunningCoreHandle,
    ) -> BoxFuture<'a, Result<CoreStats, R3xError>> {
        Box::pin(async move { Ok(collect_pid_stats(handle)) })
    }

    fn stop<'a>(&'a self, handle: RunningCoreHandle) -> BoxFuture<'a, Result<(), R3xError>> {
        Box::pin(async move { stop_process_handle(&self.processes, handle) })
    }

    fn cleanup<'a>(&'a self, work_dir: &'a Path) -> BoxFuture<'a, Result<(), R3xError>> {
        Box::pin(async move {
            let auth_file = work_dir.join("auth.txt");
            if auth_file.exists() {
                let _ = fs::remove_file(&auth_file);
            }
            cleanup_runtime_dir(work_dir);
            Ok(())
        })
    }
}
