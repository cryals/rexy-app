use super::common::{
    check_health_with_optional_endpoint, cleanup_runtime_dir, collect_pid_stats, resolve_manifest,
    restrict_secret_file, spawn_process_with_args, stop_process_handle, validate_basic_endpoint,
};
use crate::supervisor::ProcessRegistry;
use parking_lot::RwLock;
use r3x_domain::{
    CoreCapabilities, CoreId, CoreManifest, LogEntry, Profile, ProtocolType, R3xError,
    SupportStatus, TransportConfig,
};
use r3x_engine::{
    BoxFuture, CoreAdapter, CoreConfigContext, CoreHealth, CoreStats, GeneratedCoreConfig,
    RunningCoreHandle,
};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

pub struct MieruAdapter {
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl MieruAdapter {
    #[must_use]
    pub fn new(binary_path: Option<PathBuf>) -> Self {
        Self {
            manifest: resolve_manifest(CoreId::Mieru, "Mieru", "GPL-3.0-only"),
            binary_path: RwLock::new(binary_path),
            processes: ProcessRegistry::new(),
        }
    }

    pub fn set_binary_path(&self, path: Option<PathBuf>) {
        *self.binary_path.write() = path;
    }

    fn build_config_json(ctx: &CoreConfigContext) -> Result<String, R3xError> {
        let p = &ctx.profile;
        let user = p.auth.username.as_deref().unwrap_or("r3x-user");
        let pass = p
            .auth
            .inline_secret
            .as_ref()
            .map(|s| s.expose())
            .unwrap_or("");
        let proto = match p.transport {
            TransportConfig::UdpRaw => "UDP",
            _ => "TCP",
        };
        let cfg = json!({
            "activeProfile": "default",
            "socks5Port": ctx.socks_port,
            "advancedSettings": {
                "allowLocalLAN": ctx.allow_lan
            },
            "loggingLevel": "INFO",
            "profiles": [
                {
                    "profileName": "default",
                    "user": {
                        "name": user,
                        "password": pass
                    },
                    "servers": [
                        {
                            "ipAddress": p.endpoint.host,
                            "portBindings": [
                                {
                                    "port": p.endpoint.port,
                                    "protocol": proto
                                }
                            ]
                        }
                    ],
                    "mtu": p.protocol.mtu.unwrap_or(1400)
                }
            ]
        });
        serde_json::to_string_pretty(&cfg)
            .map_err(|e| R3xError::Storage(format!("serialize Mieru JSON: {e}")))
    }
}

impl CoreAdapter for MieruAdapter {
    fn id(&self) -> CoreId {
        CoreId::Mieru
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
            ProtocolType::Mieru => SupportStatus::Supported,
            _ => SupportStatus::Unsupported,
        }
    }

    fn validate_profile(&self, profile: &Profile) -> Result<(), R3xError> {
        validate_basic_endpoint(profile, "Mieru")?;
        if !matches!(profile.protocol.protocol_type, ProtocolType::Mieru) {
            return Err(R3xError::Validation(
                "Mieru adapter supports only mieru profiles".to_owned(),
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
            let contents = Self::build_config_json(ctx)?;
            let config_path = ctx.work_dir.join("mieru.json");
            fs::write(&config_path, &contents)?;
            restrict_secret_file(&config_path)?;
            Ok(GeneratedCoreConfig {
                core_id: CoreId::Mieru,
                config_path,
                config_contents: contents,
                local_http_port: None,
                local_socks_port: Some(ctx.socks_port),
                tun_interface_name: None,
                api_endpoint: Some(format!("127.0.0.1:{}", ctx.socks_port)),
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
                "apply".to_owned(),
                "config".to_owned(),
                config.config_path.display().to_string(),
            ];
            spawn_process_with_args(
                CoreId::Mieru,
                &self.binary_path,
                &self.processes,
                work_dir,
                args,
                config.api_endpoint.clone(),
                log_tx,
            )
        })
    }

    fn health_check<'a>(
        &'a self,
        handle: &'a RunningCoreHandle,
    ) -> BoxFuture<'a, Result<CoreHealth, R3xError>> {
        Box::pin(async move {
            Ok(check_health_with_optional_endpoint("Mieru", &self.processes, handle, true).await)
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
            cleanup_runtime_dir(work_dir);
            Ok(())
        })
    }
}
