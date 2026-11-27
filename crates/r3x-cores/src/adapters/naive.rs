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

pub struct NaiveProxyAdapter {
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl NaiveProxyAdapter {
    #[must_use]
    pub fn new(binary_path: Option<PathBuf>) -> Self {
        Self {
            manifest: resolve_manifest(CoreId::NaiveProxy, "NaiveProxy", "BSD-3-Clause"),
            binary_path: RwLock::new(binary_path),
            processes: ProcessRegistry::new(),
        }
    }

    pub fn set_binary_path(&self, path: Option<PathBuf>) {
        *self.binary_path.write() = path;
    }

    fn build_config_json(ctx: &CoreConfigContext) -> Result<String, R3xError> {
        let p = &ctx.profile;
        let user = p.auth.username.as_deref().unwrap_or("");
        let pass = p
            .auth
            .inline_secret
            .as_ref()
            .map(|s| s.expose())
            .unwrap_or("");
        let scheme = match p.transport {
            TransportConfig::Quic { .. } | TransportConfig::Http3 => "quic",
            _ => "https",
        };
        let auth_part = if user.is_empty() && pass.is_empty() {
            String::new()
        } else {
            format!("{user}:{pass}@")
        };
        let proxy_url = format!(
            "{scheme}://{auth_part}{}:{}",
            p.endpoint.host, p.endpoint.port
        );
        let listen_ip = if ctx.allow_lan {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        };
        let cfg = json!({
            "listen": format!("socks://{listen_ip}:{}", ctx.socks_port),
            "proxy": proxy_url,
        });
        serde_json::to_string_pretty(&cfg)
            .map_err(|e| R3xError::Storage(format!("serialize NaiveProxy JSON: {e}")))
    }
}

impl CoreAdapter for NaiveProxyAdapter {
    fn id(&self) -> CoreId {
        CoreId::NaiveProxy
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
            ProtocolType::NaiveProxy => SupportStatus::Supported,
            _ => SupportStatus::Unsupported,
        }
    }

    fn validate_profile(&self, profile: &Profile) -> Result<(), R3xError> {
        validate_basic_endpoint(profile, "NaiveProxy")?;
        if !matches!(profile.protocol.protocol_type, ProtocolType::NaiveProxy) {
            return Err(R3xError::Validation(
                "NaiveProxy adapter supports only naive_proxy profiles".to_owned(),
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
            let config_path = ctx.work_dir.join("naive.json");
            fs::write(&config_path, &contents)?;
            restrict_secret_file(&config_path)?;
            Ok(GeneratedCoreConfig {
                core_id: CoreId::NaiveProxy,
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
            let args = vec![config.config_path.display().to_string()];
            spawn_process_with_args(
                CoreId::NaiveProxy,
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
            Ok(
                check_health_with_optional_endpoint("NaiveProxy", &self.processes, handle, true)
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
            cleanup_runtime_dir(work_dir);
            Ok(())
        })
    }
}
