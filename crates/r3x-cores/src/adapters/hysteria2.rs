use super::common::{
    check_health_with_optional_endpoint, cleanup_runtime_dir, collect_pid_stats, resolve_manifest,
    spawn_process_with_args, stop_process_handle, validate_basic_endpoint,
};
use crate::supervisor::ProcessRegistry;
use parking_lot::RwLock;
use r3x_domain::{
    ConnectionMode, CoreCapabilities, CoreId, CoreManifest, LogEntry, Profile, ProtocolType,
    R3xError, SecurityConfig, SupportStatus,
};
use r3x_engine::{
    BoxFuture, CoreAdapter, CoreConfigContext, CoreHealth, CoreStats, GeneratedCoreConfig,
    RunningCoreHandle,
};
use serde_yaml_ng::{Mapping, Value};
use std::fs;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

pub struct Hysteria2Adapter {
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl Hysteria2Adapter {
    #[must_use]
    pub fn new(binary_path: Option<PathBuf>) -> Self {
        Self {
            manifest: resolve_manifest(CoreId::Hysteria2, "Hysteria 2", "MIT"),
            binary_path: RwLock::new(binary_path),
            processes: ProcessRegistry::new(),
        }
    }

    pub fn set_binary_path(&self, path: Option<PathBuf>) {
        *self.binary_path.write() = path;
    }

    fn build_yaml(ctx: &CoreConfigContext) -> Result<String, R3xError> {
        let p = &ctx.profile;
        let auth = p
            .auth
            .inline_secret
            .as_ref()
            .map(|s| s.expose().to_owned())
            .unwrap_or_default();

        let mut root = Mapping::new();
        root.insert(
            Value::String("server".to_owned()),
            Value::String(format!("{}:{}", p.endpoint.host, p.endpoint.port)),
        );
        root.insert(Value::String("auth".to_owned()), Value::String(auth));

        if let SecurityConfig::Tls(tls) = &p.security {
            let mut tls_map = Mapping::new();
            tls_map.insert(
                Value::String("sni".to_owned()),
                Value::String(tls.sni.clone().unwrap_or_else(|| p.endpoint.host.clone())),
            );
            tls_map.insert(
                Value::String("insecure".to_owned()),
                Value::Bool(tls.allow_insecure),
            );
            root.insert(Value::String("tls".to_owned()), Value::Mapping(tls_map));
        }

        if let Some(obfs_pw) = p.options.raw_extra.get("obfs-password") {
            let mut obfs = Mapping::new();
            obfs.insert(
                Value::String("type".to_owned()),
                Value::String(
                    p.options
                        .raw_extra
                        .get("obfs")
                        .cloned()
                        .unwrap_or_else(|| "salamander".to_owned()),
                ),
            );
            let mut sal = Mapping::new();
            sal.insert(
                Value::String("password".to_owned()),
                Value::String(obfs_pw.clone()),
            );
            obfs.insert(Value::String("salamander".to_owned()), Value::Mapping(sal));
            root.insert(Value::String("obfs".to_owned()), Value::Mapping(obfs));
        }

        if p.options.up_mbps.is_some() || p.options.down_mbps.is_some() {
            let mut bw = Mapping::new();
            if let Some(up) = p.options.up_mbps {
                bw.insert(
                    Value::String("up".to_owned()),
                    Value::String(format!("{up} mbps")),
                );
            }
            if let Some(down) = p.options.down_mbps {
                bw.insert(
                    Value::String("down".to_owned()),
                    Value::String(format!("{down} mbps")),
                );
            }
            root.insert(Value::String("bandwidth".to_owned()), Value::Mapping(bw));
        }

        let listen_ip = if ctx.allow_lan {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        };
        let mut socks = Mapping::new();
        socks.insert(
            Value::String("listen".to_owned()),
            Value::String(format!("{listen_ip}:{}", ctx.socks_port)),
        );
        root.insert(Value::String("socks5".to_owned()), Value::Mapping(socks));

        let mut http = Mapping::new();
        http.insert(
            Value::String("listen".to_owned()),
            Value::String(format!("{listen_ip}:{}", ctx.http_port)),
        );
        root.insert(Value::String("http".to_owned()), Value::Mapping(http));

        if matches!(ctx.mode, ConnectionMode::Tun | ConnectionMode::Mixed) {
            let mut tun = Mapping::new();
            tun.insert(
                Value::String("name".to_owned()),
                Value::String(ctx.tun_interface_name.clone()),
            );
            root.insert(Value::String("tun".to_owned()), Value::Mapping(tun));
        }

        serde_yaml_ng::to_string(&root)
            .map_err(|e| R3xError::Storage(format!("serialize Hysteria 2 YAML: {e}")))
    }
}

impl CoreAdapter for Hysteria2Adapter {
    fn id(&self) -> CoreId {
        CoreId::Hysteria2
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
            ProtocolType::Hysteria2 => SupportStatus::Supported,
            _ => SupportStatus::Unsupported,
        }
    }

    fn validate_profile(&self, profile: &Profile) -> Result<(), R3xError> {
        validate_basic_endpoint(profile, "Hysteria 2")?;
        if !matches!(profile.protocol.protocol_type, ProtocolType::Hysteria2) {
            return Err(R3xError::Validation(
                "Hysteria 2 adapter only supports hysteria2 profiles".to_owned(),
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
            let contents = Self::build_yaml(ctx)?;
            let config_path = ctx.work_dir.join("hysteria2.yaml");
            fs::write(&config_path, &contents)?;
            Ok(GeneratedCoreConfig {
                core_id: CoreId::Hysteria2,
                config_path,
                config_contents: contents,
                local_http_port: Some(ctx.http_port),
                local_socks_port: Some(ctx.socks_port),
                tun_interface_name: matches!(ctx.mode, ConnectionMode::Tun | ConnectionMode::Mixed)
                    .then(|| ctx.tun_interface_name.clone()),
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
                "client".to_owned(),
                "-c".to_owned(),
                config.config_path.display().to_string(),
            ];
            spawn_process_with_args(
                CoreId::Hysteria2,
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
                check_health_with_optional_endpoint("Hysteria 2", &self.processes, handle, true)
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
