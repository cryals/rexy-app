use super::common::{
    check_health_with_optional_endpoint, cleanup_runtime_dir, collect_pid_stats, resolve_manifest,
    restrict_secret_file, spawn_process_with_args, stop_process_handle, validate_basic_endpoint,
};
use crate::supervisor::ProcessRegistry;
use parking_lot::RwLock;
use r3x_domain::{
    CoreCapabilities, CoreId, CoreIntegrationType, CoreManifest, CpuArch, LogEntry, Platform,
    Profile, ProtocolType, R3xError, SupportStatus,
};
use r3x_engine::{
    BoxFuture, CoreAdapter, CoreConfigContext, CoreHealth, CoreStats, GeneratedCoreConfig,
    RunningCoreHandle,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

pub struct ShadowsocksRustAdapter {
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl ShadowsocksRustAdapter {
    #[must_use]
    pub fn new(binary_path: Option<PathBuf>) -> Self {
        Self {
            manifest: resolve_manifest(CoreId::ShadowsocksRust, "shadowsocks-rust", "MIT"),
            binary_path: RwLock::new(binary_path),
            processes: ProcessRegistry::new(),
        }
    }

    pub fn set_binary_path(&self, path: Option<PathBuf>) {
        *self.binary_path.write() = path;
    }
}

impl CoreAdapter for ShadowsocksRustAdapter {
    fn id(&self) -> CoreId {
        CoreId::ShadowsocksRust
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
            ProtocolType::Shadowsocks | ProtocolType::Shadowsocks2022 => SupportStatus::Supported,
            _ => SupportStatus::Unsupported,
        }
    }

    fn validate_profile(&self, profile: &Profile) -> Result<(), R3xError> {
        validate_basic_endpoint(profile, "shadowsocks-rust")?;
        if profile
            .auth
            .inline_secret
            .as_ref()
            .is_none_or(|s| s.is_empty())
        {
            return Err(R3xError::Validation(
                "Shadowsocks profile missing password/PSK".to_owned(),
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
            let p = &ctx.profile;
            let listen_ip = if ctx.allow_lan {
                "0.0.0.0"
            } else {
                "127.0.0.1"
            };
            let cfg = json!({
                "server": p.endpoint.host,
                "server_port": p.endpoint.port,
                "password": p.auth.inline_secret.as_ref().map(|s| s.expose()).unwrap_or_default(),
                "method": p.protocol.cipher.as_deref().unwrap_or("aes-256-gcm"),
                "local_address": listen_ip,
                "local_port": ctx.socks_port,
                "mode": "tcp_and_udp",
            });
            let contents =
                serde_json::to_string_pretty(&cfg).map_err(|e| R3xError::Storage(e.to_string()))?;
            let config_path = ctx.work_dir.join("sslocal.json");
            fs::write(&config_path, &contents)?;
            restrict_secret_file(&config_path)?;
            Ok(GeneratedCoreConfig {
                core_id: CoreId::ShadowsocksRust,
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
            let args = vec!["-c".to_owned(), config.config_path.display().to_string()];
            spawn_process_with_args(
                CoreId::ShadowsocksRust,
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
            Ok(check_health_with_optional_endpoint(
                "shadowsocks-rust",
                &self.processes,
                handle,
                true,
            )
            .await)
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

pub struct V2FlyAdapter {
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl V2FlyAdapter {
    #[must_use]
    pub fn new(binary_path: Option<PathBuf>) -> Self {
        Self {
            manifest: resolve_manifest(CoreId::V2Fly, "V2Fly (v2ray-core)", "MIT"),
            binary_path: RwLock::new(binary_path),
            processes: ProcessRegistry::new(),
        }
    }
}

impl CoreAdapter for V2FlyAdapter {
    fn id(&self) -> CoreId {
        CoreId::V2Fly
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
            ProtocolType::Vless
            | ProtocolType::Vmess
            | ProtocolType::Trojan
            | ProtocolType::Shadowsocks
            | ProtocolType::Socks5
            | ProtocolType::Http => SupportStatus::Legacy,
            _ => SupportStatus::Unsupported,
        }
    }

    fn validate_profile(&self, profile: &Profile) -> Result<(), R3xError> {
        validate_basic_endpoint(profile, "V2Fly")
    }

    fn generate_config<'a>(
        &'a self,
        ctx: &'a CoreConfigContext,
    ) -> BoxFuture<'a, Result<GeneratedCoreConfig, R3xError>> {
        Box::pin(async move {
            let xray = super::xray::XrayAdapter::new(None);
            let mut gen_cfg = xray.generate_config(ctx).await?;
            gen_cfg.core_id = CoreId::V2Fly;
            Ok(gen_cfg)
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
                "run".to_owned(),
                "-c".to_owned(),
                config.config_path.display().to_string(),
            ];
            spawn_process_with_args(
                CoreId::V2Fly,
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
            Ok(check_health_with_optional_endpoint("V2Fly", &self.processes, handle, true).await)
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

pub struct JuicityAdapter {
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl JuicityAdapter {
    #[must_use]
    pub fn new(binary_path: Option<PathBuf>) -> Self {
        Self {
            manifest: resolve_manifest(CoreId::Juicity, "Juicity", "GPL-3.0-only"),
            binary_path: RwLock::new(binary_path),
            processes: ProcessRegistry::new(),
        }
    }
}

impl CoreAdapter for JuicityAdapter {
    fn id(&self) -> CoreId {
        CoreId::Juicity
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
        if matches!(profile.protocol.protocol_type, ProtocolType::Juicity) {
            SupportStatus::Supported
        } else {
            SupportStatus::Unsupported
        }
    }

    fn validate_profile(&self, profile: &Profile) -> Result<(), R3xError> {
        validate_basic_endpoint(profile, "Juicity")
    }

    fn generate_config<'a>(
        &'a self,
        ctx: &'a CoreConfigContext,
    ) -> BoxFuture<'a, Result<GeneratedCoreConfig, R3xError>> {
        Box::pin(async move {
            self.validate_profile(&ctx.profile)?;
            fs::create_dir_all(&ctx.work_dir)?;
            let p = &ctx.profile;
            let listen_ip = if ctx.allow_lan {
                "0.0.0.0"
            } else {
                "127.0.0.1"
            };
            let cfg = json!({
                "listen": format!("{listen_ip}:{}", ctx.socks_port),
                "server": format!("{}:{}", p.endpoint.host, p.endpoint.port),
                "uuid": p.auth.username.as_deref().unwrap_or_default(),
                "password": p.auth.inline_secret.as_ref().map(|s| s.expose()).unwrap_or_default(),
                "congestion_control": p.options.congestion_control.as_deref().unwrap_or("bbr"),
                "allow_insecure": p.security.allows_insecure_tls(),
            });
            let contents =
                serde_json::to_string_pretty(&cfg).map_err(|e| R3xError::Storage(e.to_string()))?;
            let config_path = ctx.work_dir.join("juicity.json");
            fs::write(&config_path, &contents)?;
            restrict_secret_file(&config_path)?;
            Ok(GeneratedCoreConfig {
                core_id: CoreId::Juicity,
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
                "run".to_owned(),
                "-c".to_owned(),
                config.config_path.display().to_string(),
            ];
            spawn_process_with_args(
                CoreId::Juicity,
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
            Ok(check_health_with_optional_endpoint("Juicity", &self.processes, handle, true).await)
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

pub struct BrookAdapter {
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl BrookAdapter {
    #[must_use]
    pub fn new(binary_path: Option<PathBuf>) -> Self {
        Self {
            manifest: resolve_manifest(CoreId::Brook, "Brook", "GPL-3.0-only"),
            binary_path: RwLock::new(binary_path),
            processes: ProcessRegistry::new(),
        }
    }
}

impl CoreAdapter for BrookAdapter {
    fn id(&self) -> CoreId {
        CoreId::Brook
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
        if matches!(profile.protocol.protocol_type, ProtocolType::Brook) {
            SupportStatus::Supported
        } else {
            SupportStatus::Unsupported
        }
    }

    fn validate_profile(&self, profile: &Profile) -> Result<(), R3xError> {
        validate_basic_endpoint(profile, "Brook")
    }

    fn generate_config<'a>(
        &'a self,
        ctx: &'a CoreConfigContext,
    ) -> BoxFuture<'a, Result<GeneratedCoreConfig, R3xError>> {
        Box::pin(async move {
            self.validate_profile(&ctx.profile)?;
            fs::create_dir_all(&ctx.work_dir)?;
            let p = &ctx.profile;
            let listen_ip = if ctx.allow_lan {
                "0.0.0.0"
            } else {
                "127.0.0.1"
            };
            let cfg = json!({
                "server": format!("{}:{}", p.endpoint.host, p.endpoint.port),
                "password": p.auth.inline_secret.as_ref().map(|s| s.expose()).unwrap_or_default(),
                "socks5": format!("{listen_ip}:{}", ctx.socks_port),
            });
            let contents =
                serde_json::to_string_pretty(&cfg).map_err(|e| R3xError::Storage(e.to_string()))?;
            let config_path = ctx.work_dir.join("brook.json");
            fs::write(&config_path, &contents)?;
            restrict_secret_file(&config_path)?;
            Ok(GeneratedCoreConfig {
                core_id: CoreId::Brook,
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
            let parsed: serde_json::Value =
                serde_json::from_str(&config.config_contents).unwrap_or_default();
            let srv = parsed["server"].as_str().unwrap_or("127.0.0.1:443");
            let pw = parsed["password"].as_str().unwrap_or("");
            let socks = parsed["socks5"].as_str().unwrap_or("127.0.0.1:10809");
            let work_dir = config
                .config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            let args = vec![
                "client".to_owned(),
                "--server".to_owned(),
                srv.to_owned(),
                "--password".to_owned(),
                pw.to_owned(),
                "--socks5".to_owned(),
                socks.to_owned(),
            ];
            spawn_process_with_args(
                CoreId::Brook,
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
            Ok(check_health_with_optional_endpoint("Brook", &self.processes, handle, true).await)
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

pub struct TorAdapter {
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl TorAdapter {
    #[must_use]
    pub fn new(binary_path: Option<PathBuf>) -> Self {
        Self {
            manifest: resolve_manifest(CoreId::Tor, "Tor (Arti / Tor Client)", "BSD-3-Clause"),
            binary_path: RwLock::new(binary_path),
            processes: ProcessRegistry::new(),
        }
    }
}

impl CoreAdapter for TorAdapter {
    fn id(&self) -> CoreId {
        CoreId::Tor
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
        if profile
            .options
            .raw_extra
            .get("tor")
            .is_some_and(|v| v == "true" || v == "1")
        {
            SupportStatus::Experimental
        } else {
            SupportStatus::Unsupported
        }
    }

    fn validate_profile(&self, _profile: &Profile) -> Result<(), R3xError> {
        Ok(())
    }

    fn generate_config<'a>(
        &'a self,
        ctx: &'a CoreConfigContext,
    ) -> BoxFuture<'a, Result<GeneratedCoreConfig, R3xError>> {
        Box::pin(async move {
            fs::create_dir_all(&ctx.work_dir)?;
            let data_dir = ctx.work_dir.join("tor_data");
            fs::create_dir_all(&data_dir)?;
            let mut torrc = format!(
                "SocksPort {}\nDataDirectory {}\nLog notice stdout\n",
                ctx.socks_port,
                data_dir.display()
            );
            if let Some(bridge) = ctx.profile.options.raw_extra.get("bridge") {
                torrc.push_str(&format!("UseBridges 1\nBridge {bridge}\n"));
            }
            let config_path = ctx.work_dir.join("torrc");
            fs::write(&config_path, &torrc)?;
            Ok(GeneratedCoreConfig {
                core_id: CoreId::Tor,
                config_path,
                config_contents: torrc,
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
            let args = vec!["-f".to_owned(), config.config_path.display().to_string()];
            spawn_process_with_args(
                CoreId::Tor,
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
            Ok(check_health_with_optional_endpoint("Tor", &self.processes, handle, true).await)
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

/// Parameterized adapter for OS/external CLI VPN clients (OpenConnect, IKEv2, SSTP, SoftEther, OpenSSH TUN).
pub struct ExternalCliVpnAdapter {
    id: CoreId,
    protocol: ProtocolType,
    status: SupportStatus,
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl ExternalCliVpnAdapter {
    #[must_use]
    pub fn openconnect(binary_path: Option<PathBuf>) -> Self {
        Self::build(
            CoreId::OpenConnect,
            "OpenConnect",
            "LGPL-2.1-only",
            ProtocolType::OpenConnect,
            SupportStatus::Experimental,
            vec![Platform::Linux, Platform::Windows],
            binary_path,
        )
    }

    #[must_use]
    pub fn ikev2(binary_path: Option<PathBuf>) -> Self {
        Self::build(
            CoreId::Ikev2,
            "IKEv2/IPsec (strongSwan / rasdial)",
            "GPL-2.0-or-later / OS native",
            ProtocolType::Ikev2Ipsec,
            SupportStatus::Experimental,
            vec![Platform::Linux, Platform::Windows],
            binary_path,
        )
    }

    #[must_use]
    pub fn sstp(binary_path: Option<PathBuf>) -> Self {
        Self::build(
            CoreId::Sstp,
            "SSTP (sstp-client / Windows SSTP)",
            "GPL-2.0-or-later / OS native",
            ProtocolType::Sstp,
            SupportStatus::Legacy,
            vec![Platform::Linux, Platform::Windows],
            binary_path,
        )
    }

    #[must_use]
    pub fn softether(binary_path: Option<PathBuf>) -> Self {
        Self::build(
            CoreId::SoftEther,
            "SoftEther VPN Client",
            "Apache-2.0",
            ProtocolType::SoftEther,
            SupportStatus::Experimental,
            vec![Platform::Linux, Platform::Windows],
            binary_path,
        )
    }

    #[must_use]
    pub fn openssh_tun(binary_path: Option<PathBuf>) -> Self {
        Self::build(
            CoreId::OpenSshTun,
            "OpenSSH TUN (`ssh -w`)",
            "BSD",
            ProtocolType::OpenSshTun,
            SupportStatus::Experimental,
            vec![Platform::Linux],
            binary_path,
        )
    }

    fn build(
        id: CoreId,
        name: &str,
        license: &str,
        protocol: ProtocolType,
        status: SupportStatus,
        supported_platforms: Vec<Platform>,
        binary_path: Option<PathBuf>,
    ) -> Self {
        let manifest = CoreManifest {
            id,
            name: name.to_owned(),
            version: "system".to_owned(),
            release_source: "System / OS package".to_owned(),
            license: license.to_owned(),
            supported_platforms,
            supported_archs: vec![CpuArch::X86_64, CpuArch::Aarch64],
            checksums_sha256: BTreeMap::new(),
            signature_verification: "User-installed system CLI tool".to_owned(),
            capabilities: CoreCapabilities {
                protocols: vec![protocol],
                transports: vec!["TCP".to_owned(), "UDP".to_owned()],
                supports_tls: true,
                supports_reality: false,
                supports_vision: false,
                supports_udp: true,
                supports_ipv6: true,
                supports_tun: true,
                supports_system_proxy: false,
                supports_routing: true,
                supports_stats: false,
                supports_dns: true,
            },
            limitations: vec![
                "Requires user-installed OS VPN binary and elevated TUN privileges".to_owned(),
            ],
            integration_type: CoreIntegrationType::SystemService,
            changelog_summary: None,
        };
        Self {
            id,
            protocol,
            status,
            manifest,
            binary_path: RwLock::new(binary_path),
            processes: ProcessRegistry::new(),
        }
    }

    fn build_cli_args(&self, profile: &Profile) -> Vec<String> {
        let target = format!("{}:{}", profile.endpoint.host, profile.endpoint.port);
        match self.id {
            CoreId::OpenConnect => vec![target],
            CoreId::OpenSshTun => vec![
                "-N".to_owned(),
                "-w".to_owned(),
                "0:0".to_owned(),
                profile.endpoint.host.clone(),
            ],
            _ => vec!["--server".to_owned(), target],
        }
    }
}

impl CoreAdapter for ExternalCliVpnAdapter {
    fn id(&self) -> CoreId {
        self.id
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
        if profile.protocol.protocol_type == self.protocol {
            self.status
        } else {
            SupportStatus::Unsupported
        }
    }

    fn validate_profile(&self, profile: &Profile) -> Result<(), R3xError> {
        validate_basic_endpoint(profile, self.id.display_name())
    }

    fn generate_config<'a>(
        &'a self,
        ctx: &'a CoreConfigContext,
    ) -> BoxFuture<'a, Result<GeneratedCoreConfig, R3xError>> {
        Box::pin(async move {
            self.validate_profile(&ctx.profile)?;
            fs::create_dir_all(&ctx.work_dir)?;
            let args = self.build_cli_args(&ctx.profile);
            let contents = serde_json::to_string_pretty(&json!({
                "core": self.id,
                "protocol": self.protocol,
                "endpoint": format!("{}:{}", ctx.profile.endpoint.host, ctx.profile.endpoint.port),
                "args": args,
            }))
            .map_err(|e| R3xError::Storage(e.to_string()))?;
            let config_path = ctx.work_dir.join("external-vpn.json");
            fs::write(&config_path, &contents)?;
            Ok(GeneratedCoreConfig {
                core_id: self.id,
                config_path,
                config_contents: contents,
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
            let parsed: serde_json::Value =
                serde_json::from_str(&config.config_contents).unwrap_or_default();
            let args: Vec<String> = parsed["args"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let work_dir = config
                .config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            spawn_process_with_args(
                self.id,
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
            Ok(check_health_with_optional_endpoint(
                self.id.display_name(),
                &self.processes,
                handle,
                false,
            )
            .await)
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
