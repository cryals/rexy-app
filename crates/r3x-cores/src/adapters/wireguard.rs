use super::common::{
    check_health_with_optional_endpoint, cleanup_runtime_dir, collect_pid_stats, resolve_manifest,
    restrict_secret_file, spawn_process_with_args, stop_process_handle, validate_basic_endpoint,
};
use crate::supervisor::ProcessRegistry;
use parking_lot::RwLock;
use r3x_domain::{
    CoreCapabilities, CoreId, CoreManifest, LogEntry, Profile, ProtocolType, R3xError,
    SecurityConfig, SupportStatus,
};
use r3x_engine::{
    BoxFuture, CoreAdapter, CoreConfigContext, CoreHealth, CoreStats, GeneratedCoreConfig,
    RunningCoreHandle,
};
use std::fs;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

pub struct WireGuardFamilyAdapter {
    id: CoreId,
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl WireGuardFamilyAdapter {
    #[must_use]
    pub fn wireguard(binary_path: Option<PathBuf>) -> Self {
        Self {
            id: CoreId::WireGuard,
            manifest: resolve_manifest(CoreId::WireGuard, "WireGuard", "GPL-2.0-only OR MIT"),
            binary_path: RwLock::new(binary_path),
            processes: ProcessRegistry::new(),
        }
    }

    #[must_use]
    pub fn amneziawg(binary_path: Option<PathBuf>) -> Self {
        Self {
            id: CoreId::AmneziaWg,
            manifest: resolve_manifest(CoreId::AmneziaWg, "AmneziaWG", "MIT"),
            binary_path: RwLock::new(binary_path),
            processes: ProcessRegistry::new(),
        }
    }

    pub fn set_binary_path(&self, path: Option<PathBuf>) {
        *self.binary_path.write() = path;
    }

    fn validate_wg_fields(profile: &Profile, label: &str) -> Result<(), R3xError> {
        validate_basic_endpoint(profile, label)?;
        let priv_key = profile
            .auth
            .inline_secret
            .as_ref()
            .map(|s| s.expose())
            .unwrap_or("");
        if priv_key.trim().is_empty() {
            return Err(R3xError::Validation(format!(
                "{label} profile '{}' missing client PrivateKey",
                profile.effective_name()
            )));
        }
        if profile
            .auth
            .public_key
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            return Err(R3xError::Validation(format!(
                "{label} profile '{}' missing peer PublicKey",
                profile.effective_name()
            )));
        }
        Ok(())
    }

    fn render_ini(ctx: &CoreConfigContext) -> String {
        let p = &ctx.profile;
        let priv_key = p
            .auth
            .inline_secret
            .as_ref()
            .map(|s| s.expose())
            .unwrap_or("");
        let peer_pub = p.auth.public_key.as_deref().unwrap_or("");
        let addrs = if p.endpoint.local_addresses.is_empty() {
            "10.8.0.2/32".to_owned()
        } else {
            p.endpoint.local_addresses.join(", ")
        };
        let dns_list = if p.endpoint.dns_servers.is_empty() {
            p.options
                .raw_extra
                .get("dns")
                .cloned()
                .unwrap_or_else(|| "1.1.1.1".to_owned())
        } else {
            p.endpoint.dns_servers.join(", ")
        };
        let mtu = p.protocol.mtu.unwrap_or(1420);

        let mut lines = vec![
            "[Interface]".to_owned(),
            format!("PrivateKey = {priv_key}"),
            format!("Address = {addrs}"),
            format!("DNS = {dns_list}"),
            format!("MTU = {mtu}"),
        ];

        if let SecurityConfig::AmneziaWg(awg) = &p.security {
            lines.push(format!("Jc = {}", awg.jc));
            lines.push(format!("Jmin = {}", awg.jmin));
            lines.push(format!("Jmax = {}", awg.jmax));
            lines.push(format!("S1 = {}", awg.s1));
            lines.push(format!("S2 = {}", awg.s2));
            if let Some(s3) = awg.s3 {
                lines.push(format!("S3 = {s3}"));
            }
            if let Some(s4) = awg.s4 {
                lines.push(format!("S4 = {s4}"));
            }
            lines.push(format!("H1 = {}", awg.h1));
            lines.push(format!("H2 = {}", awg.h2));
            lines.push(format!("H3 = {}", awg.h3));
            lines.push(format!("H4 = {}", awg.h4));
            for (idx, junk) in awg.special_junk.iter().enumerate() {
                lines.push(format!("I{} = {junk}", idx + 1));
            }
        } else if matches!(p.protocol.protocol_type, ProtocolType::AmneziaWg) {
            for key in [
                "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2",
                "I3", "I4", "I5",
            ] {
                if let Some(val) = p.options.raw_extra.get(key) {
                    lines.push(format!("{key} = {val}"));
                }
            }
        }

        let allowed = p
            .options
            .raw_extra
            .get("allowed_ips")
            .cloned()
            .unwrap_or_else(|| "0.0.0.0/0, ::/0".to_owned());

        lines.push(String::new());
        lines.push("[Peer]".to_owned());
        lines.push(format!("PublicKey = {peer_pub}"));
        if let Some(ref psk) = p.auth.preshared_secret
            && !psk.is_empty()
        {
            lines.push(format!("PresharedKey = {}", psk.expose()));
        }
        lines.push(format!(
            "Endpoint = {}:{}",
            p.endpoint.host, p.endpoint.port
        ));
        lines.push(format!("AllowedIPs = {allowed}"));
        lines.push("PersistentKeepalive = 25".to_owned());
        lines.push(String::new());
        lines.join("\n")
    }
}

pub type WireGuardAdapter = WireGuardFamilyAdapter;
pub type AmneziaWgAdapter = WireGuardFamilyAdapter;

impl CoreAdapter for WireGuardFamilyAdapter {
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
        match (self.id, profile.protocol.protocol_type) {
            (CoreId::WireGuard, ProtocolType::WireGuard) => SupportStatus::Supported,
            (CoreId::AmneziaWg, ProtocolType::AmneziaWg | ProtocolType::WireGuard) => {
                SupportStatus::Supported
            }
            _ => SupportStatus::Unsupported,
        }
    }

    fn validate_profile(&self, profile: &Profile) -> Result<(), R3xError> {
        if !self.supports_profile(profile).is_runnable() {
            return Err(R3xError::Validation(format!(
                "{} does not support {}",
                self.id.display_name(),
                profile.protocol.protocol_type.display_name()
            )));
        }
        Self::validate_wg_fields(profile, self.id.display_name())
    }

    fn generate_config<'a>(
        &'a self,
        ctx: &'a CoreConfigContext,
    ) -> BoxFuture<'a, Result<GeneratedCoreConfig, R3xError>> {
        Box::pin(async move {
            self.validate_profile(&ctx.profile)?;
            fs::create_dir_all(&ctx.work_dir)?;
            let contents = Self::render_ini(ctx);
            let filename = if self.id == CoreId::AmneziaWg {
                "amneziawg.conf"
            } else {
                "wireguard.conf"
            };
            let config_path = ctx.work_dir.join(filename);
            fs::write(&config_path, &contents)?;
            restrict_secret_file(&config_path)?;
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
            let work_dir = config
                .config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            let iface = config
                .tun_interface_name
                .clone()
                .unwrap_or_else(|| "r3x-tun0".to_owned());
            let args = vec![
                "--config".to_owned(),
                config.config_path.display().to_string(),
                "--interface".to_owned(),
                iface,
            ];
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
