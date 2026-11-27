use r3x_domain::{
    ActiveConnectionInfo, ConnectionMode, CoreCapabilities, CoreId, CoreManifest, CpuArch,
    DnsConfig, LogEntry, Platform, Profile, R3xError, RoutingRule, SupportStatus,
};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use tokio::sync::mpsc;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone)]
pub struct CoreConfigContext {
    pub profile: Profile,
    pub mode: ConnectionMode,
    pub dns: DnsConfig,
    pub routing_rules: Vec<RoutingRule>,
    pub work_dir: PathBuf,
    pub mixed_port: u16,
    pub socks_port: u16,
    pub http_port: u16,
    pub ipv6_enabled: bool,
    pub allow_lan: bool,
    pub tun_interface_name: String,
    pub tun_fd: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct GeneratedCoreConfig {
    pub core_id: CoreId,
    pub config_path: PathBuf,
    pub config_contents: String,
    pub local_http_port: Option<u16>,
    pub local_socks_port: Option<u16>,
    pub tun_interface_name: Option<String>,
    pub api_endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RunningCoreHandle {
    pub core_id: CoreId,
    pub pid: Option<u32>,
    pub work_dir: PathBuf,
    pub api_endpoint: Option<String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct CoreHealth {
    pub process_alive: bool,
    pub control_api_reachable: bool,
    pub tunnel_ready: bool,
    pub details: String,
}

impl CoreHealth {
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.process_alive && self.control_api_reachable && self.tunnel_ready
    }
}

#[derive(Debug, Clone, Default)]
pub struct CoreStats {
    pub down_bps: Option<u64>,
    pub up_bps: Option<u64>,
    pub total_down_bytes: Option<u64>,
    pub total_up_bytes: Option<u64>,
    pub core_cpu_pct: Option<f32>,
    pub core_rss_bytes: Option<u64>,
    pub active_connections: Vec<ActiveConnectionInfo>,
}

pub trait CoreAdapter: Send + Sync {
    fn id(&self) -> CoreId;
    fn version(&self) -> &str;
    fn manifest(&self) -> CoreManifest;
    fn capabilities(&self) -> CoreCapabilities;

    fn is_platform_supported(&self, platform: Platform, arch: CpuArch) -> bool {
        let m = self.manifest();
        m.supported_platforms.contains(&platform) && m.supported_archs.contains(&arch)
    }

    fn supports_profile(&self, profile: &Profile) -> SupportStatus;

    fn validate_profile(&self, profile: &Profile) -> Result<(), R3xError>;

    fn generate_config<'a>(
        &'a self,
        ctx: &'a CoreConfigContext,
    ) -> BoxFuture<'a, Result<GeneratedCoreConfig, R3xError>>;

    fn start<'a>(
        &'a self,
        config: &'a GeneratedCoreConfig,
        log_tx: mpsc::Sender<LogEntry>,
    ) -> BoxFuture<'a, Result<RunningCoreHandle, R3xError>>;

    fn health_check<'a>(
        &'a self,
        handle: &'a RunningCoreHandle,
    ) -> BoxFuture<'a, Result<CoreHealth, R3xError>>;

    fn collect_stats<'a>(
        &'a self,
        handle: &'a RunningCoreHandle,
    ) -> BoxFuture<'a, Result<CoreStats, R3xError>>;

    fn stop<'a>(&'a self, handle: RunningCoreHandle) -> BoxFuture<'a, Result<(), R3xError>>;

    fn cleanup<'a>(&'a self, work_dir: &'a Path) -> BoxFuture<'a, Result<(), R3xError>>;
}
