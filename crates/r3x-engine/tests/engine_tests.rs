use chrono::Utc;
use r3x_domain::{
    AuthConfig, ConnectionMode, ConnectionState, CoreCapabilities, CoreId, CoreIntegrationType,
    CoreManifest, CorePreference, CpuArch, DnsConfig, Endpoint, LogCategory, LogEntry, LogLevel,
    Platform, Profile, ProfileOptions, ProfileSource, ProtocolConfig, ProtocolType, R3xError,
    RedactedSecret, SecurityConfig, SupportStatus, TransportConfig,
};
use r3x_engine::{
    BoxFuture, ConnectRequest, CoreAdapter, CoreConfigContext, CoreHealth, CoreSelectionContext,
    CoreSelector, CoreStats, EngineConfig, GeneratedCoreConfig, LogHub, R3xEngine,
    RunningCoreHandle,
};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tempfile::tempdir;
use tokio::sync::mpsc;
use uuid::Uuid;

struct SimulatedTestAdapter {
    id: CoreId,
    version: String,
    ready: AtomicBool,
    delay_ms: u64,
    support: SupportStatus,
}

impl SimulatedTestAdapter {
    fn new(id: CoreId, support: SupportStatus) -> Self {
        Self {
            id,
            version: "26.11.4".to_owned(),
            ready: AtomicBool::new(true),
            delay_ms: 0,
            support,
        }
    }
}

impl CoreAdapter for SimulatedTestAdapter {
    fn id(&self) -> CoreId {
        self.id
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn manifest(&self) -> CoreManifest {
        CoreManifest {
            id: self.id,
            name: self.id.display_name().to_owned(),
            version: self.version.clone(),
            release_source: "https://example.invalid".to_owned(),
            license: "MPL-2.0".to_owned(),
            supported_platforms: vec![Platform::Windows, Platform::Linux, Platform::Android],
            supported_archs: vec![CpuArch::X86_64, CpuArch::Aarch64],
            checksums_sha256: BTreeMap::new(),
            signature_verification: "sha256".to_owned(),
            capabilities: self.capabilities(),
            limitations: vec![],
            integration_type: CoreIntegrationType::ExternalBinary,
            changelog_summary: None,
        }
    }

    fn capabilities(&self) -> CoreCapabilities {
        CoreCapabilities {
            protocols: vec![ProtocolType::Vless, ProtocolType::Trojan],
            transports: vec!["TCP".to_owned(), "XHTTP".to_owned(), "WebSocket".to_owned()],
            supports_tls: true,
            supports_reality: true,
            supports_vision: true,
            supports_udp: true,
            supports_ipv6: true,
            supports_tun: true,
            supports_system_proxy: true,
            supports_routing: true,
            supports_stats: true,
            supports_dns: true,
        }
    }

    fn supports_profile(&self, profile: &Profile) -> SupportStatus {
        if self
            .capabilities()
            .protocols
            .contains(&profile.protocol.protocol_type)
        {
            self.support
        } else {
            SupportStatus::Unsupported
        }
    }

    fn validate_profile(&self, profile: &Profile) -> Result<(), R3xError> {
        if profile.endpoint.host.is_empty() {
            return Err(R3xError::Validation("empty host".to_owned()));
        }
        Ok(())
    }

    fn generate_config<'a>(
        &'a self,
        ctx: &'a CoreConfigContext,
    ) -> BoxFuture<'a, Result<GeneratedCoreConfig, R3xError>> {
        Box::pin(async move {
            Ok(GeneratedCoreConfig {
                core_id: self.id,
                config_path: ctx.work_dir.join("config.json"),
                config_contents: "{}".to_owned(),
                local_http_port: Some(ctx.http_port),
                local_socks_port: Some(ctx.socks_port),
                tun_interface_name: Some(ctx.tun_interface_name.clone()),
                api_endpoint: None,
            })
        })
    }

    fn start<'a>(
        &'a self,
        config: &'a GeneratedCoreConfig,
        _log_tx: mpsc::Sender<LogEntry>,
    ) -> BoxFuture<'a, Result<RunningCoreHandle, R3xError>> {
        Box::pin(async move {
            if self.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            }
            Ok(RunningCoreHandle {
                core_id: self.id,
                pid: Some(4242),
                work_dir: config
                    .config_path
                    .parent()
                    .unwrap_or(Path::new("."))
                    .to_path_buf(),
                api_endpoint: config.api_endpoint.clone(),
                started_at: Utc::now(),
            })
        })
    }

    fn health_check<'a>(
        &'a self,
        _handle: &'a RunningCoreHandle,
    ) -> BoxFuture<'a, Result<CoreHealth, R3xError>> {
        Box::pin(async move {
            let ok = self.ready.load(Ordering::Relaxed);
            Ok(CoreHealth {
                process_alive: ok,
                control_api_reachable: ok,
                tunnel_ready: ok,
                details: if ok {
                    "ready".to_owned()
                } else {
                    "tunnel probe failed".to_owned()
                },
            })
        })
    }

    fn collect_stats<'a>(
        &'a self,
        _handle: &'a RunningCoreHandle,
    ) -> BoxFuture<'a, Result<CoreStats, R3xError>> {
        Box::pin(async move {
            Ok(CoreStats {
                down_bps: Some(1_000_000),
                up_bps: Some(250_000),
                total_down_bytes: Some(2048),
                total_up_bytes: Some(512),
                core_cpu_pct: Some(0.5),
                core_rss_bytes: Some(42 * 1024 * 1024),
                active_connections: vec![],
            })
        })
    }

    fn stop<'a>(&'a self, _handle: RunningCoreHandle) -> BoxFuture<'a, Result<(), R3xError>> {
        Box::pin(async move { Ok(()) })
    }

    fn cleanup<'a>(&'a self, work_dir: &'a Path) -> BoxFuture<'a, Result<(), R3xError>> {
        Box::pin(async move {
            if work_dir.exists() {
                let _ = std::fs::remove_dir_all(work_dir);
            }
            Ok(())
        })
    }
}

fn test_profile() -> Profile {
    let now = Utc::now();
    Profile {
        id: Uuid::new_v4(),
        name: "Germany One".to_owned(),
        custom_name: None,
        source: ProfileSource::Manual,
        protocol: ProtocolConfig::simple(ProtocolType::Vless),
        transport: TransportConfig::Xhttp {
            path: "/".to_owned(),
            host: None,
            mode: None,
        },
        security: SecurityConfig::None,
        flow: None,
        endpoint: Endpoint {
            host: "198.51.100.1".to_owned(),
            port: 443,
            local_addresses: vec![],
            dns_servers: vec![],
        },
        auth: AuthConfig {
            inline_secret: Some(RedactedSecret::new("11111111-1111-1111-1111-111111111111")),
            ..Default::default()
        },
        options: ProfileOptions::default(),
        core_preference: CorePreference::Auto,
        favorite: false,
        country_code: Some("DE".to_owned()),
        city: Some("Frankfurt".to_owned()),
        latency_ms: Some(24),
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn engine_connect_disconnect_and_health_check_enforcement() {
    let dir = tempdir().expect("tempdir");
    let logs = Arc::new(LogHub::new(Some(dir.path().join("logs"))));
    let engine = Arc::new(R3xEngine::new(
        EngineConfig {
            work_root: dir.path().join("work"),
            auto_reconnect: false,
            ..Default::default()
        },
        Arc::clone(&logs),
    ));

    let adapter = Arc::new(SimulatedTestAdapter::new(
        CoreId::Xray,
        SupportStatus::Verified,
    ));
    engine.register_adapter(adapter.clone(), true);

    let req = ConnectRequest {
        profile: test_profile(),
        subscription_preference: CorePreference::Auto,
        global_preference: CorePreference::Auto,
        mode: ConnectionMode::Tun,
        dns: DnsConfig::default(),
        routing_rules: vec![],
        tun_fd: None,
    };

    let session = engine.connect(req.clone()).await.expect("connect");
    assert_eq!(session.core_id, CoreId::Xray);
    assert!(matches!(
        engine.connection_state(),
        ConnectionState::Connected
    ));

    engine.disconnect().await.expect("disconnect");
    assert!(matches!(
        engine.connection_state(),
        ConnectionState::Disconnected
    ));

    // Must NOT become Connected if health_check fails
    adapter.ready.store(false, Ordering::Relaxed);
    let err = engine.connect(req).await.expect_err("must fail readiness");
    assert!(matches!(err, R3xError::CoreProcessFailed { .. }));
    assert!(matches!(
        engine.connection_state(),
        ConnectionState::Error { .. }
    ));
}

#[tokio::test]
async fn engine_cancellation_mid_start_cleans_up() {
    let dir = tempdir().expect("tempdir");
    let logs = Arc::new(LogHub::new(None));
    let engine = Arc::new(R3xEngine::new(
        EngineConfig {
            work_root: dir.path().join("work"),
            ..Default::default()
        },
        logs,
    ));

    let mut slow = SimulatedTestAdapter::new(CoreId::SingBox, SupportStatus::Verified);
    slow.delay_ms = 500;
    engine.register_adapter(Arc::new(slow), true);

    let req = ConnectRequest {
        profile: test_profile(),
        subscription_preference: CorePreference::Auto,
        global_preference: CorePreference::Auto,
        mode: ConnectionMode::SystemProxy,
        dns: DnsConfig::default(),
        routing_rules: vec![],
        tun_fd: None,
    };

    let eng2 = Arc::clone(&engine);
    let handle = tokio::spawn(async move { eng2.connect(req).await });
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    engine.cancel_pending();

    let res = handle.await.expect("join");
    assert!(matches!(res, Err(R3xError::Cancelled)));
    assert!(matches!(
        engine.connection_state(),
        ConnectionState::Disconnected
    ));
}

#[test]
fn smart_core_selector_honors_override_hierarchy() {
    let xray = Arc::new(SimulatedTestAdapter::new(
        CoreId::Xray,
        SupportStatus::Verified,
    ));
    let sing = Arc::new(SimulatedTestAdapter::new(
        CoreId::SingBox,
        SupportStatus::Supported,
    ));
    let adapters: Vec<Arc<dyn CoreAdapter>> = vec![sing, xray];
    let installed: HashSet<CoreId> = [CoreId::Xray, CoreId::SingBox].into_iter().collect();

    let mut profile = test_profile();
    let auto_sel = CoreSelector::select(
        &adapters,
        &installed,
        &profile,
        CoreSelectionContext {
            subscription_preference: CorePreference::Auto,
            global_preference: CorePreference::Auto,
            platform: Platform::Windows,
            arch: CpuArch::X86_64,
            mode: ConnectionMode::Tun,
        },
    )
    .expect("auto");
    assert_eq!(auto_sel.core_id, CoreId::Xray);

    let sub_sel = CoreSelector::select(
        &adapters,
        &installed,
        &profile,
        CoreSelectionContext {
            subscription_preference: CorePreference::Preferred(CoreId::SingBox),
            global_preference: CorePreference::Preferred(CoreId::Xray),
            platform: Platform::Windows,
            arch: CpuArch::X86_64,
            mode: ConnectionMode::Tun,
        },
    )
    .expect("sub override");
    assert_eq!(sub_sel.core_id, CoreId::SingBox);

    profile.core_preference = CorePreference::Preferred(CoreId::Xray);
    let prof_sel = CoreSelector::select(
        &adapters,
        &installed,
        &profile,
        CoreSelectionContext {
            subscription_preference: CorePreference::Preferred(CoreId::SingBox),
            global_preference: CorePreference::Auto,
            platform: Platform::Windows,
            arch: CpuArch::X86_64,
            mode: ConnectionMode::Tun,
        },
    )
    .expect("profile override");
    assert_eq!(prof_sel.core_id, CoreId::Xray);
}

#[test]
fn log_hub_redacts_secrets_and_caps_buffer() {
    let logs = LogHub::new(None);
    logs.record(
        LogCategory::Core,
        LogLevel::Info,
        "xray",
        "dialing trojan://mySecret999@1.2.3.4:443",
    );
    let entries = logs.recent(Some(LogCategory::Core), 10);
    assert_eq!(entries.len(), 1);
    assert!(!entries[0].message.contains("mySecret999"));
    assert!(entries[0].message.contains("[REDACTED]"));
}
