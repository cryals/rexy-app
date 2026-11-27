use crate::manifests::find_manifest;
use crate::supervisor::{
    ProcessRegistry, SupervisedProcess, probe_tcp_ready, read_process_metrics,
};
use chrono::Utc;
use parking_lot::RwLock;
use r3x_domain::{
    ConnectionMode, CoreCapabilities, CoreId, CoreManifest, LogEntry, Profile, ProtocolType,
    R3xError, RuleAction, RuleMatcher, SecurityConfig, SupportStatus, TransportConfig,
};
use r3x_engine::{
    BoxFuture, CoreAdapter, CoreConfigContext, CoreHealth, CoreStats, GeneratedCoreConfig,
    RunningCoreHandle,
};
use serde_yaml_ng::{Mapping, Value};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub struct MihomoAdapter {
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl MihomoAdapter {
    #[must_use]
    pub fn new(binary_path: Option<PathBuf>) -> Self {
        let manifest = find_manifest(CoreId::Mihomo).unwrap_or_else(|| CoreManifest {
            id: CoreId::Mihomo,
            name: "Mihomo".to_owned(),
            version: "1.19.12".to_owned(),
            release_source: "https://github.com/MetaCubeX/mihomo/releases".to_owned(),
            license: "GPL-3.0-only".to_owned(),
            supported_platforms: Vec::new(),
            supported_archs: Vec::new(),
            checksums_sha256: Default::default(),
            signature_verification: "sha256".to_owned(),
            capabilities: CoreCapabilities {
                protocols: vec![
                    ProtocolType::Vless,
                    ProtocolType::Trojan,
                    ProtocolType::Mieru,
                ],
                transports: vec!["TCP".to_owned()],
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
            },
            limitations: Vec::new(),
            integration_type: r3x_domain::CoreIntegrationType::ExternalBinary,
            changelog_summary: None,
        });
        Self {
            manifest,
            binary_path: RwLock::new(binary_path),
            processes: ProcessRegistry::new(),
        }
    }

    pub fn set_binary_path(&self, path: Option<PathBuf>) {
        *self.binary_path.write() = path;
    }

    fn build_proxy_map(profile: &Profile) -> Result<Mapping, R3xError> {
        let mut m = Mapping::new();
        m.insert(
            Value::String("name".to_owned()),
            Value::String("r3x-node".to_owned()),
        );
        m.insert(
            Value::String("server".to_owned()),
            Value::String(profile.endpoint.host.clone()),
        );
        m.insert(
            Value::String("port".to_owned()),
            Value::Number(u64::from(profile.endpoint.port).into()),
        );
        m.insert(Value::String("udp".to_owned()), Value::Bool(true));

        let secret = profile
            .auth
            .inline_secret
            .as_ref()
            .map(|s| s.expose().to_owned())
            .unwrap_or_default();

        match profile.protocol.protocol_type {
            ProtocolType::Vless => {
                m.insert(
                    Value::String("type".to_owned()),
                    Value::String("vless".to_owned()),
                );
                m.insert(Value::String("uuid".to_owned()), Value::String(secret));
            }
            ProtocolType::Vmess => {
                m.insert(
                    Value::String("type".to_owned()),
                    Value::String("vmess".to_owned()),
                );
                m.insert(Value::String("uuid".to_owned()), Value::String(secret));
                m.insert(
                    Value::String("alterId".to_owned()),
                    Value::Number(u64::from(profile.protocol.alter_id.unwrap_or(0)).into()),
                );
                m.insert(
                    Value::String("cipher".to_owned()),
                    Value::String(
                        profile
                            .protocol
                            .cipher
                            .clone()
                            .unwrap_or_else(|| "auto".to_owned()),
                    ),
                );
            }
            ProtocolType::Trojan => {
                m.insert(
                    Value::String("type".to_owned()),
                    Value::String("trojan".to_owned()),
                );
                m.insert(Value::String("password".to_owned()), Value::String(secret));
            }
            ProtocolType::Shadowsocks | ProtocolType::Shadowsocks2022 => {
                m.insert(
                    Value::String("type".to_owned()),
                    Value::String("ss".to_owned()),
                );
                m.insert(
                    Value::String("cipher".to_owned()),
                    Value::String(
                        profile
                            .protocol
                            .cipher
                            .clone()
                            .unwrap_or_else(|| "aes-256-gcm".to_owned()),
                    ),
                );
                m.insert(Value::String("password".to_owned()), Value::String(secret));
            }
            ProtocolType::Hysteria2 => {
                m.insert(
                    Value::String("type".to_owned()),
                    Value::String("hysteria2".to_owned()),
                );
                m.insert(Value::String("password".to_owned()), Value::String(secret));
            }
            ProtocolType::TuicV5 => {
                m.insert(
                    Value::String("type".to_owned()),
                    Value::String("tuic".to_owned()),
                );
                m.insert(Value::String("uuid".to_owned()), Value::String(secret));
                m.insert(
                    Value::String("password".to_owned()),
                    Value::String(
                        profile
                            .auth
                            .secondary_secret
                            .as_ref()
                            .map(|s| s.expose().to_owned())
                            .unwrap_or_default(),
                    ),
                );
            }
            ProtocolType::Mieru => {
                m.insert(
                    Value::String("type".to_owned()),
                    Value::String("mieru".to_owned()),
                );
                if let Some(ref u) = profile.auth.username {
                    m.insert(
                        Value::String("username".to_owned()),
                        Value::String(u.clone()),
                    );
                }
                m.insert(Value::String("password".to_owned()), Value::String(secret));
                m.insert(
                    Value::String("transport".to_owned()),
                    Value::String(profile.transport.label().to_ascii_uppercase()),
                );
            }
            ProtocolType::Snell => {
                m.insert(
                    Value::String("type".to_owned()),
                    Value::String("snell".to_owned()),
                );
                m.insert(Value::String("psk".to_owned()), Value::String(secret));
            }
            ProtocolType::WireGuard => {
                m.insert(
                    Value::String("type".to_owned()),
                    Value::String("wireguard".to_owned()),
                );
                m.insert(
                    Value::String("private-key".to_owned()),
                    Value::String(secret),
                );
                m.insert(
                    Value::String("public-key".to_owned()),
                    Value::String(profile.auth.public_key.clone().unwrap_or_default()),
                );
                m.insert(
                    Value::String("ip".to_owned()),
                    Value::String(
                        profile
                            .endpoint
                            .local_addresses
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "10.0.0.2".to_owned()),
                    ),
                );
            }
            ProtocolType::Socks5 => {
                m.insert(
                    Value::String("type".to_owned()),
                    Value::String("socks5".to_owned()),
                );
            }
            ProtocolType::Http | ProtocolType::Https => {
                m.insert(
                    Value::String("type".to_owned()),
                    Value::String("http".to_owned()),
                );
            }
            other => {
                return Err(R3xError::CoreIncompatible {
                    core: "Mihomo".to_owned(),
                    reason: format!("protocol {other:?} unsupported by Mihomo adapter"),
                });
            }
        }

        match &profile.security {
            SecurityConfig::Tls(t) => {
                m.insert(Value::String("tls".to_owned()), Value::Bool(true));
                if let Some(ref sni) = t.sni {
                    m.insert(
                        Value::String("servername".to_owned()),
                        Value::String(sni.clone()),
                    );
                }
                m.insert(
                    Value::String("skip-cert-verify".to_owned()),
                    Value::Bool(t.allow_insecure),
                );
            }
            SecurityConfig::Reality(r) => {
                m.insert(Value::String("tls".to_owned()), Value::Bool(true));
                m.insert(
                    Value::String("servername".to_owned()),
                    Value::String(r.sni.clone()),
                );
                let mut reality = Mapping::new();
                reality.insert(
                    Value::String("public-key".to_owned()),
                    Value::String(r.public_key.clone()),
                );
                reality.insert(
                    Value::String("short-id".to_owned()),
                    Value::String(r.short_id.clone()),
                );
                m.insert(
                    Value::String("reality-opts".to_owned()),
                    Value::Mapping(reality),
                );
            }
            _ => {}
        }

        match &profile.transport {
            TransportConfig::WebSocket { path, host, .. } => {
                m.insert(
                    Value::String("network".to_owned()),
                    Value::String("ws".to_owned()),
                );
                let mut ws = Mapping::new();
                ws.insert(
                    Value::String("path".to_owned()),
                    Value::String(path.clone()),
                );
                if let Some(h) = host {
                    let mut hdrs = Mapping::new();
                    hdrs.insert(Value::String("Host".to_owned()), Value::String(h.clone()));
                    ws.insert(Value::String("headers".to_owned()), Value::Mapping(hdrs));
                }
                m.insert(Value::String("ws-opts".to_owned()), Value::Mapping(ws));
            }
            TransportConfig::Grpc { service_name, .. } => {
                m.insert(
                    Value::String("network".to_owned()),
                    Value::String("grpc".to_owned()),
                );
                let mut grpc = Mapping::new();
                grpc.insert(
                    Value::String("grpc-service-name".to_owned()),
                    Value::String(service_name.clone()),
                );
                m.insert(Value::String("grpc-opts".to_owned()), Value::Mapping(grpc));
            }
            _ => {}
        }

        Ok(m)
    }

    fn build_rules(ctx: &CoreConfigContext) -> Vec<Value> {
        let mut out = Vec::new();
        for rule in &ctx.routing_rules {
            if !rule.enabled {
                continue;
            }
            let target = match rule.action {
                RuleAction::Proxy | RuleAction::SelectedProfile(_) => "PROXY",
                RuleAction::Direct => "DIRECT",
                RuleAction::Block => "REJECT",
            };
            let entry = match &rule.matcher {
                RuleMatcher::Domain(d) => format!("DOMAIN,{d},{target}"),
                RuleMatcher::DomainSuffix(d) => format!("DOMAIN-SUFFIX,{d},{target}"),
                RuleMatcher::DomainKeyword(d) => format!("DOMAIN-KEYWORD,{d},{target}"),
                RuleMatcher::Ip(ip) => format!("IP-CIDR,{ip}/32,{target}"),
                RuleMatcher::Cidr(c) => format!("IP-CIDR,{c},{target}"),
                RuleMatcher::GeoIp(g) => format!("GEOIP,{g},{target}"),
                RuleMatcher::ProcessName(p) => format!("PROCESS-NAME,{p},{target}"),
                RuleMatcher::Port(p) => format!("DST-PORT,{p},{target}"),
                _ => continue,
            };
            out.push(Value::String(entry));
        }
        out.push(Value::String("MATCH,PROXY".to_owned()));
        out
    }
}

impl CoreAdapter for MihomoAdapter {
    fn id(&self) -> CoreId {
        CoreId::Mihomo
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
        if self
            .manifest
            .capabilities
            .protocols
            .contains(&profile.protocol.protocol_type)
            && self
                .manifest
                .capabilities
                .supports_transport(&profile.transport)
        {
            SupportStatus::Supported
        } else {
            SupportStatus::Unsupported
        }
    }

    fn validate_profile(&self, profile: &Profile) -> Result<(), R3xError> {
        if profile.endpoint.host.trim().is_empty() || profile.endpoint.port == 0 {
            return Err(R3xError::Validation(
                "endpoint host and port must be non-empty".to_owned(),
            ));
        }
        Ok(())
    }

    fn generate_config<'a>(
        &'a self,
        ctx: &'a CoreConfigContext,
    ) -> BoxFuture<'a, Result<GeneratedCoreConfig, R3xError>> {
        Box::pin(async move {
            let mut root = Mapping::new();
            root.insert(
                Value::String("mixed-port".to_owned()),
                Value::Number(u64::from(ctx.mixed_port).into()),
            );
            root.insert(
                Value::String("allow-lan".to_owned()),
                Value::Bool(ctx.allow_lan),
            );
            root.insert(
                Value::String("ipv6".to_owned()),
                Value::Bool(ctx.ipv6_enabled),
            );
            root.insert(
                Value::String("mode".to_owned()),
                Value::String("rule".to_owned()),
            );
            root.insert(
                Value::String("log-level".to_owned()),
                Value::String("warning".to_owned()),
            );

            let controller_port = ctx.http_port.saturating_add(110);
            let controller = format!("127.0.0.1:{controller_port}");
            root.insert(
                Value::String("external-controller".to_owned()),
                Value::String(controller.clone()),
            );

            let mut tun = Mapping::new();
            let tun_enabled = matches!(ctx.mode, ConnectionMode::Tun | ConnectionMode::Mixed);
            tun.insert(Value::String("enable".to_owned()), Value::Bool(tun_enabled));
            tun.insert(
                Value::String("stack".to_owned()),
                Value::String("mixed".to_owned()),
            );
            tun.insert(
                Value::String("device".to_owned()),
                Value::String(ctx.tun_interface_name.clone()),
            );
            tun.insert(
                Value::String("auto-route".to_owned()),
                Value::Bool(tun_enabled),
            );
            root.insert(Value::String("tun".to_owned()), Value::Mapping(tun));

            let mut dns = Mapping::new();
            dns.insert(Value::String("enable".to_owned()), Value::Bool(true));
            dns.insert(
                Value::String("nameserver".to_owned()),
                Value::Sequence(vec![Value::String(ctx.dns.primary.address.clone())]),
            );
            root.insert(Value::String("dns".to_owned()), Value::Mapping(dns));

            root.insert(
                Value::String("proxies".to_owned()),
                Value::Sequence(vec![Value::Mapping(Self::build_proxy_map(&ctx.profile)?)]),
            );

            let mut group = Mapping::new();
            group.insert(
                Value::String("name".to_owned()),
                Value::String("PROXY".to_owned()),
            );
            group.insert(
                Value::String("type".to_owned()),
                Value::String("select".to_owned()),
            );
            group.insert(
                Value::String("proxies".to_owned()),
                Value::Sequence(vec![Value::String("r3x-node".to_owned())]),
            );
            root.insert(
                Value::String("proxy-groups".to_owned()),
                Value::Sequence(vec![Value::Mapping(group)]),
            );
            root.insert(
                Value::String("rules".to_owned()),
                Value::Sequence(Self::build_rules(ctx)),
            );

            let yaml = serde_yaml_ng::to_string(&Value::Mapping(root))
                .map_err(|e| R3xError::Storage(format!("serialize mihomo YAML: {e}")))?;
            let config_path = ctx.work_dir.join("mihomo.yaml");
            fs::write(&config_path, &yaml)?;

            Ok(GeneratedCoreConfig {
                core_id: CoreId::Mihomo,
                config_path,
                config_contents: yaml,
                local_http_port: Some(ctx.mixed_port),
                local_socks_port: Some(ctx.mixed_port),
                tun_interface_name: if tun_enabled {
                    Some(ctx.tun_interface_name.clone())
                } else {
                    None
                },
                api_endpoint: Some(controller),
            })
        })
    }

    fn start<'a>(
        &'a self,
        config: &'a GeneratedCoreConfig,
        log_tx: mpsc::Sender<LogEntry>,
    ) -> BoxFuture<'a, Result<RunningCoreHandle, R3xError>> {
        Box::pin(async move {
            let binary = self
                .binary_path
                .read()
                .clone()
                .ok_or_else(|| R3xError::CoreNotInstalled("Mihomo".to_owned()))?;
            let work_dir = config
                .config_path
                .parent()
                .unwrap_or(Path::new("."))
                .to_path_buf();
            let args = vec![
                "-d".to_owned(),
                work_dir.to_string_lossy().into_owned(),
                "-f".to_owned(),
                config.config_path.to_string_lossy().into_owned(),
            ];
            let proc_handle = Arc::new(SupervisedProcess::spawn(
                CoreId::Mihomo,
                &binary,
                &args,
                &work_dir,
                log_tx,
            )?);
            let pid = proc_handle.pid;
            self.processes.insert(proc_handle);
            Ok(RunningCoreHandle {
                core_id: CoreId::Mihomo,
                pid: Some(pid),
                work_dir,
                api_endpoint: config.api_endpoint.clone(),
                started_at: Utc::now(),
            })
        })
    }

    fn health_check<'a>(
        &'a self,
        handle: &'a RunningCoreHandle,
    ) -> BoxFuture<'a, Result<CoreHealth, R3xError>> {
        Box::pin(async move {
            let alive = handle
                .pid
                .and_then(|p| self.processes.get(p))
                .is_some_and(|p| p.is_alive());
            let api_ready = if alive {
                if let Some(ref ep) = handle.api_endpoint
                    && let Ok(addr) = ep.parse::<SocketAddr>()
                {
                    probe_tcp_ready(addr, Duration::from_millis(1200)).await
                } else {
                    false
                }
            } else {
                false
            };

            Ok(CoreHealth {
                process_alive: alive,
                control_api_reachable: api_ready,
                tunnel_ready: alive && api_ready,
                details: if alive && api_ready {
                    "Mihomo external-controller reachable".to_owned()
                } else if !alive {
                    "Mihomo process terminated".to_owned()
                } else {
                    "Mihomo external-controller unreachable".to_owned()
                },
            })
        })
    }

    fn collect_stats<'a>(
        &'a self,
        handle: &'a RunningCoreHandle,
    ) -> BoxFuture<'a, Result<CoreStats, R3xError>> {
        Box::pin(async move {
            let (cpu, rss) = handle.pid.map(read_process_metrics).unwrap_or((None, None));
            Ok(CoreStats {
                core_cpu_pct: cpu,
                core_rss_bytes: rss,
                ..CoreStats::default()
            })
        })
    }

    fn stop<'a>(&'a self, handle: RunningCoreHandle) -> BoxFuture<'a, Result<(), R3xError>> {
        Box::pin(async move {
            if let Some(pid) = handle.pid
                && let Some(proc_handle) = self.processes.remove(pid)
            {
                proc_handle.terminate()?;
            }
            Ok(())
        })
    }

    fn cleanup<'a>(&'a self, work_dir: &'a Path) -> BoxFuture<'a, Result<(), R3xError>> {
        Box::pin(async move {
            let cfg = work_dir.join("mihomo.yaml");
            if cfg.exists() {
                let _ = fs::remove_file(&cfg);
            }
            if work_dir.exists() {
                let _ = fs::remove_dir_all(work_dir);
            }
            Ok(())
        })
    }
}
