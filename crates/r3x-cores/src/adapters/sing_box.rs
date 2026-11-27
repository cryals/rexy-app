use crate::manifests::find_manifest;
use crate::supervisor::{
    ProcessRegistry, SupervisedProcess, probe_tcp_ready, read_process_metrics,
};
use chrono::Utc;
use parking_lot::RwLock;
use r3x_domain::{
    ConnectionMode, CoreCapabilities, CoreId, CoreManifest, DnsMode, FlowType, LogEntry, Profile,
    ProtocolType, R3xError, RuleAction, RuleMatcher, SecurityConfig, SupportStatus,
    TransportConfig,
};
use r3x_engine::{
    BoxFuture, CoreAdapter, CoreConfigContext, CoreHealth, CoreStats, GeneratedCoreConfig,
    RunningCoreHandle,
};
use serde_json::{Value, json};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub struct SingBoxAdapter {
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl SingBoxAdapter {
    #[must_use]
    pub fn new(binary_path: Option<PathBuf>) -> Self {
        let manifest = find_manifest(CoreId::SingBox).unwrap_or_else(|| CoreManifest {
            id: CoreId::SingBox,
            name: "sing-box".to_owned(),
            version: "1.12.12".to_owned(),
            release_source: "https://github.com/SagerNet/sing-box/releases".to_owned(),
            license: "GPL-3.0-only".to_owned(),
            supported_platforms: Vec::new(),
            supported_archs: Vec::new(),
            checksums_sha256: Default::default(),
            signature_verification: "sha256".to_owned(),
            capabilities: CoreCapabilities {
                protocols: vec![
                    ProtocolType::Vless,
                    ProtocolType::Hysteria2,
                    ProtocolType::TuicV5,
                ],
                transports: vec!["TCP".to_owned(), "QUIC".to_owned()],
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

    fn build_tls_object(profile: &Profile) -> Option<Value> {
        match &profile.security {
            SecurityConfig::None => None,
            SecurityConfig::Tls(t) => Some(json!({
                "enabled": true,
                "server_name": t.sni.clone().unwrap_or_else(|| profile.endpoint.host.clone()),
                "insecure": t.allow_insecure,
                "alpn": t.alpn,
                "utls": {
                    "enabled": t.fingerprint.is_some(),
                    "fingerprint": t.fingerprint.clone().unwrap_or_else(|| "chrome".to_owned()),
                }
            })),
            SecurityConfig::Reality(r) => Some(json!({
                "enabled": true,
                "server_name": r.sni,
                "reality": {
                    "enabled": true,
                    "public_key": r.public_key,
                    "short_id": r.short_id,
                },
                "utls": {
                    "enabled": true,
                    "fingerprint": r.fingerprint.clone().unwrap_or_else(|| "chrome".to_owned()),
                }
            })),
            _ => None,
        }
    }

    fn build_transport_object(profile: &Profile) -> Option<Value> {
        match &profile.transport {
            TransportConfig::WebSocket { path, host, .. } => Some(json!({
                "type": "ws",
                "path": path,
                "headers": host.as_ref().map(|h| json!({ "Host": h })).unwrap_or_else(|| json!({}))
            })),
            TransportConfig::Grpc { service_name, .. } => Some(json!({
                "type": "grpc",
                "service_name": service_name
            })),
            TransportConfig::HttpUpgrade { path, host } => Some(json!({
                "type": "httpupgrade",
                "path": path,
                "host": host
            })),
            TransportConfig::Http2 { path, hosts } => Some(json!({
                "type": "http",
                "path": path,
                "host": hosts
            })),
            _ => None,
        }
    }

    fn build_outbound(profile: &Profile) -> Result<Value, R3xError> {
        let secret = profile
            .auth
            .inline_secret
            .as_ref()
            .map(|s| s.expose().to_owned())
            .unwrap_or_default();

        let mut obj = match profile.protocol.protocol_type {
            ProtocolType::Vless => {
                let mut v = json!({
                    "type": "vless",
                    "tag": "proxy",
                    "server": profile.endpoint.host,
                    "server_port": profile.endpoint.port,
                    "uuid": secret,
                });
                if let Some(flow) = profile.flow {
                    v["flow"] = json!(match flow {
                        FlowType::XtlsRprxVision => "xtls-rprx-vision",
                        FlowType::XtlsRprxVisionUdp443 => "xtls-rprx-vision-udp443",
                    });
                }
                v
            }
            ProtocolType::Vmess => json!({
                "type": "vmess",
                "tag": "proxy",
                "server": profile.endpoint.host,
                "server_port": profile.endpoint.port,
                "uuid": secret,
                "security": profile.protocol.cipher.clone().unwrap_or_else(|| "auto".to_owned()),
                "alter_id": profile.protocol.alter_id.unwrap_or(0),
            }),
            ProtocolType::Trojan => json!({
                "type": "trojan",
                "tag": "proxy",
                "server": profile.endpoint.host,
                "server_port": profile.endpoint.port,
                "password": secret,
            }),
            ProtocolType::Shadowsocks | ProtocolType::Shadowsocks2022 => json!({
                "type": "shadowsocks",
                "tag": "proxy",
                "server": profile.endpoint.host,
                "server_port": profile.endpoint.port,
                "method": profile.protocol.cipher.clone().unwrap_or_else(|| "aes-256-gcm".to_owned()),
                "password": secret,
            }),
            ProtocolType::Hysteria2 => {
                let mut h = json!({
                    "type": "hysteria2",
                    "tag": "proxy",
                    "server": profile.endpoint.host,
                    "server_port": profile.endpoint.port,
                    "password": secret,
                });
                if let Some(up) = profile.options.up_mbps {
                    h["up_mbps"] = json!(up);
                }
                if let Some(dn) = profile.options.down_mbps {
                    h["down_mbps"] = json!(dn);
                }
                if let Some(obfs) = profile.protocol.protocol_params.get("obfs") {
                    h["obfs"] = json!({
                        "type": obfs,
                        "password": profile.auth.secondary_secret.as_ref().map(|s| s.expose()).unwrap_or_default()
                    });
                }
                h
            }
            ProtocolType::TuicV5 | ProtocolType::TuicV4 => json!({
                "type": "tuic",
                "tag": "proxy",
                "server": profile.endpoint.host,
                "server_port": profile.endpoint.port,
                "uuid": secret,
                "password": profile.auth.secondary_secret.as_ref().map(|s| s.expose()).unwrap_or_default(),
                "congestion_control": profile.options.congestion_control.clone().unwrap_or_else(|| "bbr".to_owned()),
            }),
            ProtocolType::AnyTls => json!({
                "type": "anytls",
                "tag": "proxy",
                "server": profile.endpoint.host,
                "server_port": profile.endpoint.port,
                "password": secret,
            }),
            ProtocolType::WireGuard => json!({
                "type": "wireguard",
                "tag": "proxy",
                "server": profile.endpoint.host,
                "server_port": profile.endpoint.port,
                "local_address": if profile.endpoint.local_addresses.is_empty() {
                    vec!["10.0.0.2/32".to_owned()]
                } else {
                    profile.endpoint.local_addresses.clone()
                },
                "private_key": secret,
                "peer_public_key": profile.auth.public_key.clone().unwrap_or_default(),
                "mtu": profile.protocol.mtu.unwrap_or(1408),
            }),
            ProtocolType::Socks5 => json!({
                "type": "socks",
                "tag": "proxy",
                "server": profile.endpoint.host,
                "server_port": profile.endpoint.port,
                "username": profile.auth.username,
                "password": if secret.is_empty() { Value::Null } else { json!(secret) }
            }),
            ProtocolType::Http | ProtocolType::Https => json!({
                "type": "http",
                "tag": "proxy",
                "server": profile.endpoint.host,
                "server_port": profile.endpoint.port,
                "username": profile.auth.username,
                "password": if secret.is_empty() { Value::Null } else { json!(secret) }
            }),
            other => {
                return Err(R3xError::CoreIncompatible {
                    core: "sing-box".to_owned(),
                    reason: format!("protocol {other:?} unsupported by sing-box adapter"),
                });
            }
        };

        if profile.protocol.protocol_type != ProtocolType::WireGuard {
            if let Some(tls) = Self::build_tls_object(profile) {
                obj["tls"] = tls;
            }
            if let Some(tr) = Self::build_transport_object(profile) {
                obj["transport"] = tr;
            }
        }
        Ok(obj)
    }

    fn build_route_rules(ctx: &CoreConfigContext) -> Vec<Value> {
        let mut rules = Vec::new();
        for rule in &ctx.routing_rules {
            if !rule.enabled {
                continue;
            }
            let outbound = match rule.action {
                RuleAction::Proxy | RuleAction::SelectedProfile(_) => "proxy",
                RuleAction::Direct => "direct",
                RuleAction::Block => "block",
            };
            let mut r = json!({ "outbound": outbound });
            match &rule.matcher {
                RuleMatcher::Domain(d) => r["domain"] = json!([d]),
                RuleMatcher::DomainSuffix(d) => r["domain_suffix"] = json!([d]),
                RuleMatcher::DomainKeyword(d) => r["domain_keyword"] = json!([d]),
                RuleMatcher::Ip(ip) => r["ip_cidr"] = json!([ip]),
                RuleMatcher::Cidr(c) => r["ip_cidr"] = json!([c.to_string()]),
                RuleMatcher::Port(p) => r["port"] = json!([p]),
                RuleMatcher::Protocol(pr) => r["protocol"] = json!([pr]),
                RuleMatcher::ProcessName(pn) => r["process_name"] = json!([pn]),
                _ => continue,
            }
            rules.push(r);
        }
        rules
    }
}

impl CoreAdapter for SingBoxAdapter {
    fn id(&self) -> CoreId {
        CoreId::SingBox
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
            let listen_ip = if ctx.allow_lan {
                "0.0.0.0"
            } else {
                "127.0.0.1"
            };
            let mut inbounds = Vec::new();
            let mut local_http = None;
            let mut local_socks = None;
            let mut tun_name = None;

            if matches!(
                ctx.mode,
                ConnectionMode::SystemProxy | ConnectionMode::Mixed
            ) {
                inbounds.push(json!({
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": listen_ip,
                    "listen_port": ctx.mixed_port,
                    "sniff": true
                }));
                local_http = Some(ctx.mixed_port);
                local_socks = Some(ctx.mixed_port);
            }

            if matches!(ctx.mode, ConnectionMode::Tun | ConnectionMode::Mixed) {
                let mut tun = json!({
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": ctx.tun_interface_name,
                    "address": if ctx.ipv6_enabled {
                        json!(["172.19.0.1/30", "fdfe:dcba:9876::1/126"])
                    } else {
                        json!(["172.19.0.1/30"])
                    },
                    "auto_route": ctx.tun_fd.is_none(),
                    "strict_route": ctx.tun_fd.is_none(),
                    "stack": "mixed",
                    "sniff": true
                });
                if let Some(fd) = ctx.tun_fd {
                    tun["file_descriptor"] = json!(fd);
                }
                inbounds.push(tun);
                tun_name = Some(ctx.tun_interface_name.clone());
            }

            let dns_addr = match ctx.dns.primary.mode {
                DnsMode::System => "local",
                _ => ctx.dns.primary.address.as_str(),
            };
            let clash_port = ctx.http_port.saturating_add(100);

            let cfg = json!({
                "log": { "level": "warn", "timestamp": true },
                "dns": {
                    "servers": [{
                        "tag": "primary-dns",
                        "address": dns_addr
                    }]
                },
                "inbounds": inbounds,
                "outbounds": [
                    Self::build_outbound(&ctx.profile)?,
                    { "type": "direct", "tag": "direct" },
                    { "type": "block", "tag": "block" }
                ],
                "route": {
                    "rules": Self::build_route_rules(ctx),
                    "final": "proxy",
                    "auto_detect_interface": true
                },
                "experimental": {
                    "clash_api": {
                        "external_controller": format!("127.0.0.1:{clash_port}")
                    }
                }
            });

            let config_path = ctx.work_dir.join("sing-box.json");
            let contents = serde_json::to_string_pretty(&cfg)
                .map_err(|e| R3xError::Storage(format!("serialize sing-box config: {e}")))?;
            fs::write(&config_path, &contents)?;

            Ok(GeneratedCoreConfig {
                core_id: CoreId::SingBox,
                config_path,
                config_contents: contents,
                local_http_port: local_http,
                local_socks_port: local_socks,
                tun_interface_name: tun_name,
                api_endpoint: Some(format!("127.0.0.1:{clash_port}")),
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
                .ok_or_else(|| R3xError::CoreNotInstalled("sing-box".to_owned()))?;
            let work_dir = config
                .config_path
                .parent()
                .unwrap_or(Path::new("."))
                .to_path_buf();
            let args = vec![
                "run".to_owned(),
                "-c".to_owned(),
                config.config_path.to_string_lossy().into_owned(),
            ];
            let proc_handle = Arc::new(SupervisedProcess::spawn(
                CoreId::SingBox,
                &binary,
                &args,
                &work_dir,
                log_tx,
            )?);
            let pid = proc_handle.pid;
            self.processes.insert(proc_handle);
            Ok(RunningCoreHandle {
                core_id: CoreId::SingBox,
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
                    "sing-box control API reachable".to_owned()
                } else if !alive {
                    "sing-box process terminated".to_owned()
                } else {
                    "sing-box control API unreachable".to_owned()
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
            let cfg = work_dir.join("sing-box.json");
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
