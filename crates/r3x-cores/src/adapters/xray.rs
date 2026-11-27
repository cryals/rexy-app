use crate::manifests::find_manifest;
use crate::supervisor::{
    ProcessRegistry, SupervisedProcess, probe_tcp_ready, read_process_metrics,
};
use chrono::Utc;
use parking_lot::RwLock;
use r3x_domain::{
    CoreCapabilities, CoreId, CoreManifest, DnsMode, FlowType, LogEntry, Profile, ProtocolType,
    R3xError, RuleAction, RuleMatcher, SecurityConfig, SupportStatus, TransportConfig,
};
use r3x_engine::{
    BoxFuture, CoreAdapter, CoreConfigContext, CoreHealth, CoreStats, GeneratedCoreConfig,
    RunningCoreHandle,
};
use serde_json::{Value, json};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub struct XrayAdapter {
    manifest: CoreManifest,
    binary_path: RwLock<Option<PathBuf>>,
    processes: ProcessRegistry,
}

impl XrayAdapter {
    #[must_use]
    pub fn new(binary_path: Option<PathBuf>) -> Self {
        let manifest = find_manifest(CoreId::Xray).unwrap_or_else(|| CoreManifest {
            id: CoreId::Xray,
            name: "Xray-core".to_owned(),
            version: "26.2.6".to_owned(),
            release_source: "https://github.com/XTLS/Xray-core/releases".to_owned(),
            license: "MPL-2.0".to_owned(),
            supported_platforms: Vec::new(),
            supported_archs: Vec::new(),
            checksums_sha256: Default::default(),
            signature_verification: "sha256".to_owned(),
            capabilities: CoreCapabilities {
                protocols: vec![
                    ProtocolType::Vless,
                    ProtocolType::Vmess,
                    ProtocolType::Trojan,
                ],
                transports: vec!["TCP".to_owned()],
                supports_tls: true,
                supports_reality: true,
                supports_vision: true,
                supports_udp: true,
                supports_ipv6: true,
                supports_tun: false,
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

    fn build_stream_settings(profile: &Profile) -> Value {
        let (network, transport_key, transport_val) = match &profile.transport {
            TransportConfig::WebSocket { path, host, .. } => {
                let headers = host.as_ref().map(|h| json!({ "Host": h }));
                let mut ws = json!({ "path": path });
                if let Some(h) = headers {
                    ws["headers"] = h;
                }
                ("ws", Some("wsSettings"), Some(ws))
            }
            TransportConfig::Grpc {
                service_name,
                multi_mode,
            } => (
                "grpc",
                Some("grpcSettings"),
                Some(json!({ "serviceName": service_name, "multiMode": multi_mode })),
            ),
            TransportConfig::Xhttp { path, host, mode } => {
                let mut x = json!({ "path": path });
                if let Some(h) = host {
                    x["host"] = json!(h);
                }
                if let Some(m) = mode {
                    x["mode"] = json!(m);
                }
                ("xhttp", Some("xhttpSettings"), Some(x))
            }
            TransportConfig::HttpUpgrade { path, host } => {
                let mut hu = json!({ "path": path });
                if let Some(h) = host {
                    hu["host"] = json!(h);
                }
                ("httpupgrade", Some("httpupgradeSettings"), Some(hu))
            }
            TransportConfig::Mkcp { header_type, seed } => (
                "kcp",
                Some("kcpSettings"),
                Some(json!({
                    "header": { "type": header_type.clone().unwrap_or_else(|| "none".to_owned()) },
                    "seed": seed
                })),
            ),
            TransportConfig::Quic {
                security,
                header_type,
            } => (
                "quic",
                Some("quicSettings"),
                Some(json!({
                    "security": security.clone().unwrap_or_else(|| "none".to_owned()),
                    "header": { "type": header_type.clone().unwrap_or_else(|| "none".to_owned()) }
                })),
            ),
            TransportConfig::Http2 { path, hosts } => (
                "h2",
                Some("httpSettings"),
                Some(json!({ "path": path, "host": hosts })),
            ),
            _ => ("raw", None, None),
        };

        let mut stream = json!({ "network": network });
        if let (Some(k), Some(v)) = (transport_key, transport_val) {
            stream[k] = v;
        }

        match &profile.security {
            SecurityConfig::None => {
                stream["security"] = json!("none");
            }
            SecurityConfig::Tls(t) => {
                stream["security"] = json!("tls");
                stream["tlsSettings"] = json!({
                    "serverName": t.sni.clone().unwrap_or_else(|| profile.endpoint.host.clone()),
                    "allowInsecure": t.allow_insecure,
                    "alpn": t.alpn,
                    "fingerprint": t.fingerprint.clone().unwrap_or_else(|| "chrome".to_owned()),
                });
            }
            SecurityConfig::Reality(r) => {
                stream["security"] = json!("reality");
                stream["realitySettings"] = json!({
                    "serverName": r.sni,
                    "publicKey": r.public_key,
                    "shortId": r.short_id,
                    "spiderX": r.spider_x.clone().unwrap_or_else(|| "/".to_owned()),
                    "fingerprint": r.fingerprint.clone().unwrap_or_else(|| "chrome".to_owned()),
                });
            }
            SecurityConfig::VlessEncryption { .. }
            | SecurityConfig::NoiseWg
            | SecurityConfig::AmneziaWg(_) => {
                stream["security"] = json!("none");
            }
        }
        stream
    }

    fn build_outbound(profile: &Profile) -> Result<Value, R3xError> {
        let secret = profile
            .auth
            .inline_secret
            .as_ref()
            .map(|s| s.expose().to_owned())
            .unwrap_or_default();

        let outbound = match profile.protocol.protocol_type {
            ProtocolType::Vless => {
                let mut user = json!({
                    "id": secret,
                    "encryption": profile.protocol.protocol_params.get("encryption").cloned().unwrap_or_else(|| "none".to_owned()),
                });
                if let Some(flow) = profile.flow {
                    user["flow"] = json!(match flow {
                        FlowType::XtlsRprxVision => "xtls-rprx-vision",
                        FlowType::XtlsRprxVisionUdp443 => "xtls-rprx-vision-udp443",
                    });
                }
                json!({
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": profile.endpoint.host,
                            "port": profile.endpoint.port,
                            "users": [user]
                        }]
                    },
                    "streamSettings": Self::build_stream_settings(profile),
                    "mux": { "enabled": profile.options.mux_enabled }
                })
            }
            ProtocolType::Vmess => json!({
                "tag": "proxy",
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": profile.endpoint.host,
                        "port": profile.endpoint.port,
                        "users": [{
                            "id": secret,
                            "alterId": profile.protocol.alter_id.unwrap_or(0),
                            "security": profile.protocol.cipher.clone().unwrap_or_else(|| "auto".to_owned()),
                        }]
                    }]
                },
                "streamSettings": Self::build_stream_settings(profile),
                "mux": { "enabled": profile.options.mux_enabled }
            }),
            ProtocolType::Trojan => json!({
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": profile.endpoint.host,
                        "port": profile.endpoint.port,
                        "password": secret,
                    }]
                },
                "streamSettings": Self::build_stream_settings(profile)
            }),
            ProtocolType::Shadowsocks | ProtocolType::Shadowsocks2022 => json!({
                "tag": "proxy",
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": profile.endpoint.host,
                        "port": profile.endpoint.port,
                        "method": profile.protocol.cipher.clone().unwrap_or_else(|| "aes-256-gcm".to_owned()),
                        "password": secret,
                    }]
                }
            }),
            ProtocolType::Socks5 | ProtocolType::Socks4 | ProtocolType::Socks4a => {
                let mut srv = json!({
                    "address": profile.endpoint.host,
                    "port": profile.endpoint.port,
                });
                if let Some(ref u) = profile.auth.username {
                    srv["users"] = json!([{ "user": u, "pass": secret }]);
                }
                json!({
                    "tag": "proxy",
                    "protocol": "socks",
                    "settings": { "servers": [srv] }
                })
            }
            ProtocolType::Http | ProtocolType::Https => {
                let mut srv = json!({
                    "address": profile.endpoint.host,
                    "port": profile.endpoint.port,
                });
                if let Some(ref u) = profile.auth.username {
                    srv["users"] = json!([{ "user": u, "pass": secret }]);
                }
                json!({
                    "tag": "proxy",
                    "protocol": "http",
                    "settings": { "servers": [srv] },
                    "streamSettings": Self::build_stream_settings(profile)
                })
            }
            other => {
                return Err(R3xError::CoreIncompatible {
                    core: "Xray-core".to_owned(),
                    reason: format!("protocol {other:?} unsupported by Xray outbound generator"),
                });
            }
        };
        Ok(outbound)
    }

    fn build_routing_rules(ctx: &CoreConfigContext) -> Vec<Value> {
        let mut rules = Vec::new();
        for rule in &ctx.routing_rules {
            if !rule.enabled {
                continue;
            }
            let outbound_tag = match rule.action {
                RuleAction::Proxy | RuleAction::SelectedProfile(_) => "proxy",
                RuleAction::Direct => "direct",
                RuleAction::Block => "block",
            };
            let mut obj = json!({
                "type": "field",
                "outboundTag": outbound_tag,
            });
            match &rule.matcher {
                RuleMatcher::Domain(d) => obj["domain"] = json!([format!("full:{d}")]),
                RuleMatcher::DomainSuffix(d) => obj["domain"] = json!([format!("domain:{d}")]),
                RuleMatcher::DomainKeyword(d) => obj["domain"] = json!([d]),
                RuleMatcher::Ip(ip) => obj["ip"] = json!([ip]),
                RuleMatcher::Cidr(c) => obj["ip"] = json!([c.to_string()]),
                RuleMatcher::GeoIp(g) => obj["ip"] = json!([format!("geoip:{g}")]),
                RuleMatcher::GeoSite(g) => obj["domain"] = json!([format!("geosite:{g}")]),
                RuleMatcher::Port(p) => obj["port"] = json!(p.to_string()),
                RuleMatcher::PortRange { start, end } => {
                    obj["port"] = json!(format!("{start}-{end}"))
                }
                RuleMatcher::Protocol(pr) => obj["protocol"] = json!([pr]),
                _ => continue,
            }
            rules.push(obj);
        }
        rules
    }
}

impl CoreAdapter for XrayAdapter {
    fn id(&self) -> CoreId {
        CoreId::Xray
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
        if matches!(
            profile.protocol.protocol_type,
            ProtocolType::Vless | ProtocolType::Vmess | ProtocolType::Trojan
        ) && profile
            .auth
            .inline_secret
            .as_ref()
            .is_none_or(|s| s.is_empty())
        {
            return Err(R3xError::Validation(
                "Xray outbound requires UUID or password credential".to_owned(),
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
            let outbound = Self::build_outbound(&ctx.profile)?;
            let dns_server = match ctx.dns.primary.mode {
                DnsMode::System => json!("localhost"),
                _ => json!(ctx.dns.primary.address),
            };
            let cfg = json!({
                "log": { "loglevel": "warning" },
                "stats": {},
                "dns": { "servers": [dns_server] },
                "inbounds": [
                    {
                        "tag": "socks-in",
                        "port": ctx.socks_port,
                        "listen": listen_ip,
                        "protocol": "socks",
                        "settings": { "udp": true },
                        "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
                    },
                    {
                        "tag": "http-in",
                        "port": ctx.http_port,
                        "listen": listen_ip,
                        "protocol": "http",
                        "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
                    }
                ],
                "outbounds": [
                    outbound,
                    { "tag": "direct", "protocol": "freedom" },
                    { "tag": "block", "protocol": "blackhole" }
                ],
                "routing": {
                    "domainStrategy": "AsIs",
                    "rules": Self::build_routing_rules(ctx)
                }
            });

            let config_path = ctx.work_dir.join("xray.json");
            let contents = serde_json::to_string_pretty(&cfg)
                .map_err(|e| R3xError::Storage(format!("serialize xray config: {e}")))?;
            fs::write(&config_path, &contents)?;

            Ok(GeneratedCoreConfig {
                core_id: CoreId::Xray,
                config_path,
                config_contents: contents,
                local_http_port: Some(ctx.http_port),
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
            let binary = self
                .binary_path
                .read()
                .clone()
                .ok_or_else(|| R3xError::CoreNotInstalled("Xray-core".to_owned()))?;
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
                CoreId::Xray,
                &binary,
                &args,
                &work_dir,
                log_tx,
            )?);
            let pid = proc_handle.pid;
            self.processes.insert(proc_handle);
            Ok(RunningCoreHandle {
                core_id: CoreId::Xray,
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
            let endpoint_ready = if alive {
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
                control_api_reachable: endpoint_ready,
                tunnel_ready: alive && endpoint_ready,
                details: if alive && endpoint_ready {
                    "Xray SOCKS/HTTP inbound accepting connections".to_owned()
                } else if !alive {
                    "Xray process terminated".to_owned()
                } else {
                    format!(
                        "Xray inbound unreachable at {}",
                        handle.api_endpoint.as_deref().unwrap_or("unknown")
                    )
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
            let cfg = work_dir.join("xray.json");
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

pub fn loopback_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}
