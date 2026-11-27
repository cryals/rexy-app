use crate::dns::check_dns_leaks;
use crate::routing::RoutingManager;
use chrono::Utc;
use r3x_domain::{
    AppSettings, ConnectionState, CpuArch, DiagnosticCheckId, DiagnosticReport, DiagnosticResult,
    DiagnosticStatus, DnsConfig, Platform, Profile, SecurityConfig,
};
use r3x_engine::{CoreSelectionContext, CoreSelector, R3xEngine};
use r3x_network::{
    check_tun_capability, create_platform_proxy_backend, is_local_port_available,
    list_network_interfaces,
};
use r3x_security::Redactor;
use r3x_storage::{R3xDatabase, create_default_secret_store};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, lookup_host};

pub struct DiagnosticContext {
    pub db: Arc<R3xDatabase>,
    pub engine: Arc<R3xEngine>,
    pub active_profile: Option<Profile>,
    pub settings: AppSettings,
    pub dns: DnsConfig,
    /// Overridable TCP target for connectivity probes (default "1.1.1.1:443").
    pub connectivity_probe_addr: Option<String>,
    /// Overridable HTTP(S) target for TLS verification probe.
    pub tls_probe_url: Option<String>,
    /// Overridable hostname for system DNS lookup check.
    pub dns_lookup_host: Option<String>,
}

pub struct NetworkDoctor {
    ctx: DiagnosticContext,
}

impl NetworkDoctor {
    #[must_use]
    pub fn new(ctx: DiagnosticContext) -> Self {
        Self { ctx }
    }

    pub async fn run_all(&self) -> DiagnosticReport {
        let mut results = Vec::with_capacity(DiagnosticCheckId::all().len());
        for &check_id in DiagnosticCheckId::all() {
            results.push(self.run_check(check_id).await);
        }
        let report = DiagnosticReport {
            generated_at: Utc::now(),
            platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            results,
        };
        let redacted = Redactor::redact_diagnostic_report(&report);
        let _ = self.ctx.db.save_diagnostic_report(&redacted);
        redacted
    }

    pub async fn run_check(&self, id: DiagnosticCheckId) -> DiagnosticResult {
        let start = Instant::now();
        let mut res = match id {
            DiagnosticCheckId::InternetConnectivity => self.check_internet_connectivity().await,
            DiagnosticCheckId::DnsResolution => self.check_dns_resolution().await,
            DiagnosticCheckId::ServerReachability => self.check_server_reachability().await,
            DiagnosticCheckId::TlsConnectivity => self.check_tls_connectivity().await,
            DiagnosticCheckId::CoreProcessHealth => self.check_core_health(),
            DiagnosticCheckId::ConfigurationValidity => self.check_config_validity(),
            DiagnosticCheckId::CoreCompatibility => self.check_core_compatibility(),
            DiagnosticCheckId::TunInterface => self.check_tun_interface(),
            DiagnosticCheckId::SystemProxy => self.check_system_proxy(),
            DiagnosticCheckId::RoutingState => self.check_routing_state(),
            DiagnosticCheckId::Ipv4Connectivity => self.check_ip_family(false),
            DiagnosticCheckId::Ipv6Connectivity => self.check_ip_family(true),
            DiagnosticCheckId::DnsLeaks => {
                let connected = matches!(
                    self.ctx.engine.connection_state(),
                    ConnectionState::Connected
                );
                check_dns_leaks(&self.ctx.dns, connected)
            }
            DiagnosticCheckId::NetworkAdapterConflicts => self.check_adapter_conflicts(),
            DiagnosticCheckId::RequiredPermissions => self.check_permissions(),
            DiagnosticCheckId::LocalPortAvailability => self.check_local_ports(),
        };
        if res.duration_ms.is_none() {
            res.duration_ms = Some(start.elapsed().as_millis() as u64);
        }
        res
    }

    async fn check_internet_connectivity(&self) -> DiagnosticResult {
        let target = self
            .ctx
            .connectivity_probe_addr
            .as_deref()
            .unwrap_or("1.1.1.1:443");
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(target)).await {
            Ok(Ok(_)) => DiagnosticResult {
                check_id: DiagnosticCheckId::InternetConnectivity,
                status: DiagnosticStatus::Passed,
                summary: format!("TCP connectivity verified to {target}"),
                technical_details: format!("target={target}"),
                suggested_actions: Vec::new(),
                related_settings_section: Some("connection".to_owned()),
                duration_ms: None,
            },
            Ok(Err(e)) => DiagnosticResult {
                check_id: DiagnosticCheckId::InternetConnectivity,
                status: DiagnosticStatus::Failed,
                summary: format!("Unable to reach TCP probe target {target}"),
                technical_details: format!("error={e}"),
                suggested_actions: vec![
                    "Check physical network link, firewall, or proxy conflict".to_owned(),
                ],
                related_settings_section: Some("connection".to_owned()),
                duration_ms: None,
            },
            Err(_) => DiagnosticResult {
                check_id: DiagnosticCheckId::InternetConnectivity,
                status: DiagnosticStatus::Failed,
                summary: format!("Timed out probing {target} (3s)"),
                technical_details: format!("target={target}; timeout=3000ms"),
                suggested_actions: vec!["Verify network connectivity or firewall rules".to_owned()],
                related_settings_section: Some("connection".to_owned()),
                duration_ms: None,
            },
        }
    }

    async fn check_dns_resolution(&self) -> DiagnosticResult {
        let host = self
            .ctx
            .dns_lookup_host
            .as_deref()
            .unwrap_or("example.com:443");
        match tokio::time::timeout(Duration::from_secs(3), lookup_host(host)).await {
            Ok(Ok(addrs)) => {
                let resolved: Vec<String> = addrs.take(4).map(|a| a.ip().to_string()).collect();
                if resolved.is_empty() {
                    DiagnosticResult {
                        check_id: DiagnosticCheckId::DnsResolution,
                        status: DiagnosticStatus::Warning,
                        summary: format!("Resolver returned zero addresses for {host}"),
                        technical_details: format!("target={host}"),
                        suggested_actions: vec!["Inspect DNS resolver settings".to_owned()],
                        related_settings_section: Some("routing_dns".to_owned()),
                        duration_ms: None,
                    }
                } else {
                    DiagnosticResult {
                        check_id: DiagnosticCheckId::DnsResolution,
                        status: DiagnosticStatus::Passed,
                        summary: format!("Resolved {host} to {}", resolved.join(", ")),
                        technical_details: format!("target={host}; ips={resolved:?}"),
                        suggested_actions: Vec::new(),
                        related_settings_section: Some("routing_dns".to_owned()),
                        duration_ms: None,
                    }
                }
            }
            Ok(Err(e)) => DiagnosticResult {
                check_id: DiagnosticCheckId::DnsResolution,
                status: DiagnosticStatus::Failed,
                summary: format!("System DNS lookup failed for {host}"),
                technical_details: format!("error={e}"),
                suggested_actions: vec![
                    "Switch DNS mode to DoH/DoT or check local resolver".to_owned(),
                ],
                related_settings_section: Some("routing_dns".to_owned()),
                duration_ms: None,
            },
            Err(_) => DiagnosticResult {
                check_id: DiagnosticCheckId::DnsResolution,
                status: DiagnosticStatus::Failed,
                summary: format!("DNS lookup timed out for {host}"),
                technical_details: format!("target={host}; timeout=3000ms"),
                suggested_actions: vec!["Check firewall or upstream DNS availability".to_owned()],
                related_settings_section: Some("routing_dns".to_owned()),
                duration_ms: None,
            },
        }
    }

    async fn check_server_reachability(&self) -> DiagnosticResult {
        let Some(ref profile) = self.ctx.active_profile else {
            return DiagnosticResult {
                check_id: DiagnosticCheckId::ServerReachability,
                status: DiagnosticStatus::NotTested,
                summary: "No server profile selected".to_owned(),
                technical_details: "active_profile=None".to_owned(),
                suggested_actions: vec!["Select a server profile first".to_owned()],
                related_settings_section: Some("servers".to_owned()),
                duration_ms: None,
            };
        };
        let target = format!("{}:{}", profile.endpoint.host, profile.endpoint.port);
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&target)).await {
            Ok(Ok(_)) => DiagnosticResult {
                check_id: DiagnosticCheckId::ServerReachability,
                status: DiagnosticStatus::Passed,
                summary: format!("TCP handshake succeeded with {target}"),
                technical_details: format!(
                    "profile={}; protocol={:?}",
                    profile.effective_name(),
                    profile.protocol.protocol_type
                ),
                suggested_actions: Vec::new(),
                related_settings_section: Some("servers".to_owned()),
                duration_ms: None,
            },
            Ok(Err(e)) => DiagnosticResult {
                check_id: DiagnosticCheckId::ServerReachability,
                status: DiagnosticStatus::Failed,
                summary: format!("Server endpoint {target} unreachable: {e}"),
                technical_details: format!("target={target}; error={e}"),
                suggested_actions: vec![
                    "Confirm remote port is reachable or switch server".to_owned(),
                ],
                related_settings_section: Some("servers".to_owned()),
                duration_ms: None,
            },
            Err(_) => DiagnosticResult {
                check_id: DiagnosticCheckId::ServerReachability,
                status: DiagnosticStatus::Failed,
                summary: format!("TCP connect to {target} timed out (3s)"),
                technical_details: format!("target={target}; timeout=3000ms"),
                suggested_actions: vec!["Test server latency or try a different node".to_owned()],
                related_settings_section: Some("servers".to_owned()),
                duration_ms: None,
            },
        }
    }

    async fn check_tls_connectivity(&self) -> DiagnosticResult {
        let url_opt = if let Some(ref custom) = self.ctx.tls_probe_url {
            Some((custom.clone(), "configured TLS probe"))
        } else if let Some(ref profile) = self.ctx.active_profile {
            match &profile.security {
                SecurityConfig::Tls(tls) => {
                    let sni = tls.sni.as_deref().unwrap_or(&profile.endpoint.host);
                    Some((
                        format!("https://{sni}:{}", profile.endpoint.port),
                        "profile TLS SNI",
                    ))
                }
                SecurityConfig::Reality(r) => Some((
                    format!("https://{}:443", r.sni),
                    "profile REALITY masquerade SNI",
                )),
                _ => None,
            }
        } else {
            None
        };

        let Some((probe_url, kind)) = url_opt else {
            return DiagnosticResult {
                check_id: DiagnosticCheckId::TlsConnectivity,
                status: DiagnosticStatus::NotTested,
                summary: "Active profile does not use HTTPS/TLS/REALITY SNI".to_owned(),
                technical_details: "tls_probe=not_applicable".to_owned(),
                suggested_actions: Vec::new(),
                related_settings_section: Some("servers".to_owned()),
                duration_ms: None,
            };
        };

        let _ = rustls::crypto::ring::default_provider().install_default();
        let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_secs(4))
            .user_agent("R3X-TLS-Doctor/0.1")
            .build()
        else {
            return DiagnosticResult {
                check_id: DiagnosticCheckId::TlsConnectivity,
                status: DiagnosticStatus::Failed,
                summary: "Failed initializing rustls HTTP client".to_owned(),
                technical_details: format!("probe={probe_url}"),
                suggested_actions: Vec::new(),
                related_settings_section: Some("connection".to_owned()),
                duration_ms: None,
            };
        };

        match client.head(&probe_url).send().await {
            Ok(resp) => DiagnosticResult {
                check_id: DiagnosticCheckId::TlsConnectivity,
                status: DiagnosticStatus::Passed,
                summary: format!(
                    "Verified TLS handshake against {probe_url} ({kind}, HTTP {})",
                    resp.status().as_u16()
                ),
                technical_details: format!("url={probe_url}; status={}", resp.status()),
                suggested_actions: Vec::new(),
                related_settings_section: Some("servers".to_owned()),
                duration_ms: None,
            },
            Err(e) => DiagnosticResult {
                check_id: DiagnosticCheckId::TlsConnectivity,
                status: DiagnosticStatus::Warning,
                summary: format!("TLS probe to {probe_url} did not complete strict HTTPS check"),
                technical_details: format!("kind={kind}; error={e}"),
                suggested_actions: vec![
                    "If using custom TLS certificates or raw non-HTTP ALPN proxy servers, inspect core logs".to_owned(),
                ],
                related_settings_section: Some("servers".to_owned()),
                duration_ms: None,
            },
        }
    }

    fn check_core_health(&self) -> DiagnosticResult {
        let state = self.ctx.engine.connection_state();
        let installed = self.ctx.engine.installed_cores();
        match self.ctx.engine.current_session() {
            Some(sess) => DiagnosticResult {
                check_id: DiagnosticCheckId::CoreProcessHealth,
                status: DiagnosticStatus::Passed,
                summary: format!(
                    "Core {} v{} running ({})",
                    sess.core_id,
                    sess.core_version,
                    state.as_label()
                ),
                technical_details: format!("session_id={}; mode={:?}", sess.session_id, sess.mode),
                suggested_actions: Vec::new(),
                related_settings_section: Some("cores".to_owned()),
                duration_ms: None,
            },
            None => DiagnosticResult {
                check_id: DiagnosticCheckId::CoreProcessHealth,
                status: if matches!(state, ConnectionState::Error { .. }) {
                    DiagnosticStatus::Failed
                } else {
                    DiagnosticStatus::NotTested
                },
                summary: format!(
                    "Engine state: {}; {} core binary(s) installed",
                    state.as_label(),
                    installed.len()
                ),
                technical_details: format!("installed_cores={installed:?}"),
                suggested_actions: if installed.is_empty() {
                    vec!["Install a core binary in Core Manager before connecting".to_owned()]
                } else {
                    Vec::new()
                },
                related_settings_section: Some("cores".to_owned()),
                duration_ms: None,
            },
        }
    }

    fn check_config_validity(&self) -> DiagnosticResult {
        let Some(ref profile) = self.ctx.active_profile else {
            return DiagnosticResult {
                check_id: DiagnosticCheckId::ConfigurationValidity,
                status: DiagnosticStatus::NotTested,
                summary: "No active profile selected for validation".to_owned(),
                technical_details: "active_profile=None".to_owned(),
                suggested_actions: vec!["Import or select a server profile".to_owned()],
                related_settings_section: Some("servers".to_owned()),
                duration_ms: None,
            };
        };

        let adapters = self.ctx.engine.adapters();
        let matching = adapters
            .iter()
            .filter(|a| a.supports_profile(profile).is_runnable())
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return DiagnosticResult {
                check_id: DiagnosticCheckId::ConfigurationValidity,
                status: DiagnosticStatus::Warning,
                summary: format!(
                    "No registered adapter currently claims runnable support for {}",
                    profile.protocol.protocol_type.display_name()
                ),
                technical_details: format!("profile={}", profile.effective_name()),
                suggested_actions: vec![
                    "Check Protocol Support Matrix or select another profile".to_owned(),
                ],
                related_settings_section: Some("cores".to_owned()),
                duration_ms: None,
            };
        }

        for adapter in matching {
            if let Err(err) = adapter.validate_profile(profile) {
                return DiagnosticResult {
                    check_id: DiagnosticCheckId::ConfigurationValidity,
                    status: DiagnosticStatus::Failed,
                    summary: format!("{} validation rejected profile: {err}", adapter.id()),
                    technical_details: format!("adapter={}; error={err}", adapter.id()),
                    suggested_actions: vec![
                        "Edit profile fields (host, port, auth secret) and retry".to_owned(),
                    ],
                    related_settings_section: Some("servers".to_owned()),
                    duration_ms: None,
                };
            }
        }

        DiagnosticResult {
            check_id: DiagnosticCheckId::ConfigurationValidity,
            status: DiagnosticStatus::Passed,
            summary: format!(
                "Profile '{}' passed schema & adapter validation",
                profile.effective_name()
            ),
            technical_details: format!("protocol={:?}", profile.protocol.protocol_type),
            suggested_actions: Vec::new(),
            related_settings_section: Some("servers".to_owned()),
            duration_ms: None,
        }
    }

    fn check_core_compatibility(&self) -> DiagnosticResult {
        let installed = self.ctx.engine.installed_cores();
        let Some(ref profile) = self.ctx.active_profile else {
            return DiagnosticResult {
                check_id: DiagnosticCheckId::CoreCompatibility,
                status: if installed.is_empty() {
                    DiagnosticStatus::Warning
                } else {
                    DiagnosticStatus::Passed
                },
                summary: format!("{} installed core(s) discovered", installed.len()),
                technical_details: format!("installed={installed:?}"),
                suggested_actions: if installed.is_empty() {
                    vec!["Install Xray-core, sing-box, or Mihomo in Core Manager".to_owned()]
                } else {
                    Vec::new()
                },
                related_settings_section: Some("cores".to_owned()),
                duration_ms: None,
            };
        };

        let adapters = self.ctx.engine.adapters();
        let ctx = CoreSelectionContext {
            subscription_preference: r3x_domain::CorePreference::Auto,
            global_preference: self.ctx.settings.global_core_preference,
            platform: Platform::current(),
            arch: CpuArch::current(),
            mode: self.ctx.settings.preferred_connection_mode,
        };
        match CoreSelector::select(&adapters, &installed, profile, ctx) {
            Ok(sel) => DiagnosticResult {
                check_id: DiagnosticCheckId::CoreCompatibility,
                status: DiagnosticStatus::Passed,
                summary: format!("Selected {} ({})", sel.core_id, sel.reason),
                technical_details: format!("support={:?}; mode={:?}", sel.support_status, ctx.mode),
                suggested_actions: Vec::new(),
                related_settings_section: Some("cores".to_owned()),
                duration_ms: None,
            },
            Err(err) => DiagnosticResult {
                check_id: DiagnosticCheckId::CoreCompatibility,
                status: DiagnosticStatus::Warning,
                summary: err.to_string(),
                technical_details: format!(
                    "protocol={:?}; mode={:?}; installed={installed:?}",
                    profile.protocol.protocol_type, ctx.mode
                ),
                suggested_actions: vec![
                    "Install the required core binary or switch connection mode (Proxy / Mixed / TUN)".to_owned(),
                ],
                related_settings_section: Some("cores".to_owned()),
                duration_ms: None,
            },
        }
    }

    fn check_tun_interface(&self) -> DiagnosticResult {
        let tun = check_tun_capability();
        DiagnosticResult {
            check_id: DiagnosticCheckId::TunInterface,
            status: if tun.available && !tun.requires_elevation {
                DiagnosticStatus::Passed
            } else if tun.available {
                DiagnosticStatus::Warning
            } else {
                DiagnosticStatus::Failed
            },
            summary: tun.details,
            technical_details: format!(
                "available={}; requires_elevation={}",
                tun.available, tun.requires_elevation
            ),
            suggested_actions: if tun.requires_elevation {
                vec![
                    "Use r3x-daemon service with TUN permissions or switch to Proxy mode"
                        .to_owned(),
                ]
            } else {
                Vec::new()
            },
            related_settings_section: Some("connection".to_owned()),
            duration_ms: None,
        }
    }

    fn check_system_proxy(&self) -> DiagnosticResult {
        let backend = create_platform_proxy_backend();
        if !backend.is_supported() {
            return DiagnosticResult {
                check_id: DiagnosticCheckId::SystemProxy,
                status: DiagnosticStatus::Unsupported,
                summary: format!(
                    "System proxy backend unsupported ({})",
                    backend.backend_name()
                ),
                technical_details: "supported=false".to_owned(),
                suggested_actions: vec![
                    "Use TUN mode or configure applications manually".to_owned(),
                ],
                related_settings_section: Some("connection".to_owned()),
                duration_ms: None,
            };
        }
        match backend.read_snapshot() {
            Ok(snap) => DiagnosticResult {
                check_id: DiagnosticCheckId::SystemProxy,
                status: DiagnosticStatus::Passed,
                summary: format!(
                    "System proxy {} ({})",
                    if snap.enabled { "enabled" } else { "disabled" },
                    snap.server.as_deref().unwrap_or("none")
                ),
                technical_details: format!("backend={}; bypass={:?}", snap.backend, snap.bypass),
                suggested_actions: Vec::new(),
                related_settings_section: Some("connection".to_owned()),
                duration_ms: None,
            },
            Err(e) => DiagnosticResult {
                check_id: DiagnosticCheckId::SystemProxy,
                status: DiagnosticStatus::Warning,
                summary: format!("Unable to query system proxy: {e}"),
                technical_details: format!("backend={}", backend.backend_name()),
                suggested_actions: Vec::new(),
                related_settings_section: Some("connection".to_owned()),
                duration_ms: None,
            },
        }
    }

    fn check_routing_state(&self) -> DiagnosticResult {
        let mgr = RoutingManager::new(Arc::clone(&self.ctx.db));
        match mgr.list_rules_sorted() {
            Ok(rules) => {
                let enabled_count = rules.iter().filter(|r| r.enabled).count();
                for r in &rules {
                    if let Err(err) = crate::routing::validate_rule(r) {
                        return DiagnosticResult {
                            check_id: DiagnosticCheckId::RoutingState,
                            status: DiagnosticStatus::Failed,
                            summary: format!("Invalid routing rule '{}': {err}", r.name),
                            technical_details: format!("rule_id={}", r.id),
                            suggested_actions: vec![
                                "Fix or disable the invalid routing rule".to_owned(),
                            ],
                            related_settings_section: Some("routing_dns".to_owned()),
                            duration_ms: None,
                        };
                    }
                }
                DiagnosticResult {
                    check_id: DiagnosticCheckId::RoutingState,
                    status: DiagnosticStatus::Passed,
                    summary: format!(
                        "{} routing rule(s) validated ({enabled_count} enabled)",
                        rules.len()
                    ),
                    technical_details: format!("total={}; enabled={enabled_count}", rules.len()),
                    suggested_actions: Vec::new(),
                    related_settings_section: Some("routing_dns".to_owned()),
                    duration_ms: None,
                }
            }
            Err(e) => DiagnosticResult {
                check_id: DiagnosticCheckId::RoutingState,
                status: DiagnosticStatus::Failed,
                summary: format!("Failed reading routing rules: {e}"),
                technical_details: format!("error={e}"),
                suggested_actions: Vec::new(),
                related_settings_section: Some("routing_dns".to_owned()),
                duration_ms: None,
            },
        }
    }

    fn check_ip_family(&self, ipv6: bool) -> DiagnosticResult {
        let ifaces = list_network_interfaces();
        let mut addrs = Vec::new();
        for iface in &ifaces {
            for net in &iface.ip_networks {
                let ip_str = net.split('/').next().unwrap_or(net);
                if let Ok(ip) = ip_str.parse::<IpAddr>()
                    && !ip.is_loopback()
                    && ip.is_ipv6() == ipv6
                {
                    addrs.push(format!("{}: {net}", iface.name));
                }
            }
        }
        if ipv6 {
            let status = if addrs.is_empty() {
                if self.ctx.settings.ipv6_enabled {
                    DiagnosticStatus::Warning
                } else {
                    DiagnosticStatus::Passed
                }
            } else {
                DiagnosticStatus::Passed
            };
            DiagnosticResult {
                check_id: DiagnosticCheckId::Ipv6Connectivity,
                status,
                summary: format!(
                    "{} non-loopback IPv6 address(es); app IPv6 setting={}",
                    addrs.len(),
                    if self.ctx.settings.ipv6_enabled {
                        "on"
                    } else {
                        "off"
                    }
                ),
                technical_details: format!("ipv6_addrs={addrs:?}"),
                suggested_actions: if addrs.is_empty() && self.ctx.settings.ipv6_enabled {
                    vec!["Disable IPv6 routing in Settings if ISP lacks IPv6".to_owned()]
                } else {
                    Vec::new()
                },
                related_settings_section: Some("connection".to_owned()),
                duration_ms: None,
            }
        } else {
            DiagnosticResult {
                check_id: DiagnosticCheckId::Ipv4Connectivity,
                status: if addrs.is_empty() {
                    DiagnosticStatus::Warning
                } else {
                    DiagnosticStatus::Passed
                },
                summary: format!(
                    "{} active non-loopback IPv4 interface address(es)",
                    addrs.len()
                ),
                technical_details: format!("ipv4_addrs={addrs:?}"),
                suggested_actions: if addrs.is_empty() {
                    vec!["Check Ethernet / Wi-Fi DHCP lease".to_owned()]
                } else {
                    Vec::new()
                },
                related_settings_section: Some("connection".to_owned()),
                duration_ms: None,
            }
        }
    }

    fn check_adapter_conflicts(&self) -> DiagnosticResult {
        let ifaces = list_network_interfaces();
        let vpn_ifaces: Vec<String> = ifaces
            .iter()
            .filter(|i| {
                let n = i.name.to_ascii_lowercase();
                n.contains("wintun")
                    || n.contains("wireguard")
                    || n.contains("tailscale")
                    || n.contains("zerotier")
                    || n.contains("tap")
                    || n.starts_with("tun")
                    || n.starts_with("utun")
                    || n.starts_with("wg")
            })
            .map(|i| i.name.clone())
            .collect();

        let third_party = vpn_ifaces
            .iter()
            .filter(|n| !n.to_ascii_lowercase().contains("r3x"))
            .count();

        DiagnosticResult {
            check_id: DiagnosticCheckId::NetworkAdapterConflicts,
            status: if third_party > 0 {
                DiagnosticStatus::Warning
            } else {
                DiagnosticStatus::Passed
            },
            summary: if third_party > 0 {
                format!(
                    "Detected {third_party} external VPN/tunnel adapter(s): {}",
                    vpn_ifaces.join(", ")
                )
            } else {
                format!(
                    "No conflicting third-party VPN adapters ({} interfaces inspected)",
                    ifaces.len()
                )
            },
            technical_details: format!("vpn_adapters={vpn_ifaces:?}"),
            suggested_actions: if third_party > 0 {
                vec!["Ensure no other VPN client is modifying routes simultaneously".to_owned()]
            } else {
                Vec::new()
            },
            related_settings_section: Some("advanced".to_owned()),
            duration_ms: None,
        }
    }

    fn check_permissions(&self) -> DiagnosticResult {
        let tun = check_tun_capability();
        let store = create_default_secret_store();
        let status = if store.is_available() && (!tun.requires_elevation || tun.available) {
            DiagnosticStatus::Passed
        } else {
            DiagnosticStatus::Warning
        };
        DiagnosticResult {
            check_id: DiagnosticCheckId::RequiredPermissions,
            status,
            summary: format!(
                "SecretStore: {} ({}) | {}",
                store.backend_name(),
                if store.is_available() {
                    "ok"
                } else {
                    "unavailable"
                },
                tun.details
            ),
            technical_details: format!(
                "secret_store={}; available={}; tun_available={}; requires_elevation={}",
                store.backend_name(),
                store.is_available(),
                tun.available,
                tun.requires_elevation
            ),
            suggested_actions: if !store.is_available() {
                vec!["Enable platform credential manager / keyring service".to_owned()]
            } else {
                Vec::new()
            },
            related_settings_section: Some("privacy".to_owned()),
            duration_ms: None,
        }
    }

    fn check_local_ports(&self) -> DiagnosticResult {
        let mixed_ok = is_local_port_available(self.ctx.settings.mixed_port);
        let socks_ok = is_local_port_available(self.ctx.settings.socks_port);
        let http_ok = is_local_port_available(self.ctx.settings.http_port);
        let all_ok = mixed_ok && socks_ok && http_ok;
        DiagnosticResult {
            check_id: DiagnosticCheckId::LocalPortAvailability,
            status: if all_ok {
                DiagnosticStatus::Passed
            } else {
                DiagnosticStatus::Warning
            },
            summary: format!(
                "Ports mixed:{} ({}), socks:{} ({}), http:{} ({})",
                self.ctx.settings.mixed_port,
                if mixed_ok { "free" } else { "in use" },
                self.ctx.settings.socks_port,
                if socks_ok { "free" } else { "in use" },
                self.ctx.settings.http_port,
                if http_ok { "free" } else { "in use" },
            ),
            technical_details: format!(
                "mixed_ok={mixed_ok}; socks_ok={socks_ok}; http_ok={http_ok}"
            ),
            suggested_actions: if all_ok {
                Vec::new()
            } else {
                vec!["Change conflicting inbound ports in Settings -> Connection".to_owned()]
            },
            related_settings_section: Some("connection".to_owned()),
            duration_ms: None,
        }
    }
}

#[must_use]
pub fn export_redacted_report(report: &DiagnosticReport) -> String {
    let redacted = Redactor::redact_diagnostic_report(report);
    let raw = serde_json::to_string_pretty(&redacted).unwrap_or_else(|_| "{}".to_owned());
    Redactor::redact_str(&raw)
}
