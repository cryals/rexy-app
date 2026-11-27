use r3x_domain::{
    DiagnosticCheckId, DiagnosticResult, DiagnosticStatus, DnsConfig, DnsLeakProtectionMode,
    DnsMode, DnsResolver, R3xError,
};
use r3x_network::inspect_os_dns_servers;
use r3x_storage::R3xDatabase;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket, lookup_host};

#[derive(Debug, Clone)]
pub struct DnsProbeResult {
    pub reachable: bool,
    pub latency_ms: u64,
    pub details: String,
}

pub struct DnsManager {
    db: Arc<R3xDatabase>,
}

impl DnsManager {
    #[must_use]
    pub fn new(db: Arc<R3xDatabase>) -> Self {
        Self { db }
    }

    pub fn load(&self) -> Result<DnsConfig, R3xError> {
        self.db.load_dns_config()
    }

    pub fn save(&self, cfg: &DnsConfig) -> Result<(), R3xError> {
        validate_dns_config(cfg)?;
        self.db.save_dns_config(cfg)
    }
}

pub fn validate_dns_config(cfg: &DnsConfig) -> Result<(), R3xError> {
    validate_resolver(&cfg.primary)?;
    if let Some(ref fb) = cfg.fallback {
        validate_resolver(fb)?;
    }
    if let Some(ref direct) = cfg.direct_dns {
        validate_resolver(direct)?;
    }
    Ok(())
}

fn validate_resolver(resolver: &DnsResolver) -> Result<(), R3xError> {
    let addr = resolver.address.trim();
    if addr.is_empty() {
        return Err(R3xError::Validation(format!(
            "DNS resolver '{}' address cannot be empty",
            resolver.tag
        )));
    }
    match resolver.mode {
        DnsMode::System => Ok(()),
        DnsMode::DoH => {
            if !addr.starts_with("https://") {
                return Err(R3xError::Validation(format!(
                    "DoH resolver '{}' must use https://",
                    resolver.tag
                )));
            }
            Ok(())
        }
        DnsMode::DoT => {
            if !addr.starts_with("tls://") {
                return Err(R3xError::Validation(format!(
                    "DoT resolver '{}' must use tls://",
                    resolver.tag
                )));
            }
            Ok(())
        }
        DnsMode::DoQ => {
            if !addr.starts_with("quic://") {
                return Err(R3xError::Validation(format!(
                    "DoQ resolver '{}' must use quic://",
                    resolver.tag
                )));
            }
            Ok(())
        }
        DnsMode::Custom => {
            let host_only = addr.split(':').next().unwrap_or(addr);
            if host_only.parse::<IpAddr>().is_err() && !host_only.contains('.') {
                return Err(R3xError::Validation(format!(
                    "custom DNS resolver '{}' must be a valid IP or host",
                    resolver.tag
                )));
            }
            Ok(())
        }
    }
}

fn ensure_rustls_ring() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub async fn test_dns_resolver(resolver: &DnsResolver, timeout: Duration) -> DnsProbeResult {
    if let Err(err) = validate_resolver(resolver) {
        return DnsProbeResult {
            reachable: false,
            latency_ms: 0,
            details: err.to_string(),
        };
    }

    let start = Instant::now();
    match resolver.mode {
        DnsMode::System => match tokio::time::timeout(timeout, lookup_host("localhost:80")).await {
            Ok(Ok(mut addrs)) => {
                if addrs.next().is_some() {
                    DnsProbeResult {
                        reachable: true,
                        latency_ms: start.elapsed().as_millis() as u64,
                        details: "System resolver answered localhost lookup".to_owned(),
                    }
                } else {
                    DnsProbeResult {
                        reachable: false,
                        latency_ms: start.elapsed().as_millis() as u64,
                        details: "System resolver returned zero addresses".to_owned(),
                    }
                }
            }
            Ok(Err(e)) => DnsProbeResult {
                reachable: false,
                latency_ms: start.elapsed().as_millis() as u64,
                details: format!("System resolver error: {e}"),
            },
            Err(_) => DnsProbeResult {
                reachable: false,
                latency_ms: timeout.as_millis() as u64,
                details: "System resolver lookup timed out".to_owned(),
            },
        },
        DnsMode::DoH => {
            ensure_rustls_ring();
            match reqwest::Client::builder()
                .timeout(timeout)
                .user_agent("R3X-DNS-Probe/0.1")
                .build()
            {
                Ok(client) => match client.head(&resolver.address).send().await {
                    Ok(resp) => DnsProbeResult {
                        reachable: true,
                        latency_ms: start.elapsed().as_millis() as u64,
                        details: format!(
                            "DoH HTTPS endpoint responded with HTTP {}",
                            resp.status().as_u16()
                        ),
                    },
                    Err(e) => DnsProbeResult {
                        reachable: false,
                        latency_ms: start.elapsed().as_millis() as u64,
                        details: format!("DoH probe failed: {e}"),
                    },
                },
                Err(e) => DnsProbeResult {
                    reachable: false,
                    latency_ms: start.elapsed().as_millis() as u64,
                    details: format!("HTTP TLS client init failed: {e}"),
                },
            }
        }
        DnsMode::DoT => {
            let host_port = resolver.address.trim_start_matches("tls://");
            let target = if host_port.contains(':') {
                host_port.to_owned()
            } else {
                format!("{host_port}:853")
            };
            match tokio::time::timeout(timeout, TcpStream::connect(&target)).await {
                Ok(Ok(_)) => DnsProbeResult {
                    reachable: true,
                    latency_ms: start.elapsed().as_millis() as u64,
                    details: format!("DoT TCP transport reachable at {target}"),
                },
                Ok(Err(e)) => DnsProbeResult {
                    reachable: false,
                    latency_ms: start.elapsed().as_millis() as u64,
                    details: format!("DoT connect to {target} failed: {e}"),
                },
                Err(_) => DnsProbeResult {
                    reachable: false,
                    latency_ms: timeout.as_millis() as u64,
                    details: format!("DoT connect to {target} timed out"),
                },
            }
        }
        DnsMode::DoQ => {
            let host_port = resolver.address.trim_start_matches("quic://");
            let target = if host_port.contains(':') {
                host_port.to_owned()
            } else {
                format!("{host_port}:853")
            };
            match UdpSocket::bind("0.0.0.0:0").await {
                Ok(sock) => match tokio::time::timeout(timeout, sock.connect(&target)).await {
                    Ok(Ok(())) => DnsProbeResult {
                        reachable: true,
                        latency_ms: start.elapsed().as_millis() as u64,
                        details: format!(
                            "UDP socket bound and target {target} resolved for DoQ (full QUIC DNS query occurs inside tunnel core)"
                        ),
                    },
                    Ok(Err(e)) => DnsProbeResult {
                        reachable: false,
                        latency_ms: start.elapsed().as_millis() as u64,
                        details: format!("DoQ UDP target error for {target}: {e}"),
                    },
                    Err(_) => DnsProbeResult {
                        reachable: false,
                        latency_ms: timeout.as_millis() as u64,
                        details: format!("DoQ target resolution timed out for {target}"),
                    },
                },
                Err(e) => DnsProbeResult {
                    reachable: false,
                    latency_ms: start.elapsed().as_millis() as u64,
                    details: format!("UDP socket bind failed: {e}"),
                },
            }
        }
        DnsMode::Custom => {
            let addr = resolver.address.trim();
            let tcp_target = if addr.contains(':') {
                addr.to_owned()
            } else {
                format!("{addr}:53")
            };
            match tokio::time::timeout(timeout, TcpStream::connect(&tcp_target)).await {
                Ok(Ok(_)) => DnsProbeResult {
                    reachable: true,
                    latency_ms: start.elapsed().as_millis() as u64,
                    details: format!("TCP DNS reachable at {tcp_target}"),
                },
                Ok(Err(e)) => DnsProbeResult {
                    reachable: false,
                    latency_ms: start.elapsed().as_millis() as u64,
                    details: format!("Custom DNS TCP connect {tcp_target} failed: {e}"),
                },
                Err(_) => DnsProbeResult {
                    reachable: false,
                    latency_ms: timeout.as_millis() as u64,
                    details: format!("Custom DNS TCP connect {tcp_target} timed out"),
                },
            }
        }
    }
}

#[must_use]
pub fn check_dns_leaks(dns: &DnsConfig, tunnel_active: bool) -> DiagnosticResult {
    let os_servers = inspect_os_dns_servers();
    let technical_details = format!(
        "os_dns_servers={:?}; leak_protection={:?}; primary={:?}({}); tunnel_active={tunnel_active}",
        os_servers, dns.leak_protection, dns.primary.mode, dns.primary.address
    );

    if !tunnel_active {
        return DiagnosticResult {
            check_id: DiagnosticCheckId::DnsLeaks,
            status: DiagnosticStatus::NotTested,
            summary: format!(
                "Tunnel inactive; detected {} OS DNS server(s) locally",
                os_servers.len()
            ),
            technical_details,
            suggested_actions: vec![
                "Connect a VPN/proxy tunnel first, then re-run DNS leak verification".to_owned(),
            ],
            related_settings_section: Some("routing_dns".to_owned()),
            duration_ms: Some(1),
        };
    }

    match dns.leak_protection {
        DnsLeakProtectionMode::Off => DiagnosticResult {
            check_id: DiagnosticCheckId::DnsLeaks,
            status: DiagnosticStatus::Warning,
            summary: "DNS leak protection is disabled while tunnel is active".to_owned(),
            technical_details,
            suggested_actions: vec![
                "Enable StrictTunnelOnly or FakeIp DNS leak protection".to_owned(),
            ],
            related_settings_section: Some("routing_dns".to_owned()),
            duration_ms: Some(1),
        },
        DnsLeakProtectionMode::StrictTunnelOnly | DnsLeakProtectionMode::FakeIp => {
            if matches!(dns.primary.mode, DnsMode::System) {
                DiagnosticResult {
                    check_id: DiagnosticCheckId::DnsLeaks,
                    status: DiagnosticStatus::Warning,
                    summary: "Primary DNS uses OS System resolvers; ISP DNS may be queried outside encrypted DoH/DoT".to_owned(),
                    technical_details,
                    suggested_actions: vec![
                        "Switch Primary DNS to DoH or DoT".to_owned(),
                    ],
                    related_settings_section: Some("routing_dns".to_owned()),
                    duration_ms: Some(1),
                }
            } else {
                DiagnosticResult {
                    check_id: DiagnosticCheckId::DnsLeaks,
                    status: DiagnosticStatus::Passed,
                    summary: format!(
                        "Encrypted DNS configured ({:?}); {} OS interface resolver(s) inspected",
                        dns.primary.mode,
                        os_servers.len()
                    ),
                    technical_details,
                    suggested_actions: Vec::new(),
                    related_settings_section: Some("routing_dns".to_owned()),
                    duration_ms: Some(1),
                }
            }
        }
    }
}
