use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RedactedSecret(String);

impl RedactedSecret {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProfileSource {
    Manual,
    ImportedUri,
    ImportedFile { filename: String },
    QrCode,
    Subscription { subscription_id: Uuid },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolType {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Shadowsocks2022,
    Hysteria2,
    Hysteria1,
    TuicV5,
    TuicV4,
    AnyTls,
    ShadowTlsV3,
    ShadowTlsV1V2,
    NaiveProxy,
    Mieru,
    Snell,
    Juicity,
    Http,
    Https,
    Socks5,
    Socks4,
    Socks4a,
    Ssh,
    ShadowsocksR,
    Brook,
    Masque,
    TrustTunnel,
    Sudoku,
    MtProto,
    WireGuard,
    AmneziaWg,
    OpenVpnUdp,
    OpenVpnTcp,
    OpenVpnCloak,
    Ikev2Ipsec,
    Ikev1Ipsec,
    L2tpIpsec,
    Sstp,
    OpenConnect,
    SoftEther,
    OpenSshTun,
    Tailscale,
    Headscale,
    ZeroTier,
    Nebula,
}

impl ProtocolType {
    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Vless => "VLESS",
            Self::Vmess => "VMess",
            Self::Trojan => "Trojan",
            Self::Shadowsocks => "Shadowsocks",
            Self::Shadowsocks2022 => "Shadowsocks 2022",
            Self::Hysteria2 => "Hysteria 2",
            Self::Hysteria1 => "Hysteria 1",
            Self::TuicV5 => "TUIC v5",
            Self::TuicV4 => "TUIC v4",
            Self::AnyTls => "AnyTLS",
            Self::ShadowTlsV3 => "ShadowTLS v3",
            Self::ShadowTlsV1V2 => "ShadowTLS v1/v2",
            Self::NaiveProxy => "NaiveProxy",
            Self::Mieru => "Mieru",
            Self::Snell => "Snell",
            Self::Juicity => "Juicity",
            Self::Http => "HTTP Proxy",
            Self::Https => "HTTPS Proxy",
            Self::Socks5 => "SOCKS5",
            Self::Socks4 => "SOCKS4",
            Self::Socks4a => "SOCKS4a",
            Self::Ssh => "SSH Forwarding",
            Self::ShadowsocksR => "ShadowsocksR",
            Self::Brook => "Brook",
            Self::Masque => "MASQUE",
            Self::TrustTunnel => "TrustTunnel",
            Self::Sudoku => "Sudoku",
            Self::MtProto => "MTProto (Telegram)",
            Self::WireGuard => "WireGuard",
            Self::AmneziaWg => "AmneziaWG",
            Self::OpenVpnUdp => "OpenVPN UDP",
            Self::OpenVpnTcp => "OpenVPN TCP",
            Self::OpenVpnCloak => "OpenVPN + Cloak",
            Self::Ikev2Ipsec => "IKEv2/IPsec",
            Self::Ikev1Ipsec => "IKEv1/IPsec",
            Self::L2tpIpsec => "L2TP/IPsec",
            Self::Sstp => "SSTP",
            Self::OpenConnect => "OpenConnect",
            Self::SoftEther => "SoftEther VPN",
            Self::OpenSshTun => "OpenSSH TUN",
            Self::Tailscale => "Tailscale",
            Self::Headscale => "Headscale",
            Self::ZeroTier => "ZeroTier",
            Self::Nebula => "Nebula",
        }
    }

    #[must_use]
    pub fn is_vpn_tunnel(self) -> bool {
        matches!(
            self,
            Self::WireGuard
                | Self::AmneziaWg
                | Self::OpenVpnUdp
                | Self::OpenVpnTcp
                | Self::OpenVpnCloak
                | Self::Ikev2Ipsec
                | Self::Ikev1Ipsec
                | Self::L2tpIpsec
                | Self::Sstp
                | Self::OpenConnect
                | Self::SoftEther
                | Self::OpenSshTun
                | Self::Tailscale
                | Self::Headscale
                | Self::ZeroTier
                | Self::Nebula
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolConfig {
    pub protocol_type: ProtocolType,
    pub cipher: Option<String>,
    pub alter_id: Option<u16>,
    pub mtu: Option<u16>,
    pub protocol_params: BTreeMap<String, String>,
}

impl ProtocolConfig {
    #[must_use]
    pub fn simple(protocol_type: ProtocolType) -> Self {
        Self {
            protocol_type,
            cipher: None,
            alter_id: None,
            mtu: None,
            protocol_params: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransportConfig {
    RawTcp {
        header_type: Option<String>,
    },
    WebSocket {
        path: String,
        host: Option<String>,
        max_early_data: Option<u32>,
        early_data_header_name: Option<String>,
    },
    Grpc {
        service_name: String,
        multi_mode: bool,
    },
    Xhttp {
        path: String,
        host: Option<String>,
        mode: Option<String>,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
    },
    Mkcp {
        header_type: Option<String>,
        seed: Option<String>,
    },
    Quic {
        security: Option<String>,
        header_type: Option<String>,
    },
    Http2 {
        path: String,
        hosts: Vec<String>,
    },
    Http3,
    UdpRaw,
}

impl TransportConfig {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::RawTcp { .. } => "TCP",
            Self::WebSocket { .. } => "WebSocket",
            Self::Grpc { .. } => "gRPC",
            Self::Xhttp { .. } => "XHTTP",
            Self::HttpUpgrade { .. } => "HTTPUpgrade",
            Self::Mkcp { .. } => "mKCP",
            Self::Quic { .. } => "QUIC",
            Self::Http2 { .. } => "HTTP/2",
            Self::Http3 => "HTTP/3",
            Self::UdpRaw => "UDP",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsSettings {
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    pub ech_config: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealitySettings {
    pub sni: String,
    pub public_key: String,
    pub short_id: String,
    pub spider_x: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmneziaWgObfuscation {
    pub version: String,
    pub jc: u16,
    pub jmin: u16,
    pub jmax: u16,
    pub s1: u16,
    pub s2: u16,
    pub s3: Option<u16>,
    pub s4: Option<u16>,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
    pub special_junk: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "layer", rename_all = "snake_case")]
pub enum SecurityConfig {
    None,
    Tls(TlsSettings),
    Reality(RealitySettings),
    VlessEncryption {
        encryption: String,
        decryption: Option<String>,
    },
    NoiseWg,
    AmneziaWg(AmneziaWgObfuscation),
}

impl SecurityConfig {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Tls(_) => "TLS",
            Self::Reality(_) => "REALITY",
            Self::VlessEncryption { .. } => "VLESS Encryption",
            Self::NoiseWg => "Noise IK",
            Self::AmneziaWg(_) => "AmneziaWG",
        }
    }

    #[must_use]
    pub fn allows_insecure_tls(&self) -> bool {
        matches!(self, Self::Tls(t) if t.allow_insecure)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlowType {
    XtlsRprxVision,
    XtlsRprxVisionUdp443,
}

impl FlowType {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::XtlsRprxVision => "xtls-rprx-vision",
            Self::XtlsRprxVisionUdp443 => "xtls-rprx-vision-udp443",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub local_addresses: Vec<String>,
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthConfig {
    pub username: Option<String>,
    pub secret_ref: Option<String>,
    pub inline_secret: Option<RedactedSecret>,
    pub secondary_secret: Option<RedactedSecret>,
    pub public_key: Option<String>,
    pub preshared_secret: Option<RedactedSecret>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileOptions {
    pub mux_enabled: bool,
    pub mux_concurrency: Option<u16>,
    pub xudp_enabled: bool,
    pub udp_over_tcp: bool,
    pub packet_encoding: Option<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub congestion_control: Option<String>,
    pub raw_extra: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: Uuid,
    pub name: String,
    pub custom_name: Option<String>,
    pub source: ProfileSource,
    pub protocol: ProtocolConfig,
    pub transport: TransportConfig,
    pub security: SecurityConfig,
    pub flow: Option<FlowType>,
    pub endpoint: Endpoint,
    pub auth: AuthConfig,
    pub options: ProfileOptions,
    pub core_preference: crate::core::CorePreference,
    pub favorite: bool,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub latency_ms: Option<u32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Profile {
    #[must_use]
    pub fn effective_name(&self) -> &str {
        self.custom_name.as_deref().unwrap_or(&self.name)
    }

    #[must_use]
    pub fn dedup_fingerprint(&self) -> String {
        format!(
            "{:?}:{}:{}:{}",
            self.protocol.protocol_type,
            self.endpoint.host.to_ascii_lowercase(),
            self.endpoint.port,
            self.transport.label()
        )
    }
}
