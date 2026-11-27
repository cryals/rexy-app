use crate::profile::{ProtocolType, TransportConfig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoreId {
    Xray,
    SingBox,
    Mihomo,
    Hysteria2,
    #[serde(rename = "wireguard")]
    WireGuard,
    #[serde(rename = "amneziawg")]
    AmneziaWg,
    #[serde(rename = "naiveproxy")]
    NaiveProxy,
    Mieru,
    #[serde(rename = "openvpn")]
    OpenVpn,
    ShadowsocksRust,
    #[serde(rename = "v2fly")]
    V2Fly,
    Juicity,
    Brook,
    Tor,
    #[serde(rename = "openconnect")]
    OpenConnect,
    Ikev2,
    Sstp,
    #[serde(rename = "softether")]
    SoftEther,
    #[serde(rename = "openssh-tun")]
    OpenSshTun,
}

impl CoreId {
    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Xray => "Xray-core",
            Self::SingBox => "sing-box",
            Self::Mihomo => "Mihomo",
            Self::Hysteria2 => "Hysteria 2",
            Self::WireGuard => "WireGuard",
            Self::AmneziaWg => "AmneziaWG",
            Self::NaiveProxy => "NaiveProxy",
            Self::Mieru => "Mieru",
            Self::OpenVpn => "OpenVPN",
            Self::ShadowsocksRust => "shadowsocks-rust",
            Self::V2Fly => "V2Fly",
            Self::Juicity => "Juicity",
            Self::Brook => "Brook",
            Self::Tor => "Tor",
            Self::OpenConnect => "OpenConnect",
            Self::Ikev2 => "IKEv2/IPsec",
            Self::Sstp => "SSTP",
            Self::SoftEther => "SoftEther",
            Self::OpenSshTun => "OpenSSH TUN",
        }
    }

    #[must_use]
    pub fn is_primary_universal(self) -> bool {
        matches!(self, Self::Xray | Self::SingBox | Self::Mihomo)
    }
}

impl fmt::Display for CoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Linux,
    Android,
}

impl Platform {
    #[must_use]
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(target_os = "android")]
        {
            Self::Android
        }
        #[cfg(all(not(target_os = "windows"), not(target_os = "android")))]
        {
            Self::Linux
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuArch {
    X86_64,
    Aarch64,
    Armv7,
    X86,
}

impl CpuArch {
    #[must_use]
    pub fn current() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::X86_64
        }
        #[cfg(target_arch = "aarch64")]
        {
            Self::Aarch64
        }
        #[cfg(target_arch = "arm")]
        {
            Self::Armv7
        }
        #[cfg(target_arch = "x86")]
        {
            Self::X86
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "x86"
        )))]
        {
            Self::X86_64
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportStatus {
    Unsupported,
    Blocked,
    ImportOnly,
    Legacy,
    Experimental,
    Supported,
    Verified,
}

impl SupportStatus {
    #[must_use]
    pub fn is_runnable(self) -> bool {
        matches!(
            self,
            Self::Verified | Self::Supported | Self::Experimental | Self::Legacy
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreIntegrationType {
    ExternalBinary,
    EmbeddedAndroidLib,
    SystemService,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreCapabilities {
    pub protocols: Vec<ProtocolType>,
    pub transports: Vec<String>,
    pub supports_tls: bool,
    pub supports_reality: bool,
    pub supports_vision: bool,
    pub supports_udp: bool,
    pub supports_ipv6: bool,
    pub supports_tun: bool,
    pub supports_system_proxy: bool,
    pub supports_routing: bool,
    pub supports_stats: bool,
    pub supports_dns: bool,
}

impl CoreCapabilities {
    #[must_use]
    pub fn supports_transport(&self, transport: &TransportConfig) -> bool {
        let label = transport.label();
        self.transports
            .iter()
            .any(|t| t.eq_ignore_ascii_case(label))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreManifest {
    pub id: CoreId,
    pub name: String,
    pub version: String,
    pub release_source: String,
    pub license: String,
    pub supported_platforms: Vec<Platform>,
    pub supported_archs: Vec<CpuArch>,
    pub checksums_sha256: BTreeMap<String, String>,
    pub signature_verification: String,
    pub capabilities: CoreCapabilities,
    pub limitations: Vec<String>,
    pub integration_type: CoreIntegrationType,
    pub changelog_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CoreInstallState {
    NotInstalled,
    Installed {
        version: String,
        binary_path: String,
        sha256: String,
    },
    FailedVerification {
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "core", rename_all = "snake_case")]
pub enum CorePreference {
    #[default]
    Auto,
    Preferred(CoreId),
}
