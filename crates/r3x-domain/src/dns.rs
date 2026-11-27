use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    System,
    Custom,
    DoH,
    DoT,
    DoQ,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsLeakProtectionMode {
    Off,
    StrictTunnelOnly,
    FakeIp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResolver {
    pub tag: String,
    pub mode: DnsMode,
    pub address: String,
    pub bootstrap_ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsConfig {
    pub primary: DnsResolver,
    pub fallback: Option<DnsResolver>,
    pub direct_dns: Option<DnsResolver>,
    pub enable_ipv6: bool,
    pub leak_protection: DnsLeakProtectionMode,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            primary: DnsResolver {
                tag: "primary-doh".to_owned(),
                mode: DnsMode::DoH,
                address: "https://1.1.1.1/dns-query".to_owned(),
                bootstrap_ip: Some("1.1.1.1".to_owned()),
            },
            fallback: Some(DnsResolver {
                tag: "fallback-dot".to_owned(),
                mode: DnsMode::DoT,
                address: "tls://9.9.9.9".to_owned(),
                bootstrap_ip: Some("9.9.9.9".to_owned()),
            }),
            direct_dns: Some(DnsResolver {
                tag: "direct-system".to_owned(),
                mode: DnsMode::System,
                address: "system".to_owned(),
                bootstrap_ip: None,
            }),
            enable_ipv6: false,
            leak_protection: DnsLeakProtectionMode::StrictTunnelOnly,
        }
    }
}
