use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunConfig {
    pub interface_name: String,
    pub ipv4_cidr: String,
    pub ipv6_cidr: Option<String>,
    pub mtu: u16,
    pub strict_route: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            interface_name: "r3x-tun0".to_owned(),
            ipv4_cidr: "172.19.0.1/30".to_owned(),
            ipv6_cidr: Some("fdfe:dcba:9876::1/126".to_owned()),
            mtu: 9000,
            strict_route: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunCapabilityReport {
    pub available: bool,
    pub requires_elevation: bool,
    pub details: String,
}

#[must_use]
pub fn check_tun_capability() -> TunCapabilityReport {
    #[cfg(target_os = "linux")]
    {
        let tun_dev = std::path::Path::new("/dev/net/tun").exists();
        if !tun_dev {
            return TunCapabilityReport {
                available: false,
                requires_elevation: true,
                details: "/dev/net/tun device missing".to_owned(),
            };
        }
        let is_root = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .map(|l| l.split_whitespace().nth(1) == Some("0"))
            })
            .unwrap_or(false);
        TunCapabilityReport {
            available: is_root,
            requires_elevation: !is_root,
            details: if is_root {
                "TUN device accessible with root privileges".to_owned()
            } else {
                "/dev/net/tun present; requires CAP_NET_ADMIN or r3x-daemon service".to_owned()
            },
        }
    }
    #[cfg(target_os = "windows")]
    {
        TunCapabilityReport {
            available: true,
            requires_elevation: true,
            details: "Windows TUN requires Wintun + elevated R3X daemon or administrator prompt"
                .to_owned(),
        }
    }
    #[cfg(target_os = "android")]
    {
        TunCapabilityReport {
            available: true,
            requires_elevation: false,
            details: "Android TUN uses VpnService user permission".to_owned(),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
    {
        TunCapabilityReport {
            available: false,
            requires_elevation: true,
            details: "TUN capability check unavailable on this OS".to_owned(),
        }
    }
}
