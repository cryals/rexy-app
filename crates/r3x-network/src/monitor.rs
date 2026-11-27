use r3x_domain::R3xError;
use serde::{Deserialize, Serialize};
use std::net::TcpListener;
use sysinfo::Networks;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub mac_address: String,
    pub total_received_bytes: u64,
    pub total_transmitted_bytes: u64,
    pub ip_networks: Vec<String>,
}

#[must_use]
pub fn is_local_port_available(port: u16) -> bool {
    if port == 0 {
        return false;
    }
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

pub fn find_free_local_port(preferred: u16) -> Result<u16, R3xError> {
    if is_local_port_available(preferred) {
        return Ok(preferred);
    }
    let ephemeral = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| R3xError::Network(format!("failed finding free local port: {e}")))?;
    let port = ephemeral
        .local_addr()
        .map_err(|e| R3xError::Network(format!("failed reading ephemeral port: {e}")))?
        .port();
    Ok(port)
}

#[must_use]
pub fn list_network_interfaces() -> Vec<NetworkInterfaceInfo> {
    let Ok(networks) = Networks::new_with_refreshed_list() else {
        return Vec::new();
    };
    networks
        .iter()
        .map(|(name, data)| NetworkInterfaceInfo {
            name: name.to_string_lossy().into_owned(),
            mac_address: data.mac_address().to_string(),
            total_received_bytes: data.total_received(),
            total_transmitted_bytes: data.total_transmitted(),
            ip_networks: data.ip_networks().iter().map(ToString::to_string).collect(),
        })
        .collect()
}

/// Inspect active OS DNS nameservers using platform native configuration sources.
#[must_use]
pub fn inspect_os_dns_servers() -> Vec<String> {
    #[cfg_attr(
        not(any(target_os = "windows", target_os = "linux")),
        allow(unused_mut)
    )]
    let mut servers = Vec::new();
    #[cfg(target_os = "windows")]
    {
        use winreg::RegKey;
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        for sub in [
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces",
        ] {
            if let Ok(root) = hklm.open_subkey_with_flags(sub, KEY_READ) {
                for iface_name in root.enum_keys().flatten() {
                    if let Ok(iface) = root.open_subkey_with_flags(&iface_name, KEY_READ) {
                        for val_name in ["NameServer", "DhcpNameServer"] {
                            if let Ok(raw) = iface.get_value::<String, _>(val_name) {
                                for token in raw.split([',', ' ', ';']) {
                                    let trimmed = token.trim();
                                    if !trimmed.is_empty() && !servers.iter().any(|s| s == trimmed)
                                    {
                                        servers.push(trimmed.to_owned());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in contents.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("nameserver") {
                    let addr = rest.trim();
                    if !addr.is_empty() && !servers.iter().any(|s| s == addr) {
                        servers.push(addr.to_owned());
                    }
                }
            }
        }
    }
    servers
}
