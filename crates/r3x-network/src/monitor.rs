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
        })
        .collect()
}
