pub mod kill_switch;
pub mod monitor;
pub mod proxy;
pub mod recovery;
pub mod tun;

pub use kill_switch::KillSwitchManager;
pub use monitor::{
    NetworkInterfaceInfo, find_free_local_port, inspect_os_dns_servers, is_local_port_available,
    list_network_interfaces,
};
pub use proxy::{
    SystemProxyBackend, SystemProxyManager, SystemProxySnapshot, create_platform_proxy_backend,
};
pub use recovery::{NetworkRecoveryState, RecoveryReport, recover_network_state};
pub use tun::{TunConfig, check_tun_capability};
