pub(crate) mod common;
pub mod hysteria2;
pub mod mieru;
pub mod mihomo;
pub mod naive;
pub mod openvpn;
pub mod sing_box;
pub mod specialized;
pub mod wireguard;
pub mod xray;

pub use hysteria2::Hysteria2Adapter;
pub use mieru::MieruAdapter;
pub use mihomo::MihomoAdapter;
pub use naive::NaiveProxyAdapter;
pub use openvpn::OpenVpnAdapter;
pub use sing_box::SingBoxAdapter;
pub use specialized::{
    BrookAdapter, ExternalCliVpnAdapter, JuicityAdapter, ShadowsocksRustAdapter, TorAdapter,
    V2FlyAdapter,
};
pub use wireguard::{AmneziaWgAdapter, WireGuardAdapter};
pub use xray::XrayAdapter;

use crate::manager::CoreManager;
use r3x_domain::CoreId;
use r3x_engine::CoreAdapter;
use std::sync::Arc;

#[must_use]
pub fn create_primary_adapters(core_manager: &CoreManager) -> Vec<Arc<dyn CoreAdapter>> {
    let installed = core_manager.discover_installed();
    let bin = |id: CoreId| installed.get(&id).map(|r| r.binary_path.clone());
    vec![
        Arc::new(XrayAdapter::new(bin(CoreId::Xray))),
        Arc::new(SingBoxAdapter::new(bin(CoreId::SingBox))),
        Arc::new(MihomoAdapter::new(bin(CoreId::Mihomo))),
    ]
}

#[must_use]
pub fn create_all_adapters(core_manager: &CoreManager) -> Vec<Arc<dyn CoreAdapter>> {
    let installed = core_manager.discover_installed();
    let bin = |id: CoreId| installed.get(&id).map(|r| r.binary_path.clone());
    vec![
        Arc::new(XrayAdapter::new(bin(CoreId::Xray))),
        Arc::new(SingBoxAdapter::new(bin(CoreId::SingBox))),
        Arc::new(MihomoAdapter::new(bin(CoreId::Mihomo))),
        Arc::new(Hysteria2Adapter::new(bin(CoreId::Hysteria2))),
        Arc::new(WireGuardAdapter::wireguard(bin(CoreId::WireGuard))),
        Arc::new(AmneziaWgAdapter::amneziawg(bin(CoreId::AmneziaWg))),
        Arc::new(NaiveProxyAdapter::new(bin(CoreId::NaiveProxy))),
        Arc::new(MieruAdapter::new(bin(CoreId::Mieru))),
        Arc::new(OpenVpnAdapter::new(bin(CoreId::OpenVpn))),
        Arc::new(ShadowsocksRustAdapter::new(bin(CoreId::ShadowsocksRust))),
        Arc::new(V2FlyAdapter::new(bin(CoreId::V2Fly))),
        Arc::new(JuicityAdapter::new(bin(CoreId::Juicity))),
        Arc::new(BrookAdapter::new(bin(CoreId::Brook))),
        Arc::new(TorAdapter::new(bin(CoreId::Tor))),
        Arc::new(ExternalCliVpnAdapter::openconnect(bin(CoreId::OpenConnect))),
        Arc::new(ExternalCliVpnAdapter::ikev2(bin(CoreId::Ikev2))),
        Arc::new(ExternalCliVpnAdapter::sstp(bin(CoreId::Sstp))),
        Arc::new(ExternalCliVpnAdapter::softether(bin(CoreId::SoftEther))),
        Arc::new(ExternalCliVpnAdapter::openssh_tun(bin(CoreId::OpenSshTun))),
    ]
}
