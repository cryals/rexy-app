pub mod adapters;
pub mod manager;
pub mod manifests;
pub mod supervisor;

pub use adapters::{
    AmneziaWgAdapter, BrookAdapter, ExternalCliVpnAdapter, Hysteria2Adapter, JuicityAdapter,
    MieruAdapter, MihomoAdapter, NaiveProxyAdapter, OpenVpnAdapter, ShadowsocksRustAdapter,
    SingBoxAdapter, TorAdapter, V2FlyAdapter, WireGuardAdapter, XrayAdapter, create_all_adapters,
    create_primary_adapters,
};
pub use manager::{ActiveCoreRecord, CoreManager};
pub use manifests::{default_core_manifests, find_manifest};
pub use supervisor::{SupervisedProcess, probe_tcp_ready, read_process_metrics};
