pub mod mihomo;
pub mod sing_box;
pub mod xray;

pub use mihomo::MihomoAdapter;
pub use sing_box::SingBoxAdapter;
pub use xray::XrayAdapter;

use crate::manager::CoreManager;
use r3x_domain::CoreId;
use r3x_engine::CoreAdapter;
use std::sync::Arc;

#[must_use]
pub fn create_primary_adapters(core_manager: &CoreManager) -> Vec<Arc<dyn CoreAdapter>> {
    let installed = core_manager.discover_installed();

    let xray_bin = installed.get(&CoreId::Xray).map(|r| r.binary_path.clone());
    let sing_bin = installed
        .get(&CoreId::SingBox)
        .map(|r| r.binary_path.clone());
    let mihomo_bin = installed
        .get(&CoreId::Mihomo)
        .map(|r| r.binary_path.clone());

    vec![
        Arc::new(XrayAdapter::new(xray_bin)),
        Arc::new(SingBoxAdapter::new(sing_bin)),
        Arc::new(MihomoAdapter::new(mihomo_bin)),
    ]
}
