use r3x_domain::{CoreId, CoreManifest, R3xError};

const EMBEDDED_MANIFESTS: &[&str] = &[
    include_str!("../../../resources/core-manifests/xray.json"),
    include_str!("../../../resources/core-manifests/sing-box.json"),
    include_str!("../../../resources/core-manifests/mihomo.json"),
    include_str!("../../../resources/core-manifests/hysteria2.json"),
    include_str!("../../../resources/core-manifests/wireguard.json"),
    include_str!("../../../resources/core-manifests/amneziawg.json"),
    include_str!("../../../resources/core-manifests/naiveproxy.json"),
    include_str!("../../../resources/core-manifests/mieru.json"),
    include_str!("../../../resources/core-manifests/openvpn.json"),
    include_str!("../../../resources/core-manifests/shadowsocks-rust.json"),
    include_str!("../../../resources/core-manifests/v2fly.json"),
    include_str!("../../../resources/core-manifests/juicity.json"),
    include_str!("../../../resources/core-manifests/brook.json"),
    include_str!("../../../resources/core-manifests/tor.json"),
];

pub fn default_core_manifests() -> Result<Vec<CoreManifest>, R3xError> {
    let mut manifests = Vec::with_capacity(EMBEDDED_MANIFESTS.len());
    for raw in EMBEDDED_MANIFESTS {
        let parsed: CoreManifest = serde_json::from_str(raw)
            .map_err(|e| R3xError::Storage(format!("invalid embedded core manifest JSON: {e}")))?;
        manifests.push(parsed);
    }
    Ok(manifests)
}

#[must_use]
pub fn find_manifest(id: CoreId) -> Option<CoreManifest> {
    default_core_manifests()
        .ok()
        .and_then(|list| list.into_iter().find(|m| m.id == id))
}
