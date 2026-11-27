use crate::adapter::CoreAdapter;
use r3x_domain::{
    ConnectionMode, CoreId, CorePreference, CpuArch, Platform, Profile, R3xError, SecurityConfig,
    SupportStatus,
};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct CoreSelectionResult {
    pub core_id: CoreId,
    pub support_status: SupportStatus,
    pub reason: String,
}

#[derive(Debug, Clone, Copy)]
pub struct CoreSelectionContext {
    pub subscription_preference: CorePreference,
    pub global_preference: CorePreference,
    pub platform: Platform,
    pub arch: CpuArch,
    pub mode: ConnectionMode,
}

pub struct CoreSelector;

impl CoreSelector {
    pub fn select(
        adapters: &[Arc<dyn CoreAdapter>],
        installed_cores: &HashSet<CoreId>,
        profile: &Profile,
        ctx: CoreSelectionContext,
    ) -> Result<CoreSelectionResult, R3xError> {
        let effective_pref = match profile.core_preference {
            CorePreference::Preferred(id) => Some(("profile override", id)),
            CorePreference::Auto => match ctx.subscription_preference {
                CorePreference::Preferred(id) => Some(("subscription override", id)),
                CorePreference::Auto => match ctx.global_preference {
                    CorePreference::Preferred(id) => Some(("global preference", id)),
                    CorePreference::Auto => None,
                },
            },
        };

        if let Some((source, preferred_id)) = effective_pref {
            let adapter = adapters
                .iter()
                .find(|a| a.id() == preferred_id)
                .ok_or_else(|| R3xError::CoreIncompatible {
                    core: preferred_id.to_string(),
                    reason: format!("requested by {source}, but adapter is not registered"),
                })?;

            Self::check_candidate(adapter.as_ref(), installed_cores, profile, ctx)?;
            let status = adapter.supports_profile(profile);
            return Ok(CoreSelectionResult {
                core_id: preferred_id,
                support_status: status,
                reason: format!("selected via {source} ({status:?})"),
            });
        }

        let mut ranked: Vec<(u8, SupportStatus, CoreId)> = Vec::new();
        for adapter in adapters {
            if Self::check_candidate(adapter.as_ref(), installed_cores, profile, ctx).is_ok() {
                let status = adapter.supports_profile(profile);
                let status_score = match status {
                    SupportStatus::Verified => 40,
                    SupportStatus::Supported => 30,
                    SupportStatus::Experimental => 20,
                    SupportStatus::Legacy => 10,
                    _ => 0,
                };
                let universal_bonus = if adapter.id().is_primary_universal() {
                    5
                } else {
                    0
                };
                ranked.push((status_score + universal_bonus, status, adapter.id()));
            }
        }

        ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.2.cmp(&b.2)));
        if let Some((_, status, core_id)) = ranked.first().copied() {
            Ok(CoreSelectionResult {
                core_id,
                support_status: status,
                reason: format!("auto-selected best compatible core ({status:?})"),
            })
        } else {
            Err(R3xError::CoreIncompatible {
                core: "auto".to_owned(),
                reason: format!(
                    "no installed compatible core supports {} over {} on {:?}/{:?} in {:?} mode",
                    profile.protocol.protocol_type.display_name(),
                    profile.transport.label(),
                    ctx.platform,
                    ctx.arch,
                    ctx.mode
                ),
            })
        }
    }

    fn check_candidate(
        adapter: &dyn CoreAdapter,
        installed_cores: &HashSet<CoreId>,
        profile: &Profile,
        ctx: CoreSelectionContext,
    ) -> Result<(), R3xError> {
        let id = adapter.id();
        if !installed_cores.contains(&id) {
            return Err(R3xError::CoreNotInstalled(id.to_string()));
        }
        if !adapter.is_platform_supported(ctx.platform, ctx.arch) {
            return Err(R3xError::CoreIncompatible {
                core: id.to_string(),
                reason: format!("unsupported on {:?}/{:?}", ctx.platform, ctx.arch),
            });
        }
        let caps = adapter.capabilities();
        match ctx.mode {
            ConnectionMode::Tun if !caps.supports_tun => {
                return Err(R3xError::CoreIncompatible {
                    core: id.to_string(),
                    reason: "does not support TUN mode".to_owned(),
                });
            }
            ConnectionMode::SystemProxy if !caps.supports_system_proxy => {
                return Err(R3xError::CoreIncompatible {
                    core: id.to_string(),
                    reason: "does not support System Proxy mode".to_owned(),
                });
            }
            ConnectionMode::Mixed if !(caps.supports_tun && caps.supports_system_proxy) => {
                return Err(R3xError::CoreIncompatible {
                    core: id.to_string(),
                    reason: "does not support Mixed mode".to_owned(),
                });
            }
            _ => {}
        }

        if matches!(profile.security, SecurityConfig::Reality(_)) && !caps.supports_reality {
            return Err(R3xError::CoreIncompatible {
                core: id.to_string(),
                reason: "does not support REALITY".to_owned(),
            });
        }
        if profile.flow.is_some() && !caps.supports_vision {
            return Err(R3xError::CoreIncompatible {
                core: id.to_string(),
                reason: "does not support XTLS Vision flow".to_owned(),
            });
        }
        let status = adapter.supports_profile(profile);
        if !status.is_runnable() {
            return Err(R3xError::CoreIncompatible {
                core: id.to_string(),
                reason: format!("profile support status is {status:?}"),
            });
        }
        adapter.validate_profile(profile)
    }
}
