use crate::recovery::{clear_recovery_state, load_recovery_state, save_recovery_state};
use r3x_domain::R3xError;
use std::path::PathBuf;

/// Guarded kill-switch state manager that persists recovery markers first
/// so unexpected termination never locks the user out of networking permanently.
pub struct KillSwitchManager {
    cache_dir: PathBuf,
    active: bool,
}

impl KillSwitchManager {
    #[must_use]
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            active: false,
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn activate(&mut self) -> Result<(), R3xError> {
        let mut recovery = load_recovery_state(&self.cache_dir)?.unwrap_or_default();
        recovery.kill_switch_active = true;
        save_recovery_state(&self.cache_dir, &recovery)?;
        self.active = true;
        Ok(())
    }

    pub fn deactivate(&mut self) -> Result<(), R3xError> {
        self.active = false;
        if let Some(mut recovery) = load_recovery_state(&self.cache_dir)? {
            recovery.kill_switch_active = false;
            if !recovery.has_active_changes() {
                clear_recovery_state(&self.cache_dir)?;
            } else {
                save_recovery_state(&self.cache_dir, &recovery)?;
            }
        }
        Ok(())
    }
}
