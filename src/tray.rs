use crate::{MainWindow, R3xAppState};
use r3x_domain::WindowState;
use r3x_storage::R3xDatabase;
use slint::{ComponentHandle, Global, LogicalSize};
use std::sync::Arc;
use tracing::warn;

/// Desktop tray & window lifecycle state coordinator.
///
/// Native OS notification-area icon creation (`tray-icon` + `libayatana-appindicator` on Linux)
/// is intentionally abstracted here so core desktop builds stay warning-free and compatible
/// with headless/Wayland CI environments while persisting `WindowState` cleanly.
pub struct DesktopTrayHandle {
    minimize_to_tray_enabled: bool,
}

impl DesktopTrayHandle {
    #[must_use]
    pub fn initialize(db: &Arc<R3xDatabase>) -> Self {
        let settings = db.load_settings().unwrap_or_default();
        Self {
            minimize_to_tray_enabled: settings.minimize_to_tray,
        }
    }

    #[must_use]
    pub fn is_minimize_to_tray(&self) -> bool {
        self.minimize_to_tray_enabled
    }
}

pub fn restore_window_state(ui: &MainWindow, win_state: &WindowState) {
    let w = (win_state.width as f32).clamp(360.0, 3840.0);
    let h = (win_state.height as f32).clamp(600.0, 2160.0);
    ui.window().set_size(LogicalSize::new(w, h));
    ui.window().set_maximized(win_state.maximized);
    R3xAppState::get(ui).set_drawer_collapsed(win_state.drawer_collapsed);
}

pub fn attach_window_close_persistence(ui: &MainWindow, db: &Arc<R3xDatabase>) {
    let ui_weak = ui.as_weak();
    let db = Arc::clone(db);
    ui.window().on_close_requested(move || {
        if let Some(w) = ui_weak.upgrade() {
            let scale = w.window().scale_factor().max(1.0);
            let phys = w.window().size();
            let logical_w = ((phys.width as f32) / scale).round().max(360.0) as u32;
            let logical_h = ((phys.height as f32) / scale).round().max(600.0) as u32;
            let collapsed = R3xAppState::get(&w).get_drawer_collapsed();
            let maximized = w.window().is_maximized();
            if let Ok(mut settings) = db.load_settings() {
                settings.window_state = WindowState {
                    width: logical_w,
                    height: logical_h,
                    x: None,
                    y: None,
                    maximized,
                    drawer_collapsed: collapsed,
                };
                if let Err(err) = db.save_settings(&settings) {
                    warn!(error = %err, "Failed persisting window geometry on close");
                }
            }
        }
        slint::CloseRequestResponse::HideWindow
    });
}
