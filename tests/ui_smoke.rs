use r3x_app_lib::{R3xAppState, R3xPalette, build_window, init_services};
use r3x_storage::AppPaths;
use slint::Global;
use tempfile::tempdir;

#[test]
fn ui_shell_instantiates_switches_themes_and_navigates() {
    i_slint_backend_testing::init_no_event_loop();

    let dir = tempdir().expect("tempdir");
    let paths = AppPaths::from_root(dir.path());
    let bootstrap = init_services(&paths).expect("init services");
    let ui = build_window(&bootstrap).expect("build main window");

    let state = R3xAppState::get(&ui);
    assert_eq!(state.get_current_nav(), 0);

    // Navigate to Settings (7)
    state.invoke_nav_selected(7);
    assert_eq!(state.get_current_nav(), 7);

    // Switch to Light theme (1) -> verify surface lightens
    state.invoke_theme_selected(1);
    assert!(!R3xPalette::get(&ui).get_is_dark());

    // Switch to AMOLED (3) -> verify dark + amoled
    state.invoke_theme_selected(3);
    assert!(R3xPalette::get(&ui).get_is_dark());
    assert!(R3xPalette::get(&ui).get_is_amoled());

    // Verify theme persisted to SQLite
    let saved = bootstrap.db.load_settings().expect("load settings");
    assert_eq!(saved.theme_mode, r3x_domain::ThemeMode::Amoled);
}
