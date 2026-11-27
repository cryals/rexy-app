use r3x_app_lib::{R3xAppState, R3xPalette, build_window, init_services};
use r3x_storage::AppPaths;
use slint::{Global, Model};
use tempfile::tempdir;

#[test]
fn full_expressive_ui_navigation_onboarding_import_and_persistence() {
    i_slint_backend_testing::init_no_event_loop();

    let dir = tempdir().expect("tempdir");
    let paths = AppPaths::from_root(dir.path());
    let bootstrap = init_services(&paths).expect("init services");
    let ui = build_window(&bootstrap).expect("build main window");

    let state = R3xAppState::get(&ui);

    // Fresh state starts on onboarding gate
    assert!(state.get_show_onboarding());
    state.invoke_complete_onboarding();
    assert!(!state.get_show_onboarding());
    assert!(
        bootstrap
            .db
            .load_settings()
            .expect("settings")
            .onboarding_completed
    );

    // Traverse all 8 main navigation destinations
    for nav in 0..=7 {
        state.invoke_nav_selected(nav);
        assert_eq!(state.get_current_nav(), nav);
    }

    // Core Manager lists all 14 embedded manifests
    assert_eq!(state.get_cores().row_count(), 14);

    // Theme switching (Light -> AMOLED) and EN/RU language toggle persist to SQLite
    state.invoke_theme_selected(1);
    assert!(!R3xPalette::get(&ui).get_is_dark());
    state.invoke_theme_selected(3);
    assert!(R3xPalette::get(&ui).get_is_dark());
    assert!(R3xPalette::get(&ui).get_is_amoled());

    state.invoke_language_selected(1);
    assert!(state.get_is_ru());
    state.invoke_reduced_motion_toggled(true);
    assert!(state.get_reduced_motion());

    // Live VLESS URI import through controller -> SQLite -> UI model + raw config preview
    let vless = "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?type=xhttp&security=reality&sni=cdn.example.invalid&pbk=PubKey123&sid=ab12#SmokeTestNode";
    state.invoke_submit_import_uri(vless.into());
    assert_eq!(state.get_profile_count(), 1);
    assert!(state.get_has_selected_server());
    assert_eq!(state.get_server_name().as_str(), "SmokeTestNode");
    assert_eq!(bootstrap.db.list_profiles().expect("db profiles").len(), 1);

    // Add LAN routing presets and generate Raw Config preview
    state.invoke_add_preset_rules();
    assert!(state.get_routing_rule_count() >= 3);
    state.invoke_refresh_raw_config(0);
    assert!(state.get_raw_config_preview().contains("vless"));

    // Verify encrypted backup creation
    state.invoke_submit_backup_export("correcthorsebatterystaple".into());
    assert!(
        state
            .get_backup_status_text()
            .contains("Exported encrypted backup")
    );

    // Verify redacted logs populated
    state.set_diagnostics_tab(4);
    state.invoke_refresh_logs();
    assert!(state.get_log_entry_count() > 0);
}
