use r3x_cores::{CoreManager, create_primary_adapters};
use r3x_domain::{Language, LogCategory, LogLevel, ThemeMode};
use r3x_engine::{EngineConfig, LogHub, R3xEngine};
use r3x_storage::{AppPaths, R3xDatabase};
use std::sync::Arc;
use tracing::{info, warn};

slint::include_modules!();

pub struct AppBootstrap {
    pub db: Arc<R3xDatabase>,
    pub logs: Arc<LogHub>,
    pub engine: Arc<R3xEngine>,
}

pub fn init_services(paths: &AppPaths) -> Result<AppBootstrap, r3x_domain::R3xError> {
    paths.ensure_all_dirs()?;
    let logs = Arc::new(LogHub::new(Some(paths.logs_dir.clone())));

    let db_outcome = R3xDatabase::open_with_recovery(&paths.db_path)?;
    if let Some(quarantined) = db_outcome.quarantined_corrupt_path {
        let msg = format!(
            "Recovered from corrupt database; previous file quarantined at {}",
            quarantined.display()
        );
        warn!("{msg}");
        logs.record(LogCategory::Application, LogLevel::Warn, "r3x-storage", msg);
    }

    let db = Arc::new(db_outcome.db);
    let settings = db.load_settings()?;
    let engine_cfg = EngineConfig {
        work_root: paths.cache_dir.join("runtime"),
        mixed_port: settings.mixed_port,
        socks_port: settings.socks_port,
        http_port: settings.http_port,
        ipv6_enabled: settings.ipv6_enabled,
        allow_lan: settings.allow_lan,
        auto_reconnect: settings.auto_reconnect,
        ..EngineConfig::default()
    };
    let engine = Arc::new(R3xEngine::new(engine_cfg, Arc::clone(&logs)));
    let core_mgr = CoreManager::new(paths.cores_dir.clone(), Some(Arc::clone(&db)));
    let installed_cores = core_mgr.discover_installed();
    for adapter in create_primary_adapters(&core_mgr) {
        let installed = installed_cores.contains_key(&adapter.id());
        engine.register_adapter(adapter, installed);
    }
    logs.record(
        LogCategory::Application,
        LogLevel::Info,
        "r3x-app",
        format!(
            "R3X services initialized ({} installed core(s))",
            installed_cores.len()
        ),
    );

    Ok(AppBootstrap { db, logs, engine })
}

pub fn sync_ui_from_state(ui: &MainWindow, bootstrap: &AppBootstrap) {
    let settings = bootstrap.db.load_settings().unwrap_or_default();
    let subs = bootstrap.db.list_subscriptions().unwrap_or_default();
    let profiles = bootstrap.db.list_profiles().unwrap_or_default();
    let rules = bootstrap.db.list_routing_rules().unwrap_or_default();
    let log_count = bootstrap.logs.recent(None, 5000).len();
    let installed_count = bootstrap.engine.installed_cores().len();

    let state = R3xAppState::get(ui);
    state.set_active_core_name("Xray · sing-box · Mihomo".into());
    state.set_active_core_subtitle(if installed_count > 0 {
        format!("{installed_count} core(s) verified · Standby").into()
    } else {
        "Standby · No core binaries installed yet".into()
    });
    state.set_active_core_badge(if installed_count > 0 {
        "Ready".into()
    } else {
        "Standby".into()
    });
    state.set_subscription_count(subs.len() as i32);
    state.set_profile_count(profiles.len() as i32);
    state.set_routing_rule_count(rules.len() as i32);
    state.set_log_entry_count(log_count as i32);
    state.set_reduced_motion(settings.reduced_motion);
    state.set_interface_advanced(matches!(
        settings.interface_mode,
        r3x_domain::InterfaceMode::Advanced
    ));
    state.set_language_index(match settings.language {
        Language::Ru => 1,
        Language::System | Language::En => 0,
    });

    let theme_idx = match settings.theme_mode {
        ThemeMode::System => 0,
        ThemeMode::Light => 1,
        ThemeMode::Dark => 2,
        ThemeMode::Amoled => 3,
    };
    state.set_theme_mode_index(theme_idx);
    apply_theme_index(ui, theme_idx);
    R3xMetrics::get(ui).set_reduced_motion(settings.reduced_motion);
}

fn apply_theme_index(ui: &MainWindow, idx: i32) {
    let mode = match idx {
        0 => R3xThemeMode::System,
        1 => R3xThemeMode::Light,
        3 => R3xThemeMode::Amoled,
        _ => R3xThemeMode::Dark,
    };
    R3xThemeController::get(ui).invoke_apply_theme(mode, true);
}

pub fn wire_ui_callbacks(ui: &MainWindow, bootstrap: &AppBootstrap) {
    let ui_weak = ui.as_weak();
    let db = Arc::clone(&bootstrap.db);
    let logs = Arc::clone(&bootstrap.logs);

    let state = R3xAppState::get(ui);

    let ui_nav = ui_weak.clone();
    state.on_nav_selected(move |idx| {
        if let Some(w) = ui_nav.upgrade() {
            R3xAppState::get(&w).set_current_nav(idx);
        }
    });

    let ui_theme = ui_weak.clone();
    let db_theme = Arc::clone(&db);
    state.on_theme_selected(move |idx| {
        if let Some(w) = ui_theme.upgrade() {
            R3xAppState::get(&w).set_theme_mode_index(idx);
            apply_theme_index(&w, idx);
            if let Ok(mut s) = db_theme.load_settings() {
                s.theme_mode = match idx {
                    0 => ThemeMode::System,
                    1 => ThemeMode::Light,
                    3 => ThemeMode::Amoled,
                    _ => ThemeMode::Dark,
                };
                let _ = db_theme.save_settings(&s);
            }
        }
    });

    let ui_lang = ui_weak.clone();
    let db_lang = Arc::clone(&db);
    state.on_language_selected(move |idx| {
        if let Some(w) = ui_lang.upgrade() {
            R3xAppState::get(&w).set_language_index(idx);
            if let Ok(mut s) = db_lang.load_settings() {
                s.language = if idx == 1 { Language::Ru } else { Language::En };
                let _ = db_lang.save_settings(&s);
            }
        }
    });

    let ui_motion = ui_weak.clone();
    let db_motion = Arc::clone(&db);
    state.on_reduced_motion_toggled(move |enabled| {
        if let Some(w) = ui_motion.upgrade() {
            R3xAppState::get(&w).set_reduced_motion(enabled);
            R3xMetrics::get(&w).set_reduced_motion(enabled);
            if let Ok(mut s) = db_motion.load_settings() {
                s.reduced_motion = enabled;
                let _ = db_motion.save_settings(&s);
            }
        }
    });

    let ui_adv = ui_weak.clone();
    let db_adv = Arc::clone(&db);
    state.on_interface_mode_toggled(move |advanced| {
        if let Some(w) = ui_adv.upgrade() {
            R3xAppState::get(&w).set_interface_advanced(advanced);
            if let Ok(mut s) = db_adv.load_settings() {
                s.interface_mode = if advanced {
                    r3x_domain::InterfaceMode::Advanced
                } else {
                    r3x_domain::InterfaceMode::Simple
                };
                let _ = db_adv.save_settings(&s);
            }
        }
    });

    let ui_hero = ui_weak.clone();
    let logs_hero = Arc::clone(&logs);
    state.on_hero_action_clicked(move || {
        if let Some(w) = ui_hero.upgrade() {
            let app_state = R3xAppState::get(&w);
            if !app_state.get_has_selected_server() {
                logs_hero.record(
                    LogCategory::Connection,
                    LogLevel::Info,
                    "r3x-ui",
                    "Connection requested without a selected server; routing user to Subscriptions",
                );
                app_state.set_current_nav(1);
            }
        }
    });

    let ui_srv = ui_weak.clone();
    state.on_open_server_selector(move || {
        if let Some(w) = ui_srv.upgrade() {
            R3xAppState::get(&w).set_current_nav(2);
        }
    });

    let ui_diag = ui_weak.clone();
    state.on_open_diagnostics_clicked(move || {
        if let Some(w) = ui_diag.upgrade() {
            R3xAppState::get(&w).set_current_nav(5);
        }
    });

    let ui_qs = ui_weak;
    state.on_quick_settings_clicked(move || {
        if let Some(w) = ui_qs.upgrade() {
            R3xAppState::get(&w).set_current_nav(7);
        }
    });
}

pub fn build_window(bootstrap: &AppBootstrap) -> Result<MainWindow, slint::PlatformError> {
    let ui = MainWindow::new()?;
    sync_ui_from_state(&ui, bootstrap);
    wire_ui_callbacks(&ui, bootstrap);
    Ok(ui)
}

pub fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let paths = match AppPaths::from_env_or_system() {
        Ok(p) => p,
        Err(err) => {
            eprintln!("Failed resolving application paths: {err}");
            return;
        }
    };
    let bootstrap = match init_services(&paths) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("Failed initializing R3X services: {err}");
            return;
        }
    };

    info!("Starting R3X desktop UI");
    match build_window(&bootstrap) {
        Ok(ui) => {
            if let Err(err) = ui.run() {
                eprintln!("UI event loop exited with error: {err}");
            }
        }
        Err(err) => {
            eprintln!("Failed constructing R3X window: {err}");
        }
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(android_app: slint::android::AndroidApp) {
    if let Err(err) = slint::android::init(android_app) {
        eprintln!("Failed initializing Slint Android backend: {err}");
        return;
    }
    let root = std::env::temp_dir().join("dev.rexy.r3x");
    let paths = AppPaths::from_root(&root);
    if let Ok(bootstrap) = init_services(&paths)
        && let Ok(ui) = build_window(&bootstrap)
    {
        MaterialWindowAdapter::get(&ui).set_disable_hover(true);
        let _ = ui.run();
    }
}
