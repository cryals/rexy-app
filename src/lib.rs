pub mod controller;
#[cfg(any(target_os = "windows", target_os = "linux"))]
pub mod tray;

use r3x_cores::{CoreManager, create_all_adapters};
use r3x_diagnostics::{RoutingManager, TelemetryHub};
use r3x_domain::{LogCategory, LogLevel};
use r3x_engine::{EngineConfig, LogHub, R3xEngine};
use r3x_profiles::SubscriptionManager;
use r3x_storage::{AppPaths, R3xDatabase, SecretStore, create_default_secret_store};
#[cfg(target_os = "android")]
use slint::{ComponentHandle, Global};
use std::sync::Arc;
use tracing::{info, warn};

slint::include_modules!();

#[derive(Clone)]
pub struct AppBootstrap {
    pub paths: AppPaths,
    pub runtime: Arc<tokio::runtime::Runtime>,
    pub db: Arc<R3xDatabase>,
    pub logs: Arc<LogHub>,
    pub engine: Arc<R3xEngine>,
    pub core_manager: Arc<CoreManager>,
    pub routing: Arc<RoutingManager>,
    pub telemetry: Arc<TelemetryHub>,
    pub sub_manager: Arc<SubscriptionManager>,
    pub secret_store: Arc<dyn SecretStore>,
}

pub fn init_services(paths: &AppPaths) -> Result<AppBootstrap, r3x_domain::R3xError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    paths.ensure_all_dirs()?;

    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("r3x-async")
            .build()
            .map_err(|e| r3x_domain::R3xError::Storage(format!("tokio runtime init: {e}")))?,
    );

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
    let core_manager = Arc::new(CoreManager::new(
        paths.cores_dir.clone(),
        Some(Arc::clone(&db)),
    ));
    let installed_cores = core_manager.discover_installed();
    for adapter in create_all_adapters(&core_manager) {
        let installed = installed_cores.contains_key(&adapter.id());
        engine.register_adapter(adapter, installed);
    }

    let routing = Arc::new(RoutingManager::new(Arc::clone(&db)));
    let telemetry = Arc::new(TelemetryHub::new());
    let sub_manager = Arc::new(SubscriptionManager::new(Arc::clone(&db))?);
    let secret_store = create_default_secret_store();

    logs.record(
        LogCategory::Application,
        LogLevel::Info,
        "r3x-app",
        format!(
            "R3X services initialized ({} installed core(s), secret store: {})",
            installed_cores.len(),
            secret_store.backend_name()
        ),
    );

    Ok(AppBootstrap {
        paths: paths.clone(),
        runtime,
        db,
        logs,
        engine,
        core_manager,
        routing,
        telemetry,
        sub_manager,
        secret_store,
    })
}

pub fn build_window(bootstrap: &AppBootstrap) -> Result<MainWindow, slint::PlatformError> {
    let ui = MainWindow::new()?;
    let arc_boot = Arc::new(bootstrap.clone());
    controller::sync_all_models(&ui, &arc_boot);
    controller::wire_all_callbacks(&ui, &arc_boot);
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
        Ok(b) => Arc::new(b),
        Err(err) => {
            eprintln!("Failed initializing R3X services: {err}");
            return;
        }
    };

    info!("Starting R3X desktop UI");
    match build_window(&bootstrap) {
        Ok(ui) => {
            #[cfg(any(target_os = "windows", target_os = "linux"))]
            let _tray = {
                let settings = bootstrap.db.load_settings().unwrap_or_default();
                tray::restore_window_state(&ui, &settings.window_state);
                let handle = tray::DesktopTrayHandle::initialize(&bootstrap.db);
                if handle.is_minimize_to_tray() {
                    tray::attach_window_close_persistence(&ui, &bootstrap.db);
                }
                handle
            };
            let _telemetry_timer = controller::start_telemetry_timer(&ui, &bootstrap);
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
        let arc_boot = Arc::new(bootstrap);
        let _telemetry_timer = controller::start_telemetry_timer(&ui, &arc_boot);
        let _ = ui.run();
    }
}
