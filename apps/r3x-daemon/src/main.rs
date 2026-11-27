use r3x_cores::{CoreManager, create_all_adapters};
use r3x_domain::{ConnectionMode, CoreId, LogCategory, LogLevel, R3xError};
use r3x_engine::{ConnectRequest, EngineConfig, LogHub, R3xEngine};
use r3x_ipc::transport::BoxFuture;
use r3x_ipc::{IpcCommand, IpcErrorPayload, IpcHandler, IpcPayload, IpcServer, SocketAddress};
use r3x_network::{SystemProxyManager, create_platform_proxy_backend, recover_network_state};
use r3x_profiles::SubscriptionManager;
use r3x_security::generate_ipc_token;
use r3x_storage::{AppPaths, R3xDatabase};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

struct DaemonIpcHandler {
    engine: Arc<R3xEngine>,
    db: Arc<R3xDatabase>,
    sub_mgr: Arc<SubscriptionManager>,
    proxy_mgr: Arc<SystemProxyManager>,
    logs: Arc<LogHub>,
    cancel: CancellationToken,
}

impl DaemonIpcHandler {
    fn err_payload(err: &R3xError) -> IpcPayload {
        IpcPayload::Error(IpcErrorPayload {
            code: err.code().to_owned(),
            message: err.to_string(),
            server_version: None,
            client_version: None,
        })
    }
}

impl IpcHandler for DaemonIpcHandler {
    fn handle(&self, command: IpcCommand) -> BoxFuture<'_, IpcPayload> {
        Box::pin(async move {
            match command {
                IpcCommand::GetStatus => IpcPayload::Status {
                    state: self.engine.connection_state(),
                    session: self.engine.current_session(),
                },
                IpcCommand::Connect { profile_id, mode } => {
                    let profile = match self.db.get_profile(profile_id) {
                        Ok(Some(p)) => p,
                        Ok(None) => {
                            return Self::err_payload(&R3xError::Validation(format!(
                                "profile {profile_id} not found"
                            )));
                        }
                        Err(e) => return Self::err_payload(&e),
                    };
                    let settings = self.db.load_settings().unwrap_or_default();
                    let dns = self.db.load_dns_config().unwrap_or_default();
                    let routing_rules = self.db.list_routing_rules().unwrap_or_default();
                    let req = ConnectRequest {
                        profile,
                        subscription_preference: r3x_domain::CorePreference::Auto,
                        global_preference: settings.global_core_preference,
                        mode,
                        dns,
                        routing_rules,
                        tun_fd: None,
                    };
                    match self.engine.connect(req).await {
                        Ok(session) => {
                            if matches!(mode, ConnectionMode::SystemProxy | ConnectionMode::Mixed)
                                && let Some(port) = session.local_http_port
                                && let Err(err) = self.proxy_mgr.enable_loopback(port)
                            {
                                warn!(error = %err, "Failed setting system proxy; disconnecting");
                                let _ = self.engine.disconnect().await;
                                return Self::err_payload(&err);
                            }
                            IpcPayload::Status {
                                state: self.engine.connection_state(),
                                session: Some(session),
                            }
                        }
                        Err(err) => Self::err_payload(&err),
                    }
                }
                IpcCommand::Disconnect => {
                    let _ = self.proxy_mgr.disable_and_restore();
                    match self.engine.disconnect().await {
                        Ok(()) => IpcPayload::Ok,
                        Err(err) => Self::err_payload(&err),
                    }
                }
                IpcCommand::Reconnect => {
                    let prev_session = self.engine.current_session();
                    let _ = self.proxy_mgr.disable_and_restore();
                    if let Err(err) = self.engine.disconnect().await {
                        return Self::err_payload(&err);
                    }
                    if let Some(sess) = prev_session {
                        return self
                            .handle(IpcCommand::Connect {
                                profile_id: sess.profile_id,
                                mode: sess.mode,
                            })
                            .await;
                    }
                    IpcPayload::Ok
                }
                IpcCommand::ListProfiles => match self.db.list_profiles() {
                    Ok(items) => IpcPayload::Profiles { items },
                    Err(e) => Self::err_payload(&e),
                },
                IpcCommand::ListSubscriptions => match self.db.list_subscriptions() {
                    Ok(items) => IpcPayload::Subscriptions { items },
                    Err(e) => Self::err_payload(&e),
                },
                IpcCommand::RefreshSubscriptions => {
                    let subs = match self.db.list_subscriptions() {
                        Ok(s) => s,
                        Err(e) => return Self::err_payload(&e),
                    };
                    for s in subs {
                        if s.enabled {
                            let _ = self.sub_mgr.refresh_subscription(s.id).await;
                        }
                    }
                    match self.db.list_subscriptions() {
                        Ok(items) => IpcPayload::Subscriptions { items },
                        Err(e) => Self::err_payload(&e),
                    }
                }
                IpcCommand::ListCores => {
                    let ids: Vec<CoreId> = self.engine.installed_cores().into_iter().collect();
                    IpcPayload::Cores { ids }
                }
                IpcCommand::GetRecentLogs { category, limit } => IpcPayload::Logs {
                    entries: self.logs.recent(category, limit),
                },
                IpcCommand::GetTelemetry => IpcPayload::Telemetry {
                    snapshot: self.engine.telemetry(),
                },
                IpcCommand::Shutdown => {
                    let _ = self.proxy_mgr.disable_and_restore();
                    let _ = self.engine.disconnect().await;
                    self.cancel.cancel();
                    IpcPayload::Ok
                }
                IpcCommand::Handshake { .. } | IpcCommand::Ping | IpcCommand::RunDiagnostics => {
                    IpcPayload::Ok
                }
            }
        })
    }
}

fn load_or_create_ipc_token(data_dir: &Path) -> Result<String, R3xError> {
    let token_path = data_dir.join("ipc.token");
    if token_path.exists() {
        let existing = fs::read_to_string(&token_path)?.trim().to_owned();
        if existing.len() >= 32 {
            return Ok(existing);
        }
    }
    let token = generate_ipc_token();
    fs::write(&token_path, &token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(token)
}

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    if let Err(err) = run_daemon().await {
        eprintln!("r3x-daemon error: {err}");
        std::process::exit(1);
    }
}

async fn run_daemon() -> Result<(), R3xError> {
    let paths = AppPaths::from_env_or_system()?;
    paths.ensure_all_dirs()?;

    let proxy_backend = create_platform_proxy_backend();
    let recovery = recover_network_state(&paths.cache_dir, proxy_backend.as_ref())?;
    if recovery.had_pending_state {
        info!(notes = ?recovery.notes, "Recovered stale network state on daemon startup");
    }

    let logs = Arc::new(LogHub::new(Some(paths.logs_dir.clone())));
    let db_res = R3xDatabase::open_with_recovery(&paths.db_path)?;
    let db = Arc::new(db_res.db);
    let settings = db.load_settings()?;

    let engine = Arc::new(R3xEngine::new(
        EngineConfig {
            work_root: paths.cache_dir.join("runtime"),
            mixed_port: settings.mixed_port,
            socks_port: settings.socks_port,
            http_port: settings.http_port,
            ipv6_enabled: settings.ipv6_enabled,
            allow_lan: settings.allow_lan,
            auto_reconnect: settings.auto_reconnect,
            ..EngineConfig::default()
        },
        Arc::clone(&logs),
    ));

    let core_mgr = CoreManager::new(paths.cores_dir.clone(), Some(Arc::clone(&db)));
    let installed = core_mgr.discover_installed();
    for adapter in create_all_adapters(&core_mgr) {
        let is_inst = installed.contains_key(&adapter.id());
        engine.register_adapter(adapter, is_inst);
    }

    let sub_mgr = Arc::new(SubscriptionManager::new(Arc::clone(&db))?);
    let proxy_mgr = Arc::new(SystemProxyManager::new(
        proxy_backend,
        paths.cache_dir.clone(),
    ));

    let token = load_or_create_ipc_token(&paths.data_dir)?;
    let cancel = CancellationToken::new();
    let handler = Arc::new(DaemonIpcHandler {
        engine: Arc::clone(&engine),
        db,
        sub_mgr,
        proxy_mgr: Arc::clone(&proxy_mgr),
        logs: Arc::clone(&logs),
        cancel: cancel.clone(),
    });

    let server = IpcServer::bind(SocketAddress::default_daemon(), token, handler)?;
    logs.record(
        LogCategory::Application,
        LogLevel::Info,
        "r3x-daemon",
        "R3X daemon IPC server listening",
    );
    info!("r3x-daemon listening on local IPC");

    let ctrl_cancel = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            ctrl_cancel.cancel();
        }
    });

    server.run(cancel).await?;
    let _ = proxy_mgr.disable_and_restore();
    let _ = engine.disconnect().await;
    Ok(())
}
