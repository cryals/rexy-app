use crate::adapter::{CoreAdapter, CoreConfigContext, RunningCoreHandle};
use crate::events::EngineEvent;
use crate::logging::LogHub;
use crate::selector::{CoreSelectionContext, CoreSelector};
use chrono::Utc;
use parking_lot::RwLock;
use r3x_domain::{
    ConnectionMode, ConnectionSession, ConnectionState, CoreId, CorePreference, CpuArch, DnsConfig,
    LogCategory, LogEntry, LogLevel, Platform, Profile, R3xError, RoutingRule, TelemetrySnapshot,
};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub work_root: PathBuf,
    pub mixed_port: u16,
    pub socks_port: u16,
    pub http_port: u16,
    pub ipv6_enabled: bool,
    pub allow_lan: bool,
    pub auto_reconnect: bool,
    pub max_reconnect_attempts: u32,
    pub health_check_timeout_ms: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            work_root: std::env::temp_dir().join("r3x-runtime"),
            mixed_port: 10808,
            socks_port: 10809,
            http_port: 10810,
            ipv6_enabled: false,
            allow_lan: false,
            auto_reconnect: true,
            max_reconnect_attempts: 3,
            health_check_timeout_ms: 5000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub profile: Profile,
    pub subscription_preference: CorePreference,
    pub global_preference: CorePreference,
    pub mode: ConnectionMode,
    pub dns: DnsConfig,
    pub routing_rules: Vec<RoutingRule>,
    pub tun_fd: Option<i32>,
}

struct ActiveRuntime {
    session: ConnectionSession,
    handle: RunningCoreHandle,
    adapter: Arc<dyn CoreAdapter>,
    work_dir: PathBuf,
    request: ConnectRequest,
    watcher_cancel: CancellationToken,
    watcher_task: Option<JoinHandle<()>>,
}

struct EngineStateInner {
    connection_state: ConnectionState,
    active: Option<ActiveRuntime>,
    telemetry: TelemetrySnapshot,
    in_flight_cancel: Option<CancellationToken>,
}

pub struct R3xEngine {
    config: RwLock<EngineConfig>,
    adapters: RwLock<Vec<Arc<dyn CoreAdapter>>>,
    installed_cores: RwLock<HashSet<CoreId>>,
    state: RwLock<EngineStateInner>,
    transition_lock: Mutex<()>,
    events_tx: broadcast::Sender<EngineEvent>,
    logs: Arc<LogHub>,
}

impl R3xEngine {
    #[must_use]
    pub fn new(config: EngineConfig, logs: Arc<LogHub>) -> Self {
        let (events_tx, _) = broadcast::channel(256);
        Self {
            config: RwLock::new(config),
            adapters: RwLock::new(Vec::new()),
            installed_cores: RwLock::new(HashSet::new()),
            state: RwLock::new(EngineStateInner {
                connection_state: ConnectionState::Disconnected,
                active: None,
                telemetry: TelemetrySnapshot::default(),
                in_flight_cancel: None,
            }),
            transition_lock: Mutex::new(()),
            events_tx,
            logs,
        }
    }

    pub fn register_adapter(&self, adapter: Arc<dyn CoreAdapter>, installed: bool) {
        let id = adapter.id();
        self.adapters.write().push(adapter);
        if installed {
            self.installed_cores.write().insert(id);
        }
    }

    pub fn set_core_installed(&self, core_id: CoreId, installed: bool) {
        let mut guard = self.installed_cores.write();
        if installed {
            guard.insert(core_id);
        } else {
            guard.remove(&core_id);
        }
    }

    #[must_use]
    pub fn installed_cores(&self) -> HashSet<CoreId> {
        self.installed_cores.read().clone()
    }

    #[must_use]
    pub fn connection_state(&self) -> ConnectionState {
        self.state.read().connection_state.clone()
    }

    #[must_use]
    pub fn current_session(&self) -> Option<ConnectionSession> {
        self.state.read().active.as_ref().map(|a| a.session.clone())
    }

    #[must_use]
    pub fn telemetry(&self) -> TelemetrySnapshot {
        self.state.read().telemetry.clone()
    }

    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.events_tx.subscribe()
    }

    #[must_use]
    pub fn logs(&self) -> &Arc<LogHub> {
        &self.logs
    }

    pub fn cancel_pending(&self) {
        if let Some(tok) = self.state.read().in_flight_cancel.as_ref() {
            tok.cancel();
        }
    }

    fn transition(
        &self,
        next: ConnectionState,
        session: Option<ConnectionSession>,
    ) -> Result<(), R3xError> {
        let prev = {
            let mut guard = self.state.write();
            let prev = guard.connection_state.clone();
            if !prev.can_transition_to(&next) {
                return Err(R3xError::InvalidStateTransition {
                    from: prev.as_label().to_owned(),
                    to: next.as_label().to_owned(),
                });
            }
            guard.connection_state = next.clone();
            prev
        };

        let _ = self.events_tx.send(EngineEvent::StateChanged {
            previous: prev,
            current: next,
            session,
        });
        Ok(())
    }

    pub async fn connect(
        self: &Arc<Self>,
        req: ConnectRequest,
    ) -> Result<ConnectionSession, R3xError> {
        let _guard = self.transition_lock.lock().await;

        let current = self.connection_state();
        if matches!(current, ConnectionState::Connected) || current.is_busy() {
            return Err(R3xError::InvalidStateTransition {
                from: current.as_label().to_owned(),
                to: "Preparing".to_owned(),
            });
        }

        let op_cancel = CancellationToken::new();
        self.state.write().in_flight_cancel = Some(op_cancel.clone());

        let result = self.connect_inner(req, op_cancel).await;
        self.state.write().in_flight_cancel = None;
        result
    }

    async fn connect_inner(
        self: &Arc<Self>,
        req: ConnectRequest,
        cancel: CancellationToken,
    ) -> Result<ConnectionSession, R3xError> {
        self.transition(ConnectionState::Preparing, None)?;
        self.logs.record(
            LogCategory::Connection,
            LogLevel::Info,
            "r3x-engine",
            format!(
                "Preparing connection to '{}' ({:?})",
                req.profile.effective_name(),
                req.mode
            ),
        );

        if cancel.is_cancelled() {
            self.cancel_to_disconnected();
            return Err(R3xError::Cancelled);
        }

        self.transition(ConnectionState::Validating, None)?;
        let adapters = self.adapters.read().clone();
        let installed = self.installed_cores.read().clone();

        let selection = match CoreSelector::select(
            &adapters,
            &installed,
            &req.profile,
            CoreSelectionContext {
                subscription_preference: req.subscription_preference,
                global_preference: req.global_preference,
                platform: Platform::current(),
                arch: CpuArch::current(),
                mode: req.mode,
            },
        ) {
            Ok(sel) => sel,
            Err(err) => {
                self.fail_to_error(&err);
                return Err(err);
            }
        };

        let adapter = adapters
            .into_iter()
            .find(|a| a.id() == selection.core_id)
            .ok_or_else(|| R3xError::CoreNotInstalled(selection.core_id.to_string()))?;

        let cfg_snapshot = self.config.read().clone();
        let session_id = Uuid::new_v4();
        let work_dir = cfg_snapshot.work_root.join(session_id.to_string());
        std::fs::create_dir_all(&work_dir)?;

        let ctx = CoreConfigContext {
            profile: req.profile.clone(),
            mode: req.mode,
            dns: req.dns.clone(),
            routing_rules: req.routing_rules.clone(),
            work_dir: work_dir.clone(),
            mixed_port: cfg_snapshot.mixed_port,
            socks_port: cfg_snapshot.socks_port,
            http_port: cfg_snapshot.http_port,
            ipv6_enabled: cfg_snapshot.ipv6_enabled,
            allow_lan: cfg_snapshot.allow_lan,
            tun_interface_name: "r3x-tun0".to_owned(),
            tun_fd: req.tun_fd,
        };

        let generated = match adapter.generate_config(&ctx).await {
            Ok(g) => g,
            Err(err) => {
                let _ = adapter.cleanup(&work_dir).await;
                self.fail_to_error(&err);
                return Err(err);
            }
        };

        if cancel.is_cancelled() {
            let _ = adapter.cleanup(&work_dir).await;
            self.cancel_to_disconnected();
            return Err(R3xError::Cancelled);
        }

        self.transition(ConnectionState::StartingCore, None)?;
        let (log_tx, mut log_rx) = mpsc::channel::<LogEntry>(128);
        let logs_ref = Arc::clone(&self.logs);
        let events_ref = self.events_tx.clone();
        tokio::spawn(async move {
            while let Some(entry) = log_rx.recv().await {
                let clean = logs_ref.push_entry(entry);
                let _ = events_ref.send(EngineEvent::LogAppended { entry: clean });
            }
        });

        let handle = tokio::select! {
            () = cancel.cancelled() => {
                let _ = adapter.cleanup(&work_dir).await;
                self.cancel_to_disconnected();
                return Err(R3xError::Cancelled);
            }
            res = adapter.start(&generated, log_tx) => match res {
                Ok(h) => h,
                Err(err) => {
                    let _ = adapter.cleanup(&work_dir).await;
                    self.fail_to_error(&err);
                    return Err(err);
                }
            }
        };

        if matches!(req.mode, ConnectionMode::Tun | ConnectionMode::Mixed) {
            self.transition(ConnectionState::EstablishingTunnel, None)?;
        }
        self.transition(ConnectionState::Connecting, None)?;

        // Readiness verification: never enter Connected solely on process spawn.
        let timeout_dur = Duration::from_millis(cfg_snapshot.health_check_timeout_ms);
        let health_res = tokio::select! {
            () = cancel.cancelled() => {
                let _ = adapter.stop(handle).await;
                let _ = adapter.cleanup(&work_dir).await;
                self.cancel_to_disconnected();
                return Err(R3xError::Cancelled);
            }
            res = tokio::time::timeout(timeout_dur, adapter.health_check(&handle)) => res
        };

        match health_res {
            Ok(Ok(health)) if health.is_ready() => {}
            Ok(Ok(health)) => {
                let err = R3xError::CoreProcessFailed {
                    core: adapter.id().to_string(),
                    reason: format!("health check not ready: {}", health.details),
                };
                let _ = adapter.stop(handle).await;
                let _ = adapter.cleanup(&work_dir).await;
                self.fail_to_error(&err);
                return Err(err);
            }
            Ok(Err(err)) => {
                let _ = adapter.stop(handle).await;
                let _ = adapter.cleanup(&work_dir).await;
                self.fail_to_error(&err);
                return Err(err);
            }
            Err(_) => {
                let err = R3xError::Timeout(cfg_snapshot.health_check_timeout_ms);
                let _ = adapter.stop(handle).await;
                let _ = adapter.cleanup(&work_dir).await;
                self.fail_to_error(&err);
                return Err(err);
            }
        }

        let session = ConnectionSession {
            session_id,
            profile_id: req.profile.id,
            profile_name: req.profile.effective_name().to_owned(),
            core_id: adapter.id(),
            core_version: adapter.version().to_owned(),
            mode: req.mode,
            started_at: Utc::now(),
            local_http_port: generated.local_http_port,
            local_socks_port: generated.local_socks_port,
            tun_interface_name: generated.tun_interface_name,
        };

        let watcher_cancel = CancellationToken::new();
        let watcher_task =
            self.spawn_health_watcher(Arc::clone(&adapter), handle.clone(), watcher_cancel.clone());

        self.state.write().active = Some(ActiveRuntime {
            session: session.clone(),
            handle,
            adapter,
            work_dir,
            request: req,
            watcher_cancel,
            watcher_task: Some(watcher_task),
        });

        self.transition(ConnectionState::Connected, Some(session.clone()))?;
        self.logs.record(
            LogCategory::Connection,
            LogLevel::Info,
            "r3x-engine",
            format!(
                "Connected via {} ({})",
                session.core_id, session.core_version
            ),
        );
        Ok(session)
    }

    fn spawn_health_watcher(
        self: &Arc<Self>,
        adapter: Arc<dyn CoreAdapter>,
        handle: RunningCoreHandle,
        cancel: CancellationToken,
    ) -> JoinHandle<()> {
        let engine = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            interval.tick().await;
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    _ = interval.tick() => {
                        let Some(eng) = engine.upgrade() else { break };
                        if !matches!(eng.connection_state(), ConnectionState::Connected) {
                            break;
                        }
                        let health = adapter.health_check(&handle).await;
                        match health {
                            Ok(h) if h.is_ready() => {
                                if let Ok(stats) = adapter.collect_stats(&handle).await {
                                    let mut guard = eng.state.write();
                                    guard.telemetry.down_bps = stats.down_bps;
                                    guard.telemetry.up_bps = stats.up_bps;
                                    guard.telemetry.total_down_bytes = stats.total_down_bytes;
                                    guard.telemetry.total_up_bytes = stats.total_up_bytes;
                                    guard.telemetry.core_cpu_pct = stats.core_cpu_pct;
                                    guard.telemetry.core_rss_bytes = stats.core_rss_bytes;
                                    guard.telemetry.active_connections = Some(stats.active_connections.len());
                                    let snap = guard.telemetry.clone();
                                    drop(guard);
                                    let _ = eng.events_tx.send(EngineEvent::TelemetryUpdated { snapshot: snap });
                                }
                            }
                            _ => {
                                eng.logs.record(
                                    LogCategory::Core,
                                    LogLevel::Error,
                                    adapter.id().display_name(),
                                    "Core process health check failed while connected",
                                );
                                eng.handle_unexpected_drop().await;
                                break;
                            }
                        }
                    }
                }
            }
        })
    }

    async fn handle_unexpected_drop(self: &Arc<Self>) {
        let auto_reconnect = self.config.read().auto_reconnect;
        let max_attempts = self.config.read().max_reconnect_attempts;

        let prev_req = {
            let mut guard = self.state.write();
            guard.telemetry.failed_connections =
                guard.telemetry.failed_connections.saturating_add(1);
            guard.active.as_ref().map(|a| a.request.clone())
        };

        if !auto_reconnect || prev_req.is_none() || max_attempts == 0 {
            let err = R3xError::CoreProcessFailed {
                core: "active".to_owned(),
                reason: "core exited unexpectedly".to_owned(),
            };
            self.cleanup_active_runtime().await;
            self.fail_to_error(&err);
            return;
        }

        self.cleanup_active_runtime().await;
        if self
            .transition(ConnectionState::Reconnecting { attempt: 1 }, None)
            .is_err()
        {
            return;
        }

        if let Some(req) = prev_req {
            for attempt in 1..=max_attempts {
                {
                    let mut guard = self.state.write();
                    guard.telemetry.reconnect_count =
                        guard.telemetry.reconnect_count.saturating_add(1);
                    guard.connection_state = ConnectionState::Reconnecting { attempt };
                }
                let backoff = Duration::from_millis(50 * u64::from(attempt));
                tokio::time::sleep(backoff).await;

                if let Ok(_guard) = self.transition_lock.try_lock() {
                    let cancel = CancellationToken::new();
                    if self.connect_inner(req.clone(), cancel).await.is_ok() {
                        return;
                    }
                }
            }
        }

        let err = R3xError::CoreProcessFailed {
            core: "active".to_owned(),
            reason: "automatic reconnect attempts exhausted".to_owned(),
        };
        self.fail_to_error(&err);
    }

    async fn cleanup_active_runtime(&self) {
        let active = self.state.write().active.take();
        if let Some(mut runtime) = active {
            runtime.watcher_cancel.cancel();
            if let Some(task) = runtime.watcher_task.take() {
                task.abort();
            }
            let _ = runtime.adapter.stop(runtime.handle).await;
            let _ = runtime.adapter.cleanup(&runtime.work_dir).await;
        }
    }

    pub async fn disconnect(&self) -> Result<(), R3xError> {
        self.cancel_pending();
        let _guard = self.transition_lock.lock().await;

        let current = self.connection_state();
        if matches!(current, ConnectionState::Disconnected) {
            return Ok(());
        }
        if matches!(current, ConnectionState::Error { .. }) {
            self.cleanup_active_runtime().await;
            self.transition(ConnectionState::Disconnected, None)?;
            return Ok(());
        }

        self.transition(ConnectionState::Disconnecting, None)?;
        self.cleanup_active_runtime().await;
        {
            let mut guard = self.state.write();
            guard.telemetry = TelemetrySnapshot {
                reconnect_count: guard.telemetry.reconnect_count,
                failed_connections: guard.telemetry.failed_connections,
                ..TelemetrySnapshot::default()
            };
        }
        self.transition(ConnectionState::Disconnected, None)?;
        self.logs.record(
            LogCategory::Connection,
            LogLevel::Info,
            "r3x-engine",
            "Disconnected cleanly",
        );
        Ok(())
    }

    fn cancel_to_disconnected(&self) {
        let _ = self.transition(ConnectionState::Disconnecting, None);
        let _ = self.transition(ConnectionState::Disconnected, None);
    }

    fn fail_to_error(&self, err: &R3xError) {
        let code = err.code().to_owned();
        let message = err.to_string();
        self.logs.record(
            LogCategory::Connection,
            LogLevel::Error,
            "r3x-engine",
            &message,
        );
        let _ = self.transition(
            ConnectionState::Error {
                code: code.clone(),
                message: message.clone(),
            },
            None,
        );
        let _ = self
            .events_tx
            .send(EngineEvent::ErrorRaised { code, message });
    }
}
