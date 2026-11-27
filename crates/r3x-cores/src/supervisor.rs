use chrono::Utc;
use parking_lot::Mutex;
use r3x_domain::{CoreId, LogCategory, LogEntry, LogLevel, R3xError};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

pub struct SupervisedProcess {
    pub pid: u32,
    child: Arc<Mutex<Child>>,
}

impl SupervisedProcess {
    pub fn spawn(
        core_id: CoreId,
        binary: &Path,
        args: &[String],
        work_dir: &Path,
        log_tx: mpsc::Sender<LogEntry>,
    ) -> Result<Self, R3xError> {
        let mut cmd = Command::new(binary);
        cmd.args(args)
            .current_dir(work_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        #[cfg(target_os = "windows")]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = cmd.spawn().map_err(|e| R3xError::CoreProcessFailed {
            core: core_id.to_string(),
            reason: format!("failed spawning {}: {e}", binary.display()),
        })?;

        let pid = child.id().unwrap_or(0);
        let source = core_id.display_name().to_owned();

        if let Some(stdout) = child.stdout.take() {
            let tx = log_tx.clone();
            let src = source.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = tx
                        .send(LogEntry {
                            id: 0,
                            timestamp: Utc::now(),
                            category: LogCategory::Core,
                            level: LogLevel::Info,
                            source: src.clone(),
                            message: line,
                        })
                        .await;
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = log_tx
                        .send(LogEntry {
                            id: 0,
                            timestamp: Utc::now(),
                            category: LogCategory::Core,
                            level: LogLevel::Warn,
                            source: source.clone(),
                            message: line,
                        })
                        .await;
                }
            });
        }

        Ok(Self {
            pid,
            child: Arc::new(Mutex::new(child)),
        })
    }

    #[must_use]
    pub fn is_alive(&self) -> bool {
        let mut guard = self.child.lock();
        matches!(guard.try_wait(), Ok(None))
    }

    pub fn terminate(&self) -> Result<(), R3xError> {
        let mut guard = self.child.lock();
        if matches!(guard.try_wait(), Ok(Some(_))) {
            return Ok(());
        }
        guard.start_kill().map_err(|e| R3xError::CoreProcessFailed {
            core: format!("pid-{}", self.pid),
            reason: format!("failed stopping core process: {e}"),
        })
    }
}

pub async fn probe_tcp_ready(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

#[must_use]
pub fn read_process_metrics(pid: u32) -> (Option<f32>, Option<u64>) {
    if pid == 0 {
        return (None, None);
    }
    let Ok(mut sys) = System::new() else {
        return (None, None);
    };
    let target = Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::everything(),
    );
    if let Some(proc_info) = sys.process(target) {
        (Some(proc_info.cpu_usage()), Some(proc_info.memory()))
    } else {
        (None, None)
    }
}

pub(crate) struct ProcessRegistry {
    processes: Mutex<HashMap<u32, Arc<SupervisedProcess>>>,
}

impl ProcessRegistry {
    pub fn new() -> Self {
        Self {
            processes: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, proc_handle: Arc<SupervisedProcess>) {
        self.processes.lock().insert(proc_handle.pid, proc_handle);
    }

    pub fn get(&self, pid: u32) -> Option<Arc<SupervisedProcess>> {
        self.processes.lock().get(&pid).cloned()
    }

    pub fn remove(&self, pid: u32) -> Option<Arc<SupervisedProcess>> {
        self.processes.lock().remove(&pid)
    }
}
