use parking_lot::Mutex;
use r3x_domain::R3xError;
use r3x_network::{
    KillSwitchManager, SystemProxyBackend, SystemProxyManager, SystemProxySnapshot,
    check_tun_capability, find_free_local_port, is_local_port_available, list_network_interfaces,
    recover_network_state,
};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tempfile::tempdir;

struct MockProxyBackend {
    state: Mutex<SystemProxySnapshot>,
    fail_apply: AtomicBool,
}

impl MockProxyBackend {
    fn new(initial: SystemProxySnapshot) -> Self {
        Self {
            state: Mutex::new(initial),
            fail_apply: AtomicBool::new(false),
        }
    }
}

impl SystemProxyBackend for MockProxyBackend {
    fn backend_name(&self) -> &'static str {
        "mock_proxy"
    }

    fn is_supported(&self) -> bool {
        true
    }

    fn read_snapshot(&self) -> Result<SystemProxySnapshot, R3xError> {
        Ok(self.state.lock().clone())
    }

    fn apply_snapshot(&self, snapshot: &SystemProxySnapshot) -> Result<(), R3xError> {
        if self.fail_apply.load(Ordering::Relaxed) {
            return Err(R3xError::Network("simulated apply error".to_owned()));
        }
        *self.state.lock() = snapshot.clone();
        Ok(())
    }
}

#[test]
fn transactional_system_proxy_restore_and_crash_recovery() {
    let dir = tempdir().expect("tempdir");
    let initial = SystemProxySnapshot {
        enabled: true,
        server: Some("corp-proxy.internal:8080".to_owned()),
        bypass: Some("*.corp".to_owned()),
        backend: "mock_proxy".to_owned(),
    };
    let backend = Arc::new(MockProxyBackend::new(initial.clone()));
    let mgr = SystemProxyManager::new(backend.clone(), dir.path().to_path_buf());

    mgr.enable_loopback(10808).expect("enable");
    assert_eq!(
        backend.read_snapshot().expect("read").server.as_deref(),
        Some("127.0.0.1:10808")
    );

    // Simulate daemon crash + restart recovery
    let report = recover_network_state(dir.path(), backend.as_ref()).expect("recover");
    assert!(report.had_pending_state);
    assert!(report.restored_proxy);
    assert_eq!(backend.read_snapshot().expect("restored"), initial);

    // Rollback on apply failure
    backend.fail_apply.store(true, Ordering::Relaxed);
    assert!(mgr.enable_loopback(10808).is_err());
    backend.fail_apply.store(false, Ordering::Relaxed);
    assert_eq!(backend.read_snapshot().expect("after rollback"), initial);
}

#[test]
fn port_conflict_detection_kill_switch_and_interfaces() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let busy_port = listener.local_addr().expect("addr").port();
    assert!(!is_local_port_available(busy_port));

    let free_port = find_free_local_port(busy_port).expect("find free");
    assert_ne!(free_port, busy_port);
    drop(listener);
    assert!(is_local_port_available(busy_port));

    let dir = tempdir().expect("tempdir");
    let mut ks = KillSwitchManager::new(dir.path().to_path_buf());
    ks.activate().expect("activate");
    assert!(ks.is_active());
    let rep = recover_network_state(
        dir.path(),
        &MockProxyBackend::new(SystemProxySnapshot {
            enabled: false,
            server: None,
            bypass: None,
            backend: "mock".to_owned(),
        }),
    )
    .expect("recover");
    assert!(rep.cleared_kill_switch);

    let _tun = check_tun_capability();
    let _ifaces = list_network_interfaces();
}
