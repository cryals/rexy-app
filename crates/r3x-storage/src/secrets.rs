use parking_lot::RwLock;
use r3x_domain::R3xError;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use zeroize::Zeroize;

pub trait SecretStore: Send + Sync {
    fn backend_name(&self) -> &'static str;
    fn is_available(&self) -> bool;
    fn set_secret(&self, key: &str, value: &str) -> Result<(), R3xError>;
    fn get_secret(&self, key: &str) -> Result<Option<String>, R3xError>;
    fn delete_secret(&self, key: &str) -> Result<(), R3xError>;
}

pub trait AndroidKeystoreBridge: Send + Sync {
    fn set_secret(&self, key: &str, value: &str) -> Result<(), R3xError>;
    fn get_secret(&self, key: &str) -> Result<Option<String>, R3xError>;
    fn delete_secret(&self, key: &str) -> Result<(), R3xError>;
}

static ANDROID_BRIDGE: OnceLock<RwLock<Option<Arc<dyn AndroidKeystoreBridge>>>> = OnceLock::new();

pub fn register_android_keystore_bridge(bridge: Arc<dyn AndroidKeystoreBridge>) {
    let slot = ANDROID_BRIDGE.get_or_init(|| RwLock::new(None));
    *slot.write() = Some(bridge);
}

#[derive(Debug, Default)]
pub struct MemorySecretStore {
    entries: RwLock<HashMap<String, String>>,
}

impl MemorySecretStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Drop for MemorySecretStore {
    fn drop(&mut self) {
        let mut guard = self.entries.write();
        for v in guard.values_mut() {
            v.zeroize();
        }
        guard.clear();
    }
}

impl SecretStore for MemorySecretStore {
    fn backend_name(&self) -> &'static str {
        "in_memory_test_store"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn set_secret(&self, key: &str, value: &str) -> Result<(), R3xError> {
        self.entries
            .write()
            .insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>, R3xError> {
        Ok(self.entries.read().get(key).cloned())
    }

    fn delete_secret(&self, key: &str) -> Result<(), R3xError> {
        if let Some(mut old) = self.entries.write().remove(key) {
            old.zeroize();
        }
        Ok(())
    }
}

/// Returned whenever no platform secure credential backend is available.
/// Never falls back silently to plaintext storage on disk.
#[derive(Debug, Default)]
pub struct UnavailableSecretStore {
    reason: String,
}

impl UnavailableSecretStore {
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl SecretStore for UnavailableSecretStore {
    fn backend_name(&self) -> &'static str {
        "unavailable"
    }

    fn is_available(&self) -> bool {
        false
    }

    fn set_secret(&self, _key: &str, _value: &str) -> Result<(), R3xError> {
        Err(R3xError::SecretStoreUnavailable(self.reason.clone()))
    }

    fn get_secret(&self, _key: &str) -> Result<Option<String>, R3xError> {
        Err(R3xError::SecretStoreUnavailable(self.reason.clone()))
    }

    fn delete_secret(&self, _key: &str) -> Result<(), R3xError> {
        Err(R3xError::SecretStoreUnavailable(self.reason.clone()))
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub struct KeyringSecretStore {
    service: String,
    lock: parking_lot::Mutex<()>,
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
impl KeyringSecretStore {
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            lock: parking_lot::Mutex::new(()),
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
impl SecretStore for KeyringSecretStore {
    fn backend_name(&self) -> &'static str {
        #[cfg(target_os = "windows")]
        {
            "windows_credential_manager"
        }
        #[cfg(target_os = "linux")]
        {
            "linux_secret_service"
        }
    }

    fn is_available(&self) -> bool {
        let _guard = self.lock.lock();
        keyring::Entry::new(&self.service, "__r3x_probe__").is_ok()
    }

    fn set_secret(&self, key: &str, value: &str) -> Result<(), R3xError> {
        let _guard = self.lock.lock();
        let entry = keyring::Entry::new(&self.service, key)
            .map_err(|e| R3xError::SecretStoreUnavailable(e.to_string()))?;
        entry
            .set_password(value)
            .map_err(|e| R3xError::SecretStoreUnavailable(e.to_string()))
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>, R3xError> {
        let _guard = self.lock.lock();
        let entry = keyring::Entry::new(&self.service, key)
            .map_err(|e| R3xError::SecretStoreUnavailable(e.to_string()))?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(R3xError::SecretStoreUnavailable(err.to_string())),
        }
    }

    fn delete_secret(&self, key: &str) -> Result<(), R3xError> {
        let _guard = self.lock.lock();
        let entry = keyring::Entry::new(&self.service, key)
            .map_err(|e| R3xError::SecretStoreUnavailable(e.to_string()))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(R3xError::SecretStoreUnavailable(err.to_string())),
        }
    }
}

#[cfg(target_os = "android")]
struct AndroidKeystoreStore;

#[cfg(target_os = "android")]
impl SecretStore for AndroidKeystoreStore {
    fn backend_name(&self) -> &'static str {
        "android_keystore"
    }

    fn is_available(&self) -> bool {
        ANDROID_BRIDGE
            .get()
            .is_some_and(|slot| slot.read().is_some())
    }

    fn set_secret(&self, key: &str, value: &str) -> Result<(), R3xError> {
        let bridge = ANDROID_BRIDGE
            .get()
            .and_then(|s| s.read().clone())
            .ok_or_else(|| {
                R3xError::SecretStoreUnavailable(
                    "Android Keystore bridge not initialized".to_owned(),
                )
            })?;
        bridge.set_secret(key, value)
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>, R3xError> {
        let bridge = ANDROID_BRIDGE
            .get()
            .and_then(|s| s.read().clone())
            .ok_or_else(|| {
                R3xError::SecretStoreUnavailable(
                    "Android Keystore bridge not initialized".to_owned(),
                )
            })?;
        bridge.get_secret(key)
    }

    fn delete_secret(&self, key: &str) -> Result<(), R3xError> {
        let bridge = ANDROID_BRIDGE
            .get()
            .and_then(|s| s.read().clone())
            .ok_or_else(|| {
                R3xError::SecretStoreUnavailable(
                    "Android Keystore bridge not initialized".to_owned(),
                )
            })?;
        bridge.delete_secret(key)
    }
}

#[must_use]
pub fn create_default_secret_store() -> Arc<dyn SecretStore> {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        let store = KeyringSecretStore::new("dev.rexy.r3x");
        if store.is_available() {
            Arc::new(store)
        } else {
            Arc::new(UnavailableSecretStore::new(
                "OS credential store is not accessible in this session",
            ))
        }
    }
    #[cfg(target_os = "android")]
    {
        Arc::new(AndroidKeystoreStore)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "android")))]
    {
        Arc::new(UnavailableSecretStore::new(
            "No platform secret store implementation for this OS",
        ))
    }
}
