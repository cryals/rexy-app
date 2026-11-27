use jni::JNIEnv;
use jni::JavaVM;
use jni::objects::{JClass, JString, JValue};
use jni::sys::{JNI_TRUE, jboolean, jint};
use r3x_domain::R3xError;
use r3x_storage::{AndroidKeystoreBridge, register_android_keystore_bridge};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, OnceLock};

static ACTIVE_TUN_FD: AtomicI32 = AtomicI32::new(-1);
static NETWORK_AVAILABLE: AtomicBool = AtomicBool::new(true);
static NETWORK_METERED: AtomicBool = AtomicBool::new(false);
static ANDROID_DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

#[must_use]
pub fn active_tun_fd() -> Option<i32> {
    let fd = ACTIVE_TUN_FD.load(Ordering::Acquire);
    (fd >= 0).then_some(fd)
}

#[must_use]
pub fn android_data_dir() -> Option<PathBuf> {
    ANDROID_DATA_DIR.get().cloned()
}

#[must_use]
pub fn is_network_available() -> bool {
    NETWORK_AVAILABLE.load(Ordering::Acquire)
}

#[must_use]
pub fn is_network_metered() -> bool {
    NETWORK_METERED.load(Ordering::Acquire)
}

struct JniAndroidKeystoreBridge {
    jvm: JavaVM,
}

impl JniAndroidKeystoreBridge {
    fn clear_exception_to_err(env: &mut JNIEnv<'_>, op: &str) -> Result<(), R3xError> {
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
            return Err(R3xError::SecretStoreUnavailable(format!(
                "Android Keystore call failed during {op}"
            )));
        }
        Ok(())
    }
}

impl AndroidKeystoreBridge for JniAndroidKeystoreBridge {
    fn set_secret(&self, key: &str, value: &str) -> Result<(), R3xError> {
        let mut env = self
            .jvm
            .attach_current_thread()
            .map_err(|e| R3xError::SecretStoreUnavailable(format!("JNI attach failed: {e}")))?;
        let j_key = env
            .new_string(key)
            .map_err(|e| R3xError::SecretStoreUnavailable(format!("JNI string error: {e}")))?;
        let j_val = env
            .new_string(value)
            .map_err(|e| R3xError::SecretStoreUnavailable(format!("JNI string error: {e}")))?;
        let _ = env.call_static_method(
            "dev/rexy/r3x/R3xKeystoreStore",
            "setSecret",
            "(Ljava/lang/String;Ljava/lang/String;)V",
            &[JValue::Object(&j_key), JValue::Object(&j_val)],
        );
        Self::clear_exception_to_err(&mut env, "setSecret")
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>, R3xError> {
        let mut env = self
            .jvm
            .attach_current_thread()
            .map_err(|e| R3xError::SecretStoreUnavailable(format!("JNI attach failed: {e}")))?;
        let j_key = env
            .new_string(key)
            .map_err(|e| R3xError::SecretStoreUnavailable(format!("JNI string error: {e}")))?;
        let call_res = env.call_static_method(
            "dev/rexy/r3x/R3xKeystoreStore",
            "getSecret",
            "(Ljava/lang/String;)Ljava/lang/String;",
            &[JValue::Object(&j_key)],
        );
        Self::clear_exception_to_err(&mut env, "getSecret")?;
        let val = call_res
            .map_err(|e| R3xError::SecretStoreUnavailable(format!("JNI return error: {e}")))?;
        let obj = val
            .l()
            .map_err(|e| R3xError::SecretStoreUnavailable(format!("JNI object error: {e}")))?;
        if obj.is_null() {
            return Ok(None);
        }
        let jstr = JString::from(obj);
        let decoded = env
            .get_string(&jstr)
            .map_err(|e| R3xError::SecretStoreUnavailable(format!("JNI decode error: {e}")))?;
        Ok(Some(String::from(decoded)))
    }

    fn delete_secret(&self, key: &str) -> Result<(), R3xError> {
        let mut env = self
            .jvm
            .attach_current_thread()
            .map_err(|e| R3xError::SecretStoreUnavailable(format!("JNI attach failed: {e}")))?;
        let j_key = env
            .new_string(key)
            .map_err(|e| R3xError::SecretStoreUnavailable(format!("JNI string error: {e}")))?;
        let _ = env.call_static_method(
            "dev/rexy/r3x/R3xKeystoreStore",
            "deleteSecret",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&j_key)],
        );
        Self::clear_exception_to_err(&mut env, "deleteSecret")
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_rexy_r3x_R3xNativeBridge_setDataDir(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    path: JString<'_>,
) {
    if let Ok(java_str) = env.get_string(&path) {
        let p = PathBuf::from(String::from(java_str));
        let _ = ANDROID_DATA_DIR.set(p);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_rexy_r3x_R3xNativeBridge_initKeystoreBridge(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) {
    if let Ok(jvm) = env.get_java_vm() {
        register_android_keystore_bridge(Arc::new(JniAndroidKeystoreBridge { jvm }));
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_rexy_r3x_R3xNativeBridge_onVpnTunnelEstablished(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    tun_fd: jint,
) {
    ACTIVE_TUN_FD.store(tun_fd, Ordering::Release);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_rexy_r3x_R3xNativeBridge_onVpnTunnelRevoked(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) {
    ACTIVE_TUN_FD.store(-1, Ordering::Release);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_rexy_r3x_R3xNativeBridge_onNetworkChanged(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    available: jboolean,
    metered: jboolean,
) {
    NETWORK_AVAILABLE.store(available == JNI_TRUE, Ordering::Release);
    NETWORK_METERED.store(metered == JNI_TRUE, Ordering::Release);
}
