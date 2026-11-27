use crate::manifests::find_manifest;
use r3x_domain::{CoreId, CoreInstallState, R3xError};
use r3x_security::{
    ArchiveLimits, compute_sha256_file, extract_targz_safely, extract_zip_safely,
    sanitize_filename, verify_sha256_file,
};
use r3x_storage::R3xDatabase;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveCoreRecord {
    pub core_id: CoreId,
    pub version: String,
    pub binary_path: PathBuf,
    pub sha256: String,
    pub previous_version: Option<String>,
    pub previous_binary_path: Option<PathBuf>,
    pub previous_sha256: Option<String>,
}

pub struct CoreManager {
    cores_dir: PathBuf,
    db: Option<Arc<R3xDatabase>>,
}

impl CoreManager {
    #[must_use]
    pub fn new(cores_dir: PathBuf, db: Option<Arc<R3xDatabase>>) -> Self {
        Self { cores_dir, db }
    }

    #[must_use]
    pub fn binary_filename(core_id: CoreId) -> &'static str {
        let base = match core_id {
            CoreId::Xray => "xray",
            CoreId::SingBox => "sing-box",
            CoreId::Mihomo => "mihomo",
            CoreId::Hysteria2 => "hysteria",
            CoreId::WireGuard => "wireguard",
            CoreId::AmneziaWg => "amneziawg-go",
            CoreId::NaiveProxy => "naive",
            CoreId::Mieru => "mieru",
            CoreId::OpenVpn => "openvpn",
            CoreId::ShadowsocksRust => "sslocal",
            CoreId::V2Fly => "v2ray",
            CoreId::Juicity => "juicity-client",
            CoreId::Brook => "brook",
            CoreId::Tor => "tor",
            CoreId::OpenConnect => "openconnect",
            CoreId::Ikev2 => "swanctl",
            CoreId::Sstp => "sstpc",
            CoreId::SoftEther => "vpnclient",
            CoreId::OpenSshTun => "ssh",
        };
        #[cfg(target_os = "windows")]
        {
            match base {
                "xray" => "xray.exe",
                "sing-box" => "sing-box.exe",
                "mihomo" => "mihomo.exe",
                "hysteria" => "hysteria.exe",
                "wireguard" => "wireguard.exe",
                "amneziawg-go" => "amneziawg-go.exe",
                "naive" => "naive.exe",
                "mieru" => "mieru.exe",
                "openvpn" => "openvpn.exe",
                "sslocal" => "sslocal.exe",
                "v2ray" => "v2ray.exe",
                "juicity-client" => "juicity-client.exe",
                "brook" => "brook.exe",
                "tor" => "tor.exe",
                "openconnect" => "openconnect.exe",
                "swanctl" => "swanctl.exe",
                "sstpc" => "sstpc.exe",
                "vpnclient" => "vpnclient.exe",
                _ => "ssh.exe",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            base
        }
    }

    fn core_root(&self, core_id: CoreId) -> PathBuf {
        let slug = serde_json::to_value(core_id)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{core_id:?}").to_ascii_lowercase());
        self.cores_dir.join(slug)
    }

    fn active_record_path(&self, core_id: CoreId) -> PathBuf {
        self.core_root(core_id).join("active.json")
    }

    pub fn install_from_archive(
        &self,
        core_id: CoreId,
        version: &str,
        archive_path: &Path,
        expected_archive_sha256: &str,
    ) -> Result<ActiveCoreRecord, R3xError> {
        verify_sha256_file(archive_path, expected_archive_sha256)?;

        let safe_ver = sanitize_filename(version);
        let install_dir = self.core_root(core_id).join(&safe_ver);
        if install_dir.exists() {
            fs::remove_dir_all(&install_dir)?;
        }
        fs::create_dir_all(&install_dir)?;

        let archive_name = archive_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let extracted = if archive_name.ends_with(".zip") {
            extract_zip_safely(archive_path, &install_dir, ArchiveLimits::default())?
        } else if archive_name.ends_with(".tar.gz") || archive_name.ends_with(".tgz") {
            extract_targz_safely(archive_path, &install_dir, ArchiveLimits::default())?
        } else {
            return Err(R3xError::Validation(format!(
                "unsupported core archive format: {archive_name}"
            )));
        };

        let expected_bin = Self::binary_filename(core_id);
        let binary_path = extracted
            .into_iter()
            .find(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.eq_ignore_ascii_case(expected_bin))
            })
            .ok_or_else(|| R3xError::CoreIncompatible {
                core: core_id.to_string(),
                reason: format!("archive missing expected binary '{expected_bin}'"),
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&binary_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&binary_path, perms)?;
        }

        let bin_sha256 = compute_sha256_file(&binary_path)?;
        let prev = self.load_active_record(core_id).ok().flatten();

        let record = ActiveCoreRecord {
            core_id,
            version: safe_ver,
            binary_path: binary_path.clone(),
            sha256: bin_sha256.clone(),
            previous_version: prev.as_ref().map(|p| p.version.clone()),
            previous_binary_path: prev.as_ref().map(|p| p.binary_path.clone()),
            previous_sha256: prev.as_ref().map(|p| p.sha256.clone()),
        };

        self.save_active_record(&record)?;
        self.persist_state_to_db(core_id, &record, &bin_sha256);
        Ok(record)
    }

    pub fn rollback(&self, core_id: CoreId) -> Result<ActiveCoreRecord, R3xError> {
        let current = self.load_active_record(core_id)?.ok_or_else(|| {
            R3xError::CoreNotInstalled(format!("{core_id} has no installed active record"))
        })?;
        let (prev_ver, prev_bin, prev_sha) = match (
            current.previous_version.clone(),
            current.previous_binary_path.clone(),
            current.previous_sha256.clone(),
        ) {
            (Some(v), Some(p), Some(s)) => (v, p, s),
            _ => {
                return Err(R3xError::Validation(format!(
                    "no previous version available to roll back {core_id}"
                )));
            }
        };

        verify_sha256_file(&prev_bin, &prev_sha)?;
        let rolled = ActiveCoreRecord {
            core_id,
            version: prev_ver,
            binary_path: prev_bin,
            sha256: prev_sha.clone(),
            previous_version: Some(current.version),
            previous_binary_path: Some(current.binary_path),
            previous_sha256: Some(current.sha256),
        };
        self.save_active_record(&rolled)?;
        self.persist_state_to_db(core_id, &rolled, &prev_sha);
        Ok(rolled)
    }

    pub fn uninstall(&self, core_id: CoreId) -> Result<(), R3xError> {
        let root = self.core_root(core_id);
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        if let Some(ref db) = self.db
            && let Some(manifest) = find_manifest(core_id)
        {
            let _ = db.save_core_metadata(&manifest, &CoreInstallState::NotInstalled);
        }
        Ok(())
    }

    pub fn verify_installed_binary(&self, core_id: CoreId) -> Result<PathBuf, R3xError> {
        let rec = self
            .load_active_record(core_id)?
            .ok_or_else(|| R3xError::CoreNotInstalled(core_id.to_string()))?;
        if !rec.binary_path.exists() {
            return Err(R3xError::CoreNotInstalled(format!(
                "binary missing at {}",
                rec.binary_path.display()
            )));
        }
        verify_sha256_file(&rec.binary_path, &rec.sha256)?;
        Ok(rec.binary_path)
    }

    #[must_use]
    pub fn discover_installed(&self) -> HashMap<CoreId, ActiveCoreRecord> {
        let mut out = HashMap::new();
        for core_id in [
            CoreId::Xray,
            CoreId::SingBox,
            CoreId::Mihomo,
            CoreId::Hysteria2,
            CoreId::WireGuard,
            CoreId::AmneziaWg,
            CoreId::NaiveProxy,
            CoreId::Mieru,
            CoreId::OpenVpn,
            CoreId::ShadowsocksRust,
            CoreId::V2Fly,
            CoreId::Juicity,
            CoreId::Brook,
            CoreId::Tor,
        ] {
            if let Ok(Some(rec)) = self.load_active_record(core_id)
                && verify_sha256_file(&rec.binary_path, &rec.sha256).is_ok()
            {
                out.insert(core_id, rec);
            }
        }
        out
    }

    fn load_active_record(&self, core_id: CoreId) -> Result<Option<ActiveCoreRecord>, R3xError> {
        let path = self.active_record_path(core_id);
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path)?;
        let rec: ActiveCoreRecord = serde_json::from_str(&raw)
            .map_err(|e| R3xError::Storage(format!("invalid active core metadata: {e}")))?;
        Ok(Some(rec))
    }

    fn save_active_record(&self, rec: &ActiveCoreRecord) -> Result<(), R3xError> {
        let path = self.active_record_path(rec.core_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(rec)
            .map_err(|e| R3xError::Storage(format!("serialize active record: {e}")))?;
        fs::write(&path, raw)?;
        Ok(())
    }

    fn persist_state_to_db(&self, core_id: CoreId, rec: &ActiveCoreRecord, sha256: &str) {
        if let Some(ref db) = self.db
            && let Some(manifest) = find_manifest(core_id)
        {
            let state = CoreInstallState::Installed {
                version: rec.version.clone(),
                binary_path: rec.binary_path.to_string_lossy().into_owned(),
                sha256: sha256.to_owned(),
            };
            let _ = db.save_core_metadata(&manifest, &state);
        }
    }
}
