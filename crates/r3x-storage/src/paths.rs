use directories::ProjectDirs;
use r3x_domain::R3xError;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub cores_dir: PathBuf,
    pub backups_dir: PathBuf,
    pub db_path: PathBuf,
}

impl AppPaths {
    pub fn from_env_or_system() -> Result<Self, R3xError> {
        if let Ok(override_dir) = std::env::var("R3X_DATA_DIR") {
            let trimmed = override_dir.trim();
            if !trimmed.is_empty() {
                return Ok(Self::from_root(Path::new(trimmed)));
            }
        }
        Self::from_system()
    }

    pub fn from_system() -> Result<Self, R3xError> {
        let proj = ProjectDirs::from("dev", "rexy", "R3X").ok_or_else(|| {
            R3xError::Storage("unable to resolve platform application directories".to_owned())
        })?;
        let data_dir = proj.data_local_dir().to_path_buf();
        let config_dir = proj.config_local_dir().to_path_buf();
        let cache_dir = proj.cache_dir().to_path_buf();
        Ok(Self {
            logs_dir: data_dir.join("logs"),
            cores_dir: data_dir.join("cores"),
            backups_dir: data_dir.join("backups"),
            db_path: data_dir.join("r3x.db"),
            data_dir,
            config_dir,
            cache_dir,
        })
    }

    #[must_use]
    pub fn from_root(root: &Path) -> Self {
        let data_dir = root.join("data");
        Self {
            config_dir: root.join("config"),
            cache_dir: root.join("cache"),
            logs_dir: data_dir.join("logs"),
            cores_dir: data_dir.join("cores"),
            backups_dir: data_dir.join("backups"),
            db_path: data_dir.join("r3x.db"),
            data_dir,
        }
    }

    pub fn ensure_all_dirs(&self) -> Result<(), R3xError> {
        for dir in [
            &self.data_dir,
            &self.config_dir,
            &self.cache_dir,
            &self.logs_dir,
            &self.cores_dir,
            &self.backups_dir,
        ] {
            fs::create_dir_all(dir)?;
        }
        Ok(())
    }
}
