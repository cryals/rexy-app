use flate2::read::GzDecoder;
use r3x_domain::R3xError;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use tar::{Archive, EntryType};
use zip::ZipArchive;

#[derive(Debug, Clone, Copy)]
pub struct ArchiveLimits {
    pub max_file_count: usize,
    pub max_total_bytes: u64,
    pub max_single_file_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_file_count: 512,
            max_total_bytes: 256 * 1024 * 1024,
            max_single_file_bytes: 128 * 1024 * 1024,
        }
    }
}

pub fn validate_relative_archive_path(raw: &Path) -> Result<PathBuf, R3xError> {
    if raw.is_absolute() {
        return Err(R3xError::SecurityViolation(format!(
            "archive entry contains absolute path: {}",
            raw.display()
        )));
    }
    let raw_str = raw.to_string_lossy();
    if raw_str.contains('\\') && raw_str.starts_with("\\\\") {
        return Err(R3xError::SecurityViolation(
            "archive entry contains UNC prefix".to_owned(),
        ));
    }
    let mut sanitized = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Normal(part) => {
                let s = part.to_string_lossy();
                if s.contains(':') {
                    return Err(R3xError::SecurityViolation(format!(
                        "archive entry contains drive/colon prefix: {s}"
                    )));
                }
                sanitized.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(R3xError::SecurityViolation(format!(
                    "archive entry attempts path traversal: {}",
                    raw.display()
                )));
            }
        }
    }
    if sanitized.as_os_str().is_empty() {
        return Err(R3xError::SecurityViolation(
            "archive entry resolved to empty path".to_owned(),
        ));
    }
    Ok(sanitized)
}

fn ensure_within_dest(dest_root: &Path, candidate: &Path) -> Result<PathBuf, R3xError> {
    let canonical_root = dest_root
        .canonicalize()
        .map_err(|e| R3xError::Storage(format!("failed to canonicalize dest root: {e}")))?;
    if let Some(parent) = candidate.parent() {
        fs::create_dir_all(parent)?;
        let canonical_parent = parent.canonicalize()?;
        if !canonical_parent.starts_with(&canonical_root) {
            return Err(R3xError::SecurityViolation(format!(
                "resolved target escapes destination root: {}",
                candidate.display()
            )));
        }
    }
    Ok(candidate.to_path_buf())
}

pub fn extract_zip_safely(
    archive_path: &Path,
    dest_dir: &Path,
    limits: ArchiveLimits,
) -> Result<Vec<PathBuf>, R3xError> {
    fs::create_dir_all(dest_dir)?;
    let file = File::open(archive_path)?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| R3xError::Validation(format!("invalid zip archive: {e}")))?;

    if archive.len() > limits.max_file_count {
        return Err(R3xError::SecurityViolation(format!(
            "zip entry count {} exceeds limit {}",
            archive.len(),
            limits.max_file_count
        )));
    }

    let mut total_written: u64 = 0;
    let mut extracted = Vec::new();

    for idx in 0..archive.len() {
        let entry = archive
            .by_index(idx)
            .map_err(|e| R3xError::Validation(format!("corrupt zip entry {idx}: {e}")))?;

        let rel = entry
            .enclosed_name()
            .ok_or_else(|| {
                let name = entry
                    .name()
                    .map(|n| n.into_owned())
                    .unwrap_or_else(|_| "<invalid-name>".to_owned());
                R3xError::SecurityViolation(format!("zip entry '{name}' has unsafe path"))
            })?
            .to_path_buf();
        let safe_rel = validate_relative_archive_path(&rel)?;

        if entry.is_symlink() {
            return Err(R3xError::SecurityViolation(format!(
                "symlinks are forbidden in core archives: {}",
                safe_rel.display()
            )));
        }

        let target = ensure_within_dest(dest_dir, &dest_dir.join(&safe_rel))?;
        if entry.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }

        if entry.size() > limits.max_single_file_bytes {
            return Err(R3xError::SecurityViolation(format!(
                "zip entry {} declares size {} exceeding limit {}",
                safe_rel.display(),
                entry.size(),
                limits.max_single_file_bytes
            )));
        }

        let mut out_file = File::create(&target)?;
        let mut limited = entry.take(limits.max_single_file_bytes.saturating_add(1));
        let copied = io::copy(&mut limited, &mut out_file)?;
        if copied > limits.max_single_file_bytes {
            let _ = fs::remove_file(&target);
            return Err(R3xError::SecurityViolation(format!(
                "zip entry {} exceeded single-file decompressed limit",
                safe_rel.display()
            )));
        }
        total_written = total_written.saturating_add(copied);
        if total_written > limits.max_total_bytes {
            let _ = fs::remove_file(&target);
            return Err(R3xError::SecurityViolation(format!(
                "zip archive exceeded total decompressed limit of {} bytes",
                limits.max_total_bytes
            )));
        }
        extracted.push(target);
    }

    Ok(extracted)
}

pub fn extract_targz_safely(
    archive_path: &Path,
    dest_dir: &Path,
    limits: ArchiveLimits,
) -> Result<Vec<PathBuf>, R3xError> {
    fs::create_dir_all(dest_dir)?;
    let file = File::open(archive_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    let mut file_count: usize = 0;
    let mut total_written: u64 = 0;
    let mut extracted = Vec::new();

    let entries = archive
        .entries()
        .map_err(|e| R3xError::Validation(format!("invalid tar.gz archive: {e}")))?;

    for entry_res in entries {
        let entry =
            entry_res.map_err(|e| R3xError::Validation(format!("corrupt tar entry: {e}")))?;
        file_count = file_count.saturating_add(1);
        if file_count > limits.max_file_count {
            return Err(R3xError::SecurityViolation(format!(
                "tar.gz entry count exceeds limit {}",
                limits.max_file_count
            )));
        }

        let entry_type = entry.header().entry_type();
        if entry_type == EntryType::Symlink || entry_type == EntryType::Link {
            return Err(R3xError::SecurityViolation(
                "symlinks and hardlinks are forbidden in core archives".to_owned(),
            ));
        }

        let raw_path = entry
            .path()
            .map_err(|e| R3xError::Validation(format!("invalid tar path: {e}")))?
            .into_owned();
        let safe_rel = validate_relative_archive_path(&raw_path)?;
        let target = ensure_within_dest(dest_dir, &dest_dir.join(&safe_rel))?;

        if entry_type.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        if !entry_type.is_file() {
            continue;
        }

        let declared_size = entry.header().size().unwrap_or(0);
        if declared_size > limits.max_single_file_bytes {
            return Err(R3xError::SecurityViolation(format!(
                "tar entry {} size {} exceeds limit {}",
                safe_rel.display(),
                declared_size,
                limits.max_single_file_bytes
            )));
        }

        let mut out_file = File::create(&target)?;
        let mut limited = entry.take(limits.max_single_file_bytes.saturating_add(1));
        let copied = io::copy(&mut limited, &mut out_file)?;
        if copied > limits.max_single_file_bytes {
            let _ = fs::remove_file(&target);
            return Err(R3xError::SecurityViolation(format!(
                "tar entry {} exceeded single-file decompressed limit",
                safe_rel.display()
            )));
        }
        total_written = total_written.saturating_add(copied);
        if total_written > limits.max_total_bytes {
            let _ = fs::remove_file(&target);
            return Err(R3xError::SecurityViolation(format!(
                "tar.gz archive exceeded total limit of {} bytes",
                limits.max_total_bytes
            )));
        }
        extracted.push(target);
    }

    Ok(extracted)
}
