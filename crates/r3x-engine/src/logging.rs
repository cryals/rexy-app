use chrono::Utc;
use parking_lot::Mutex;
use r3x_domain::{LogCategory, LogEntry, LogLevel, RingBuffer};
use r3x_security::Redactor;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::broadcast;

const MAX_COMBINED_ENTRIES: usize = 5000;
const MAX_CATEGORY_ENTRIES: usize = 1500;
const MAX_LOG_FILE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_ROTATED_FILES: usize = 5;

struct LogState {
    combined: RingBuffer<LogEntry>,
    by_category: HashMap<LogCategory, RingBuffer<LogEntry>>,
    log_dir: Option<PathBuf>,
}

pub struct LogHub {
    next_id: AtomicU64,
    state: Mutex<LogState>,
    tx: broadcast::Sender<LogEntry>,
}

impl LogHub {
    #[must_use]
    pub fn new(log_dir: Option<PathBuf>) -> Self {
        if let Some(ref dir) = log_dir {
            let _ = fs::create_dir_all(dir);
        }
        let (tx, _) = broadcast::channel(512);
        Self {
            next_id: AtomicU64::new(1),
            state: Mutex::new(LogState {
                combined: RingBuffer::new(MAX_COMBINED_ENTRIES),
                by_category: HashMap::new(),
                log_dir,
            }),
            tx,
        }
    }

    pub fn record(
        &self,
        category: LogCategory,
        level: LogLevel,
        source: impl Into<String>,
        message: impl AsRef<str>,
    ) -> LogEntry {
        let raw = LogEntry {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            timestamp: Utc::now(),
            category,
            level,
            source: source.into(),
            message: message.as_ref().to_owned(),
        };
        self.push_entry(raw)
    }

    pub fn push_entry(&self, entry: LogEntry) -> LogEntry {
        let mut clean = Redactor::redact_log_entry(&entry);
        if clean.id == 0 {
            clean.id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }

        {
            let mut guard = self.state.lock();
            guard.combined.push(clean.clone());
            guard
                .by_category
                .entry(clean.category)
                .or_insert_with(|| RingBuffer::new(MAX_CATEGORY_ENTRIES))
                .push(clean.clone());

            if let Some(ref dir) = guard.log_dir {
                Self::append_rotating_file(dir, &clean);
            }
        }

        let _ = self.tx.send(clean.clone());
        clean
    }

    fn append_rotating_file(dir: &Path, entry: &LogEntry) {
        let active = dir.join("r3x.log");
        if let Ok(meta) = fs::metadata(&active)
            && meta.len() >= MAX_LOG_FILE_BYTES
        {
            for idx in (1..MAX_ROTATED_FILES).rev() {
                let src = dir.join(format!("r3x.log.{idx}"));
                let dst = dir.join(format!("r3x.log.{}", idx + 1));
                if src.exists() {
                    let _ = fs::rename(&src, &dst);
                }
            }
            let _ = fs::rename(&active, dir.join("r3x.log.1"));
        }

        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&active) {
            let line = format!(
                "{} [{:?}] [{:?}] {}: {}\n",
                entry.timestamp.to_rfc3339(),
                entry.level,
                entry.category,
                entry.source,
                entry.message
            );
            let _ = file.write_all(line.as_bytes());
        }
    }

    #[must_use]
    pub fn recent(&self, category: Option<LogCategory>, limit: usize) -> Vec<LogEntry> {
        let guard = self.state.lock();
        let iter: Box<dyn Iterator<Item = &LogEntry> + '_> = match category {
            Some(cat) => match guard.by_category.get(&cat) {
                Some(buf) => Box::new(buf.iter()),
                None => return Vec::new(),
            },
            None => Box::new(guard.combined.iter()),
        };
        let all: Vec<LogEntry> = iter.cloned().collect();
        let start = all.len().saturating_sub(limit);
        all[start..].to_vec()
    }

    pub fn clear(&self, category: Option<LogCategory>) {
        let mut guard = self.state.lock();
        match category {
            Some(cat) => {
                if let Some(buf) = guard.by_category.get_mut(&cat) {
                    buf.clear();
                }
            }
            None => {
                guard.combined.clear();
                guard.by_category.clear();
            }
        }
    }

    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        self.tx.subscribe()
    }
}
