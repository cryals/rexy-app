use crate::migrations::{apply_migrations, schema_version};
use chrono::Utc;
use parking_lot::Mutex;
use r3x_domain::{
    AppSettings, ConnectionHistoryEntry, CoreId, CoreInstallState, CoreManifest, DiagnosticReport,
    DnsConfig, Profile, ProfileSource, R3xError, RoutingRule, RuleSet, Subscription,
};
use r3x_security::{EncryptedEnvelope, decrypt_backup, encrypt_backup};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;
use uuid::Uuid;

#[derive(Debug)]
pub struct DatabaseOpenResult {
    pub db: R3xDatabase,
    pub quarantined_corrupt_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBundle {
    pub format_version: u32,
    pub exported_at: String,
    pub settings: AppSettings,
    pub dns: DnsConfig,
    pub subscriptions: Vec<Subscription>,
    pub profiles: Vec<Profile>,
    pub routing_rules: Vec<RoutingRule>,
    pub rule_sets: Vec<RuleSet>,
}

#[derive(Debug)]
pub struct R3xDatabase {
    conn: Mutex<Connection>,
}

impl R3xDatabase {
    pub fn open_with_recovery(path: &Path) -> Result<DatabaseOpenResult, R3xError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut quarantined_corrupt_path = None;
        if path.exists() {
            match Self::try_open_and_check(path) {
                Ok(conn) => {
                    return Ok(DatabaseOpenResult {
                        db: Self {
                            conn: Mutex::new(conn),
                        },
                        quarantined_corrupt_path: None,
                    });
                }
                Err(err) => {
                    let ts = Utc::now().format("%Y%m%dT%H%M%SZ");
                    let backup_name = format!(
                        "{}.corrupt.{ts}",
                        path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("r3x.db")
                    );
                    let quarantine = path.with_file_name(backup_name);
                    warn!(
                        error = %err,
                        quarantine = %quarantine.display(),
                        "SQLite database corruption detected; quarantining and recreating"
                    );
                    fs::rename(path, &quarantine)?;
                    for suffix in ["-wal", "-shm"] {
                        let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
                        if sidecar.exists() {
                            let _ = fs::remove_file(sidecar);
                        }
                    }
                    quarantined_corrupt_path = Some(quarantine);
                }
            }
        }

        let conn = Self::try_open_and_check(path)?;
        Ok(DatabaseOpenResult {
            db: Self {
                conn: Mutex::new(conn),
            },
            quarantined_corrupt_path,
        })
    }

    pub fn open_in_memory() -> Result<Self, R3xError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| R3xError::Storage(format!("failed opening in-memory db: {e}")))?;
        Self::configure_and_migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn try_open_and_check(path: &Path) -> Result<Connection, R3xError> {
        let conn = Connection::open(path)
            .map_err(|e| R3xError::Storage(format!("failed opening {}: {e}", path.display())))?;
        let check: String = conn
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|e| R3xError::Storage(format!("SQLite quick_check failed: {e}")))?;
        if !check.eq_ignore_ascii_case("ok") {
            return Err(R3xError::Storage(format!(
                "SQLite quick_check reported corruption: {check}"
            )));
        }
        Self::configure_and_migrate(&conn)?;
        Ok(conn)
    }

    fn configure_and_migrate(conn: &Connection) -> Result<(), R3xError> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )
        .map_err(|e| R3xError::Storage(format!("failed configuring SQLite pragmas: {e}")))?;
        apply_migrations(conn)
    }

    pub fn schema_version(&self) -> Result<i64, R3xError> {
        let conn = self.conn.lock();
        schema_version(&conn)
    }

    pub fn upsert_subscription(&self, sub: &Subscription) -> Result<(), R3xError> {
        let json = serde_json::to_string(sub)
            .map_err(|e| R3xError::Storage(format!("serialize subscription: {e}")))?;
        let status_str = serde_json::to_string(&sub.status)
            .map_err(|e| R3xError::Storage(format!("serialize status: {e}")))?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO subscriptions (id, name, enabled, pinned, status, data_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name,
               enabled = excluded.enabled,
               pinned = excluded.pinned,
               status = excluded.status,
               data_json = excluded.data_json,
               updated_at = excluded.updated_at",
            params![
                sub.id.to_string(),
                sub.name,
                i32::from(sub.enabled),
                i32::from(sub.pinned),
                status_str,
                json,
                sub.updated_at.to_rfc3339()
            ],
        )
        .map_err(|e| R3xError::Storage(format!("upsert subscription: {e}")))?;
        Ok(())
    }

    pub fn list_subscriptions(&self) -> Result<Vec<Subscription>, R3xError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT data_json FROM subscriptions ORDER BY pinned DESC, name ASC")
            .map_err(|e| R3xError::Storage(format!("prepare list_subscriptions: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| R3xError::Storage(format!("query list_subscriptions: {e}")))?;
        let mut items = Vec::new();
        for r in rows {
            let raw = r.map_err(|e| R3xError::Storage(e.to_string()))?;
            let sub: Subscription = serde_json::from_str(&raw)
                .map_err(|e| R3xError::Storage(format!("decode subscription: {e}")))?;
            items.push(sub);
        }
        Ok(items)
    }

    pub fn delete_subscription(&self, id: Uuid) -> Result<(), R3xError> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM subscriptions WHERE id = ?1",
            params![id.to_string()],
        )
        .map_err(|e| R3xError::Storage(format!("delete subscription: {e}")))?;
        Ok(())
    }

    pub fn upsert_profile(&self, profile: &Profile) -> Result<(), R3xError> {
        let sub_id = match &profile.source {
            ProfileSource::Subscription { subscription_id } => Some(subscription_id.to_string()),
            _ => None,
        };
        let protocol_str = format!("{:?}", profile.protocol.protocol_type);
        let json = serde_json::to_string(profile)
            .map_err(|e| R3xError::Storage(format!("serialize profile: {e}")))?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO profiles (id, subscription_id, name, custom_name, favorite, protocol, latency_ms, data_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
               subscription_id = excluded.subscription_id,
               name = excluded.name,
               custom_name = excluded.custom_name,
               favorite = excluded.favorite,
               protocol = excluded.protocol,
               latency_ms = excluded.latency_ms,
               data_json = excluded.data_json,
               updated_at = excluded.updated_at",
            params![
                profile.id.to_string(),
                sub_id,
                profile.name,
                profile.custom_name,
                i32::from(profile.favorite),
                protocol_str,
                profile.latency_ms.map(i64::from),
                json,
                profile.updated_at.to_rfc3339(),
            ],
        )
        .map_err(|e| R3xError::Storage(format!("upsert profile: {e}")))?;
        Ok(())
    }

    pub fn replace_subscription_profiles(
        &self,
        subscription_id: Uuid,
        profiles: &[Profile],
    ) -> Result<(), R3xError> {
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction()
            .map_err(|e| R3xError::Storage(format!("begin tx: {e}")))?;

        let existing = {
            let mut stmt = tx
                .prepare("SELECT data_json FROM profiles WHERE subscription_id = ?1")
                .map_err(|e| R3xError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map(params![subscription_id.to_string()], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(|e| R3xError::Storage(e.to_string()))?;
            let mut prev = Vec::new();
            for r in rows {
                let raw = r.map_err(|e| R3xError::Storage(e.to_string()))?;
                if let Ok(p) = serde_json::from_str::<Profile>(&raw) {
                    prev.push(p);
                }
            }
            prev
        };

        tx.execute(
            "DELETE FROM profiles WHERE subscription_id = ?1",
            params![subscription_id.to_string()],
        )
        .map_err(|e| R3xError::Storage(e.to_string()))?;

        for p in profiles {
            let mut merged = p.clone();
            if let Some(old) = existing
                .iter()
                .find(|e| e.dedup_fingerprint() == p.dedup_fingerprint())
            {
                merged.favorite = old.favorite || p.favorite;
                if merged.custom_name.is_none() {
                    merged.custom_name = old.custom_name.clone();
                }
            }
            let json = serde_json::to_string(&merged)
                .map_err(|e| R3xError::Storage(format!("serialize profile: {e}")))?;
            let protocol_str = format!("{:?}", merged.protocol.protocol_type);
            tx.execute(
                "INSERT INTO profiles (id, subscription_id, name, custom_name, favorite, protocol, latency_ms, data_json, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    merged.id.to_string(),
                    subscription_id.to_string(),
                    merged.name,
                    merged.custom_name,
                    i32::from(merged.favorite),
                    protocol_str,
                    merged.latency_ms.map(i64::from),
                    json,
                    merged.updated_at.to_rfc3339(),
                ],
            )
            .map_err(|e| R3xError::Storage(format!("insert profile in tx: {e}")))?;
        }

        tx.commit()
            .map_err(|e| R3xError::Storage(format!("commit replace profiles: {e}")))?;
        Ok(())
    }

    pub fn list_profiles(&self) -> Result<Vec<Profile>, R3xError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT data_json FROM profiles ORDER BY favorite DESC, name ASC")
            .map_err(|e| R3xError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| R3xError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            let raw = r.map_err(|e| R3xError::Storage(e.to_string()))?;
            let p: Profile = serde_json::from_str(&raw)
                .map_err(|e| R3xError::Storage(format!("decode profile: {e}")))?;
            out.push(p);
        }
        Ok(out)
    }

    pub fn get_profile(&self, id: Uuid) -> Result<Option<Profile>, R3xError> {
        let conn = self.conn.lock();
        let raw: Option<String> = conn
            .query_row(
                "SELECT data_json FROM profiles WHERE id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| R3xError::Storage(e.to_string()))?;
        raw.map(|s| {
            serde_json::from_str(&s).map_err(|e| R3xError::Storage(format!("decode profile: {e}")))
        })
        .transpose()
    }

    pub fn delete_profile(&self, id: Uuid) -> Result<(), R3xError> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM profiles WHERE id = ?1",
            params![id.to_string()],
        )
        .map_err(|e| R3xError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn save_settings(&self, settings: &AppSettings) -> Result<(), R3xError> {
        let json = serde_json::to_string(settings)
            .map_err(|e| R3xError::Storage(format!("serialize settings: {e}")))?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO settings (key, value_json, updated_at) VALUES ('app', ?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
            params![json, Utc::now().to_rfc3339()],
        )
        .map_err(|e| R3xError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn load_settings(&self) -> Result<AppSettings, R3xError> {
        let conn = self.conn.lock();
        let raw: Option<String> = conn
            .query_row(
                "SELECT value_json FROM settings WHERE key = 'app'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| R3xError::Storage(e.to_string()))?;
        match raw {
            Some(s) => serde_json::from_str(&s)
                .map_err(|e| R3xError::Storage(format!("decode settings: {e}"))),
            None => Ok(AppSettings::default()),
        }
    }

    pub fn save_dns_config(&self, dns: &DnsConfig) -> Result<(), R3xError> {
        let json = serde_json::to_string(dns)
            .map_err(|e| R3xError::Storage(format!("serialize dns: {e}")))?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO dns_profiles (id, is_active, data_json, updated_at) VALUES ('default', 1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at",
            params![json, Utc::now().to_rfc3339()],
        )
        .map_err(|e| R3xError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn load_dns_config(&self) -> Result<DnsConfig, R3xError> {
        let conn = self.conn.lock();
        let raw: Option<String> = conn
            .query_row(
                "SELECT data_json FROM dns_profiles WHERE is_active = 1 LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| R3xError::Storage(e.to_string()))?;
        match raw {
            Some(s) => {
                serde_json::from_str(&s).map_err(|e| R3xError::Storage(format!("decode dns: {e}")))
            }
            None => Ok(DnsConfig::default()),
        }
    }

    pub fn upsert_routing_rule(&self, rule: &RoutingRule) -> Result<(), R3xError> {
        let json = serde_json::to_string(rule)
            .map_err(|e| R3xError::Storage(format!("serialize routing rule: {e}")))?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO routing_rules (id, priority, enabled, group_name, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
               priority = excluded.priority,
               enabled = excluded.enabled,
               group_name = excluded.group_name,
               data_json = excluded.data_json",
            params![
                rule.id.to_string(),
                rule.priority,
                i32::from(rule.enabled),
                rule.group,
                json
            ],
        )
        .map_err(|e| R3xError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn list_routing_rules(&self) -> Result<Vec<RoutingRule>, R3xError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT data_json FROM routing_rules ORDER BY priority ASC")
            .map_err(|e| R3xError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| R3xError::Storage(e.to_string()))?;
        let mut rules = Vec::new();
        for r in rows {
            let raw = r.map_err(|e| R3xError::Storage(e.to_string()))?;
            let rule: RoutingRule = serde_json::from_str(&raw)
                .map_err(|e| R3xError::Storage(format!("decode rule: {e}")))?;
            rules.push(rule);
        }
        Ok(rules)
    }

    pub fn upsert_rule_set(&self, rs: &RuleSet) -> Result<(), R3xError> {
        let json = serde_json::to_string(rs)
            .map_err(|e| R3xError::Storage(format!("serialize rule set: {e}")))?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO rule_sets (id, tag, enabled, data_json) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET tag = excluded.tag, enabled = excluded.enabled, data_json = excluded.data_json",
            params![rs.id.to_string(), rs.tag, i32::from(rs.enabled), json],
        )
        .map_err(|e| R3xError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn list_rule_sets(&self) -> Result<Vec<RuleSet>, R3xError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT data_json FROM rule_sets ORDER BY tag ASC")
            .map_err(|e| R3xError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| R3xError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            let raw = r.map_err(|e| R3xError::Storage(e.to_string()))?;
            out.push(
                serde_json::from_str(&raw)
                    .map_err(|e| R3xError::Storage(format!("decode rule_set: {e}")))?,
            );
        }
        Ok(out)
    }

    pub fn append_connection_history(
        &self,
        entry: &ConnectionHistoryEntry,
    ) -> Result<(), R3xError> {
        let json = serde_json::to_string(entry)
            .map_err(|e| R3xError::Storage(format!("serialize history: {e}")))?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO connection_history (id, profile_id, started_at, ended_at, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET ended_at = excluded.ended_at, data_json = excluded.data_json",
            params![
                entry.id.to_string(),
                entry.profile_id.to_string(),
                entry.started_at.to_rfc3339(),
                entry.ended_at.map(|t| t.to_rfc3339()),
                json
            ],
        )
        .map_err(|e| R3xError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn list_connection_history(
        &self,
        limit: usize,
    ) -> Result<Vec<ConnectionHistoryEntry>, R3xError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT data_json FROM connection_history ORDER BY started_at DESC LIMIT ?1")
            .map_err(|e| R3xError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map(params![limit as i64], |row| row.get::<_, String>(0))
            .map_err(|e| R3xError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            let raw = r.map_err(|e| R3xError::Storage(e.to_string()))?;
            out.push(
                serde_json::from_str(&raw)
                    .map_err(|e| R3xError::Storage(format!("decode history: {e}")))?,
            );
        }
        Ok(out)
    }

    pub fn save_core_metadata(
        &self,
        manifest: &CoreManifest,
        install_state: &CoreInstallState,
    ) -> Result<(), R3xError> {
        let core_key =
            serde_json::to_string(&manifest.id).map_err(|e| R3xError::Storage(e.to_string()))?;
        let m_json =
            serde_json::to_string(manifest).map_err(|e| R3xError::Storage(e.to_string()))?;
        let s_json =
            serde_json::to_string(install_state).map_err(|e| R3xError::Storage(e.to_string()))?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO core_metadata (core_id, manifest_json, install_state_json, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(core_id) DO UPDATE SET
               manifest_json = excluded.manifest_json,
               install_state_json = excluded.install_state_json,
               updated_at = excluded.updated_at",
            params![core_key, m_json, s_json, Utc::now().to_rfc3339()],
        )
        .map_err(|e| R3xError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn load_core_metadata(
        &self,
        core_id: CoreId,
    ) -> Result<Option<(CoreManifest, CoreInstallState)>, R3xError> {
        let core_key =
            serde_json::to_string(&core_id).map_err(|e| R3xError::Storage(e.to_string()))?;
        let conn = self.conn.lock();
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT manifest_json, install_state_json FROM core_metadata WHERE core_id = ?1",
                params![core_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| R3xError::Storage(e.to_string()))?;
        match row {
            Some((m_raw, s_raw)) => {
                let m = serde_json::from_str(&m_raw)
                    .map_err(|e| R3xError::Storage(format!("decode manifest: {e}")))?;
                let s = serde_json::from_str(&s_raw)
                    .map_err(|e| R3xError::Storage(format!("decode install state: {e}")))?;
                Ok(Some((m, s)))
            }
            None => Ok(None),
        }
    }

    pub fn save_diagnostic_report(&self, report: &DiagnosticReport) -> Result<(), R3xError> {
        let json = serde_json::to_string(report)
            .map_err(|e| R3xError::Storage(format!("serialize report: {e}")))?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO diagnostic_results (generated_at, report_json) VALUES (?1, ?2)",
            params![report.generated_at.to_rfc3339(), json],
        )
        .map_err(|e| R3xError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn export_bundle(&self) -> Result<ExportBundle, R3xError> {
        Ok(ExportBundle {
            format_version: 1,
            exported_at: Utc::now().to_rfc3339(),
            settings: self.load_settings()?,
            dns: self.load_dns_config()?,
            subscriptions: self.list_subscriptions()?,
            profiles: self.list_profiles()?,
            routing_rules: self.list_routing_rules()?,
            rule_sets: self.list_rule_sets()?,
        })
    }

    pub fn import_bundle(&self, bundle: &ExportBundle) -> Result<(), R3xError> {
        if bundle.format_version != 1 {
            return Err(R3xError::Validation(format!(
                "unsupported export bundle version {}",
                bundle.format_version
            )));
        }
        self.save_settings(&bundle.settings)?;
        self.save_dns_config(&bundle.dns)?;
        for sub in &bundle.subscriptions {
            self.upsert_subscription(sub)?;
        }
        for profile in &bundle.profiles {
            self.upsert_profile(profile)?;
        }
        for rule in &bundle.routing_rules {
            self.upsert_routing_rule(rule)?;
        }
        for rs in &bundle.rule_sets {
            self.upsert_rule_set(rs)?;
        }
        Ok(())
    }

    pub fn export_encrypted_backup(&self, passphrase: &str) -> Result<EncryptedEnvelope, R3xError> {
        let bundle = self.export_bundle()?;
        let bytes = serde_json::to_vec(&bundle)
            .map_err(|e| R3xError::Storage(format!("serialize bundle: {e}")))?;
        encrypt_backup(&bytes, passphrase)
    }

    pub fn restore_encrypted_backup(
        &self,
        envelope: &EncryptedEnvelope,
        passphrase: &str,
    ) -> Result<(), R3xError> {
        let plain = decrypt_backup(envelope, passphrase)?;
        let bundle: ExportBundle = serde_json::from_slice(&plain)
            .map_err(|e| R3xError::Validation(format!("corrupt backup bundle JSON: {e}")))?;
        self.import_bundle(&bundle)
    }
}
