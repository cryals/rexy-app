use chrono::Utc;
use r3x_domain::R3xError;
use rusqlite::Connection;

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "initial_schema",
    sql: r#"
CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    pinned INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    data_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY NOT NULL,
    subscription_id TEXT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    custom_name TEXT NULL,
    favorite INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL,
    latency_ms INTEGER NULL,
    data_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_profiles_sub ON profiles(subscription_id);
CREATE INDEX IF NOT EXISTS idx_profiles_fav ON profiles(favorite);

CREATE TABLE IF NOT EXISTS routing_rules (
    id TEXT PRIMARY KEY NOT NULL,
    priority INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    group_name TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_routing_priority ON routing_rules(priority);

CREATE TABLE IF NOT EXISTS rule_sets (
    id TEXT PRIMARY KEY NOT NULL,
    tag TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    data_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_profiles (
    id TEXT PRIMARY KEY NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 0,
    data_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY NOT NULL,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS connection_history (
    id TEXT PRIMARY KEY NOT NULL,
    profile_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_started ON connection_history(started_at DESC);

CREATE TABLE IF NOT EXISTS core_metadata (
    core_id TEXT PRIMARY KEY NOT NULL,
    manifest_json TEXT NOT NULL,
    install_state_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS diagnostic_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    generated_at TEXT NOT NULL,
    report_json TEXT NOT NULL
);
"#,
}];

pub fn apply_migrations(conn: &Connection) -> Result<(), R3xError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        );",
    )
    .map_err(|e| R3xError::Storage(format!("failed creating schema_migrations: {e}")))?;

    let current_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
        .map_err(|e| R3xError::Storage(format!("failed reading schema version: {e}")))?;

    for migration in MIGRATIONS {
        if migration.version > current_version {
            conn.execute_batch(migration.sql).map_err(|e| {
                R3xError::Storage(format!(
                    "migration v{} ({}) failed: {e}",
                    migration.version, migration.name
                ))
            })?;
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![migration.version, migration.name, Utc::now().to_rfc3339()],
            )
            .map_err(|e| {
                R3xError::Storage(format!(
                    "failed recording migration v{}: {e}",
                    migration.version
                ))
            })?;
        }
    }
    Ok(())
}

pub fn schema_version(conn: &Connection) -> Result<i64, R3xError> {
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )
    .map_err(|e| R3xError::Storage(format!("failed querying schema version: {e}")))
}
