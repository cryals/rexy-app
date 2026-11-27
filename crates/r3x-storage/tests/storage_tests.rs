use chrono::Utc;
use r3x_domain::{
    AppSettings, AuthConfig, ConnectionHistoryEntry, ConnectionMode, CoreId, CorePreference,
    Endpoint, Profile, ProfileOptions, ProfileSource, ProtocolConfig, ProtocolType, RedactedSecret,
    RoutingRule, RuleAction, RuleMatcher, SecurityConfig, Subscription, SubscriptionImportSource,
    SubscriptionMetadata, SubscriptionStatus, ThemeMode, TransportConfig,
};
use r3x_storage::{AppPaths, MemorySecretStore, R3xDatabase, SecretStore, UnavailableSecretStore};
use tempfile::tempdir;
use uuid::Uuid;

fn sample_subscription() -> Subscription {
    let now = Utc::now();
    Subscription {
        id: Uuid::new_v4(),
        name: "Test Feed".to_owned(),
        source: SubscriptionImportSource::RemoteUrl {
            url: "https://example.invalid/sub".to_owned(),
        },
        enabled: true,
        pinned: true,
        status: SubscriptionStatus::Active,
        metadata: SubscriptionMetadata::default(),
        core_preference: CorePreference::Auto,
        last_updated_at: Some(now),
        last_error: None,
        server_count: 1,
        created_at: now,
        updated_at: now,
    }
}

fn sample_profile(sub_id: Option<Uuid>, name: &str) -> Profile {
    let now = Utc::now();
    Profile {
        id: Uuid::new_v4(),
        name: name.to_owned(),
        custom_name: None,
        source: match sub_id {
            Some(subscription_id) => ProfileSource::Subscription { subscription_id },
            None => ProfileSource::Manual,
        },
        protocol: ProtocolConfig::simple(ProtocolType::Vless),
        transport: TransportConfig::RawTcp { header_type: None },
        security: SecurityConfig::None,
        flow: None,
        endpoint: Endpoint {
            host: "203.0.113.5".to_owned(),
            port: 443,
            local_addresses: vec![],
            dns_servers: vec![],
        },
        auth: AuthConfig {
            inline_secret: Some(RedactedSecret::new("secret-token")),
            ..Default::default()
        },
        options: ProfileOptions::default(),
        core_preference: CorePreference::Auto,
        favorite: false,
        country_code: Some("DE".to_owned()),
        city: Some("Frankfurt".to_owned()),
        latency_ms: Some(25),
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn sqlite_migrations_crud_and_custom_name_preservation() {
    let db = R3xDatabase::open_in_memory().expect("open in memory");
    assert_eq!(db.schema_version().expect("version"), 1);

    let sub = sample_subscription();
    db.upsert_subscription(&sub).expect("upsert sub");
    assert_eq!(db.list_subscriptions().expect("list").len(), 1);

    let mut p = sample_profile(Some(sub.id), "Node A");
    p.custom_name = Some("My Favorite Node".to_owned());
    p.favorite = true;
    db.upsert_profile(&p).expect("upsert profile");

    let refreshed = sample_profile(Some(sub.id), "Node A");
    db.replace_subscription_profiles(sub.id, &[refreshed])
        .expect("replace profiles");

    let profiles = db.list_profiles().expect("list profiles");
    assert_eq!(profiles.len(), 1);
    assert!(profiles[0].favorite);
    assert_eq!(profiles[0].custom_name.as_deref(), Some("My Favorite Node"));

    let settings = AppSettings {
        theme_mode: ThemeMode::Amoled,
        ..AppSettings::default()
    };
    db.save_settings(&settings).expect("save settings");
    assert_eq!(
        db.load_settings().expect("load settings").theme_mode,
        ThemeMode::Amoled
    );

    let rule = RoutingRule {
        id: Uuid::new_v4(),
        name: "Bypass LAN".to_owned(),
        enabled: true,
        priority: 10,
        group: "default".to_owned(),
        matcher: RuleMatcher::GeoIp("private".to_owned()),
        action: RuleAction::Direct,
    };
    db.upsert_routing_rule(&rule).expect("upsert rule");
    assert_eq!(db.list_routing_rules().expect("list rules").len(), 1);

    let hist = ConnectionHistoryEntry {
        id: Uuid::new_v4(),
        profile_id: p.id,
        profile_name: "Node A".to_owned(),
        core_id: CoreId::Xray,
        mode: ConnectionMode::Tun,
        started_at: Utc::now(),
        ended_at: Some(Utc::now()),
        bytes_down: 1024,
        bytes_up: 512,
        disconnect_reason: "user_disconnect".to_owned(),
    };
    db.append_connection_history(&hist).expect("append history");
    assert_eq!(db.list_connection_history(10).expect("list hist").len(), 1);

    // Cascade delete subscription deletes child profiles
    db.delete_subscription(sub.id).expect("delete sub");
    assert!(
        db.list_profiles()
            .expect("list profiles after cascade")
            .is_empty()
    );
}

#[test]
fn corruption_recovery_quarantines_corrupt_db_and_recreates() {
    let dir = tempdir().expect("tempdir");
    let paths = AppPaths::from_root(dir.path());
    paths.ensure_all_dirs().expect("dirs");
    std::fs::write(&paths.db_path, b"NOT A SQLITE FILE CORRUPT GARBAGE 123456").expect("corrupt");

    let outcome = R3xDatabase::open_with_recovery(&paths.db_path).expect("recover");
    let quarantined = outcome
        .quarantined_corrupt_path
        .expect("should report quarantined path");
    assert!(quarantined.exists());
    assert_eq!(outcome.db.schema_version().expect("version"), 1);
}

#[test]
fn encrypted_backup_restore_and_secret_store_guarantees() {
    let db1 = R3xDatabase::open_in_memory().expect("db1");
    let profile = sample_profile(None, "Manual Node");
    db1.upsert_profile(&profile).expect("upsert");

    let envelope = db1
        .export_encrypted_backup("VeryStrongPassphrase99")
        .expect("backup");

    let db2 = R3xDatabase::open_in_memory().expect("db2");
    assert!(
        db2.restore_encrypted_backup(&envelope, "WrongPassphrase")
            .is_err()
    );
    db2.restore_encrypted_backup(&envelope, "VeryStrongPassphrase99")
        .expect("restore");
    assert_eq!(db2.list_profiles().expect("list").len(), 1);

    let mem_store = MemorySecretStore::new();
    mem_store.set_secret("k1", "v1").expect("set");
    assert_eq!(
        mem_store.get_secret("k1").expect("get"),
        Some("v1".to_owned())
    );
    mem_store.delete_secret("k1").expect("del");
    assert_eq!(mem_store.get_secret("k1").expect("get after del"), None);

    let unavailable = UnavailableSecretStore::new("locked");
    assert!(!unavailable.is_available());
    assert!(unavailable.set_secret("k", "v").is_err());
    assert!(unavailable.get_secret("k").is_err());
}
