use chrono::Utc;
use r3x_domain::{
    AppSettings, AuthConfig, ConnectionState, CorePreference, Endpoint, FlowType, Profile,
    ProfileOptions, ProfileSource, ProtocolConfig, ProtocolType, RedactedSecret, RingBuffer,
    SecurityConfig, SubscriptionMetadata, TlsSettings, TransportConfig,
};
use uuid::Uuid;

#[test]
fn fsm_legal_and_illegal_transitions() {
    assert!(ConnectionState::Disconnected.can_transition_to(&ConnectionState::Preparing));
    assert!(!ConnectionState::Disconnected.can_transition_to(&ConnectionState::Connected));
    assert!(!ConnectionState::Preparing.can_transition_to(&ConnectionState::Connected));
    assert!(ConnectionState::Connecting.can_transition_to(&ConnectionState::Connected));
    assert!(ConnectionState::Connected.can_transition_to(&ConnectionState::Disconnecting));
    assert!(
        ConnectionState::Connected.can_transition_to(&ConnectionState::Reconnecting { attempt: 1 })
    );
    assert!(ConnectionState::Disconnecting.can_transition_to(&ConnectionState::Disconnected));
}

#[test]
fn ring_buffer_bounds_and_fifo_eviction() {
    let mut ring = RingBuffer::new(3);
    assert!(ring.is_empty());
    ring.push(10);
    ring.push(20);
    ring.push(30);
    ring.push(40);
    assert_eq!(ring.len(), 3);
    assert_eq!(ring.capacity(), 3);
    let collected: Vec<i32> = ring.iter().copied().collect();
    assert_eq!(collected, vec![20, 30, 40]);
    assert_eq!(ring.latest(), Some(&40));
}

#[test]
fn auth_config_debug_redacts_secrets() {
    let auth = AuthConfig {
        username: Some("alice".to_owned()),
        secret_ref: None,
        inline_secret: Some(RedactedSecret::new("super-secret-uuid-1234")),
        secondary_secret: Some(RedactedSecret::new("secondary-secret-999")),
        public_key: None,
        preshared_secret: None,
    };
    let rendered = format!("{auth:?}");
    assert!(!rendered.contains("super-secret-uuid-1234"));
    assert!(!rendered.contains("secondary-secret-999"));
    assert!(rendered.contains("[REDACTED]"));
}

#[test]
fn unlimited_subscription_has_no_percentage_ratio() {
    let unlimited = SubscriptionMetadata {
        upload_bytes: 100_000,
        download_bytes: 900_000_000,
        total_bytes: None,
        ..Default::default()
    };
    assert!(unlimited.is_unlimited());
    assert_eq!(unlimited.usage_ratio(), None);

    let zero_limit = SubscriptionMetadata {
        total_bytes: Some(0),
        ..unlimited.clone()
    };
    assert!(zero_limit.is_unlimited());
    assert_eq!(zero_limit.usage_ratio(), None);

    let metered = SubscriptionMetadata {
        upload_bytes: 25,
        download_bytes: 25,
        total_bytes: Some(100),
        ..Default::default()
    };
    assert!(!metered.is_unlimited());
    assert_eq!(metered.usage_ratio(), Some(0.5));
}

#[test]
fn profile_and_settings_serde_roundtrip() {
    let now = Utc::now();
    let profile = Profile {
        id: Uuid::new_v4(),
        name: "Germany One".to_owned(),
        custom_name: Some("DE Frankfurt".to_owned()),
        source: ProfileSource::Manual,
        protocol: ProtocolConfig::simple(ProtocolType::Vless),
        transport: TransportConfig::Xhttp {
            path: "/xhttp".to_owned(),
            host: Some("cdn.example.invalid".to_owned()),
            mode: Some("auto".to_owned()),
        },
        security: SecurityConfig::Tls(TlsSettings {
            sni: Some("cdn.example.invalid".to_owned()),
            alpn: vec!["h2".to_owned()],
            fingerprint: Some("chrome".to_owned()),
            allow_insecure: false,
            ech_config: None,
        }),
        flow: Some(FlowType::XtlsRprxVision),
        endpoint: Endpoint {
            host: "203.0.113.10".to_owned(),
            port: 443,
            local_addresses: vec![],
            dns_servers: vec![],
        },
        auth: AuthConfig {
            inline_secret: Some(RedactedSecret::new("11111111-1111-1111-1111-111111111111")),
            ..Default::default()
        },
        options: ProfileOptions::default(),
        core_preference: CorePreference::Auto,
        favorite: true,
        country_code: Some("DE".to_owned()),
        city: Some("Frankfurt".to_owned()),
        latency_ms: Some(24),
        created_at: now,
        updated_at: now,
    };

    let json = serde_json::to_string(&profile).expect("profile serialization");
    let decoded: Profile = serde_json::from_str(&json).expect("profile deserialization");
    assert_eq!(profile, decoded);
    assert_eq!(decoded.effective_name(), "DE Frankfurt");

    let settings = AppSettings::default();
    let s_json = serde_json::to_string(&settings).expect("settings serialization");
    let s_decoded: AppSettings = serde_json::from_str(&s_json).expect("settings deserialization");
    assert_eq!(settings, s_decoded);
}
