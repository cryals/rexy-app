use chrono::Utc;
use r3x_diagnostics::{
    DiagnosticContext, NetworkDoctor, RoutingManager, TelemetryHub, build_area_path,
    build_line_path, check_dns_leaks, default_rule_presets, export_redacted_report,
    measure_tcp_latency, preview_core_routing, test_dns_resolver, validate_dns_config,
    validate_rule,
};
use r3x_domain::{
    AppSettings, CoreId, DiagnosticCheckId, DnsConfig, DnsLeakProtectionMode, DnsMode, DnsResolver,
    Profile, ProfileSource, ProtocolConfig, ProtocolType, RedactedSecret, RoutingRule, RuleAction,
    RuleMatcher, SecurityConfig, TimeRange, TrafficSample, TransportConfig,
};
use r3x_engine::{EngineConfig, LogHub, R3xEngine};
use r3x_storage::R3xDatabase;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use uuid::Uuid;

#[test]
fn routing_manager_crud_validation_and_core_previews() {
    let db = Arc::new(R3xDatabase::open_in_memory().expect("db"));
    let mgr = RoutingManager::new(Arc::clone(&db));

    let added = mgr.install_default_presets().expect("presets");
    assert_eq!(added, default_rule_presets().len());

    let invalid = RoutingRule {
        id: Uuid::new_v4(),
        name: "BadIP".to_owned(),
        enabled: true,
        priority: 5,
        group: "Test".to_owned(),
        matcher: RuleMatcher::Ip("not-an-ip".to_owned()),
        action: RuleAction::Direct,
    };
    assert!(validate_rule(&invalid).is_err());

    let custom = RoutingRule {
        id: Uuid::new_v4(),
        name: "Bypass API".to_owned(),
        enabled: true,
        priority: 1,
        group: "Custom".to_owned(),
        matcher: RuleMatcher::DomainSuffix("example.invalid".to_owned()),
        action: RuleAction::Proxy,
    };
    mgr.upsert_rule(&custom).expect("upsert");
    let rules = mgr.list_rules_sorted().expect("list");
    assert_eq!(rules[0].name, "Bypass API");

    let xray_preview = preview_core_routing(CoreId::Xray, &rules);
    assert!(
        xray_preview["rules"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    );
    let sb_preview = preview_core_routing(CoreId::SingBox, &rules);
    assert!(
        sb_preview["rules"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    );
    let mh_preview = preview_core_routing(CoreId::Mihomo, &rules);
    assert!(
        mh_preview["rules"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    );

    let exported = mgr.export_rules_json().expect("export");
    mgr.delete_rule(custom.id).expect("delete");
    let imported = mgr.import_rules_json(&exported).expect("reimport");
    assert!(imported >= 2);
}

#[tokio::test]
async fn dns_validation_local_probe_and_leak_check() {
    let mut bad = DnsConfig::default();
    bad.primary.mode = DnsMode::DoH;
    bad.primary.address = "http://insecure.invalid/dns-query".to_owned();
    assert!(validate_dns_config(&bad).is_err());

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let resolver = DnsResolver {
        tag: "local-custom".to_owned(),
        mode: DnsMode::Custom,
        address: addr.to_string(),
        bootstrap_ip: None,
    };
    let probe = test_dns_resolver(&resolver, Duration::from_secs(2)).await;
    assert!(probe.reachable);

    let cfg = DnsConfig {
        leak_protection: DnsLeakProtectionMode::StrictTunnelOnly,
        ..DnsConfig::default()
    };
    let leak_inactive = check_dns_leaks(&cfg, false);
    assert_eq!(
        leak_inactive.status,
        r3x_domain::DiagnosticStatus::NotTested
    );
    let leak_active = check_dns_leaks(&cfg, true);
    assert_eq!(leak_active.status, r3x_domain::DiagnosticStatus::Passed);
}

#[tokio::test]
async fn network_doctor_executes_all_16_checks_and_redacts_export() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            if listener.accept().await.is_err() {
                break;
            }
        }
    });

    let db = Arc::new(R3xDatabase::open_in_memory().expect("db"));
    let logs = Arc::new(LogHub::new(None));
    let engine = Arc::new(R3xEngine::new(EngineConfig::default(), logs));

    let secret_token = "99999999-8888-7777-6666-555555555555";
    let profile = Profile {
        id: Uuid::new_v4(),
        name: format!("vless://{secret_token}@127.0.0.1:{}", addr.port()),
        custom_name: Some("DoctorProbeNode".to_owned()),
        source: ProfileSource::Manual,
        protocol: ProtocolConfig::simple(ProtocolType::Vless),
        transport: TransportConfig::RawTcp { header_type: None },
        security: SecurityConfig::None,
        flow: None,
        endpoint: r3x_domain::Endpoint {
            host: "127.0.0.1".to_owned(),
            port: addr.port(),
            local_addresses: Vec::new(),
            dns_servers: Vec::new(),
        },
        auth: r3x_domain::AuthConfig {
            inline_secret: Some(RedactedSecret::new(secret_token)),
            ..Default::default()
        },
        options: Default::default(),
        core_preference: r3x_domain::CorePreference::Auto,
        favorite: false,
        country_code: Some("XX".to_owned()),
        city: None,
        latency_ms: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let doctor = NetworkDoctor::new(DiagnosticContext {
        db,
        engine,
        active_profile: Some(profile),
        settings: AppSettings::default(),
        dns: DnsConfig::default(),
        connectivity_probe_addr: Some(addr.to_string()),
        tls_probe_url: Some(format!("http://{addr}/")),
        dns_lookup_host: Some("localhost:80".to_owned()),
    });

    let report = doctor.run_all().await;
    assert_eq!(report.results.len(), DiagnosticCheckId::all().len());
    assert_eq!(report.results.len(), 16);

    let json_report = export_redacted_report(&report);
    assert!(!json_report.contains(secret_token));
}

#[tokio::test]
async fn telemetry_hub_pause_sysinfo_latency_and_svg_paths() {
    let hub = TelemetryHub::new();
    hub.record_traffic(TrafficSample {
        timestamp: Utc::now(),
        down_bps: 1_500_000,
        up_bps: 250_000,
        total_down_bytes: 1024,
        total_up_bytes: 512,
    });
    hub.record_traffic(TrafficSample {
        timestamp: Utc::now(),
        down_bps: 3_000_000,
        up_bps: 500_000,
        total_down_bytes: 2048,
        total_up_bytes: 768,
    });
    assert_eq!(hub.traffic_for_range(TimeRange::OneMin).len(), 2);

    hub.set_paused(true);
    hub.record_traffic(TrafficSample {
        timestamp: Utc::now(),
        down_bps: 999,
        up_bps: 999,
        total_down_bytes: 0,
        total_up_bytes: 0,
    });
    assert_eq!(hub.traffic_len(), 2);
    hub.set_paused(false);

    let res = hub.sample_resources(None);
    assert!(res.ui_rss_bytes.unwrap_or(0) > 0);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let rtt = measure_tcp_latency("127.0.0.1", port, Duration::from_secs(2))
        .await
        .expect("rtt");
    assert!(rtt >= 1);

    assert_eq!(build_line_path(&[10.0], 600.0, 180.0, None), "");
    let line = build_line_path(&[0.0, 50.0, 100.0], 600.0, 180.0, Some(100.0));
    assert!(line.starts_with("M "));
    assert!(line.contains(" L "));
    let area = build_area_path(&[0.0, 50.0, 100.0], 600.0, 180.0, Some(100.0));
    assert!(area.ends_with(" Z"));
}
