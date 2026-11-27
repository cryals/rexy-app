use chrono::Utc;
use r3x_cores::{
    CoreManager, MihomoAdapter, SingBoxAdapter, SupervisedProcess, XrayAdapter,
    default_core_manifests, probe_tcp_ready,
};
use r3x_domain::{
    AuthConfig, ConnectionMode, CoreId, CorePreference, DnsConfig, Endpoint, LogEntry, Profile,
    ProfileOptions, ProfileSource, ProtocolConfig, ProtocolType, RealitySettings, RedactedSecret,
    RoutingRule, RuleAction, RuleMatcher, SecurityConfig, TransportConfig,
};
use r3x_engine::{CoreAdapter, CoreConfigContext};
use r3x_security::compute_sha256_bytes;
use serde_json::Value;
use std::fs::File;
use std::io::Write;
use std::net::TcpListener;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::mpsc;
use uuid::Uuid;

fn sample_ctx(profile: Profile, mode: ConnectionMode, dir: &std::path::Path) -> CoreConfigContext {
    CoreConfigContext {
        profile,
        mode,
        dns: DnsConfig::default(),
        routing_rules: vec![RoutingRule {
            id: Uuid::new_v4(),
            name: "Bypass CN".to_owned(),
            enabled: true,
            priority: 1,
            group: "default".to_owned(),
            matcher: RuleMatcher::GeoIp("private".to_owned()),
            action: RuleAction::Direct,
        }],
        work_dir: dir.to_path_buf(),
        mixed_port: 10808,
        socks_port: 10809,
        http_port: 10810,
        ipv6_enabled: false,
        allow_lan: false,
        tun_interface_name: "r3x-tun0".to_owned(),
        tun_fd: None,
    }
}

fn sample_vless_reality() -> Profile {
    let now = Utc::now();
    Profile {
        id: Uuid::new_v4(),
        name: "DE Reality".to_owned(),
        custom_name: None,
        source: ProfileSource::Manual,
        protocol: ProtocolConfig::simple(ProtocolType::Vless),
        transport: TransportConfig::Xhttp {
            path: "/xhttp".to_owned(),
            host: Some("cdn.example.invalid".to_owned()),
            mode: Some("auto".to_owned()),
        },
        security: SecurityConfig::Reality(RealitySettings {
            sni: "cdn.example.invalid".to_owned(),
            public_key: "pubkey".to_owned(),
            short_id: "1234".to_owned(),
            spider_x: None,
            fingerprint: Some("chrome".to_owned()),
        }),
        flow: Some(r3x_domain::FlowType::XtlsRprxVision),
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
        favorite: false,
        country_code: Some("DE".to_owned()),
        city: Some("Frankfurt".to_owned()),
        latency_ms: Some(24),
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn all_14_core_manifests_parse_cleanly() {
    let manifests = default_core_manifests().expect("manifests");
    assert_eq!(manifests.len(), 14);
    assert!(manifests.iter().any(|m| m.id == CoreId::Xray));
    assert!(manifests.iter().any(|m| m.id == CoreId::SingBox));
    assert!(manifests.iter().any(|m| m.id == CoreId::Mihomo));
}

#[tokio::test]
async fn xray_singbox_and_mihomo_generate_valid_configs_and_cleanup() {
    let dir = tempdir().expect("tempdir");
    let vless = sample_vless_reality();

    let xray = XrayAdapter::new(None);
    let xcfg = xray
        .generate_config(&sample_ctx(
            vless.clone(),
            ConnectionMode::SystemProxy,
            dir.path(),
        ))
        .await
        .expect("xray config");
    let xjson: Value = serde_json::from_str(&xcfg.config_contents).expect("valid xray json");
    assert_eq!(xjson["outbounds"][0]["protocol"], "vless");
    assert_eq!(xjson["outbounds"][0]["streamSettings"]["network"], "xhttp");
    assert_eq!(
        xjson["outbounds"][0]["streamSettings"]["security"],
        "reality"
    );

    let mut hy2 = vless.clone();
    hy2.protocol = ProtocolConfig::simple(ProtocolType::Hysteria2);
    hy2.transport = TransportConfig::Quic {
        security: Some("tls".to_owned()),
        header_type: None,
    };
    hy2.security = SecurityConfig::None;
    hy2.flow = None;

    let sb = SingBoxAdapter::new(None);
    let scfg = sb
        .generate_config(&sample_ctx(hy2.clone(), ConnectionMode::Tun, dir.path()))
        .await
        .expect("sing-box config");
    let sjson: Value = serde_json::from_str(&scfg.config_contents).expect("valid sb json");
    assert_eq!(sjson["inbounds"][0]["type"], "tun");
    assert_eq!(sjson["outbounds"][0]["type"], "hysteria2");

    let mihomo = MihomoAdapter::new(None);
    let mcfg = mihomo
        .generate_config(&sample_ctx(hy2, ConnectionMode::Mixed, dir.path()))
        .await
        .expect("mihomo config");
    let myaml: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&mcfg.config_contents).expect("valid mihomo yaml");
    assert_eq!(myaml["proxies"][0]["type"], "hysteria2");
    assert_eq!(myaml["tun"]["enable"], true);

    xray.cleanup(dir.path()).await.expect("cleanup");
    assert!(!dir.path().exists());
}

#[test]
fn core_manager_installs_verifies_rolls_back_and_uninstalls() {
    let dir = tempdir().expect("tempdir");
    let mgr = CoreManager::new(dir.path().join("cores"), None);
    let bin_name = CoreManager::binary_filename(CoreId::Xray);

    let zip_v1 = dir.path().join("xray-v1.zip");
    {
        let f = File::create(&zip_v1).expect("zip1");
        let mut zw = zip::ZipWriter::new(f);
        zw.start_file(bin_name, zip::write::SimpleFileOptions::default())
            .expect("entry1");
        zw.write_all(b"xray-binary-v1").expect("w1");
        zw.finish().expect("fin1");
    }
    let sha1 = compute_sha256_bytes(&std::fs::read(&zip_v1).expect("read1"));

    // Reject mismatched checksum
    assert!(
        mgr.install_from_archive(CoreId::Xray, "1.0.0", &zip_v1, &"f".repeat(64))
            .is_err()
    );

    let r1 = mgr
        .install_from_archive(CoreId::Xray, "1.0.0", &zip_v1, &sha1)
        .expect("install v1");
    assert_eq!(r1.version, "1.0.0");

    let zip_v2 = dir.path().join("xray-v2.zip");
    {
        let f = File::create(&zip_v2).expect("zip2");
        let mut zw = zip::ZipWriter::new(f);
        zw.start_file(bin_name, zip::write::SimpleFileOptions::default())
            .expect("entry2");
        zw.write_all(b"xray-binary-v2").expect("w2");
        zw.finish().expect("fin2");
    }
    let sha2 = compute_sha256_bytes(&std::fs::read(&zip_v2).expect("read2"));
    let r2 = mgr
        .install_from_archive(CoreId::Xray, "2.0.0", &zip_v2, &sha2)
        .expect("install v2");
    assert_eq!(r2.version, "2.0.0");
    assert!(mgr.verify_installed_binary(CoreId::Xray).is_ok());

    let rolled = mgr.rollback(CoreId::Xray).expect("rollback");
    assert_eq!(rolled.version, "1.0.0");

    mgr.uninstall(CoreId::Xray).expect("uninstall");
    assert!(mgr.discover_installed().is_empty());
}

#[tokio::test]
async fn supervised_process_spawns_real_listener_streams_logs_and_terminates() {
    let probe_listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral");
    let port = probe_listener.local_addr().expect("addr").port();
    drop(probe_listener);

    let dir = tempdir().expect("tempdir");
    let (tx, mut rx) = mpsc::channel::<LogEntry>(32);

    // Real cross-platform Python TCP server subprocess simulating a bound proxy core inbound.
    let script = format!(
        "import socket, sys; s=socket.socket(); s.bind(('127.0.0.1', {port})); s.listen(1); print('READY_ON_{port}', flush=True); s.accept()"
    );
    let args = vec!["-c".to_owned(), script];
    let proc_handle = SupervisedProcess::spawn(
        CoreId::Xray,
        std::path::Path::new("python"),
        &args,
        dir.path(),
        tx,
    )
    .expect("spawn real python socket listener");

    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    assert!(probe_tcp_ready(addr, Duration::from_secs(3)).await);
    assert!(proc_handle.is_alive());

    let log_entry = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("log timeout")
        .expect("log entry");
    assert!(log_entry.message.contains("READY_ON_"));

    proc_handle.terminate().expect("terminate");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!proc_handle.is_alive());
}
