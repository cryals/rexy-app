use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use proptest::prelude::*;
use qrcode::QrCode;
use r3x_domain::{
    ProfileSource, ProtocolType, SecurityConfig, SubscriptionStatus, TransportConfig,
};
use r3x_profiles::{
    ImportFormat, SubscriptionManager, decode_qr_image_bytes, encode_profile_qr_svg,
    parse_import_payload, parse_profile_uri, parse_subscription_headers, profile_to_uri,
};
use r3x_storage::R3xDatabase;
use reqwest::header::{HeaderMap, HeaderValue};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn parses_major_proxy_uris_and_separates_layers() {
    let vless = "vless://11111111-2222-3333-4444-555555555555@de.example.invalid:443?type=xhttp&security=reality&sni=cdn.example.invalid&pbk=PubKey123&sid=ab12&fp=chrome&flow=xtls-rprx-vision#Germany%20One";
    let p = parse_profile_uri(vless, ProfileSource::Manual).expect("vless");
    assert_eq!(p.name, "Germany One");
    assert_eq!(p.country_code.as_deref(), Some("DE"));
    assert_eq!(p.protocol.protocol_type, ProtocolType::Vless);
    assert!(matches!(p.transport, TransportConfig::Xhttp { .. }));
    assert!(matches!(p.security, SecurityConfig::Reality(_)));
    assert!(p.flow.is_some());

    let exported = profile_to_uri(&p).expect("export vless");
    assert!(exported.starts_with("vless://"));

    let vmess_json = r#"{"v":"2","ps":"NL Node","add":"198.51.100.2","port":"443","id":"22222222-2222-2222-2222-222222222222","aid":"0","net":"ws","path":"/ws","tls":"tls"}"#;
    let vmess_uri = format!("vmess://{}", B64.encode(vmess_json.as_bytes()));
    let vp = parse_profile_uri(&vmess_uri, ProfileSource::Manual).expect("vmess");
    assert_eq!(vp.protocol.protocol_type, ProtocolType::Vmess);
    assert!(matches!(vp.transport, TransportConfig::WebSocket { .. }));

    let ss_uri = format!(
        "ss://{}@203.0.113.10:8388#SS2022",
        B64.encode(b"2022-blake3-aes-128-gcm:secretKeyBase64")
    );
    let sp = parse_profile_uri(&ss_uri, ProfileSource::Manual).expect("ss2022");
    assert_eq!(sp.protocol.protocol_type, ProtocolType::Shadowsocks2022);

    let hy2 = "hy2://pass123@198.51.100.7:443?sni=hy.example.invalid&obfs=salamander&obfs-password=obfspw#Hysteria%20PL";
    let hp = parse_profile_uri(hy2, ProfileSource::Manual).expect("hy2");
    assert_eq!(hp.protocol.protocol_type, ProtocolType::Hysteria2);
    assert_eq!(hp.country_code.as_deref(), Some("PL"));

    let tuic = "tuic://11111111-1111-1111-1111-111111111111:pw@198.51.100.8:443?congestion_control=bbr#TUIC";
    let tp = parse_profile_uri(tuic, ProfileSource::Manual).expect("tuic");
    assert_eq!(tp.protocol.protocol_type, ProtocolType::TuicV5);
}

#[test]
fn parses_base64_yaml_json_wireguard_amneziawg_and_ovpn() {
    let uris = "vless://11111111-1111-1111-1111-111111111111@198.51.100.1:443#Node1\nvless://11111111-1111-1111-1111-111111111111@198.51.100.1:443#Dup\ntrojan://pw@198.51.100.2:443#Node2";
    let b64_sub = B64.encode(uris.as_bytes());
    let res = parse_import_payload(b64_sub.as_bytes(), ProfileSource::Manual).expect("b64 sub");
    assert_eq!(res.format, ImportFormat::Base64UriList);
    assert_eq!(res.profiles.len(), 2);
    assert_eq!(res.deduplicated_count, 1);

    let yaml = "proxies:\n  - name: Finland Edge\n    type: vless\n    server: 203.0.113.2\n    port: 443\n    uuid: 11111111-1111-1111-1111-111111111111\n    tls: true\n";
    let yres = parse_import_payload(yaml.as_bytes(), ProfileSource::Manual).expect("yaml");
    assert_eq!(yres.format, ImportFormat::ClashYaml);
    assert_eq!(yres.profiles[0].protocol.protocol_type, ProtocolType::Vless);

    let awg = "[Interface]\nPrivateKey = privkey123\nAddress = 10.8.0.2/24\nDNS = 1.1.1.1\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 25\nH1 = 101\nH2 = 102\nH3 = 103\nH4 = 104\nI1 = <b 0x1122>\n[Peer]\nPublicKey = pubkey123\nEndpoint = 203.0.113.9:51820\nAllowedIPs = 0.0.0.0/0\n";
    let ares = parse_import_payload(awg.as_bytes(), ProfileSource::Manual).expect("awg");
    assert_eq!(ares.format, ImportFormat::AmneziaWgIni);
    assert_eq!(
        ares.profiles[0].protocol.protocol_type,
        ProtocolType::AmneziaWg
    );

    let ovpn = "client\ndev tun\nproto udp\nremote 198.51.100.20 1194\ncipher AES-256-GCM\n";
    let ores = parse_import_payload(ovpn.as_bytes(), ProfileSource::Manual).expect("ovpn");
    assert_eq!(ores.format, ImportFormat::OpenVpnConfig);
    assert_eq!(
        ores.profiles[0].protocol.protocol_type,
        ProtocolType::OpenVpnUdp
    );
}

#[test]
fn parses_subscription_headers_and_sanitizes_untrusted_links() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "subscription-userinfo",
        HeaderValue::from_static("upload=100; download=900; total=0; expire=2050000000"),
    );
    headers.insert("profile-update-interval", HeaderValue::from_static("3"));
    headers.insert(
        "support-url",
        HeaderValue::from_static("javascript:alert(1)"),
    );
    headers.insert(
        "profile-web-page-url",
        HeaderValue::from_static("https://provider.example.invalid"),
    );

    let parsed = parse_subscription_headers(&headers);
    assert!(parsed.metadata.is_unlimited());
    assert_eq!(parsed.metadata.used_bytes(), 1000);
    assert_eq!(parsed.metadata.update_interval_hours, 3);
    assert!(parsed.metadata.support_url.is_none());
    assert_eq!(
        parsed.metadata.website_url.as_deref(),
        Some("https://provider.example.invalid")
    );
}

#[test]
fn qr_svg_and_image_decode_roundtrip() {
    let uri = "vless://11111111-1111-1111-1111-111111111111@198.51.100.1:443#TestQR";
    let svg = encode_profile_qr_svg(uri).expect("qr svg");
    assert!(svg.contains("<svg"));

    // Build an in-memory PNG image of the QR code and decode it via rqrr
    let code = QrCode::new(uri.as_bytes()).expect("qr");
    let modules = code.to_colors();
    let width = code.width();
    let scale = 4usize;
    let border = 4usize;
    let img_dim = (width + border * 2) * scale;
    let mut luma = image::GrayImage::from_pixel(img_dim as u32, img_dim as u32, image::Luma([255]));
    for y in 0..width {
        for x in 0..width {
            if modules[y * width + x] == qrcode::Color::Dark {
                for dy in 0..scale {
                    for dx in 0..scale {
                        luma.put_pixel(
                            ((x + border) * scale + dx) as u32,
                            ((y + border) * scale + dy) as u32,
                            image::Luma([0]),
                        );
                    }
                }
            }
        }
    }
    let mut png_bytes = Vec::new();
    image::DynamicImage::ImageLuma8(luma)
        .write_to(
            &mut std::io::Cursor::new(&mut png_bytes),
            image::ImageFormat::Png,
        )
        .expect("encode png");

    let decoded = decode_qr_image_bytes(&png_bytes).expect("decode qr");
    assert_eq!(decoded, vec![uri.to_owned()]);
}

#[tokio::test]
async fn subscription_manager_preserves_existing_profiles_on_refresh_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let fail_mode = Arc::new(AtomicBool::new(false));
    let fail_srv = Arc::clone(&fail_mode);

    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let should_fail = fail_srv.load(Ordering::Relaxed);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                if should_fail {
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nfail",
                        )
                        .await;
                } else {
                    let body =
                        "vless://11111111-1111-1111-1111-111111111111@198.51.100.1:443#LocalSrv";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSubscription-Userinfo: upload=10; download=90; total=1000\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                }
            });
        }
    });

    let db = Arc::new(R3xDatabase::open_in_memory().expect("db"));
    let mgr = SubscriptionManager::new(Arc::clone(&db)).expect("mgr");
    let sub = mgr
        .add_remote_and_fetch(Some("LocalFeed".to_owned()), &format!("http://{addr}/sub"))
        .await
        .expect("initial fetch");
    assert_eq!(sub.server_count, 1);
    assert_eq!(db.list_profiles().expect("profiles").len(), 1);

    fail_mode.store(true, Ordering::Relaxed);
    assert!(mgr.refresh_subscription(sub.id).await.is_err());

    // Must preserve the 1 working profile even though refresh failed!
    assert_eq!(db.list_profiles().expect("preserved profiles").len(), 1);
    let subs = db.list_subscriptions().expect("subs");
    assert_eq!(subs[0].status, SubscriptionStatus::Error);
}

proptest! {
    #[test]
    fn parsers_never_panic_on_arbitrary_input(raw in "\\PC{0,512}") {
        let _ = parse_profile_uri(&raw, ProfileSource::Manual);
        let _ = parse_import_payload(raw.as_bytes(), ProfileSource::Manual);
    }
}
