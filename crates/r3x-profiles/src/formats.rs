use crate::uri::{decode_base64_flexible, parse_profile_uri, split_host_port};
use chrono::Utc;
use r3x_domain::{
    AmneziaWgObfuscation, AuthConfig, CorePreference, Endpoint, Profile, ProfileOptions,
    ProfileSource, ProtocolConfig, ProtocolType, R3xError, RedactedSecret, SecurityConfig,
    TlsSettings, TransportConfig,
};
use r3x_security::{MAX_PROFILES_PER_SUBSCRIPTION, validate_subscription_size};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    UriList,
    Base64UriList,
    ClashYaml,
    SingBoxJson,
    XrayJson,
    R3xJson,
    WireGuardIni,
    AmneziaWgIni,
    OpenVpnConfig,
}

#[derive(Debug, Clone)]
pub struct ImportResult {
    pub format: ImportFormat,
    pub profiles: Vec<Profile>,
    pub deduplicated_count: usize,
    pub skipped_lines: usize,
}

pub fn parse_import_payload(raw: &[u8], source: ProfileSource) -> Result<ImportResult, R3xError> {
    validate_subscription_size(raw.len())?;
    let text = std::str::from_utf8(raw)
        .map_err(|_| R3xError::Validation("import payload must be valid UTF-8 text".to_owned()))?
        .trim();
    if text.is_empty() {
        return Err(R3xError::Validation("import payload is empty".to_owned()));
    }

    let (format, raw_profiles, skipped_lines) = if text.contains("[Interface]")
        && text.contains("[Peer]")
    {
        parse_wireguard_ini(text, &source)?
    } else if text.starts_with('{') || text.starts_with('[') {
        parse_json_payload(text, &source)?
    } else if text.contains("\nremote ") || text.starts_with("remote ") || text.contains("dev tun")
    {
        parse_openvpn_config(text, &source)?
    } else if looks_like_yaml_proxies(text) {
        parse_clash_yaml(text, &source)?
    } else if text.contains("://") {
        parse_uri_lines(text, &source, ImportFormat::UriList)?
    } else if let Ok(decoded_bytes) = decode_base64_flexible(text)
        && let Ok(decoded_text) = std::str::from_utf8(&decoded_bytes)
        && decoded_text.contains("://")
    {
        parse_uri_lines(decoded_text, &source, ImportFormat::Base64UriList)?
    } else {
        return Err(R3xError::Validation(
            "unrecognized subscription or configuration format".to_owned(),
        ));
    };

    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    let mut deduplicated_count = 0usize;
    for p in raw_profiles {
        if unique.len() >= MAX_PROFILES_PER_SUBSCRIPTION {
            break;
        }
        let fp = p.dedup_fingerprint();
        if seen.insert(fp) {
            unique.push(p);
        } else {
            deduplicated_count = deduplicated_count.saturating_add(1);
        }
    }

    Ok(ImportResult {
        format,
        profiles: unique,
        deduplicated_count,
        skipped_lines,
    })
}

fn looks_like_yaml_proxies(text: &str) -> bool {
    text.lines()
        .any(|line| line.trim_start().starts_with("proxies:"))
}

fn parse_uri_lines(
    text: &str,
    source: &ProfileSource,
    format: ImportFormat,
) -> Result<(ImportFormat, Vec<Profile>, usize), R3xError> {
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        if out.len() >= MAX_PROFILES_PER_SUBSCRIPTION {
            break;
        }
        match parse_profile_uri(trimmed, source.clone()) {
            Ok(p) => out.push(p),
            Err(_) => skipped = skipped.saturating_add(1),
        }
    }
    if out.is_empty() {
        return Err(R3xError::Validation(
            "no valid proxy URIs found in payload".to_owned(),
        ));
    }
    Ok((format, out, skipped))
}

fn parse_json_payload(
    text: &str,
    source: &ProfileSource,
) -> Result<(ImportFormat, Vec<Profile>, usize), R3xError> {
    let val: Value = serde_json::from_str(text)
        .map_err(|e| R3xError::Validation(format!("invalid JSON configuration: {e}")))?;

    if let Ok(profiles) = serde_json::from_value::<Vec<Profile>>(val.clone()) {
        return Ok((ImportFormat::R3xJson, profiles, 0));
    }
    if let Ok(single) = serde_json::from_value::<Profile>(val.clone()) {
        return Ok((ImportFormat::R3xJson, vec![single], 0));
    }

    if let Some(outbounds) = val.get("outbounds").and_then(Value::as_array) {
        let is_sing_box = outbounds.iter().any(|o| o.get("server").is_some());
        let mut profiles = Vec::new();
        let mut skipped = 0usize;
        for ob in outbounds {
            let parsed = if is_sing_box {
                parse_sing_box_outbound(ob, source)
            } else {
                parse_xray_outbound(ob, source)
            };
            match parsed {
                Some(p) => profiles.push(p),
                None => {
                    let tag_or_proto = ob
                        .get("type")
                        .or_else(|| ob.get("protocol"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if !matches!(
                        tag_or_proto,
                        "direct"
                            | "block"
                            | "freedom"
                            | "blackhole"
                            | "dns"
                            | "selector"
                            | "urltest"
                    ) {
                        skipped = skipped.saturating_add(1);
                    }
                }
            }
        }
        if profiles.is_empty() {
            return Err(R3xError::Validation(
                "JSON config contains no supported proxy outbounds".to_owned(),
            ));
        }
        let fmt = if is_sing_box {
            ImportFormat::SingBoxJson
        } else {
            ImportFormat::XrayJson
        };
        return Ok((fmt, profiles, skipped));
    }

    Err(R3xError::Validation(
        "JSON object does not match sing-box, Xray, or R3X schema".to_owned(),
    ))
}

fn parse_sing_box_outbound(ob: &Value, source: &ProfileSource) -> Option<Profile> {
    let typ = ob.get("type")?.as_str()?;
    let ptype = match typ {
        "vless" => ProtocolType::Vless,
        "vmess" => ProtocolType::Vmess,
        "trojan" => ProtocolType::Trojan,
        "shadowsocks" => ProtocolType::Shadowsocks,
        "hysteria2" => ProtocolType::Hysteria2,
        "tuic" => ProtocolType::TuicV5,
        "anytls" => ProtocolType::AnyTls,
        "wireguard" => ProtocolType::WireGuard,
        "socks" => ProtocolType::Socks5,
        "http" => ProtocolType::Http,
        "ssh" => ProtocolType::Ssh,
        _ => return None,
    };
    let host = ob.get("server")?.as_str()?.to_owned();
    let port = u16::try_from(ob.get("server_port")?.as_u64()?).ok()?;
    let name = ob
        .get("tag")
        .and_then(Value::as_str)
        .unwrap_or(&host)
        .to_owned();
    let secret = ob
        .get("uuid")
        .or_else(|| ob.get("password"))
        .and_then(Value::as_str)
        .map(RedactedSecret::new);
    let security = if ob
        .get("tls")
        .and_then(|t| t.get("enabled"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        let sni = ob
            .get("tls")
            .and_then(|t| t.get("server_name"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        SecurityConfig::Tls(TlsSettings {
            sni,
            alpn: Vec::new(),
            fingerprint: None,
            allow_insecure: false,
            ech_config: None,
        })
    } else {
        SecurityConfig::None
    };

    let now = Utc::now();
    Some(Profile {
        id: Uuid::new_v4(),
        name,
        custom_name: None,
        source: source.clone(),
        protocol: ProtocolConfig::simple(ptype),
        transport: TransportConfig::RawTcp { header_type: None },
        security,
        flow: None,
        endpoint: Endpoint {
            host,
            port,
            local_addresses: Vec::new(),
            dns_servers: Vec::new(),
        },
        auth: AuthConfig {
            inline_secret: secret,
            ..AuthConfig::default()
        },
        options: ProfileOptions::default(),
        core_preference: CorePreference::Auto,
        favorite: false,
        country_code: None,
        city: None,
        latency_ms: None,
        created_at: now,
        updated_at: now,
    })
}

fn parse_xray_outbound(ob: &Value, source: &ProfileSource) -> Option<Profile> {
    let proto_str = ob.get("protocol")?.as_str()?;
    let ptype = match proto_str {
        "vless" => ProtocolType::Vless,
        "vmess" => ProtocolType::Vmess,
        "trojan" => ProtocolType::Trojan,
        "shadowsocks" => ProtocolType::Shadowsocks,
        "socks" => ProtocolType::Socks5,
        "http" => ProtocolType::Http,
        _ => return None,
    };
    let settings = ob.get("settings")?;
    let (host, port, secret) = match ptype {
        ProtocolType::Vless | ProtocolType::Vmess => {
            let vnext = settings.get("vnext")?.as_array()?.first()?;
            let h = vnext.get("address")?.as_str()?.to_owned();
            let p = u16::try_from(vnext.get("port")?.as_u64()?).ok()?;
            let sec = vnext
                .get("users")
                .and_then(Value::as_array)
                .and_then(|u| u.first())
                .and_then(|u| u.get("id"))
                .and_then(Value::as_str)
                .map(RedactedSecret::new);
            (h, p, sec)
        }
        _ => {
            let srv = settings.get("servers")?.as_array()?.first()?;
            let h = srv.get("address")?.as_str()?.to_owned();
            let p = u16::try_from(srv.get("port")?.as_u64()?).ok()?;
            let sec = srv
                .get("password")
                .and_then(Value::as_str)
                .map(RedactedSecret::new);
            (h, p, sec)
        }
    };
    let name = ob
        .get("tag")
        .and_then(Value::as_str)
        .unwrap_or(&host)
        .to_owned();
    let now = Utc::now();
    Some(Profile {
        id: Uuid::new_v4(),
        name,
        custom_name: None,
        source: source.clone(),
        protocol: ProtocolConfig::simple(ptype),
        transport: TransportConfig::RawTcp { header_type: None },
        security: SecurityConfig::None,
        flow: None,
        endpoint: Endpoint {
            host,
            port,
            local_addresses: Vec::new(),
            dns_servers: Vec::new(),
        },
        auth: AuthConfig {
            inline_secret: secret,
            ..AuthConfig::default()
        },
        options: ProfileOptions::default(),
        core_preference: CorePreference::Auto,
        favorite: false,
        country_code: None,
        city: None,
        latency_ms: None,
        created_at: now,
        updated_at: now,
    })
}

fn parse_clash_yaml(
    text: &str,
    source: &ProfileSource,
) -> Result<(ImportFormat, Vec<Profile>, usize), R3xError> {
    let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(text)
        .map_err(|e| R3xError::Validation(format!("invalid Clash/Mihomo YAML: {e}")))?;
    let proxies = doc
        .get("proxies")
        .and_then(serde_yaml_ng::Value::as_sequence)
        .ok_or_else(|| R3xError::Validation("YAML missing 'proxies' sequence".to_owned()))?;

    let mut out = Vec::new();
    let mut skipped = 0usize;
    let now = Utc::now();

    for item in proxies {
        let Some(ptype_str) = item.get("type").and_then(|v| v.as_str()) else {
            skipped = skipped.saturating_add(1);
            continue;
        };
        let ptype = match ptype_str.to_ascii_lowercase().as_str() {
            "vless" => ProtocolType::Vless,
            "vmess" => ProtocolType::Vmess,
            "trojan" => ProtocolType::Trojan,
            "ss" => ProtocolType::Shadowsocks,
            "ssr" => ProtocolType::ShadowsocksR,
            "hysteria2" => ProtocolType::Hysteria2,
            "hysteria" => ProtocolType::Hysteria1,
            "tuic" => ProtocolType::TuicV5,
            "anytls" => ProtocolType::AnyTls,
            "mieru" => ProtocolType::Mieru,
            "snell" => ProtocolType::Snell,
            "wireguard" => ProtocolType::WireGuard,
            "socks5" => ProtocolType::Socks5,
            "http" => ProtocolType::Http,
            "ssh" => ProtocolType::Ssh,
            _ => {
                skipped = skipped.saturating_add(1);
                continue;
            }
        };

        let Some(host) = item.get("server").and_then(|v| v.as_str()) else {
            skipped = skipped.saturating_add(1);
            continue;
        };
        let Some(port) = item
            .get("port")
            .and_then(|v| v.as_u64())
            .and_then(|n| u16::try_from(n).ok())
        else {
            skipped = skipped.saturating_add(1);
            continue;
        };
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(host)
            .to_owned();

        let secret = item
            .get("uuid")
            .or_else(|| item.get("password"))
            .or_else(|| item.get("private-key"))
            .and_then(|v| v.as_str())
            .map(RedactedSecret::new);
        let mut proto = ProtocolConfig::simple(ptype);
        proto.cipher = item
            .get("cipher")
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        let security = if item.get("tls").and_then(|v| v.as_bool()) == Some(true) {
            SecurityConfig::Tls(TlsSettings {
                sni: item
                    .get("servername")
                    .or_else(|| item.get("sni"))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                alpn: Vec::new(),
                fingerprint: item
                    .get("client-fingerprint")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                allow_insecure: item
                    .get("skip-cert-verify")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                ech_config: None,
            })
        } else {
            SecurityConfig::None
        };

        let transport = match item
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp")
        {
            "ws" => TransportConfig::WebSocket {
                path: item
                    .get("ws-opts")
                    .and_then(|w| w.get("path"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("/")
                    .to_owned(),
                host: item
                    .get("ws-opts")
                    .and_then(|w| w.get("headers"))
                    .and_then(|h| h.get("Host"))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                max_early_data: None,
                early_data_header_name: None,
            },
            "grpc" => TransportConfig::Grpc {
                service_name: item
                    .get("grpc-opts")
                    .and_then(|g| g.get("grpc-service-name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned(),
                multi_mode: false,
            },
            _ => TransportConfig::RawTcp { header_type: None },
        };

        out.push(Profile {
            id: Uuid::new_v4(),
            name,
            custom_name: None,
            source: source.clone(),
            protocol: proto,
            transport,
            security,
            flow: None,
            endpoint: Endpoint {
                host: host.to_owned(),
                port,
                local_addresses: Vec::new(),
                dns_servers: Vec::new(),
            },
            auth: AuthConfig {
                username: item
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                inline_secret: secret,
                public_key: item
                    .get("public-key")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                ..AuthConfig::default()
            },
            options: ProfileOptions::default(),
            core_preference: CorePreference::Auto,
            favorite: false,
            country_code: None,
            city: None,
            latency_ms: None,
            created_at: now,
            updated_at: now,
        });
    }

    if out.is_empty() {
        return Err(R3xError::Validation(
            "no valid proxies found in YAML".to_owned(),
        ));
    }
    Ok((ImportFormat::ClashYaml, out, skipped))
}

fn parse_wireguard_ini(
    text: &str,
    source: &ProfileSource,
) -> Result<(ImportFormat, Vec<Profile>, usize), R3xError> {
    let mut kv: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            kv.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }

    let endpoint_raw = kv
        .get("endpoint")
        .ok_or_else(|| R3xError::Validation("WireGuard config missing Endpoint".to_owned()))?;
    let (host, port) = split_host_port(endpoint_raw)?;
    let private_key = kv
        .get("privatekey")
        .ok_or_else(|| R3xError::Validation("WireGuard config missing PrivateKey".to_owned()))?;
    let public_key = kv
        .get("publickey")
        .ok_or_else(|| R3xError::Validation("WireGuard config missing PublicKey".to_owned()))?;

    let has_awg = kv.contains_key("jc")
        || kv.contains_key("s1")
        || kv.contains_key("h1")
        || kv.contains_key("i1");

    let (ptype, security, fmt) = if has_awg {
        let special_junk: Vec<String> = ["i1", "i2", "i3", "i4", "i5"]
            .iter()
            .filter_map(|k| kv.get(*k).cloned())
            .collect();
        let version = if !special_junk.is_empty() {
            "2.0".to_owned()
        } else if kv.contains_key("s3") || kv.contains_key("s4") {
            "1.5".to_owned()
        } else {
            "1.0".to_owned()
        };
        let obfs = AmneziaWgObfuscation {
            version,
            jc: kv.get("jc").and_then(|v| v.parse().ok()).unwrap_or(0),
            jmin: kv.get("jmin").and_then(|v| v.parse().ok()).unwrap_or(0),
            jmax: kv.get("jmax").and_then(|v| v.parse().ok()).unwrap_or(0),
            s1: kv.get("s1").and_then(|v| v.parse().ok()).unwrap_or(0),
            s2: kv.get("s2").and_then(|v| v.parse().ok()).unwrap_or(0),
            s3: kv.get("s3").and_then(|v| v.parse().ok()),
            s4: kv.get("s4").and_then(|v| v.parse().ok()),
            h1: kv.get("h1").and_then(|v| v.parse().ok()).unwrap_or(0),
            h2: kv.get("h2").and_then(|v| v.parse().ok()).unwrap_or(0),
            h3: kv.get("h3").and_then(|v| v.parse().ok()).unwrap_or(0),
            h4: kv.get("h4").and_then(|v| v.parse().ok()).unwrap_or(0),
            special_junk,
        };
        (
            ProtocolType::AmneziaWg,
            SecurityConfig::AmneziaWg(obfs),
            ImportFormat::AmneziaWgIni,
        )
    } else {
        (
            ProtocolType::WireGuard,
            SecurityConfig::NoiseWg,
            ImportFormat::WireGuardIni,
        )
    };

    let mut proto = ProtocolConfig::simple(ptype);
    proto.mtu = kv.get("mtu").and_then(|v| v.parse().ok());

    let local_addresses = kv
        .get("address")
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let dns_servers = kv
        .get("dns")
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let name = match source {
        ProfileSource::ImportedFile { filename } => filename.clone(),
        _ => format!("{} ({host})", ptype.display_name()),
    };
    let now = Utc::now();
    let profile = Profile {
        id: Uuid::new_v4(),
        name,
        custom_name: None,
        source: source.clone(),
        protocol: proto,
        transport: TransportConfig::UdpRaw,
        security,
        flow: None,
        endpoint: Endpoint {
            host,
            port,
            local_addresses,
            dns_servers,
        },
        auth: AuthConfig {
            inline_secret: Some(RedactedSecret::new(private_key.clone())),
            public_key: Some(public_key.clone()),
            preshared_secret: kv.get("presharedkey").cloned().map(RedactedSecret::new),
            ..AuthConfig::default()
        },
        options: ProfileOptions::default(),
        core_preference: CorePreference::Auto,
        favorite: false,
        country_code: None,
        city: None,
        latency_ms: None,
        created_at: now,
        updated_at: now,
    };

    Ok((fmt, vec![profile], 0))
}

fn parse_openvpn_config(
    text: &str,
    source: &ProfileSource,
) -> Result<(ImportFormat, Vec<Profile>, usize), R3xError> {
    let mut host: Option<String> = None;
    let mut port: u16 = 1194;
    let mut is_tcp = false;
    let mut cipher: Option<String> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        match tokens[0] {
            "remote" if tokens.len() >= 2 => {
                if host.is_none() {
                    host = Some(tokens[1].to_owned());
                    if let Some(p_str) = tokens.get(2)
                        && let Ok(p) = p_str.parse()
                    {
                        port = p;
                    }
                    if let Some(proto_tok) = tokens.get(3)
                        && proto_tok.to_ascii_lowercase().contains("tcp")
                    {
                        is_tcp = true;
                    }
                }
            }
            "proto" if tokens.len() >= 2 => {
                if tokens[1].to_ascii_lowercase().contains("tcp") {
                    is_tcp = true;
                }
            }
            "cipher" | "data-ciphers" if tokens.len() >= 2 => {
                cipher = Some(tokens[1].to_owned());
            }
            _ => {}
        }
    }

    let remote_host = host.ok_or_else(|| {
        R3xError::Validation("OpenVPN config missing 'remote' directive".to_owned())
    })?;
    let ptype = if is_tcp {
        ProtocolType::OpenVpnTcp
    } else {
        ProtocolType::OpenVpnUdp
    };
    let mut proto = ProtocolConfig::simple(ptype);
    proto.cipher = cipher;
    proto
        .protocol_params
        .insert("raw_ovpn_present".to_owned(), "true".to_owned());

    let name = match source {
        ProfileSource::ImportedFile { filename } => filename.clone(),
        _ => format!("OpenVPN ({remote_host})"),
    };
    let now = Utc::now();
    let profile = Profile {
        id: Uuid::new_v4(),
        name,
        custom_name: None,
        source: source.clone(),
        protocol: proto,
        transport: if is_tcp {
            TransportConfig::RawTcp { header_type: None }
        } else {
            TransportConfig::UdpRaw
        },
        security: SecurityConfig::Tls(TlsSettings {
            sni: None,
            alpn: Vec::new(),
            fingerprint: None,
            allow_insecure: false,
            ech_config: None,
        }),
        flow: None,
        endpoint: Endpoint {
            host: remote_host,
            port,
            local_addresses: Vec::new(),
            dns_servers: Vec::new(),
        },
        auth: AuthConfig {
            inline_secret: Some(RedactedSecret::new(text.to_owned())),
            ..AuthConfig::default()
        },
        options: ProfileOptions::default(),
        core_preference: CorePreference::Auto,
        favorite: false,
        country_code: None,
        city: None,
        latency_ms: None,
        created_at: now,
        updated_at: now,
    };

    Ok((ImportFormat::OpenVpnConfig, vec![profile], 0))
}
