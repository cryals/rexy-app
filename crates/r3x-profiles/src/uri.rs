use base64::Engine;
use base64::engine::general_purpose::{
    STANDARD as B64_STD, STANDARD_NO_PAD as B64_STD_NP, URL_SAFE as B64_URL,
    URL_SAFE_NO_PAD as B64_URL_NP,
};
use chrono::Utc;
use r3x_domain::{
    AuthConfig, CorePreference, Endpoint, FlowType, Profile, ProfileOptions, ProfileSource,
    ProtocolConfig, ProtocolType, R3xError, RealitySettings, RedactedSecret, SecurityConfig,
    TlsSettings, TransportConfig,
};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use url::Url;
use uuid::Uuid;

pub(crate) fn decode_base64_flexible(input: &str) -> Result<Vec<u8>, R3xError> {
    let cleaned: String = input
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    for engine in [&B64_STD, &B64_STD_NP, &B64_URL, &B64_URL_NP] {
        if let Ok(bytes) = engine.decode(&cleaned) {
            return Ok(bytes);
        }
    }
    Err(R3xError::Validation("invalid base64 payload".to_owned()))
}

fn percent_decode(raw: &str) -> String {
    url::form_urlencoded::parse(raw.as_bytes())
        .map(|(k, v)| {
            if v.is_empty() {
                k.into_owned()
            } else {
                format!("{k}={v}")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn infer_country_code(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    for (kw, code) in [
        ("germany", "DE"),
        ("frankfurt", "DE"),
        ("poland", "PL"),
        ("warsaw", "PL"),
        ("netherlands", "NL"),
        ("amsterdam", "NL"),
        ("united states", "US"),
        ("usa", "US"),
        ("united kingdom", "GB"),
        ("london", "GB"),
        ("finland", "FI"),
        ("helsinki", "FI"),
        ("sweden", "SE"),
        ("stockholm", "SE"),
        ("france", "FR"),
        ("paris", "FR"),
        ("switzerland", "CH"),
        ("zurich", "CH"),
        ("japan", "JP"),
        ("tokyo", "JP"),
        ("singapore", "SG"),
        ("canada", "CA"),
        ("turkey", "TR"),
        ("hong kong", "HK"),
        ("ukraine", "UA"),
        ("russia", "RU"),
    ] {
        if lower.contains(kw) {
            return Some(code.to_owned());
        }
    }
    for token in name.split(|c: char| !c.is_ascii_alphanumeric()) {
        let up = token.to_ascii_uppercase();
        let code = match up.as_str() {
            "DE" | "PL" | "NL" | "US" | "GB" | "FI" | "SE" | "FR" | "CH" | "JP" | "SG" | "CA"
            | "TR" | "HK" | "UA" | "RU" => Some(up.as_str()),
            "UK" => Some("GB"),
            _ => None,
        };
        if let Some(c) = code {
            return Some(c.to_owned());
        }
    }
    None
}

fn query_map(url: &Url) -> HashMap<String, String> {
    url.query_pairs()
        .map(|(k, v)| (k.into_owned().to_ascii_lowercase(), v.into_owned()))
        .collect()
}

fn build_transport(params: &HashMap<String, String>, default_tcp: bool) -> TransportConfig {
    let kind = params
        .get("type")
        .or_else(|| params.get("net"))
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| {
            if default_tcp {
                "tcp".to_owned()
            } else {
                "udp".to_owned()
            }
        });

    let path = params
        .get("path")
        .cloned()
        .unwrap_or_else(|| "/".to_owned());
    let host = params.get("host").filter(|h| !h.is_empty()).cloned();

    match kind.as_str() {
        "ws" | "websocket" => TransportConfig::WebSocket {
            path,
            host,
            max_early_data: params.get("ed").and_then(|v| v.parse().ok()),
            early_data_header_name: params.get("eh").cloned(),
        },
        "grpc" => TransportConfig::Grpc {
            service_name: params
                .get("servicename")
                .or_else(|| params.get("service_name"))
                .cloned()
                .unwrap_or_default(),
            multi_mode: params
                .get("mode")
                .is_some_and(|m| m.eq_ignore_ascii_case("multi")),
        },
        "xhttp" | "splithttp" => TransportConfig::Xhttp {
            path,
            host,
            mode: params.get("mode").cloned(),
        },
        "httpupgrade" => TransportConfig::HttpUpgrade { path, host },
        "kcp" | "mkcp" => TransportConfig::Mkcp {
            header_type: params.get("headertype").cloned(),
            seed: params.get("seed").cloned(),
        },
        "quic" => TransportConfig::Quic {
            security: params.get("quicsecurity").cloned(),
            header_type: params.get("headertype").cloned(),
        },
        "h2" | "http" => TransportConfig::Http2 {
            path,
            hosts: host.into_iter().collect(),
        },
        "h3" | "http3" => TransportConfig::Http3,
        "udp" => TransportConfig::UdpRaw,
        _ => TransportConfig::RawTcp {
            header_type: params.get("headertype").cloned(),
        },
    }
}

fn build_security(
    params: &HashMap<String, String>,
    default_tls: bool,
    host: &str,
) -> SecurityConfig {
    let sec = params
        .get("security")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| {
            if default_tls {
                "tls".to_owned()
            } else {
                "none".to_owned()
            }
        });
    let alpn = params
        .get("alpn")
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let fp = params.get("fp").filter(|s| !s.is_empty()).cloned();
    let sni = params
        .get("sni")
        .or_else(|| params.get("peer"))
        .filter(|s| !s.is_empty())
        .cloned();
    let allow_insecure = params
        .get("allowinsecure")
        .or_else(|| params.get("insecure"))
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));

    match sec.as_str() {
        "reality" => SecurityConfig::Reality(RealitySettings {
            sni: sni.unwrap_or_else(|| host.to_owned()),
            public_key: params.get("pbk").cloned().unwrap_or_default(),
            short_id: params.get("sid").cloned().unwrap_or_default(),
            spider_x: params.get("spx").cloned(),
            fingerprint: fp,
        }),
        "tls" | "xtls" => SecurityConfig::Tls(TlsSettings {
            sni,
            alpn,
            fingerprint: fp,
            allow_insecure,
            ech_config: params.get("ech").cloned(),
        }),
        _ => {
            if let Some(enc) = params.get("encryption").filter(|e| *e != "none")
                && enc.contains('.')
            {
                return SecurityConfig::VlessEncryption {
                    encryption: enc.clone(),
                    decryption: None,
                };
            }
            SecurityConfig::None
        }
    }
}

fn build_base_profile(
    name: String,
    source: ProfileSource,
    protocol: ProtocolConfig,
    transport: TransportConfig,
    security: SecurityConfig,
    host: String,
    port: u16,
) -> Profile {
    let now = Utc::now();
    let country_code = infer_country_code(&name);
    Profile {
        id: Uuid::new_v4(),
        name,
        custom_name: None,
        source,
        protocol,
        transport,
        security,
        flow: None,
        endpoint: Endpoint {
            host,
            port,
            local_addresses: Vec::new(),
            dns_servers: Vec::new(),
        },
        auth: AuthConfig::default(),
        options: ProfileOptions::default(),
        core_preference: CorePreference::Auto,
        favorite: false,
        country_code,
        city: None,
        latency_ms: None,
        created_at: now,
        updated_at: now,
    }
}

pub fn parse_profile_uri(raw: &str, source: ProfileSource) -> Result<Profile, R3xError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 8192 {
        return Err(R3xError::Validation(
            "URI is empty or exceeds 8192 chars".to_owned(),
        ));
    }

    if let Some(rest) = trimmed.strip_prefix("vmess://") {
        return parse_vmess_uri(rest, source);
    }
    if let Some(rest) = trimmed.strip_prefix("ssr://") {
        return parse_ssr_uri(rest, source);
    }
    if let Some(rest) = trimmed.strip_prefix("ss://") {
        return parse_ss_uri(rest, source);
    }

    let url = Url::parse(trimmed)
        .map_err(|e| R3xError::Validation(format!("invalid profile URI: {e}")))?;
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| R3xError::Validation("profile URI missing host".to_owned()))?
        .trim_matches(|c| c == '[' || c == ']')
        .to_owned();
    let port = url.port().unwrap_or(match scheme.as_str() {
        "http" | "socks" | "socks5" | "socks4" | "socks4a" => 1080,
        "ssh" => 22,
        "wg" | "wireguard" | "awg" => 51820,
        _ => 443,
    });
    let params = query_map(&url);
    let fragment = url
        .fragment()
        .map(percent_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{host}:{port}"));

    let user = if url.username().is_empty() {
        None
    } else {
        Some(percent_decode(url.username()))
    };
    let password = url.password().map(percent_decode);

    match scheme.as_str() {
        "vless" => {
            let uuid_secret =
                user.ok_or_else(|| R3xError::Validation("vless URI missing UUID user".to_owned()))?;
            let mut p = build_base_profile(
                fragment,
                source,
                ProtocolConfig::simple(ProtocolType::Vless),
                build_transport(&params, true),
                build_security(&params, false, &host),
                host,
                port,
            );
            p.auth.inline_secret = Some(RedactedSecret::new(uuid_secret));
            p.flow = match params
                .get("flow")
                .map(|f| f.to_ascii_lowercase())
                .as_deref()
            {
                Some("xtls-rprx-vision") => Some(FlowType::XtlsRprxVision),
                Some("xtls-rprx-vision-udp443") => Some(FlowType::XtlsRprxVisionUdp443),
                _ => None,
            };
            if let Some(enc) = params.get("encryption") {
                p.protocol
                    .protocol_params
                    .insert("encryption".to_owned(), enc.clone());
            }
            Ok(p)
        }
        "trojan" => {
            let secret = user.ok_or_else(|| {
                R3xError::Validation("trojan URI missing password user".to_owned())
            })?;
            let mut p = build_base_profile(
                fragment,
                source,
                ProtocolConfig::simple(ProtocolType::Trojan),
                build_transport(&params, true),
                build_security(&params, true, &host),
                host,
                port,
            );
            p.auth.inline_secret = Some(RedactedSecret::new(secret));
            Ok(p)
        }
        "hysteria2" | "hy2" => {
            let secret = user.unwrap_or_default();
            let mut proto = ProtocolConfig::simple(ProtocolType::Hysteria2);
            if let Some(obfs) = params.get("obfs") {
                proto
                    .protocol_params
                    .insert("obfs".to_owned(), obfs.clone());
            }
            let mut p = build_base_profile(
                fragment,
                source,
                proto,
                TransportConfig::Quic {
                    security: Some("tls".to_owned()),
                    header_type: None,
                },
                build_security(&params, true, &host),
                host,
                port,
            );
            if !secret.is_empty() {
                p.auth.inline_secret = Some(RedactedSecret::new(secret));
            }
            if let Some(obfs_pw) = params.get("obfs-password") {
                p.auth.secondary_secret = Some(RedactedSecret::new(obfs_pw.clone()));
            }
            p.options.up_mbps = params.get("upmbps").and_then(|v| v.parse().ok());
            p.options.down_mbps = params.get("downmbps").and_then(|v| v.parse().ok());
            Ok(p)
        }
        "hysteria" | "hy" => {
            let mut p = build_base_profile(
                fragment,
                source,
                ProtocolConfig::simple(ProtocolType::Hysteria1),
                TransportConfig::Quic {
                    security: Some("tls".to_owned()),
                    header_type: None,
                },
                build_security(&params, true, &host),
                host,
                port,
            );
            if let Some(auth) = params.get("auth").or(user.as_ref()) {
                p.auth.inline_secret = Some(RedactedSecret::new(auth.clone()));
            }
            Ok(p)
        }
        "tuic" => {
            let version = params.get("version").map(String::as_str);
            let ptype = if version == Some("4") {
                ProtocolType::TuicV4
            } else {
                ProtocolType::TuicV5
            };
            let mut p = build_base_profile(
                fragment,
                source,
                ProtocolConfig::simple(ptype),
                TransportConfig::Quic {
                    security: Some("tls".to_owned()),
                    header_type: None,
                },
                build_security(&params, true, &host),
                host,
                port,
            );
            if let Some(u) = user {
                p.auth.inline_secret = Some(RedactedSecret::new(u));
            }
            if let Some(pw) = password {
                p.auth.secondary_secret = Some(RedactedSecret::new(pw));
            }
            p.options.congestion_control = params.get("congestion_control").cloned();
            Ok(p)
        }
        "anytls" | "juicity" | "mieru" | "snell" | "brook" | "ssh" => {
            let ptype = match scheme.as_str() {
                "anytls" => ProtocolType::AnyTls,
                "juicity" => ProtocolType::Juicity,
                "mieru" => ProtocolType::Mieru,
                "snell" => ProtocolType::Snell,
                "brook" => ProtocolType::Brook,
                _ => ProtocolType::Ssh,
            };
            let use_tls = matches!(ptype, ProtocolType::AnyTls | ProtocolType::Juicity);
            let mut p = build_base_profile(
                fragment,
                source,
                ProtocolConfig::simple(ptype),
                build_transport(&params, true),
                build_security(&params, use_tls, &host),
                host,
                port,
            );
            p.auth.username = user;
            if let Some(pw) = password {
                p.auth.inline_secret = Some(RedactedSecret::new(pw));
            }
            Ok(p)
        }
        "naive+https" | "naive+quic" => {
            let transport = if scheme == "naive+quic" {
                TransportConfig::Http3
            } else {
                TransportConfig::Http2 {
                    path: "/".to_owned(),
                    hosts: Vec::new(),
                }
            };
            let mut p = build_base_profile(
                fragment,
                source,
                ProtocolConfig::simple(ProtocolType::NaiveProxy),
                transport,
                build_security(&params, true, &host),
                host,
                port,
            );
            p.auth.username = user;
            if let Some(pw) = password {
                p.auth.inline_secret = Some(RedactedSecret::new(pw));
            }
            Ok(p)
        }
        "socks" | "socks5" | "socks4" | "socks4a" | "http" | "https" => {
            let ptype = match scheme.as_str() {
                "socks4" => ProtocolType::Socks4,
                "socks4a" => ProtocolType::Socks4a,
                "http" => ProtocolType::Http,
                "https" => ProtocolType::Https,
                _ => ProtocolType::Socks5,
            };
            let sec = if scheme == "https" {
                build_security(&params, true, &host)
            } else {
                SecurityConfig::None
            };
            let mut p = build_base_profile(
                fragment,
                source,
                ProtocolConfig::simple(ptype),
                TransportConfig::RawTcp { header_type: None },
                sec,
                host,
                port,
            );
            p.auth.username = user;
            if let Some(pw) = password {
                p.auth.inline_secret = Some(RedactedSecret::new(pw));
            }
            Ok(p)
        }
        "wg" | "wireguard" | "awg" => {
            let ptype = if scheme == "awg" {
                ProtocolType::AmneziaWg
            } else {
                ProtocolType::WireGuard
            };
            let mut p = build_base_profile(
                fragment,
                source,
                ProtocolConfig::simple(ptype),
                TransportConfig::UdpRaw,
                SecurityConfig::NoiseWg,
                host,
                port,
            );
            if let Some(priv_k) = user {
                p.auth.inline_secret = Some(RedactedSecret::new(priv_k));
            }
            p.auth.public_key = params.get("publickey").cloned();
            Ok(p)
        }
        _ => Err(R3xError::Validation(format!(
            "unsupported URI scheme '{scheme}'"
        ))),
    }
}

fn parse_vmess_uri(rest: &str, source: ProfileSource) -> Result<Profile, R3xError> {
    let decoded = decode_base64_flexible(rest)?;
    let val: Value = serde_json::from_slice(&decoded)
        .map_err(|e| R3xError::Validation(format!("invalid vmess JSON payload: {e}")))?;

    let host = val
        .get("add")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| R3xError::Validation("vmess missing 'add' host".to_owned()))?
        .to_owned();
    let port: u16 = match val.get("port") {
        Some(Value::Number(n)) => u16::try_from(n.as_u64().unwrap_or(0)).unwrap_or(0),
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    };
    if port == 0 {
        return Err(R3xError::Validation("vmess missing valid port".to_owned()));
    }
    let uuid = val
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| R3xError::Validation("vmess missing 'id'".to_owned()))?
        .to_owned();
    let ps = val
        .get("ps")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{host}:{port}"));

    let mut params = HashMap::new();
    for (k_json, k_param) in [
        ("net", "type"),
        ("path", "path"),
        ("host", "host"),
        ("tls", "security"),
        ("sni", "sni"),
        ("alpn", "alpn"),
        ("fp", "fp"),
        ("type", "headertype"),
    ] {
        if let Some(s) = val.get(k_json).and_then(Value::as_str)
            && !s.is_empty()
        {
            params.insert(k_param.to_owned(), s.to_owned());
        }
    }

    let mut proto = ProtocolConfig::simple(ProtocolType::Vmess);
    proto.cipher = val
        .get("scy")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| Some("auto".to_owned()));
    proto.alter_id = val
        .get("aid")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .and_then(|n| u16::try_from(n).ok());

    let mut p = build_base_profile(
        ps,
        source,
        proto,
        build_transport(&params, true),
        build_security(&params, false, &host),
        host,
        port,
    );
    p.auth.inline_secret = Some(RedactedSecret::new(uuid));
    Ok(p)
}

fn parse_ss_uri(rest: &str, source: ProfileSource) -> Result<Profile, R3xError> {
    let (without_frag, name) = match rest.split_once('#') {
        Some((a, b)) => (a, Some(percent_decode(b))),
        None => (rest, None),
    };
    let (main_part, _query) = without_frag
        .split_once('?')
        .map(|(a, b)| (a, Some(b)))
        .unwrap_or((without_frag, None));

    let (method, password, host_port) = if let Some((userinfo, hp)) = main_part.split_once('@') {
        let decoded_creds = if userinfo.contains(':') {
            userinfo.to_owned()
        } else {
            String::from_utf8(decode_base64_flexible(userinfo)?)
                .map_err(|_| R3xError::Validation("invalid UTF-8 in ss credentials".to_owned()))?
        };
        let (m, pw) = decoded_creds
            .split_once(':')
            .ok_or_else(|| R3xError::Validation("ss credentials missing ':'".to_owned()))?;
        (m.to_owned(), pw.to_owned(), hp.to_owned())
    } else {
        let decoded = String::from_utf8(decode_base64_flexible(main_part)?)
            .map_err(|_| R3xError::Validation("invalid UTF-8 in legacy ss URI".to_owned()))?;
        let (creds, hp) = decoded
            .rsplit_once('@')
            .ok_or_else(|| R3xError::Validation("legacy ss URI missing '@'".to_owned()))?;
        let (m, pw) = creds
            .split_once(':')
            .ok_or_else(|| R3xError::Validation("ss credentials missing ':'".to_owned()))?;
        (m.to_owned(), pw.to_owned(), hp.to_owned())
    };

    let (host, port) = split_host_port(&host_port)?;
    let ptype = if method.starts_with("2022-") {
        ProtocolType::Shadowsocks2022
    } else {
        ProtocolType::Shadowsocks
    };
    let mut proto = ProtocolConfig::simple(ptype);
    proto.cipher = Some(method);
    let display = name.unwrap_or_else(|| format!("{host}:{port}"));
    let mut p = build_base_profile(
        display,
        source,
        proto,
        TransportConfig::RawTcp { header_type: None },
        SecurityConfig::None,
        host,
        port,
    );
    p.auth.inline_secret = Some(RedactedSecret::new(password));
    Ok(p)
}

fn parse_ssr_uri(rest: &str, source: ProfileSource) -> Result<Profile, R3xError> {
    let decoded = String::from_utf8(decode_base64_flexible(rest)?)
        .map_err(|_| R3xError::Validation("invalid UTF-8 in ssr URI".to_owned()))?;
    let (head, tail) = decoded
        .split_once("/?")
        .map(|(a, b)| (a, Some(b)))
        .unwrap_or((decoded.as_str(), None));
    let parts: Vec<&str> = head.split(':').collect();
    if parts.len() < 6 {
        return Err(R3xError::Validation(
            "ssr URI requires host:port:protocol:method:obfs:base64pass".to_owned(),
        ));
    }
    let host = parts[0].to_owned();
    let port: u16 = parts[1]
        .parse()
        .map_err(|_| R3xError::Validation("invalid ssr port".to_owned()))?;
    let pw_bytes = decode_base64_flexible(parts[5])?;
    let password = String::from_utf8(pw_bytes)
        .map_err(|_| R3xError::Validation("invalid UTF-8 in ssr password".to_owned()))?;

    let mut remarks = format!("{host}:{port}");
    let mut extra = BTreeMap::new();
    extra.insert("ssr_protocol".to_owned(), parts[2].to_owned());
    extra.insert("ssr_obfs".to_owned(), parts[4].to_owned());
    if let Some(q) = tail {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=')
                && k == "remarks"
                && let Ok(bytes) = decode_base64_flexible(v)
                && let Ok(text) = String::from_utf8(bytes)
                && !text.is_empty()
            {
                remarks = text;
            }
        }
    }

    let mut proto = ProtocolConfig::simple(ProtocolType::ShadowsocksR);
    proto.cipher = Some(parts[3].to_owned());
    proto.protocol_params = extra;
    let mut p = build_base_profile(
        remarks,
        source,
        proto,
        TransportConfig::RawTcp { header_type: None },
        SecurityConfig::None,
        host,
        port,
    );
    p.auth.inline_secret = Some(RedactedSecret::new(password));
    Ok(p)
}

pub(crate) fn split_host_port(hp: &str) -> Result<(String, u16), R3xError> {
    let trimmed = hp.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (h, p_str) = rest
            .split_once("]:")
            .ok_or_else(|| R3xError::Validation("invalid IPv6 host:port".to_owned()))?;
        let port: u16 = p_str
            .parse()
            .map_err(|_| R3xError::Validation("invalid port".to_owned()))?;
        return Ok((h.to_owned(), port));
    }
    let (h, p_str) = trimmed
        .rsplit_once(':')
        .ok_or_else(|| R3xError::Validation("endpoint missing ':port'".to_owned()))?;
    let port: u16 = p_str
        .parse()
        .map_err(|_| R3xError::Validation("invalid port".to_owned()))?;
    if h.is_empty() || port == 0 {
        return Err(R3xError::Validation("empty host or zero port".to_owned()));
    }
    Ok((h.to_owned(), port))
}

pub fn profile_to_uri(profile: &Profile) -> Result<String, R3xError> {
    let scheme = match profile.protocol.protocol_type {
        ProtocolType::Vless => "vless",
        ProtocolType::Trojan => "trojan",
        ProtocolType::Hysteria2 => "hysteria2",
        ProtocolType::TuicV5 | ProtocolType::TuicV4 => "tuic",
        ProtocolType::Socks5 => "socks5",
        ProtocolType::Http => "http",
        ProtocolType::Https => "https",
        ProtocolType::WireGuard => "wireguard",
        ProtocolType::AmneziaWg => "awg",
        other => {
            return Err(R3xError::Validation(format!(
                "URI export not supported for {:?}",
                other
            )));
        }
    };
    let secret = profile
        .auth
        .inline_secret
        .as_ref()
        .map(RedactedSecret::expose)
        .unwrap_or_default();
    let mut url = Url::parse(&format!(
        "{scheme}://{}:{}",
        profile.endpoint.host, profile.endpoint.port
    ))
    .map_err(|e| R3xError::Validation(format!("failed constructing URI: {e}")))?;

    if let Some(ref user) = profile.auth.username {
        let _ = url.set_username(user);
        if !secret.is_empty() {
            let _ = url.set_password(Some(secret));
        }
    } else if !secret.is_empty() {
        let _ = url.set_username(secret);
    }

    {
        let mut q = url.query_pairs_mut();
        q.append_pair("type", &profile.transport.label().to_ascii_lowercase());
        match &profile.security {
            SecurityConfig::None => {
                q.append_pair("security", "none");
            }
            SecurityConfig::Tls(t) => {
                q.append_pair("security", "tls");
                if let Some(ref sni) = t.sni {
                    q.append_pair("sni", sni);
                }
                if !t.alpn.is_empty() {
                    q.append_pair("alpn", &t.alpn.join(","));
                }
                if let Some(ref fp) = t.fingerprint {
                    q.append_pair("fp", fp);
                }
            }
            SecurityConfig::Reality(r) => {
                q.append_pair("security", "reality");
                q.append_pair("sni", &r.sni);
                q.append_pair("pbk", &r.public_key);
                q.append_pair("sid", &r.short_id);
                if let Some(ref fp) = r.fingerprint {
                    q.append_pair("fp", fp);
                }
            }
            _ => {}
        }
        if let Some(flow) = profile.flow {
            q.append_pair("flow", flow.as_str());
        }
    }
    url.set_fragment(Some(profile.effective_name()));
    Ok(url.to_string())
}
