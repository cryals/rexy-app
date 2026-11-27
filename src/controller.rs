use crate::{
    AppBootstrap, ConnectionRow, CoreRow, DiagnosticRow, HeroState, LogRow, MainWindow, ProfileRow,
    R3xAppState, R3xMetrics, R3xPalette, R3xThemeController, R3xThemeMode, RoutingRuleRow,
    RuleSetRow, SubscriptionRow,
};
use chrono::Utc;
use r3x_cores::{MihomoAdapter, SingBoxAdapter, XrayAdapter, default_core_manifests};
use r3x_diagnostics::{
    DiagnosticContext, NetworkDoctor, build_area_path, build_line_path, export_redacted_report,
    measure_tcp_latency, preview_core_routing, test_dns_resolver, validate_dns_config,
};
use r3x_domain::{
    AccentConfig, AuthConfig, ConnectionMode, ConnectionState, CoreId, CorePreference,
    DiagnosticCheckId, DiagnosticStatus, DnsConfig, DnsLeakProtectionMode, DnsMode, Endpoint,
    InterfaceMode, Language, LogCategory, LogLevel, PerformanceProfile, Profile, ProfileOptions,
    ProfileSource, ProtocolConfig, ProtocolType, RedactedSecret, RoutingRule, RuleAction,
    RuleMatcher, SecurityConfig, SubscriptionImportSource, ThemeMode, TimeRange, TlsSettings,
    TrafficSample, TransportConfig,
};
use r3x_engine::{ConnectRequest, CoreAdapter, CoreConfigContext};
use r3x_network::{create_platform_proxy_backend, recover_network_state};
use r3x_profiles::{parse_import_payload, parse_profile_uri, profile_to_uri};
use r3x_security::{EncryptedEnvelope, Redactor};
use slint::{Color, ComponentHandle, Global, ModelRc, Timer, TimerMode, VecModel};
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.2} GB", b / GIB)
    } else if b >= MIB {
        format!("{:.1} MB", b / MIB)
    } else if b >= KIB {
        format!("{:.1} KB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}

fn format_rate_mbps(bps: u64) -> String {
    let mbps = (bps as f64) * 8.0 / 1_000_000.0;
    if mbps >= 0.1 || bps == 0 {
        format!("{mbps:.1} Mbps")
    } else {
        format!("{:.0} Kbps", (bps as f64) * 8.0 / 1_000.0)
    }
}

fn parse_hex_color(raw: &str) -> Option<Color> {
    let hex = raw.trim().trim_start_matches('#');
    if hex.len() != 6 {
        return None;
    }
    let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
    let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
    let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
    Some(Color::from_rgb_u8(r, g, b))
}

pub fn apply_theme_settings(ui: &MainWindow, mode: ThemeMode, accent: &AccentConfig) {
    let pal = R3xPalette::get(ui);
    match accent {
        AccentConfig::CustomHex(hex) => {
            if let Some(c) = parse_hex_color(hex) {
                pal.set_custom_accent(c);
                pal.set_custom_accent_enabled(true);
            } else {
                pal.set_custom_accent_enabled(false);
            }
        }
        AccentConfig::Dynamic | AccentConfig::Default => {
            pal.set_custom_accent_enabled(false);
        }
    }

    let r3x_mode = match mode {
        ThemeMode::System => R3xThemeMode::System,
        ThemeMode::Light => R3xThemeMode::Light,
        ThemeMode::Dark => R3xThemeMode::Dark,
        ThemeMode::Amoled => R3xThemeMode::Amoled,
    };
    R3xThemeController::get(ui).invoke_apply_theme(r3x_mode, true);
}

pub fn sync_all_models(ui: &MainWindow, bootstrap: &Arc<AppBootstrap>) {
    let settings = bootstrap.db.load_settings().unwrap_or_default();
    let dns = bootstrap.db.load_dns_config().unwrap_or_default();
    let subs = bootstrap.db.list_subscriptions().unwrap_or_default();
    let profiles = bootstrap.db.list_profiles().unwrap_or_default();
    let rules = bootstrap.routing.list_rules_sorted().unwrap_or_default();
    let rule_sets = bootstrap.routing.list_rule_sets().unwrap_or_default();
    let history = bootstrap.db.list_connection_history(50).unwrap_or_default();
    let installed_cores = bootstrap.core_manager.discover_installed();
    let manifests = default_core_manifests().unwrap_or_default();

    let state = R3xAppState::get(ui);
    state.set_show_onboarding(!settings.onboarding_completed);
    state.set_drawer_collapsed(settings.window_state.drawer_collapsed);
    state.set_reduced_motion(settings.reduced_motion);
    R3xMetrics::get(ui).set_reduced_motion(settings.reduced_motion);
    state.set_interface_advanced(matches!(settings.interface_mode, InterfaceMode::Advanced));
    state.set_language_index(match settings.language {
        Language::Ru => 1,
        Language::System | Language::En => 0,
    });
    state.set_theme_mode_index(match settings.theme_mode {
        ThemeMode::System => 0,
        ThemeMode::Light => 1,
        ThemeMode::Dark => 2,
        ThemeMode::Amoled => 3,
    });
    if let AccentConfig::CustomHex(ref hex) = settings.accent {
        state.set_custom_accent_hex(hex.into());
    }
    apply_theme_settings(ui, settings.theme_mode, &settings.accent);

    state.set_connection_mode_index(match settings.preferred_connection_mode {
        ConnectionMode::Tun => 0,
        ConnectionMode::SystemProxy => 1,
        ConnectionMode::Mixed => 2,
    });
    state.set_performance_profile_index(match settings.performance_profile {
        PerformanceProfile::Eco => 0,
        PerformanceProfile::Balanced => 1,
        PerformanceProfile::Performance => 2,
    });
    state.set_mixed_port_text(settings.mixed_port.to_string().into());
    state.set_socks_port_text(settings.socks_port.to_string().into());
    state.set_http_port_text(settings.http_port.to_string().into());
    state.set_allow_lan(settings.allow_lan);
    state.set_ipv6_enabled(settings.ipv6_enabled);
    state.set_auto_reconnect(settings.auto_reconnect);
    state.set_kill_switch(settings.kill_switch);
    state.set_minimize_to_tray(settings.minimize_to_tray);
    state.set_auto_start_on_boot(settings.auto_start_on_boot);
    state.set_connect_on_launch(settings.connect_on_launch);
    state.set_secret_store_status(
        format!(
            "{} ({})",
            bootstrap.secret_store.backend_name(),
            if bootstrap.secret_store.is_available() {
                "ready"
            } else {
                "unavailable"
            }
        )
        .into(),
    );
    state.set_global_core_pref_label(match settings.global_core_preference {
        CorePreference::Auto => "Auto (Smart Core Selector)".into(),
        CorePreference::Preferred(id) => format!("Preferred: {}", id.display_name()).into(),
    });

    // Subscriptions
    let sub_rows: Vec<SubscriptionRow> = subs
        .iter()
        .map(|s| {
            let masked_url = match &s.source {
                SubscriptionImportSource::RemoteUrl { url } => Redactor::redact_str(url),
                SubscriptionImportSource::LocalFile { filename } => filename.clone(),
                SubscriptionImportSource::Clipboard => "Clipboard".to_owned(),
            };
            let used = format_bytes(s.metadata.used_bytes());
            let unlimited = s.metadata.is_unlimited();
            let total = s
                .metadata
                .total_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "Unlimited".to_owned());
            let ratio = s.metadata.usage_ratio().unwrap_or(0.0) as f32;
            let expires = s
                .metadata
                .expire_at
                .map(|t| format!("Expires {}", t.format("%Y-%m-%d")))
                .unwrap_or_else(|| "No expiry".to_owned());
            let updated = s
                .last_updated_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "Never refreshed".to_owned());
            SubscriptionRow {
                id: s.id.to_string().into(),
                name: s.name.clone().into(),
                url_masked: masked_url.into(),
                profile_count: s.server_count as i32,
                used_text: used.into(),
                total_text: total.into(),
                usage_ratio: ratio,
                is_unlimited: unlimited,
                expires_text: expires.into(),
                last_updated: updated.into(),
                auto_update: s.enabled,
                status_text: format!("{:?}", s.status).into(),
                is_error: matches!(s.status, r3x_domain::SubscriptionStatus::Error),
            }
        })
        .collect();
    state.set_subscription_count(sub_rows.len() as i32);
    state.set_subscriptions(ModelRc::from(Rc::new(VecModel::from(sub_rows))));

    // Selected Profile Resolution
    let selected_profile = settings
        .selected_profile_id
        .and_then(|id| profiles.iter().find(|p| p.id == id))
        .or_else(|| profiles.first())
        .cloned();

    let search = state.get_server_search_query().to_ascii_lowercase();
    let fav_only = state.get_server_filter_favorites();
    let sub_filter = state.get_selected_subscription_id().to_string();

    let profile_rows: Vec<ProfileRow> = profiles
        .iter()
        .filter(|p| !fav_only || p.favorite)
        .filter(|p| {
            if sub_filter.is_empty() {
                true
            } else {
                matches!(&p.source, ProfileSource::Subscription { subscription_id } if subscription_id.to_string() == sub_filter)
            }
        })
        .filter(|p| {
            if search.is_empty() {
                true
            } else {
                p.effective_name().to_ascii_lowercase().contains(&search)
                    || p.endpoint.host.to_ascii_lowercase().contains(&search)
                    || p.protocol
                        .protocol_type
                        .display_name()
                        .to_ascii_lowercase()
                        .contains(&search)
            }
        })
        .map(|p| {
            let selected = selected_profile.as_ref().is_some_and(|sp| sp.id == p.id);
            ProfileRow {
                id: p.id.to_string().into(),
                name: p.effective_name().into(),
                protocol: p.protocol.protocol_type.display_name().into(),
                transport: p.transport.label().into(),
                security_label: p.security.label().into(),
                server_display: format!("{}:{}", Redactor::redact_str(&p.endpoint.host), p.endpoint.port).into(),
                country_code: p
                    .country_code
                    .clone()
                    .unwrap_or_else(|| "XX".to_owned())
                    .into(),
                latency_text: p
                    .latency_ms
                    .map(|ms| format!("{ms} ms"))
                    .unwrap_or_else(|| "—".to_owned())
                    .into(),
                latency_ms: p.latency_ms.map(|v| v as i32).unwrap_or(-1),
                is_favorite: p.favorite,
                is_selected: selected,
                core_hint: match p.core_preference {
                    CorePreference::Auto => "Auto".into(),
                    CorePreference::Preferred(c) => c.display_name().into(),
                },
                subscription_id: match &p.source {
                    ProfileSource::Subscription { subscription_id } => {
                        subscription_id.to_string().into()
                    }
                    _ => "".into(),
                },
            }
        })
        .collect();
    state.set_profile_count(profiles.len() as i32);
    state.set_profiles(ModelRc::from(Rc::new(VecModel::from(profile_rows))));

    if let Some(ref sp) = selected_profile {
        state.set_has_selected_server(true);
        state.set_selected_profile_id(sp.id.to_string().into());
        state.set_server_name(sp.effective_name().into());
        state.set_server_subtitle(
            format!(
                "{} · {} · {}",
                sp.protocol.protocol_type.display_name(),
                sp.transport.label(),
                sp.security.label()
            )
            .into(),
        );
        state.set_server_flag_code(
            sp.country_code
                .clone()
                .unwrap_or_else(|| "xx".to_owned())
                .to_ascii_lowercase()
                .into(),
        );
        state.set_server_latency(
            sp.latency_ms
                .map(|m| format!("{m} ms"))
                .unwrap_or_else(|| "Untested".to_owned())
                .into(),
        );
        state.set_selected_server_protocol(sp.protocol.protocol_type.display_name().into());
        state.set_selected_server_transport(sp.transport.label().into());
        state.set_selected_server_security(sp.security.label().into());
    } else {
        state.set_has_selected_server(false);
        state.set_selected_profile_id("".into());
        state.set_server_name("No server selected".into());
        state.set_server_subtitle("Import configuration or subscription".into());
        state.set_server_flag_code("xx".into());
        state.set_server_latency("—".into());
    }

    // Routing & DNS
    let rule_rows: Vec<RoutingRuleRow> = rules
        .iter()
        .map(|r| RoutingRuleRow {
            id: r.id.to_string().into(),
            name: r.name.clone().into(),
            group: r.group.clone().into(),
            matcher_summary: format!("{:?}", r.matcher).into(),
            action_label: match r.action {
                RuleAction::Proxy | RuleAction::SelectedProfile(_) => "Proxy".into(),
                RuleAction::Direct => "Direct".into(),
                RuleAction::Block => "Block".into(),
            },
            priority: r.priority,
            enabled: r.enabled,
        })
        .collect();
    state.set_routing_rule_count(rule_rows.len() as i32);
    state.set_routing_rules(ModelRc::from(Rc::new(VecModel::from(rule_rows))));

    let rs_rows: Vec<RuleSetRow> = rule_sets
        .iter()
        .map(|rs| RuleSetRow {
            id: rs.id.to_string().into(),
            tag: rs.tag.clone().into(),
            kind: rs.kind.clone().into(),
            entry_count: rs.entry_count as i32,
            enabled: rs.enabled,
        })
        .collect();
    state.set_rule_sets(ModelRc::from(Rc::new(VecModel::from(rs_rows))));

    state.set_dns_mode_index(match dns.primary.mode {
        DnsMode::System => 0,
        DnsMode::Custom => 1,
        DnsMode::DoH => 2,
        DnsMode::DoT => 3,
        DnsMode::DoQ => 4,
    });
    state.set_dns_primary_address(dns.primary.address.clone().into());
    state.set_dns_fallback_address(
        dns.fallback
            .as_ref()
            .map(|f| f.address.clone())
            .unwrap_or_default()
            .into(),
    );
    state.set_dns_ipv6(dns.enable_ipv6);
    state.set_dns_leak_mode_index(match dns.leak_protection {
        DnsLeakProtectionMode::Off => 0,
        DnsLeakProtectionMode::StrictTunnelOnly => 1,
        DnsLeakProtectionMode::FakeIp => 2,
    });

    // Connection history
    let hist_rows: Vec<ConnectionRow> = history
        .iter()
        .map(|h| ConnectionRow {
            id: h.id.to_string().into(),
            target: h.profile_name.clone().into(),
            protocol: format!("{:?}", h.mode).into(),
            rule: if h.disconnect_reason.is_empty() {
                "Ended".into()
            } else {
                h.disconnect_reason.clone().into()
            },
            core_name: h.core_id.display_name().into(),
            down_text: format_bytes(h.bytes_down).into(),
            up_text: format_bytes(h.bytes_up).into(),
            duration_text: h.started_at.format("%Y-%m-%d %H:%M").to_string().into(),
        })
        .collect();
    state.set_connection_history(ModelRc::from(Rc::new(VecModel::from(hist_rows))));

    // Core Manager
    let core_rows: Vec<CoreRow> = manifests
        .iter()
        .map(|m| {
            let inst = installed_cores.get(&m.id);
            let preferred = matches!(settings.global_core_preference, CorePreference::Preferred(id) if id == m.id);
            let platforms = m
                .supported_platforms
                .iter()
                .map(|p| format!("{p:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            CoreRow {
                id: serde_json::to_value(m.id)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_else(|| m.name.to_ascii_lowercase())
                    .into(),
                name: m.name.clone().into(),
                version: inst
                    .map(|r| r.version.clone())
                    .unwrap_or_else(|| m.version.clone())
                    .into(),
                license: m.license.clone().into(),
                install_status: if inst.is_some() {
                    "Installed".into()
                } else {
                    "Not installed".into()
                },
                is_installed: inst.is_some(),
                is_preferred: preferred,
                platforms_text: platforms.into(),
                protocols_count: m.capabilities.protocols.len() as i32,
                binary_path: inst
                    .map(|r| r.binary_path.display().to_string())
                    .unwrap_or_else(|| "Not present in cores directory".to_owned())
                    .into(),
                limitations: m.limitations.join(" ").into(),
            }
        })
        .collect();
    state.set_cores(ModelRc::from(Rc::new(VecModel::from(core_rows))));

    sync_connection_and_telemetry_ui(ui, bootstrap);
    sync_logs_to_ui(ui, bootstrap);
}

pub fn sync_connection_and_telemetry_ui(ui: &MainWindow, bootstrap: &Arc<AppBootstrap>) {
    let state = R3xAppState::get(ui);
    let conn_state = bootstrap.engine.connection_state();
    let session = bootstrap.engine.current_session();
    let installed_count = bootstrap.engine.installed_cores().len();

    match &conn_state {
        ConnectionState::Disconnected => {
            state.set_hero_state(HeroState::Disconnected);
            state.set_status_label("Not connected".into());
            state.set_session_timer("00:00:00".into());
            if state.get_has_selected_server() {
                state.set_hero_title("Ready to connect".into());
                state.set_hero_subtitle("Tap Connect to start the selected core".into());
            } else {
                state.set_hero_title("No server selected".into());
                state.set_hero_subtitle("Import a subscription or add a profile to begin".into());
            }
            state.set_active_core_name("Core adapters".into());
            state.set_active_core_subtitle(if installed_count > 0 {
                format!("{installed_count} core(s) verified · Standby").into()
            } else {
                "Standby · No core binaries installed".into()
            });
            state.set_active_core_badge(if installed_count > 0 {
                "Ready".into()
            } else {
                "Standby".into()
            });
            state.set_active_sockets_value("0 sockets".into());
            state.set_active_sockets_detail("No active tunnel".into());
        }
        ConnectionState::Connected => {
            state.set_hero_state(HeroState::Connected);
            state.set_status_label("Connected".into());
            if let Some(ref s) = session {
                let elapsed = Utc::now()
                    .signed_duration_since(s.started_at)
                    .num_seconds()
                    .max(0);
                let hrs = elapsed / 3600;
                let mins = (elapsed % 3600) / 60;
                let secs = elapsed % 60;
                state.set_session_timer(format!("{hrs:02}:{mins:02}:{secs:02}").into());
                state.set_hero_title(s.profile_name.clone().into());
                state.set_hero_subtitle(
                    format!("Protected via {} ({:?})", s.core_id, s.mode).into(),
                );
                state.set_active_core_name(s.core_id.display_name().into());
                state.set_active_core_subtitle(format!("v{} · PID managed", s.core_version).into());
                state.set_active_core_badge("Active".into());
            }
        }
        ConnectionState::Error { code, message } => {
            state.set_hero_state(HeroState::Error);
            state.set_status_label("Connection error".into());
            state.set_error_code(code.into());
            state.set_error_message(message.into());
        }
        busy => {
            state.set_hero_state(HeroState::Busy);
            state.set_status_label(busy.as_label().into());
        }
    }

    let core_pid = None;
    let res_sample = bootstrap.telemetry.sample_resources(core_pid);
    state.set_ui_ram_text(
        res_sample
            .ui_rss_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "N/A".to_owned())
            .into(),
    );
    state.set_ui_cpu_text(
        res_sample
            .ui_cpu_pct
            .map(|c| format!("{c:.1}%"))
            .unwrap_or_else(|| "N/A".to_owned())
            .into(),
    );

    let snap = bootstrap.engine.telemetry();
    state.set_core_ram_text(
        snap.core_rss_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "N/A".to_owned())
            .into(),
    );
    state.set_core_cpu_text(
        snap.core_cpu_pct
            .map(|c| format!("{c:.1}%"))
            .unwrap_or_else(|| "N/A".to_owned())
            .into(),
    );

    if matches!(conn_state, ConnectionState::Connected) {
        let down = snap.down_bps.unwrap_or(0);
        let up = snap.up_bps.unwrap_or(0);
        bootstrap.telemetry.record_traffic(TrafficSample {
            timestamp: Utc::now(),
            down_bps: down,
            up_bps: up,
            total_down_bytes: snap.total_down_bytes.unwrap_or(0),
            total_up_bytes: snap.total_up_bytes.unwrap_or(0),
        });
        state.set_download_speed(format_rate_mbps(down).into());
        state.set_upload_speed(format_rate_mbps(up).into());
        state.set_download_total(
            snap.total_down_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "Live".to_owned())
                .into(),
        );
        state.set_upload_total(
            snap.total_up_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "Live".to_owned())
                .into(),
        );
        let sock_cnt = snap.active_connections.unwrap_or(0);
        state.set_active_sockets_value(format!("{sock_cnt} sockets").into());
        state.set_active_sockets_detail("Reported by active core".into());
    }

    let range = match state.get_monitoring_range_index() {
        1 => TimeRange::FiveMin,
        2 => TimeRange::FifteenMin,
        3 => TimeRange::OneHour,
        _ => TimeRange::OneMin,
    };
    let samples = bootstrap.telemetry.traffic_for_range(range);
    if samples.len() >= 2 {
        let downs: Vec<f64> = samples.iter().map(|s| s.down_bps as f64).collect();
        let ups: Vec<f64> = samples.iter().map(|s| s.up_bps as f64).collect();
        let max_v = downs
            .iter()
            .chain(ups.iter())
            .copied()
            .fold(1024.0_f64, f64::max);
        state.set_has_traffic_data(true);
        state.set_download_stroke_path(build_line_path(&downs, 600.0, 180.0, Some(max_v)).into());
        state.set_download_fill_path(build_area_path(&downs, 600.0, 180.0, Some(max_v)).into());
        state.set_upload_stroke_path(build_line_path(&ups, 600.0, 180.0, Some(max_v)).into());
    } else {
        state.set_has_traffic_data(false);
        state.set_download_stroke_path("".into());
        state.set_download_fill_path("".into());
        state.set_upload_stroke_path("".into());
    }
}

pub fn sync_logs_to_ui(ui: &MainWindow, bootstrap: &Arc<AppBootstrap>) {
    let state = R3xAppState::get(ui);
    let cat = match state.get_diagnostics_tab() {
        2 => Some(LogCategory::Core),
        3 => Some(LogCategory::Subscription),
        4 => Some(LogCategory::Application),
        5 => Some(LogCategory::Platform),
        _ => None,
    };
    let query = state.get_log_search().to_ascii_lowercase();
    let entries = bootstrap.logs.recent(cat, 250);
    state.set_log_entry_count(bootstrap.logs.recent(None, 5000).len() as i32);

    let rows: Vec<LogRow> = entries
        .into_iter()
        .filter(|e| {
            query.is_empty()
                || e.message.to_ascii_lowercase().contains(&query)
                || e.source.to_ascii_lowercase().contains(&query)
        })
        .map(|e| LogRow {
            timestamp: e.timestamp.format("%H:%M:%S").to_string().into(),
            category: format!("{:?}", e.category).into(),
            level: format!("{:?}", e.level).into(),
            source: e.source.into(),
            message: e.message.into(),
        })
        .collect();
    state.set_log_lines(ModelRc::from(Rc::new(VecModel::from(rows))));
}

fn core_id_from_slug(slug: &str) -> Option<CoreId> {
    serde_json::from_str(&format!("\"{}\"", slug.trim())).ok()
}

pub fn wire_all_callbacks(ui: &MainWindow, bootstrap: &Arc<AppBootstrap>) {
    let ui_weak = ui.as_weak();
    let state = R3xAppState::get(ui);

    // Navigation & Onboarding & Modal Management
    {
        let u = ui_weak.clone();
        state.on_nav_selected(move |idx| {
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_current_nav(idx);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_complete_onboarding(move || {
            if let Ok(mut s) = b.db.load_settings() {
                s.onboarding_completed = true;
                let _ = b.db.save_settings(&s);
            }
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_show_onboarding(false);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_skip_onboarding(move || {
            if let Ok(mut s) = b.db.load_settings() {
                s.onboarding_completed = true;
                let _ = b.db.save_settings(&s);
            }
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_show_onboarding(false);
            }
        });
    }
    {
        let u = ui_weak.clone();
        state.on_open_modal(move |id| {
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_active_modal(id);
            }
        });
    }
    {
        let u = ui_weak.clone();
        state.on_close_modal(move || {
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_active_modal("".into());
            }
        });
    }
    {
        let u = ui_weak.clone();
        state.on_dismiss_snackbar(move || {
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_snackbar_message("".into());
            }
        });
    }
    {
        let u = ui_weak.clone();
        state.on_quick_settings_clicked(move || {
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_active_modal("quick_settings".into());
            }
        });
    }
    {
        let u = ui_weak.clone();
        state.on_open_server_selector(move || {
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_current_nav(2);
            }
        });
    }
    {
        let u = ui_weak.clone();
        state.on_open_diagnostics_clicked(move || {
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_current_nav(5);
            }
        });
    }

    // Appearance & Settings
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_theme_selected(move |idx| {
            let mode = match idx {
                0 => ThemeMode::System,
                1 => ThemeMode::Light,
                3 => ThemeMode::Amoled,
                _ => ThemeMode::Dark,
            };
            if let Ok(mut s) = b.db.load_settings() {
                s.theme_mode = mode;
                let _ = b.db.save_settings(&s);
                if let Some(w) = u.upgrade() {
                    R3xAppState::get(&w).set_theme_mode_index(idx);
                    apply_theme_settings(&w, mode, &s.accent);
                }
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_language_selected(move |idx| {
            if let Ok(mut s) = b.db.load_settings() {
                s.language = if idx == 1 { Language::Ru } else { Language::En };
                let _ = b.db.save_settings(&s);
            }
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_language_index(idx);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_reduced_motion_toggled(move |enabled| {
            if let Ok(mut s) = b.db.load_settings() {
                s.reduced_motion = enabled;
                let _ = b.db.save_settings(&s);
            }
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_reduced_motion(enabled);
                R3xMetrics::get(&w).set_reduced_motion(enabled);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_interface_mode_toggled(move |advanced| {
            if let Ok(mut s) = b.db.load_settings() {
                s.interface_mode = if advanced {
                    InterfaceMode::Advanced
                } else {
                    InterfaceMode::Simple
                };
                let _ = b.db.save_settings(&s);
            }
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_interface_advanced(advanced);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_apply_custom_accent(move |hex| {
            let trimmed = hex.trim().to_owned();
            if parse_hex_color(&trimmed).is_none() {
                if let Some(w) = u.upgrade() {
                    R3xAppState::get(&w)
                        .set_snackbar_message("Invalid hex color (use #RRGGBB)".into());
                }
                return;
            }
            if let Ok(mut s) = b.db.load_settings() {
                s.accent = AccentConfig::CustomHex(trimmed);
                let _ = b.db.save_settings(&s);
                if let Some(w) = u.upgrade() {
                    apply_theme_settings(&w, s.theme_mode, &s.accent);
                    R3xAppState::get(&w).set_snackbar_message("Custom accent applied".into());
                }
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_mode_selected(move |idx, _id| {
            if let Ok(mut s) = b.db.load_settings() {
                s.preferred_connection_mode = match idx {
                    1 => ConnectionMode::SystemProxy,
                    2 => ConnectionMode::Mixed,
                    _ => ConnectionMode::Tun,
                };
                let _ = b.db.save_settings(&s);
            }
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_connection_mode_index(idx);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_performance_profile_selected(move |idx| {
            if let Ok(mut s) = b.db.load_settings() {
                s.performance_profile = match idx {
                    0 => PerformanceProfile::Eco,
                    2 => PerformanceProfile::Performance,
                    _ => PerformanceProfile::Balanced,
                };
                let _ = b.db.save_settings(&s);
            }
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_performance_profile_index(idx);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_save_network_ports(move |mixed, socks, http| {
            let (Ok(mp), Ok(sp), Ok(hp)) = (
                mixed.trim().parse::<u16>(),
                socks.trim().parse::<u16>(),
                http.trim().parse::<u16>(),
            ) else {
                if let Some(w) = u.upgrade() {
                    R3xAppState::get(&w).set_snackbar_message("Invalid port number".into());
                }
                return;
            };
            if mp == 0 || sp == 0 || hp == 0 {
                if let Some(w) = u.upgrade() {
                    R3xAppState::get(&w).set_snackbar_message("Ports must be 1..65535".into());
                }
                return;
            }
            if let Ok(mut s) = b.db.load_settings() {
                s.mixed_port = mp;
                s.socks_port = sp;
                s.http_port = hp;
                let _ = b.db.save_settings(&s);
            }
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_snackbar_message("Saved local port configuration".into());
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_toggle_setting(move |key, enabled| {
            if let Ok(mut s) = b.db.load_settings() {
                match key.as_str() {
                    "auto_reconnect" => s.auto_reconnect = enabled,
                    "allow_lan" => s.allow_lan = enabled,
                    "ipv6_enabled" => s.ipv6_enabled = enabled,
                    "kill_switch" => s.kill_switch = enabled,
                    "minimize_to_tray" => s.minimize_to_tray = enabled,
                    "auto_start_on_boot" => s.auto_start_on_boot = enabled,
                    "connect_on_launch" => s.connect_on_launch = enabled,
                    _ => {}
                }
                let _ = b.db.save_settings(&s);
            }
            if let Some(w) = u.upgrade() {
                sync_all_models(&w, &b);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_rerun_onboarding(move || {
            if let Ok(mut s) = b.db.load_settings() {
                s.onboarding_completed = false;
                let _ = b.db.save_settings(&s);
            }
            if let Some(w) = u.upgrade() {
                let st = R3xAppState::get(&w);
                st.set_onboarding_step(0);
                st.set_show_onboarding(true);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_recover_network_clicked(move || {
            let backend = create_platform_proxy_backend();
            let msg = match recover_network_state(&b.paths.cache_dir, backend.as_ref()) {
                Ok(rep) => rep.notes.join("; "),
                Err(e) => format!("Recovery failed: {e}"),
            };
            b.logs
                .record(LogCategory::Network, LogLevel::Info, "r3x-recovery", &msg);
            if let Some(w) = u.upgrade() {
                sync_logs_to_ui(&w, &b);
                R3xAppState::get(&w).set_snackbar_message(msg.into());
            }
        });
    }

    // Encrypted Backups
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_submit_backup_export(move |passphrase| {
            let res = if passphrase.len() < 8 {
                Err(r3x_domain::R3xError::Validation(
                    "Backup passphrase must be at least 8 characters".to_owned(),
                ))
            } else {
                b.db.export_encrypted_backup(&passphrase).and_then(|env| {
                    let fname = format!("r3x-backup-{}.r3xbak", Utc::now().format("%Y%m%d-%H%M%S"));
                    let dest = b.paths.backups_dir.join(fname);
                    let json = serde_json::to_string_pretty(&env)
                        .map_err(|e| r3x_domain::R3xError::Storage(e.to_string()))?;
                    fs::write(&dest, json)?;
                    Ok(dest)
                })
            };
            if let Some(w) = u.upgrade() {
                let st = R3xAppState::get(&w);
                match res {
                    Ok(path) => {
                        st.set_backup_path_text(path.display().to_string().into());
                        st.set_backup_status_text(
                            format!("Exported encrypted backup: {}", path.display()).into(),
                        );
                    }
                    Err(e) => {
                        st.set_backup_status_text(format!("Backup failed: {e}").into());
                    }
                }
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_submit_backup_restore(move |path, passphrase| {
            let res = (|| -> Result<(), r3x_domain::R3xError> {
                let raw = fs::read_to_string(PathBuf::from(path.trim()))?;
                let env: EncryptedEnvelope = serde_json::from_str(&raw)
                    .map_err(|e| r3x_domain::R3xError::Validation(e.to_string()))?;
                b.db.restore_encrypted_backup(&env, &passphrase)
            })();
            if let Some(w) = u.upgrade() {
                sync_all_models(&w, &b);
                let st = R3xAppState::get(&w);
                st.set_backup_status_text(match res {
                    Ok(()) => "Encrypted backup restored successfully".into(),
                    Err(e) => format!("Restore failed: {e}").into(),
                });
            }
        });
    }

    // Import URI / Config / Manual Profile / Subscriptions
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_submit_import_uri(move |raw| {
            let trimmed = raw.trim();
            let parsed = if !trimmed.contains('\n') && trimmed.contains("://") {
                parse_profile_uri(trimmed, ProfileSource::ImportedUri).map(|p| vec![p])
            } else {
                parse_import_payload(trimmed.as_bytes(), ProfileSource::ImportedUri)
                    .map(|res| res.profiles)
            };
            match parsed {
                Ok(list) if !list.is_empty() => {
                    for p in &list {
                        let _ = b.db.upsert_profile(p);
                    }
                    if let Ok(mut s) = b.db.load_settings()
                        && s.selected_profile_id.is_none()
                    {
                        s.selected_profile_id = Some(list[0].id);
                        let _ = b.db.save_settings(&s);
                    }
                    b.logs.record(
                        LogCategory::Application,
                        LogLevel::Info,
                        "r3x-profiles",
                        format!("Imported {} profile(s) from UI", list.len()),
                    );
                    if let Some(w) = u.upgrade() {
                        sync_all_models(&w, &b);
                        let st = R3xAppState::get(&w);
                        st.set_form_import_text("".into());
                        st.set_snackbar_message(
                            format!("Imported {} profile(s)", list.len()).into(),
                        );
                    }
                }
                Ok(_) => {
                    if let Some(w) = u.upgrade() {
                        R3xAppState::get(&w).set_snackbar_message("No valid profiles found".into());
                    }
                }
                Err(e) => {
                    if let Some(w) = u.upgrade() {
                        R3xAppState::get(&w)
                            .set_snackbar_message(format!("Import error: {e}").into());
                    }
                }
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_submit_manual_profile(move |name, proto_idx, host, port_str, secret, sni| {
            let port = port_str.trim().parse::<u16>().unwrap_or(443);
            let proto = match proto_idx {
                1 => ProtocolType::Trojan,
                2 => ProtocolType::Shadowsocks,
                3 => ProtocolType::Hysteria2,
                _ => ProtocolType::Vless,
            };
            if host.trim().is_empty() || port == 0 {
                if let Some(w) = u.upgrade() {
                    R3xAppState::get(&w)
                        .set_snackbar_message("Host and valid port required".into());
                }
                return;
            }
            let now = Utc::now();
            let prof_name = if name.trim().is_empty() {
                format!("{} {}:{}", proto.display_name(), host.trim(), port)
            } else {
                name.trim().to_owned()
            };
            let sni_opt = (!sni.trim().is_empty()).then(|| sni.trim().to_owned());
            let security = if sni_opt.is_some()
                || matches!(proto, ProtocolType::Trojan | ProtocolType::Hysteria2)
            {
                SecurityConfig::Tls(TlsSettings {
                    sni: sni_opt,
                    alpn: Vec::new(),
                    fingerprint: Some("chrome".to_owned()),
                    allow_insecure: false,
                    ech_config: None,
                })
            } else {
                SecurityConfig::None
            };
            let profile = Profile {
                id: Uuid::new_v4(),
                name: prof_name,
                custom_name: None,
                source: ProfileSource::Manual,
                protocol: ProtocolConfig::simple(proto),
                transport: if matches!(proto, ProtocolType::Hysteria2) {
                    TransportConfig::Quic {
                        security: None,
                        header_type: None,
                    }
                } else {
                    TransportConfig::RawTcp { header_type: None }
                },
                security,
                flow: None,
                endpoint: Endpoint {
                    host: host.trim().to_owned(),
                    port,
                    local_addresses: Vec::new(),
                    dns_servers: Vec::new(),
                },
                auth: AuthConfig {
                    inline_secret: (!secret.is_empty())
                        .then(|| RedactedSecret::new(secret.to_string())),
                    ..Default::default()
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
            if b.db.upsert_profile(&profile).is_ok()
                && let Ok(mut s) = b.db.load_settings()
            {
                s.selected_profile_id = Some(profile.id);
                let _ = b.db.save_settings(&s);
            }
            if let Some(w) = u.upgrade() {
                sync_all_models(&w, &b);
                R3xAppState::get(&w).set_snackbar_message("Manual profile saved".into());
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_submit_add_subscription(move |name, url| {
            let b_bg = Arc::clone(&b);
            let u_bg = u.clone();
            let sub_name = (!name.trim().is_empty()).then(|| name.trim().to_owned());
            let sub_url = url.trim().to_owned();
            b.runtime.spawn(async move {
                let res = b_bg
                    .sub_manager
                    .add_remote_and_fetch(sub_name, &sub_url)
                    .await;
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = u_bg.upgrade() {
                        sync_all_models(&w, &b_bg);
                        let msg = match res {
                            Ok(sub) => {
                                format!("Added '{}' ({} servers)", sub.name, sub.server_count)
                            }
                            Err(e) => format!("Subscription fetch failed: {e}"),
                        };
                        R3xAppState::get(&w).set_snackbar_message(msg.into());
                    }
                });
            });
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_refresh_subscription(move |id_str| {
            let Ok(id) = Uuid::parse_str(id_str.trim()) else {
                return;
            };
            let b_bg = Arc::clone(&b);
            let u_bg = u.clone();
            b.runtime.spawn(async move {
                let res = b_bg.sub_manager.refresh_subscription(id).await;
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = u_bg.upgrade() {
                        sync_all_models(&w, &b_bg);
                        let msg = match res {
                            Ok(sub) => {
                                format!("Refreshed '{}' ({} servers)", sub.name, sub.server_count)
                            }
                            Err(e) => format!("Refresh failed: {e}"),
                        };
                        R3xAppState::get(&w).set_snackbar_message(msg.into());
                    }
                });
            });
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_refresh_all_subscriptions(move || {
            let b_bg = Arc::clone(&b);
            let u_bg = u.clone();
            b.runtime.spawn(async move {
                let mut refreshed = 0usize;
                let mut errors = 0usize;
                for sub in b_bg.db.list_subscriptions().unwrap_or_default() {
                    if sub.enabled {
                        if b_bg.sub_manager.refresh_subscription(sub.id).await.is_ok() {
                            refreshed += 1;
                        } else {
                            errors += 1;
                        }
                    }
                }
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = u_bg.upgrade() {
                        sync_all_models(&w, &b_bg);
                        R3xAppState::get(&w).set_snackbar_message(
                            format!("Refreshed {refreshed} feed(s), {errors} error(s)").into(),
                        );
                    }
                });
            });
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_delete_subscription(move |id_str| {
            if let Ok(id) = Uuid::parse_str(id_str.trim()) {
                let _ = b.db.delete_subscription(id);
                if let Some(w) = u.upgrade() {
                    sync_all_models(&w, &b);
                }
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_select_subscription(move |id_str| {
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_selected_subscription_id(id_str);
                sync_all_models(&w, &b);
            }
        });
    }

    // Server Selection, Favorites, Export & Real Latency Probes
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_select_profile(move |id_str| {
            if let Ok(id) = Uuid::parse_str(id_str.trim())
                && let Ok(mut s) = b.db.load_settings()
            {
                s.selected_profile_id = Some(id);
                let _ = b.db.save_settings(&s);
                if let Some(w) = u.upgrade() {
                    sync_all_models(&w, &b);
                }
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_toggle_favorite_profile(move |id_str| {
            if let Ok(id) = Uuid::parse_str(id_str.trim())
                && let Ok(Some(mut p)) = b.db.get_profile(id)
            {
                p.favorite = !p.favorite;
                p.updated_at = Utc::now();
                let _ = b.db.upsert_profile(&p);
                if let Some(w) = u.upgrade() {
                    sync_all_models(&w, &b);
                }
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_delete_profile(move |id_str| {
            if let Ok(id) = Uuid::parse_str(id_str.trim()) {
                let _ = b.db.delete_profile(id);
                if let Some(w) = u.upgrade() {
                    sync_all_models(&w, &b);
                }
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_set_server_filter(move |query, fav_only| {
            if let Some(w) = u.upgrade() {
                let st = R3xAppState::get(&w);
                st.set_server_search_query(query);
                st.set_server_filter_favorites(fav_only);
                sync_all_models(&w, &b);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_export_profile_uri(move |id_str| {
            if let Ok(id) = Uuid::parse_str(id_str.trim())
                && let Ok(Some(prof)) = b.db.get_profile(id)
                && let Some(w) = u.upgrade()
            {
                let out = profile_to_uri(&prof).unwrap_or_else(|e| format!("Export N/A: {e}"));
                R3xAppState::get(&w).set_exported_uri_preview(out.into());
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_test_latency_clicked(move || {
            let b_bg = Arc::clone(&b);
            let u_bg = u.clone();
            b.runtime.spawn(async move {
                let settings = b_bg.db.load_settings().unwrap_or_default();
                let profiles = b_bg.db.list_profiles().unwrap_or_default();
                let Some(mut target) = settings
                    .selected_profile_id
                    .and_then(|id| profiles.into_iter().find(|p| p.id == id))
                else {
                    return;
                };
                let probe = measure_tcp_latency(
                    &target.endpoint.host,
                    target.endpoint.port,
                    Duration::from_secs(3),
                )
                .await;
                let msg = match probe {
                    Ok(ms) => {
                        target.latency_ms = Some(ms);
                        let _ = b_bg.db.upsert_profile(&target);
                        format!("TCP handshake RTT: {ms} ms")
                    }
                    Err(e) => {
                        target.latency_ms = None;
                        let _ = b_bg.db.upsert_profile(&target);
                        format!("Latency test failed: {e}")
                    }
                };
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = u_bg.upgrade() {
                        sync_all_models(&w, &b_bg);
                        let st = R3xAppState::get(&w);
                        st.set_quality_value(msg.clone().into());
                        st.set_quality_detail("Direct TCP connect probe".into());
                        st.set_snackbar_message(msg.into());
                    }
                });
            });
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_test_all_latencies(move || {
            let b_bg = Arc::clone(&b);
            let u_bg = u.clone();
            b.runtime.spawn(async move {
                let profiles = b_bg.db.list_profiles().unwrap_or_default();
                let mut ok_cnt = 0usize;
                for mut p in profiles {
                    if let Ok(ms) = measure_tcp_latency(
                        &p.endpoint.host,
                        p.endpoint.port,
                        Duration::from_secs(2),
                    )
                    .await
                    {
                        p.latency_ms = Some(ms);
                        ok_cnt += 1;
                    } else {
                        p.latency_ms = None;
                    }
                    let _ = b_bg.db.upsert_profile(&p);
                }
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = u_bg.upgrade() {
                        sync_all_models(&w, &b_bg);
                        R3xAppState::get(&w).set_snackbar_message(
                            format!("Latency scan finished ({ok_cnt} reachable)").into(),
                        );
                    }
                });
            });
        });
    }

    // Hero Connect / Disconnect Action
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_hero_action_clicked(move || {
            let cur = b.engine.connection_state();
            if matches!(cur, ConnectionState::Connected) || cur.is_busy() {
                let b_bg = Arc::clone(&b);
                let u_bg = u.clone();
                b.runtime.spawn(async move {
                    let _ = b_bg.engine.disconnect().await;
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(w) = u_bg.upgrade() {
                            sync_all_models(&w, &b_bg);
                        }
                    });
                });
                return;
            }

            let settings = b.db.load_settings().unwrap_or_default();
            let profiles = b.db.list_profiles().unwrap_or_default();
            let selected = settings
                .selected_profile_id
                .and_then(|id| profiles.iter().find(|p| p.id == id))
                .or_else(|| profiles.first())
                .cloned();
            let Some(profile) = selected else {
                if let Some(w) = u.upgrade() {
                    R3xAppState::get(&w).set_current_nav(1);
                }
                return;
            };
            let dns = b.db.load_dns_config().unwrap_or_default();
            let rules = b.routing.list_rules_sorted().unwrap_or_default();
            let b_bg = Arc::clone(&b);
            let u_bg = u.clone();
            b.runtime.spawn(async move {
                let res = b_bg
                    .engine
                    .connect(ConnectRequest {
                        profile,
                        subscription_preference: CorePreference::Auto,
                        global_preference: settings.global_core_preference,
                        mode: settings.preferred_connection_mode,
                        dns,
                        routing_rules: rules,
                        tun_fd: None,
                    })
                    .await;
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = u_bg.upgrade() {
                        sync_all_models(&w, &b_bg);
                        if let Err(err) = res {
                            let st = R3xAppState::get(&w);
                            st.set_hero_state(HeroState::Error);
                            st.set_error_code(err.code().into());
                            st.set_error_message(err.to_string().into());
                        }
                    }
                });
            });
        });
    }

    // Routing & DNS & Raw Config Preview
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_add_preset_rules(move || {
            let _ = b.routing.install_default_presets();
            if let Some(w) = u.upgrade() {
                sync_all_models(&w, &b);
                R3xAppState::get(&w)
                    .set_snackbar_message("Installed LAN/Loopback/Ad-block presets".into());
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_submit_add_rule(move |name, type_idx, value, action_idx| {
            let matcher = match type_idx {
                1 => {
                    if let Ok(net) = value.trim().parse::<ipnet::IpNet>() {
                        RuleMatcher::Cidr(net)
                    } else {
                        RuleMatcher::Ip(value.trim().to_owned())
                    }
                }
                2 => RuleMatcher::ProcessName(value.trim().to_owned()),
                _ => RuleMatcher::DomainSuffix(value.trim().to_owned()),
            };
            let action = match action_idx {
                1 => RuleAction::Proxy,
                2 => RuleAction::Block,
                _ => RuleAction::Direct,
            };
            let rule = RoutingRule {
                id: Uuid::new_v4(),
                name: name.trim().to_owned(),
                enabled: true,
                priority: 50,
                group: "User".to_owned(),
                matcher,
                action,
            };
            let msg = match b.routing.upsert_rule(&rule) {
                Ok(()) => "Routing rule added".to_owned(),
                Err(e) => format!("Invalid rule: {e}"),
            };
            if let Some(w) = u.upgrade() {
                sync_all_models(&w, &b);
                R3xAppState::get(&w).set_snackbar_message(msg.into());
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_toggle_routing_rule(move |id_str, enabled| {
            if let Ok(id) = Uuid::parse_str(id_str.trim()) {
                let _ = b.routing.toggle_rule(id, enabled);
                if let Some(w) = u.upgrade() {
                    sync_all_models(&w, &b);
                }
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_delete_routing_rule(move |id_str| {
            if let Ok(id) = Uuid::parse_str(id_str.trim()) {
                let _ = b.routing.delete_rule(id);
                if let Some(w) = u.upgrade() {
                    sync_all_models(&w, &b);
                }
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_save_dns_config(move || {
            let Some(w) = u.upgrade() else { return };
            let st = R3xAppState::get(&w);
            let mode = match st.get_dns_mode_index() {
                0 => DnsMode::System,
                1 => DnsMode::Custom,
                3 => DnsMode::DoT,
                4 => DnsMode::DoQ,
                _ => DnsMode::DoH,
            };
            let leak = match st.get_dns_leak_mode_index() {
                0 => DnsLeakProtectionMode::Off,
                2 => DnsLeakProtectionMode::FakeIp,
                _ => DnsLeakProtectionMode::StrictTunnelOnly,
            };
            let fb_addr = st.get_dns_fallback_address().trim().to_owned();
            let mut cfg = DnsConfig::default();
            cfg.primary.mode = mode;
            cfg.primary.address = st.get_dns_primary_address().trim().to_owned();
            cfg.enable_ipv6 = st.get_dns_ipv6();
            cfg.leak_protection = leak;
            if fb_addr.is_empty() {
                cfg.fallback = None;
            } else if let Some(ref mut fb) = cfg.fallback {
                fb.address = fb_addr;
            }
            let msg = match validate_dns_config(&cfg).and_then(|()| b.db.save_dns_config(&cfg)) {
                Ok(()) => "DNS configuration saved".to_owned(),
                Err(e) => format!("Invalid DNS config: {e}"),
            };
            st.set_snackbar_message(msg.into());
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_test_dns_clicked(move || {
            let Some(w) = u.upgrade() else { return };
            let st = R3xAppState::get(&w);
            let mut resolver = DnsConfig::default().primary;
            resolver.mode = match st.get_dns_mode_index() {
                0 => DnsMode::System,
                1 => DnsMode::Custom,
                3 => DnsMode::DoT,
                4 => DnsMode::DoQ,
                _ => DnsMode::DoH,
            };
            resolver.address = st.get_dns_primary_address().trim().to_owned();
            st.set_dns_test_status("Probing...".into());
            let u_bg = u.clone();
            b.runtime.spawn(async move {
                let res = test_dns_resolver(&resolver, Duration::from_secs(3)).await;
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = u_bg.upgrade() {
                        let status = if res.reachable {
                            format!("OK ({} ms) · {}", res.latency_ms, res.details)
                        } else {
                            format!("Failed · {}", res.details)
                        };
                        R3xAppState::get(&w).set_dns_test_status(status.into());
                    }
                });
            });
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_refresh_raw_config(move |core_idx| {
            let core_id = match core_idx {
                1 => CoreId::SingBox,
                2 => CoreId::Mihomo,
                _ => CoreId::Xray,
            };
            let settings = b.db.load_settings().unwrap_or_default();
            let rules = b.routing.list_rules_sorted().unwrap_or_default();
            let dns = b.db.load_dns_config().unwrap_or_default();
            let profiles = b.db.list_profiles().unwrap_or_default();
            let selected = settings
                .selected_profile_id
                .and_then(|id| profiles.into_iter().find(|p| p.id == id));

            let preview = if let Some(prof) = selected {
                let work_dir = b.paths.cache_dir.join("preview");
                let _ = fs::create_dir_all(&work_dir);
                let ctx = CoreConfigContext {
                    profile: prof,
                    mode: settings.preferred_connection_mode,
                    dns,
                    routing_rules: rules.clone(),
                    work_dir: work_dir.clone(),
                    mixed_port: settings.mixed_port,
                    socks_port: settings.socks_port,
                    http_port: settings.http_port,
                    ipv6_enabled: settings.ipv6_enabled,
                    allow_lan: settings.allow_lan,
                    tun_interface_name: "r3x-tun0".to_owned(),
                    tun_fd: None,
                };
                let b_rt = Arc::clone(&b);
                let out = b_rt.runtime.block_on(async move {
                    let res = match core_id {
                        CoreId::Xray => XrayAdapter::new(None).generate_config(&ctx).await,
                        CoreId::SingBox => SingBoxAdapter::new(None).generate_config(&ctx).await,
                        _ => MihomoAdapter::new(None).generate_config(&ctx).await,
                    };
                    let _ = fs::remove_dir_all(&work_dir);
                    res
                });
                match out {
                    Ok(gen_cfg) => Redactor::redact_str(&gen_cfg.config_contents),
                    Err(err) => {
                        let fallback = preview_core_routing(core_id, &rules);
                        format!("// Full config N/A ({err})\n// Routing preview:\n{fallback:#}")
                    }
                }
            } else {
                serde_json::to_string_pretty(&preview_core_routing(core_id, &rules))
                    .unwrap_or_else(|_| "{}".to_owned())
            };

            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_raw_config_preview(preview.into());
            }
        });
    }

    // Connections & History
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_clear_connection_history(move || {
            let _ = b.db.clear_connection_history();
            if let Some(w) = u.upgrade() {
                sync_all_models(&w, &b);
            }
        });
    }

    // Diagnostics, Telemetry & Logs
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_set_monitoring_range(move |idx| {
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_monitoring_range_index(idx);
                sync_connection_and_telemetry_ui(&w, &b);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_toggle_monitoring_pause(move || {
            let next = !b.telemetry.is_paused();
            b.telemetry.set_paused(next);
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_monitoring_paused(next);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_run_network_doctor(move || {
            if let Some(w) = u.upgrade() {
                let st = R3xAppState::get(&w);
                st.set_doctor_running(true);
                st.set_doctor_summary("Running 16 network & core diagnostics...".into());
            }
            let b_bg = Arc::clone(&b);
            let u_bg = u.clone();
            b.runtime.spawn(async move {
                let settings = b_bg.db.load_settings().unwrap_or_default();
                let dns = b_bg.db.load_dns_config().unwrap_or_default();
                let active_profile = settings
                    .selected_profile_id
                    .and_then(|id| b_bg.db.get_profile(id).ok().flatten());
                let doctor = NetworkDoctor::new(DiagnosticContext {
                    db: Arc::clone(&b_bg.db),
                    engine: Arc::clone(&b_bg.engine),
                    active_profile,
                    settings,
                    dns,
                    connectivity_probe_addr: None,
                    tls_probe_url: None,
                    dns_lookup_host: None,
                });
                let report = doctor.run_all().await;
                let redacted_text = export_redacted_report(&report);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = u_bg.upgrade() {
                        let passed = report
                            .results
                            .iter()
                            .filter(|r| matches!(r.status, DiagnosticStatus::Passed))
                            .count();
                        let warnings = report
                            .results
                            .iter()
                            .filter(|r| matches!(r.status, DiagnosticStatus::Warning))
                            .count();
                        let failed = report
                            .results
                            .iter()
                            .filter(|r| matches!(r.status, DiagnosticStatus::Failed))
                            .count();
                        let rows: Vec<DiagnosticRow> = report
                            .results
                            .iter()
                            .map(|r| {
                                let (key, label) = match r.status {
                                    DiagnosticStatus::Passed => ("passed", "Passed"),
                                    DiagnosticStatus::Warning => ("warning", "Warning"),
                                    DiagnosticStatus::Failed => ("failed", "Failed"),
                                    DiagnosticStatus::Unsupported => ("unsupported", "Unsupported"),
                                    DiagnosticStatus::Running => ("running", "Running"),
                                    DiagnosticStatus::NotTested => ("not_tested", "Not tested"),
                                };
                                DiagnosticRow {
                                    id: format!("{:?}", r.check_id).into(),
                                    title: format_check_title(r.check_id).into(),
                                    status_key: key.into(),
                                    status_label: label.into(),
                                    summary: r.summary.clone().into(),
                                    technical_details: r.technical_details.clone().into(),
                                    suggested_action: r.suggested_actions.join(" ").into(),
                                    duration_text: r
                                        .duration_ms
                                        .map(|m| format!("{m} ms"))
                                        .unwrap_or_else(|| "—".to_owned())
                                        .into(),
                                }
                            })
                            .collect();
                        let st = R3xAppState::get(&w);
                        st.set_doctor_running(false);
                        st.set_diagnostic_checks(ModelRc::from(Rc::new(VecModel::from(rows))));
                        st.set_doctor_report_text(redacted_text.into());
                        st.set_doctor_summary(
                            format!(
                                "Completed {} checks: {} passed, {} warning(s), {} failed",
                                report.results.len(),
                                passed,
                                warnings,
                                failed
                            )
                            .into(),
                        );
                    }
                });
            });
        });
    }
    {
        let u = ui_weak.clone();
        state.on_export_doctor_report(move || {
            if let Some(w) = u.upgrade() {
                let st = R3xAppState::get(&w);
                if st.get_doctor_report_text().is_empty() {
                    st.set_snackbar_message("Run Network Doctor first".into());
                } else {
                    st.set_active_modal("report_preview".into());
                }
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_refresh_logs(move || {
            if let Some(w) = u.upgrade() {
                sync_logs_to_ui(&w, &b);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_clear_logs(move || {
            b.logs.clear(None);
            if let Some(w) = u.upgrade() {
                sync_logs_to_ui(&w, &b);
            }
        });
    }

    // Core Manager
    {
        let u = ui_weak.clone();
        state.on_select_core(move |id| {
            if let Some(w) = u.upgrade() {
                R3xAppState::get(&w).set_selected_core_id(id);
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_set_preferred_core(move |slug| {
            if let Some(core_id) = core_id_from_slug(&slug)
                && let Ok(mut s) = b.db.load_settings()
            {
                s.global_core_preference = CorePreference::Preferred(core_id);
                let _ = b.db.save_settings(&s);
                if let Some(w) = u.upgrade() {
                    sync_all_models(&w, &b);
                    R3xAppState::get(&w).set_snackbar_message(
                        format!("Global preferred core set to {}", core_id.display_name()).into(),
                    );
                }
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_reset_core_auto(move || {
            if let Ok(mut s) = b.db.load_settings() {
                s.global_core_preference = CorePreference::Auto;
                let _ = b.db.save_settings(&s);
                if let Some(w) = u.upgrade() {
                    sync_all_models(&w, &b);
                    R3xAppState::get(&w)
                        .set_snackbar_message("Core selection reset to Auto".into());
                }
            }
        });
    }
    {
        let u = ui_weak.clone();
        let b = Arc::clone(bootstrap);
        state.on_verify_cores_clicked(move || {
            let discovered = b.core_manager.discover_installed();
            for m in default_core_manifests().unwrap_or_default() {
                b.engine
                    .set_core_installed(m.id, discovered.contains_key(&m.id));
            }
            if let Some(w) = u.upgrade() {
                sync_all_models(&w, &b);
                R3xAppState::get(&w).set_snackbar_message(
                    format!("Verified {} installed core binary(s)", discovered.len()).into(),
                );
            }
        });
    }
}

fn format_check_title(id: DiagnosticCheckId) -> &'static str {
    match id {
        DiagnosticCheckId::InternetConnectivity => "Internet TCP Connectivity",
        DiagnosticCheckId::DnsResolution => "DNS Resolution",
        DiagnosticCheckId::ServerReachability => "Server Reachability",
        DiagnosticCheckId::TlsConnectivity => "TLS Handshake Verification",
        DiagnosticCheckId::CoreProcessHealth => "Core Process Health",
        DiagnosticCheckId::ConfigurationValidity => "Configuration Validity",
        DiagnosticCheckId::CoreCompatibility => "Core Compatibility & Selection",
        DiagnosticCheckId::TunInterface => "TUN Interface Readiness",
        DiagnosticCheckId::SystemProxy => "System Proxy State",
        DiagnosticCheckId::RoutingState => "Routing Rules Validation",
        DiagnosticCheckId::Ipv4Connectivity => "IPv4 Interface Check",
        DiagnosticCheckId::Ipv6Connectivity => "IPv6 Interface Check",
        DiagnosticCheckId::DnsLeaks => "DNS Leak Audit",
        DiagnosticCheckId::NetworkAdapterConflicts => "VPN Adapter Conflict Check",
        DiagnosticCheckId::RequiredPermissions => "Permissions & Secret Store",
        DiagnosticCheckId::LocalPortAvailability => "Local Inbound Port Availability",
    }
}

pub fn start_telemetry_timer(ui: &MainWindow, bootstrap: &Arc<AppBootstrap>) -> Timer {
    let settings = bootstrap.db.load_settings().unwrap_or_default();
    let interval_ms = settings.performance_profile.telemetry_interval_ms();
    let timer = Timer::default();
    let u = ui.as_weak();
    let b = Arc::clone(bootstrap);
    timer.start(
        TimerMode::Repeated,
        Duration::from_millis(interval_ms),
        move || {
            if let Some(w) = u.upgrade() {
                sync_connection_and_telemetry_ui(&w, &b);
            }
        },
    );
    timer
}
