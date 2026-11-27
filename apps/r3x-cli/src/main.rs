use chrono::Utc;
use clap::{Args, Parser, Subcommand, ValueEnum};
use r3x_cores::{CoreManager, default_core_manifests};
use r3x_domain::{
    ConnectionMode, CoreId, DiagnosticCheckId, DiagnosticReport, DiagnosticResult,
    DiagnosticStatus, LogCategory, ProfileSource, R3xError,
};
use r3x_ipc::{IPC_PROTOCOL_VERSION, IpcClient, IpcCommand, IpcPayload, SocketAddress};
use r3x_network::{
    check_tun_capability, create_platform_proxy_backend, is_local_port_available,
    list_network_interfaces, recover_network_state,
};
use r3x_profiles::{SubscriptionManager, parse_import_payload, parse_profile_uri};
use r3x_security::Redactor;
use r3x_storage::{AppPaths, R3xDatabase};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "r3x",
    version,
    about = "R3X (Rexy) — Universal Multi-Core VPN & Proxy CLI"
)]
struct Cli {
    #[arg(long, global = true, help = "Emit structured JSON output")]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    Connect(ConnectArgs),
    Disconnect,
    Reconnect,
    Profiles(ProfilesCmd),
    Subscriptions(SubscriptionsCmd),
    Cores(CoresCmd),
    Diagnostics(DiagnosticsCmd),
    Logs(LogsArgs),
    RecoverNetwork,
    Version,
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    Tun,
    Proxy,
    Mixed,
}

impl From<ModeArg> for ConnectionMode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Tun => Self::Tun,
            ModeArg::Proxy => Self::SystemProxy,
            ModeArg::Mixed => Self::Mixed,
        }
    }
}

#[derive(Args)]
struct ConnectArgs {
    #[arg(long, help = "Profile UUID or exact name")]
    profile: Option<String>,
    #[arg(long, value_enum, default_value_t = ModeArg::Proxy)]
    mode: ModeArg,
}

#[derive(Args)]
struct ProfilesCmd {
    #[command(subcommand)]
    sub: ProfilesSub,
}

#[derive(Subcommand)]
enum ProfilesSub {
    List,
    Import { target: String },
    Validate { target: String },
}

#[derive(Args)]
struct SubscriptionsCmd {
    #[command(subcommand)]
    sub: SubscriptionsSub,
}

#[derive(Subcommand)]
enum SubscriptionsSub {
    List,
    Add { name: String, url: String },
    Refresh { id: Option<Uuid> },
}

#[derive(Args)]
struct CoresCmd {
    #[command(subcommand)]
    sub: CoresSub,
}

#[derive(Subcommand)]
enum CoresSub {
    List,
    Info { id: String },
}

#[derive(Args)]
struct DiagnosticsCmd {
    #[command(subcommand)]
    sub: DiagnosticsSub,
}

#[derive(Subcommand)]
enum DiagnosticsSub {
    Run,
    Export { output: PathBuf },
}

#[derive(Args)]
struct LogsArgs {
    #[arg(long)]
    category: Option<String>,
    #[arg(long, default_value_t = 50)]
    limit: usize,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(err) = execute(cli).await {
        eprintln!("Error [{}]: {err}", err.code());
        std::process::exit(1);
    }
}

fn print_output<T: Serialize>(json_mode: bool, value: &T, human: &str) -> Result<(), R3xError> {
    if json_mode {
        let out = serde_json::to_string_pretty(value)
            .map_err(|e| R3xError::Storage(format!("JSON serialization failed: {e}")))?;
        println!("{out}");
    } else {
        println!("{human}");
    }
    Ok(())
}

fn read_ipc_client(paths: &AppPaths) -> Result<IpcClient, R3xError> {
    let tok_path = paths.data_dir.join("ipc.token");
    if !tok_path.exists() {
        return Err(R3xError::Ipc(
            "r3x-daemon IPC token not found; ensure r3x-daemon is running".to_owned(),
        ));
    }
    let token = fs::read_to_string(tok_path)?.trim().to_owned();
    Ok(IpcClient::new(SocketAddress::default_daemon(), token))
}

fn load_target_bytes(target: &str) -> Result<(Vec<u8>, ProfileSource), R3xError> {
    let path = Path::new(target);
    if path.exists() && path.is_file() {
        let bytes = fs::read(path)?;
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("import.conf")
            .to_owned();
        return Ok((bytes, ProfileSource::ImportedFile { filename }));
    }
    Ok((target.as_bytes().to_vec(), ProfileSource::ImportedUri))
}

fn parse_core_id(raw: &str) -> Result<CoreId, R3xError> {
    let norm = raw.trim().to_ascii_lowercase();
    for manifest in default_core_manifests()? {
        let slug = serde_json::to_value(manifest.id)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        if slug == norm || manifest.name.to_ascii_lowercase() == norm {
            return Ok(manifest.id);
        }
    }
    Err(R3xError::Validation(format!("unknown core id '{raw}'")))
}

fn build_baseline_diagnostics(paths: &AppPaths) -> Result<DiagnosticReport, R3xError> {
    let settings = {
        let db = R3xDatabase::open_with_recovery(&paths.db_path)?.db;
        db.load_settings()?
    };
    let core_mgr = CoreManager::new(paths.cores_dir.clone(), None);
    let installed = core_mgr.discover_installed();
    let tun = check_tun_capability();
    let proxy_backend = create_platform_proxy_backend();
    let ifaces = list_network_interfaces();
    let port_ok = is_local_port_available(settings.mixed_port);

    let results = vec![
        DiagnosticResult {
            check_id: DiagnosticCheckId::RequiredPermissions,
            status: if tun.available {
                DiagnosticStatus::Passed
            } else {
                DiagnosticStatus::Warning
            },
            summary: tun.details.clone(),
            technical_details: format!("requires_elevation={}", tun.requires_elevation),
            suggested_actions: if tun.requires_elevation {
                vec!["Run r3x-daemon with TUN privileges or use Proxy mode".to_owned()]
            } else {
                Vec::new()
            },
            related_settings_section: Some("connection".to_owned()),
            duration_ms: Some(1),
        },
        DiagnosticResult {
            check_id: DiagnosticCheckId::SystemProxy,
            status: if proxy_backend.is_supported() {
                DiagnosticStatus::Passed
            } else {
                DiagnosticStatus::Unsupported
            },
            summary: format!("System proxy backend: {}", proxy_backend.backend_name()),
            technical_details: format!("supported={}", proxy_backend.is_supported()),
            suggested_actions: Vec::new(),
            related_settings_section: Some("connection".to_owned()),
            duration_ms: Some(1),
        },
        DiagnosticResult {
            check_id: DiagnosticCheckId::LocalPortAvailability,
            status: if port_ok {
                DiagnosticStatus::Passed
            } else {
                DiagnosticStatus::Warning
            },
            summary: if port_ok {
                format!("Mixed inbound port {} is free", settings.mixed_port)
            } else {
                format!(
                    "Mixed inbound port {} is currently in use",
                    settings.mixed_port
                )
            },
            technical_details: format!("port={}", settings.mixed_port),
            suggested_actions: Vec::new(),
            related_settings_section: Some("connection".to_owned()),
            duration_ms: Some(1),
        },
        DiagnosticResult {
            check_id: DiagnosticCheckId::CoreCompatibility,
            status: if installed.is_empty() {
                DiagnosticStatus::Warning
            } else {
                DiagnosticStatus::Passed
            },
            summary: format!("{} verified core binary(s) installed", installed.len()),
            technical_details: format!(
                "interfaces={}, cores={:?}",
                ifaces.len(),
                installed.keys().collect::<Vec<_>>()
            ),
            suggested_actions: Vec::new(),
            related_settings_section: Some("cores".to_owned()),
            duration_ms: Some(1),
        },
    ];

    Ok(DiagnosticReport {
        generated_at: Utc::now(),
        platform: std::env::consts::OS.to_owned(),
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
        results,
    })
}

async fn execute(cli: Cli) -> Result<(), R3xError> {
    let paths = AppPaths::from_env_or_system()?;
    paths.ensure_all_dirs()?;

    match cli.command {
        Commands::Version => {
            #[derive(Serialize)]
            struct VersionInfo<'a> {
                name: &'a str,
                version: &'a str,
                ipc_protocol: u32,
                platform: &'a str,
                arch: &'a str,
            }
            let info = VersionInfo {
                name: "R3X",
                version: env!("CARGO_PKG_VERSION"),
                ipc_protocol: IPC_PROTOCOL_VERSION,
                platform: std::env::consts::OS,
                arch: std::env::consts::ARCH,
            };
            print_output(
                cli.json,
                &info,
                &format!(
                    "R3X v{} (IPC v{}, {}/{})",
                    info.version, info.ipc_protocol, info.platform, info.arch
                ),
            )
        }
        Commands::Status => {
            let client = read_ipc_client(&paths)?;
            let resp = client.send(IpcCommand::GetStatus).await?;
            match resp.payload {
                IpcPayload::Status { state, session } => {
                    #[derive(Serialize)]
                    struct StatusOut {
                        state: r3x_domain::ConnectionState,
                        session: Option<r3x_domain::ConnectionSession>,
                    }
                    let human = format!(
                        "State: {}{}",
                        state,
                        session
                            .as_ref()
                            .map(|s| format!(" ({} via {})", s.profile_name, s.core_id))
                            .unwrap_or_default()
                    );
                    print_output(cli.json, &StatusOut { state, session }, &human)
                }
                IpcPayload::Error(e) => Err(R3xError::Ipc(format!("{}: {}", e.code, e.message))),
                other => Err(R3xError::Ipc(format!("unexpected IPC reply: {other:?}"))),
            }
        }
        Commands::Connect(args) => {
            let db = R3xDatabase::open_with_recovery(&paths.db_path)?.db;
            let profiles = db.list_profiles()?;
            let target_id = if let Some(ref query) = args.profile {
                if let Ok(uuid) = Uuid::parse_str(query) {
                    uuid
                } else {
                    profiles
                        .iter()
                        .find(|p| p.effective_name().eq_ignore_ascii_case(query))
                        .map(|p| p.id)
                        .ok_or_else(|| {
                            R3xError::Validation(format!("profile '{query}' not found"))
                        })?
                }
            } else {
                profiles
                    .first()
                    .map(|p| p.id)
                    .ok_or_else(|| R3xError::Validation("no profiles stored".to_owned()))?
            };

            let client = read_ipc_client(&paths)?;
            let resp = client
                .send(IpcCommand::Connect {
                    profile_id: target_id,
                    mode: args.mode.into(),
                })
                .await?;
            match resp.payload {
                IpcPayload::Status { state, session } => {
                    print_output(cli.json, &session, &format!("Connected: {state}"))
                }
                IpcPayload::Error(e) => Err(R3xError::Ipc(format!("{}: {}", e.code, e.message))),
                _ => Ok(()),
            }
        }
        Commands::Disconnect => {
            let client = read_ipc_client(&paths)?;
            match client.send(IpcCommand::Disconnect).await?.payload {
                IpcPayload::Ok => print_output(cli.json, &"disconnected", "Disconnected"),
                IpcPayload::Error(e) => Err(R3xError::Ipc(format!("{}: {}", e.code, e.message))),
                _ => Ok(()),
            }
        }
        Commands::Reconnect => {
            let client = read_ipc_client(&paths)?;
            match client.send(IpcCommand::Reconnect).await?.payload {
                IpcPayload::Status { state, session } => {
                    print_output(cli.json, &session, &format!("Reconnected: {state}"))
                }
                IpcPayload::Ok => print_output(cli.json, &"ok", "Reconnected"),
                IpcPayload::Error(e) => Err(R3xError::Ipc(format!("{}: {}", e.code, e.message))),
                _ => Ok(()),
            }
        }
        Commands::Profiles(cmd) => {
            let db = R3xDatabase::open_with_recovery(&paths.db_path)?.db;
            match cmd.sub {
                ProfilesSub::List => {
                    let list = db.list_profiles()?;
                    let human = list
                        .iter()
                        .map(|p| {
                            format!(
                                "{} | {} | {} | {}:{}",
                                p.id,
                                p.effective_name(),
                                p.protocol.protocol_type.display_name(),
                                p.endpoint.host,
                                p.endpoint.port
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    print_output(
                        cli.json,
                        &list,
                        if human.is_empty() {
                            "No profiles stored."
                        } else {
                            &human
                        },
                    )
                }
                ProfilesSub::Validate { target } => {
                    let (bytes, source) = load_target_bytes(&target)?;
                    let parsed = parse_import_payload(&bytes, source)?;
                    #[derive(Serialize)]
                    struct ValidOut {
                        valid: bool,
                        count: usize,
                        deduplicated: usize,
                    }
                    let out = ValidOut {
                        valid: true,
                        count: parsed.profiles.len(),
                        deduplicated: parsed.deduplicated_count,
                    };
                    print_output(
                        cli.json,
                        &out,
                        &format!("Valid: {} profile(s) parsed", out.count),
                    )
                }
                ProfilesSub::Import { target } => {
                    let (bytes, source) = load_target_bytes(&target)?;
                    let parsed = match source {
                        ProfileSource::ImportedUri => {
                            let p = parse_profile_uri(
                                std::str::from_utf8(&bytes).unwrap_or_default(),
                                ProfileSource::ImportedUri,
                            )?;
                            vec![p]
                        }
                        other => parse_import_payload(&bytes, other)?.profiles,
                    };
                    for p in &parsed {
                        db.upsert_profile(p)?;
                    }
                    #[derive(Serialize)]
                    struct ImportedOut {
                        imported: usize,
                    }
                    print_output(
                        cli.json,
                        &ImportedOut {
                            imported: parsed.len(),
                        },
                        &format!("Imported {} profile(s)", parsed.len()),
                    )
                }
            }
        }
        Commands::Subscriptions(cmd) => {
            let db = Arc::new(R3xDatabase::open_with_recovery(&paths.db_path)?.db);
            match cmd.sub {
                SubscriptionsSub::List => {
                    let subs = db.list_subscriptions()?;
                    let human = subs
                        .iter()
                        .map(|s| {
                            format!(
                                "{} | {} | {:?} ({} servers)",
                                s.id, s.name, s.status, s.server_count
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    print_output(
                        cli.json,
                        &subs,
                        if human.is_empty() {
                            "No subscriptions stored."
                        } else {
                            &human
                        },
                    )
                }
                SubscriptionsSub::Add { name, url } => {
                    let mgr = SubscriptionManager::new(Arc::clone(&db))?;
                    let sub = mgr.add_remote_and_fetch(Some(name), &url).await?;
                    print_output(
                        cli.json,
                        &sub,
                        &format!(
                            "Added subscription '{}' ({} servers)",
                            sub.name, sub.server_count
                        ),
                    )
                }
                SubscriptionsSub::Refresh { id } => {
                    let mgr = SubscriptionManager::new(Arc::clone(&db))?;
                    let mut updated = Vec::new();
                    match id {
                        Some(target) => updated.push(mgr.refresh_subscription(target).await?),
                        None => {
                            for sub in db.list_subscriptions()? {
                                if sub.enabled {
                                    updated.push(mgr.refresh_subscription(sub.id).await?);
                                }
                            }
                        }
                    }
                    print_output(
                        cli.json,
                        &updated,
                        &format!("Refreshed {} subscription(s)", updated.len()),
                    )
                }
            }
        }
        Commands::Cores(cmd) => {
            let core_mgr = CoreManager::new(paths.cores_dir.clone(), None);
            let installed = core_mgr.discover_installed();
            let manifests = default_core_manifests()?;
            match cmd.sub {
                CoresSub::List => {
                    #[derive(Serialize)]
                    struct CoreRow {
                        id: CoreId,
                        name: String,
                        manifest_version: String,
                        license: String,
                        installed: bool,
                        installed_version: Option<String>,
                    }
                    let rows: Vec<CoreRow> = manifests
                        .into_iter()
                        .map(|m| {
                            let inst = installed.get(&m.id);
                            CoreRow {
                                id: m.id,
                                name: m.name,
                                manifest_version: m.version,
                                license: m.license,
                                installed: inst.is_some(),
                                installed_version: inst.map(|r| r.version.clone()),
                            }
                        })
                        .collect();
                    let human = rows
                        .iter()
                        .map(|r| {
                            format!(
                                "{} (v{}, {}) [{}]",
                                r.name,
                                r.manifest_version,
                                r.license,
                                if r.installed {
                                    "installed"
                                } else {
                                    "available"
                                }
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    print_output(cli.json, &rows, &human)
                }
                CoresSub::Info { id } => {
                    let cid = parse_core_id(&id)?;
                    let manifest =
                        manifests.into_iter().find(|m| m.id == cid).ok_or_else(|| {
                            R3xError::Validation(format!("manifest missing for {cid}"))
                        })?;
                    let summary = format!(
                        "{} v{} | License: {} | Source: {}",
                        manifest.name, manifest.version, manifest.license, manifest.release_source
                    );
                    print_output(cli.json, &manifest, &summary)
                }
            }
        }
        Commands::Diagnostics(cmd) => {
            let report = Redactor::redact_diagnostic_report(&build_baseline_diagnostics(&paths)?);
            match cmd.sub {
                DiagnosticsSub::Run => {
                    let human = report
                        .results
                        .iter()
                        .map(|r| format!("[{:?}] {:?}: {}", r.status, r.check_id, r.summary))
                        .collect::<Vec<_>>()
                        .join("\n");
                    print_output(cli.json, &report, &human)
                }
                DiagnosticsSub::Export { output } => {
                    let json = serde_json::to_string_pretty(&report)
                        .map_err(|e| R3xError::Storage(e.to_string()))?;
                    fs::write(&output, json)?;
                    print_output(
                        cli.json,
                        &output,
                        &format!("Exported redacted diagnostics to {}", output.display()),
                    )
                }
            }
        }
        Commands::Logs(args) => {
            let client = read_ipc_client(&paths)?;
            let cat =
                args.category
                    .as_deref()
                    .and_then(|c| match c.to_ascii_lowercase().as_str() {
                        "app" | "application" => Some(LogCategory::Application),
                        "core" => Some(LogCategory::Core),
                        "sub" | "subscription" => Some(LogCategory::Subscription),
                        "platform" => Some(LogCategory::Platform),
                        "net" | "network" => Some(LogCategory::Network),
                        "conn" | "connection" => Some(LogCategory::Connection),
                        _ => None,
                    });
            match client
                .send(IpcCommand::GetRecentLogs {
                    category: cat,
                    limit: args.limit,
                })
                .await?
                .payload
            {
                IpcPayload::Logs { entries } => {
                    let human = entries
                        .iter()
                        .map(|e| {
                            format!(
                                "{} [{:?}] {}: {}",
                                e.timestamp.to_rfc3339(),
                                e.level,
                                e.source,
                                e.message
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    print_output(
                        cli.json,
                        &entries,
                        if human.is_empty() {
                            "No log entries."
                        } else {
                            &human
                        },
                    )
                }
                IpcPayload::Error(e) => Err(R3xError::Ipc(format!("{}: {}", e.code, e.message))),
                _ => Ok(()),
            }
        }
        Commands::RecoverNetwork => {
            let backend = create_platform_proxy_backend();
            let report = recover_network_state(&paths.cache_dir, backend.as_ref())?;
            print_output(cli.json, &report, &report.notes.join("\n"))
        }
    }
}
