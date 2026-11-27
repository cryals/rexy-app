use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCheckId {
    InternetConnectivity,
    DnsResolution,
    ServerReachability,
    TlsConnectivity,
    CoreProcessHealth,
    ConfigurationValidity,
    CoreCompatibility,
    TunInterface,
    SystemProxy,
    RoutingState,
    Ipv4Connectivity,
    Ipv6Connectivity,
    DnsLeaks,
    NetworkAdapterConflicts,
    RequiredPermissions,
    LocalPortAvailability,
}

impl DiagnosticCheckId {
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::InternetConnectivity,
            Self::DnsResolution,
            Self::ServerReachability,
            Self::TlsConnectivity,
            Self::CoreProcessHealth,
            Self::ConfigurationValidity,
            Self::CoreCompatibility,
            Self::TunInterface,
            Self::SystemProxy,
            Self::RoutingState,
            Self::Ipv4Connectivity,
            Self::Ipv6Connectivity,
            Self::DnsLeaks,
            Self::NetworkAdapterConflicts,
            Self::RequiredPermissions,
            Self::LocalPortAvailability,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStatus {
    NotTested,
    Running,
    Passed,
    Warning,
    Failed,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticResult {
    pub check_id: DiagnosticCheckId,
    pub status: DiagnosticStatus,
    pub summary: String,
    pub technical_details: String,
    pub suggested_actions: Vec<String>,
    pub related_settings_section: Option<String>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub generated_at: DateTime<Utc>,
    pub platform: String,
    pub app_version: String,
    pub results: Vec<DiagnosticResult>,
}
