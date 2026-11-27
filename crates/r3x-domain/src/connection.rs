use crate::core::CoreId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Preparing,
    Validating,
    StartingCore,
    EstablishingTunnel,
    Connecting,
    Connected,
    Reconnecting { attempt: u32 },
    Disconnecting,
    Error { code: String, message: String },
}

impl ConnectionState {
    #[must_use]
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Preparing => "Preparing",
            Self::Validating => "Validating",
            Self::StartingCore => "StartingCore",
            Self::EstablishingTunnel => "EstablishingTunnel",
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
            Self::Reconnecting { .. } => "Reconnecting",
            Self::Disconnecting => "Disconnecting",
            Self::Error { .. } => "Error",
        }
    }

    #[must_use]
    pub fn is_busy(&self) -> bool {
        matches!(
            self,
            Self::Preparing
                | Self::Validating
                | Self::StartingCore
                | Self::EstablishingTunnel
                | Self::Connecting
                | Self::Reconnecting { .. }
                | Self::Disconnecting
        )
    }

    #[must_use]
    pub fn can_transition_to(&self, next: &Self) -> bool {
        use ConnectionState::{
            Connected, Connecting, Disconnected, Disconnecting, Error, EstablishingTunnel,
            Preparing, Reconnecting, StartingCore, Validating,
        };
        matches!(
            (self, next),
            (Disconnected, Preparing)
                | (Error { .. }, Preparing | Disconnected)
                | (
                    Preparing,
                    Validating | Disconnecting | Error { .. } | Disconnected
                )
                | (
                    Validating,
                    StartingCore | Disconnecting | Error { .. } | Disconnected
                )
                | (
                    StartingCore,
                    EstablishingTunnel | Connecting | Disconnecting | Error { .. }
                )
                | (
                    EstablishingTunnel,
                    Connecting | Disconnecting | Error { .. }
                )
                | (
                    Connecting,
                    Connected | Disconnecting | Error { .. } | Disconnected
                )
                | (
                    Connected,
                    Disconnecting | Reconnecting { .. } | Error { .. }
                )
                | (
                    Reconnecting { .. },
                    Preparing
                        | StartingCore
                        | Connecting
                        | Connected
                        | Disconnecting
                        | Error { .. }
                )
                | (Disconnecting, Disconnected | Error { .. })
        )
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    Tun,
    SystemProxy,
    Mixed,
}

impl ConnectionMode {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Tun => "TUN",
            Self::SystemProxy => "Proxy",
            Self::Mixed => "Mixed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionSession {
    pub session_id: Uuid,
    pub profile_id: Uuid,
    pub profile_name: String,
    pub core_id: CoreId,
    pub core_version: String,
    pub mode: ConnectionMode,
    pub started_at: DateTime<Utc>,
    pub local_http_port: Option<u16>,
    pub local_socks_port: Option<u16>,
    pub tun_interface_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionHistoryEntry {
    pub id: Uuid,
    pub profile_id: Uuid,
    pub profile_name: String,
    pub core_id: CoreId,
    pub mode: ConnectionMode,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub bytes_down: u64,
    pub bytes_up: u64,
    pub disconnect_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveConnectionInfo {
    pub id: String,
    pub protocol: String,
    pub destination: String,
    pub process_name: Option<String>,
    pub rule_matched: String,
    pub outbound: String,
    pub bytes_down: u64,
    pub bytes_up: u64,
    pub started_at: DateTime<Utc>,
}
