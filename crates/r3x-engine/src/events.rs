use r3x_domain::{
    ConnectionSession, ConnectionState, CoreId, DiagnosticResult, LogEntry, TelemetrySnapshot,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EngineEvent {
    StateChanged {
        previous: ConnectionState,
        current: ConnectionState,
        session: Option<ConnectionSession>,
    },
    TelemetryUpdated {
        snapshot: TelemetrySnapshot,
    },
    LogAppended {
        entry: LogEntry,
    },
    ProfileUpdated {
        profile_id: Uuid,
    },
    SubscriptionUpdated {
        subscription_id: Uuid,
    },
    CoreStatusChanged {
        core_id: CoreId,
        details: String,
    },
    DiagnosticProgress {
        result: DiagnosticResult,
    },
    ErrorRaised {
        code: String,
        message: String,
    },
}
