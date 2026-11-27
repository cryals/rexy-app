use r3x_domain::{
    ConnectionMode, ConnectionSession, ConnectionState, CoreId, DiagnosticReport, LogCategory,
    LogEntry, Profile, R3xError, Subscription, TelemetrySnapshot,
};
use r3x_security::MAX_IPC_FRAME_BYTES;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub const IPC_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcRequest {
    pub protocol_version: u32,
    pub request_id: Uuid,
    pub auth_token: String,
    pub command: IpcCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum IpcCommand {
    Handshake {
        client_name: String,
    },
    Ping,
    GetStatus,
    Connect {
        profile_id: Uuid,
        mode: ConnectionMode,
    },
    Disconnect,
    Reconnect,
    ListProfiles,
    ListSubscriptions,
    RefreshSubscriptions,
    ListCores,
    RunDiagnostics,
    GetRecentLogs {
        category: Option<LogCategory>,
        limit: usize,
    },
    GetTelemetry,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpcResponse {
    pub protocol_version: u32,
    pub request_id: Uuid,
    pub payload: IpcPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcErrorPayload {
    pub code: String,
    pub message: String,
    pub server_version: Option<u32>,
    pub client_version: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcPayload {
    Ok,
    Pong {
        server_version: u32,
    },
    HandshakeAck {
        server_version: u32,
        daemon_pid: u32,
    },
    Status {
        state: ConnectionState,
        session: Option<ConnectionSession>,
    },
    Profiles {
        items: Vec<Profile>,
    },
    Subscriptions {
        items: Vec<Subscription>,
    },
    Cores {
        ids: Vec<CoreId>,
    },
    Diagnostics {
        report: DiagnosticReport,
    },
    Logs {
        entries: Vec<LogEntry>,
    },
    Telemetry {
        snapshot: TelemetrySnapshot,
    },
    Error(IpcErrorPayload),
}

pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), R3xError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(value)
        .map_err(|e| R3xError::Ipc(format!("failed serializing IPC frame: {e}")))?;
    if payload.len() > MAX_IPC_FRAME_BYTES {
        return Err(R3xError::SecurityViolation(format!(
            "outbound IPC frame size {} exceeds max {}",
            payload.len(),
            MAX_IPC_FRAME_BYTES
        )));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| R3xError::Ipc("IPC frame length overflow".to_owned()))?;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| R3xError::Ipc(format!("write IPC frame length: {e}")))?;
    writer
        .write_all(&payload)
        .await
        .map_err(|e| R3xError::Ipc(format!("write IPC frame payload: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| R3xError::Ipc(format!("flush IPC frame: {e}")))?;
    Ok(())
}

pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, R3xError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| R3xError::Ipc(format!("read IPC frame length: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_IPC_FRAME_BYTES {
        return Err(R3xError::SecurityViolation(format!(
            "invalid IPC frame length {len} (max {MAX_IPC_FRAME_BYTES})"
        )));
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| R3xError::Ipc(format!("read IPC frame payload: {e}")))?;
    serde_json::from_slice(&buf).map_err(|e| R3xError::Ipc(format!("invalid IPC JSON frame: {e}")))
}
