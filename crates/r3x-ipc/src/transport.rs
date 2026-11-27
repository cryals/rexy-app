use crate::protocol::{
    IPC_PROTOCOL_VERSION, IpcCommand, IpcErrorPayload, IpcPayload, IpcRequest, IpcResponse,
    read_frame, write_frame,
};
use interprocess::local_socket::tokio::{Listener, Stream, prelude::*};
use interprocess::local_socket::{GenericFilePath, GenericNamespaced, ListenerOptions, Name};
use r3x_domain::R3xError;
use r3x_security::verify_ipc_token;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use uuid::Uuid;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone)]
pub enum SocketAddress {
    Namespaced(String),
    FilePath(PathBuf),
}

impl SocketAddress {
    #[must_use]
    pub fn default_daemon() -> Self {
        Self::Namespaced("dev.rexy.r3x.daemon.v1.sock".to_owned())
    }

    pub fn into_name(&self) -> Result<Name<'static>, R3xError> {
        match self {
            Self::Namespaced(ns) => ns
                .clone()
                .to_ns_name::<GenericNamespaced>()
                .map_err(|e| R3xError::Ipc(format!("invalid namespaced socket '{ns}': {e}"))),
            Self::FilePath(path) => path
                .clone()
                .to_fs_name::<GenericFilePath>()
                .map_err(|e| R3xError::Ipc(format!("invalid socket path {}: {e}", path.display()))),
        }
    }
}

pub trait IpcHandler: Send + Sync {
    fn handle(&self, command: IpcCommand) -> BoxFuture<'_, IpcPayload>;
}

pub struct IpcServer {
    listener: Listener,
    address: SocketAddress,
    auth_token: String,
    handler: Arc<dyn IpcHandler>,
}

impl IpcServer {
    pub fn bind(
        address: SocketAddress,
        auth_token: impl Into<String>,
        handler: Arc<dyn IpcHandler>,
    ) -> Result<Self, R3xError> {
        if let SocketAddress::FilePath(ref path) = address {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
        }
        let name = address.into_name()?;
        let listener = ListenerOptions::new()
            .name(name)
            .create_tokio()
            .map_err(|e| R3xError::Ipc(format!("failed binding IPC listener: {e}")))?;

        #[cfg(unix)]
        if let SocketAddress::FilePath(ref path) = address {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }

        Ok(Self {
            listener,
            address,
            auth_token: auth_token.into(),
            handler,
        })
    }

    pub async fn run(self, cancel: CancellationToken) -> Result<(), R3xError> {
        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    debug!("IPC server shutting down");
                    if let SocketAddress::FilePath(ref path) = self.address {
                        let _ = std::fs::remove_file(path);
                    }
                    return Ok(());
                }
                accept_res = self.listener.accept() => {
                    match accept_res {
                        Ok(stream) => {
                            let expected_token = self.auth_token.clone();
                            let handler = Arc::clone(&self.handler);
                            tokio::spawn(async move {
                                if let Err(err) = handle_connection(stream, &expected_token, handler).await {
                                    debug!(error = %err, "IPC client connection closed");
                                }
                            });
                        }
                        Err(err) => {
                            warn!(error = %err, "IPC accept error");
                        }
                    }
                }
            }
        }
    }
}

async fn handle_connection(
    mut stream: Stream,
    expected_token: &str,
    handler: Arc<dyn IpcHandler>,
) -> Result<(), R3xError> {
    let req: IpcRequest = read_frame(&mut stream).await?;
    let response_payload = if req.protocol_version != IPC_PROTOCOL_VERSION {
        IpcPayload::Error(IpcErrorPayload {
            code: "E_IPC_VERSION_MISMATCH".to_owned(),
            message: format!(
                "IPC protocol version mismatch: server v{IPC_PROTOCOL_VERSION}, client v{}",
                req.protocol_version
            ),
            server_version: Some(IPC_PROTOCOL_VERSION),
            client_version: Some(req.protocol_version),
        })
    } else if !verify_ipc_token(expected_token, &req.auth_token) {
        IpcPayload::Error(IpcErrorPayload {
            code: "E_IPC_UNAUTHORIZED".to_owned(),
            message: "invalid IPC authorization token".to_owned(),
            server_version: Some(IPC_PROTOCOL_VERSION),
            client_version: Some(req.protocol_version),
        })
    } else {
        match req.command {
            IpcCommand::Handshake { .. } => IpcPayload::HandshakeAck {
                server_version: IPC_PROTOCOL_VERSION,
                daemon_pid: std::process::id(),
            },
            IpcCommand::Ping => IpcPayload::Pong {
                server_version: IPC_PROTOCOL_VERSION,
            },
            other => handler.handle(other).await,
        }
    };

    let resp = IpcResponse {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: req.request_id,
        payload: response_payload,
    };
    write_frame(&mut stream, &resp).await
}

#[derive(Debug, Clone)]
pub struct IpcClient {
    address: SocketAddress,
    auth_token: String,
    protocol_version: u32,
}

impl IpcClient {
    #[must_use]
    pub fn new(address: SocketAddress, auth_token: impl Into<String>) -> Self {
        Self {
            address,
            auth_token: auth_token.into(),
            protocol_version: IPC_PROTOCOL_VERSION,
        }
    }

    #[must_use]
    pub fn with_protocol_version(mut self, version: u32) -> Self {
        self.protocol_version = version;
        self
    }

    pub async fn send(&self, command: IpcCommand) -> Result<IpcResponse, R3xError> {
        let name = self.address.into_name()?;
        let mut stream = Stream::connect(name)
            .await
            .map_err(|e| R3xError::Ipc(format!("failed connecting to IPC daemon: {e}")))?;

        let req = IpcRequest {
            protocol_version: self.protocol_version,
            request_id: Uuid::new_v4(),
            auth_token: self.auth_token.clone(),
            command,
        };
        write_frame(&mut stream, &req).await?;
        let resp: IpcResponse = read_frame(&mut stream).await?;
        if resp.request_id != req.request_id {
            return Err(R3xError::Ipc("IPC response request_id mismatch".to_owned()));
        }
        Ok(resp)
    }
}
