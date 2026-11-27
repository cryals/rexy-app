use r3x_domain::{ConnectionMode, ConnectionState};
use r3x_ipc::transport::BoxFuture;
use r3x_ipc::{
    IPC_PROTOCOL_VERSION, IpcClient, IpcCommand, IpcHandler, IpcPayload, IpcServer, SocketAddress,
};
use r3x_security::generate_ipc_token;
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, duplex};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct DummyDaemonHandler;

impl IpcHandler for DummyDaemonHandler {
    fn handle(&self, command: IpcCommand) -> BoxFuture<'_, IpcPayload> {
        Box::pin(async move {
            match command {
                IpcCommand::GetStatus => IpcPayload::Status {
                    state: ConnectionState::Disconnected,
                    session: None,
                },
                IpcCommand::Connect { .. } => IpcPayload::Ok,
                _ => IpcPayload::Ok,
            }
        })
    }
}

#[tokio::test]
async fn ipc_server_auth_and_version_checks() {
    let sock_name = format!("r3x-ipc-test-{}", Uuid::new_v4());
    let addr = SocketAddress::Namespaced(sock_name);
    let token = generate_ipc_token();
    let cancel = CancellationToken::new();

    let server = IpcServer::bind(addr.clone(), token.clone(), Arc::new(DummyDaemonHandler))
        .expect("bind ipc server");
    let srv_cancel = cancel.clone();
    let srv_task = tokio::spawn(async move { server.run(srv_cancel).await });

    tokio::task::yield_now().await;

    let client = IpcClient::new(addr.clone(), token);
    let hs = client
        .send(IpcCommand::Handshake {
            client_name: "r3x-test".to_owned(),
        })
        .await
        .expect("handshake");
    match hs.payload {
        IpcPayload::HandshakeAck { server_version, .. } => {
            assert_eq!(server_version, IPC_PROTOCOL_VERSION);
        }
        other => panic!("unexpected handshake payload: {other:?}"),
    }

    let st = client.send(IpcCommand::GetStatus).await.expect("status");
    assert!(matches!(
        st.payload,
        IpcPayload::Status {
            state: ConnectionState::Disconnected,
            ..
        }
    ));

    // Reject invalid token
    let bad_client = IpcClient::new(addr.clone(), "wrong-token");
    let unauth = bad_client
        .send(IpcCommand::Connect {
            profile_id: Uuid::new_v4(),
            mode: ConnectionMode::Tun,
        })
        .await
        .expect("unauthorized response");
    match unauth.payload {
        IpcPayload::Error(err) => assert_eq!(err.code, "E_IPC_UNAUTHORIZED"),
        other => panic!("expected unauthorized error, got {other:?}"),
    }

    // Reject incompatible protocol version
    let old_client = client.with_protocol_version(999);
    let mismatch = old_client
        .send(IpcCommand::Ping)
        .await
        .expect("version mismatch response");
    match mismatch.payload {
        IpcPayload::Error(err) => {
            assert_eq!(err.code, "E_IPC_VERSION_MISMATCH");
            assert_eq!(err.server_version, Some(IPC_PROTOCOL_VERSION));
            assert_eq!(err.client_version, Some(999));
        }
        other => panic!("expected version mismatch error, got {other:?}"),
    }

    cancel.cancel();
    srv_task.await.expect("join").expect("clean server exit");
}

#[tokio::test]
async fn ipc_frame_rejects_oversized_length() {
    let (mut writer, mut reader) = duplex(64);
    let huge_len: u32 = 32 * 1024 * 1024;
    writer
        .write_all(&huge_len.to_be_bytes())
        .await
        .expect("write length");
    drop(writer);
    let res: Result<r3x_ipc::IpcRequest, _> = r3x_ipc::read_frame(&mut reader).await;
    assert!(res.is_err());
}
