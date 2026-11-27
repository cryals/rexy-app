# Local IPC Protocol (`r3x-ipc`)

`r3x-daemon` and `r3x` CLI / desktop UI communicate over a strict local authenticated channel in `crates/r3x-ipc/`.

## 1. Transport Layer (`transport.rs`)

- Uses `interprocess::local_socket` for cross-platform local IPC:
  - **Windows:** Named Pipe (`\\.\pipe\r3x-daemon-...`) scoped per user session.
  - **Linux:** Unix Domain Socket created with `0600` POSIX permissions inside the runtime directory (`XDG_RUNTIME_DIR` fallback).

## 2. Wire Framing & Schema (`protocol.rs`)

Each message uses:
1. 4-byte unsigned big-endian payload length (`u32`), rejected pre-allocation if `len == 0 || len > MAX_IPC_FRAME_BYTES` (`4 * 1024 * 1024` bytes / 4 MiB).
2. UTF-8 JSON `IpcRequest` or `IpcResponse`:
   - `protocol_version: u32` (`IPC_PROTOCOL_VERSION = 1`)
   - `request_id: Uuid`
   - `auth_token: String` (256-bit random hex generated at runtime, compared via `subtle::ConstantTimeEq`)
   - `payload: IpcPayload` / command (`Status`, `Connect`, `Disconnect`, `ReloadCores`, `Shutdown`)

## 3. Security Rules

- Unauthenticated requests or invalid tokens receive typed authorization failures without side effects.
- Incompatible `protocol_version` returns `E_IPC_VERSION_MISMATCH` reporting both `server_version` and `client_version`.
- `fuzz_ipc_frame` (`fuzz/fuzz_targets/fuzz_ipc_frame.rs`) specifically fuzz-tests length prefix parsing and deserialization bounds.
