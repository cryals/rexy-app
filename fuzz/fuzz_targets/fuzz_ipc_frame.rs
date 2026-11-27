#![no_main]
use libfuzzer_sys::fuzz_target;
use r3x_ipc::protocol::{IpcRequest, read_frame};

fuzz_target!(|data: &[u8]| {
    if let Ok(rt) = tokio::runtime::Builder::new_current_thread().build() {
        let mut cursor = std::io::Cursor::new(data);
        let _ = rt.block_on(read_frame::<_, IpcRequest>(&mut cursor));
    }
});
