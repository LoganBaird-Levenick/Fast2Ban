//! Security regression tests for server: socket permissions, umask, and protocol limits.

use std::fs;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

use f2b_proto::{CodecError, MAX_MARKS_DEPTH, MAX_PAYLOAD_SIZE, MAX_STACK_DEPTH, decode};
use f2b_server::{AsyncServer, Server};

#[test]
fn test_socket_permissions_mode_0600() {
    let tmp = tempdir().unwrap();
    let sock_path = tmp.path().join("test_sec.sock");
    let server = Arc::new(Mutex::new(Server::new()));

    let async_server = AsyncServer::bind(&sock_path, server).unwrap();
    assert!(sock_path.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(&sock_path).unwrap();
        let mode = meta.mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "Socket permissions must be 0600 (owner rw only), got {mode:03o}"
        );
    }

    async_server.stop();
    assert!(!sock_path.exists());
}

#[test]
fn test_pickle_decoder_security_limits() {
    // 1. Stack depth limit
    // Send a stream pushing more items than MAX_STACK_DEPTH
    let mut deep_stack = vec![0x80, 2]; // PROTO 2
    deep_stack.resize(deep_stack.len() + MAX_STACK_DEPTH + 10, b'N');
    deep_stack.push(b'.'); // STOP
    let res = decode(&deep_stack);
    assert!(
        matches!(res, Err(CodecError::SecurityViolation(ref msg)) if msg.contains("stack depth")),
        "Expected stack depth violation, got: {res:?}"
    );

    let mut deep_marks = vec![0x80, 2]; // PROTO 2
    deep_marks.resize(deep_marks.len() + MAX_MARKS_DEPTH + 10, b'(');
    deep_marks.push(b'.'); // STOP
    let res2 = decode(&deep_marks);
    assert!(
        matches!(res2, Err(CodecError::SecurityViolation(ref msg)) if msg.contains("nesting depth")),
        "Expected nesting depth violation, got: {res2:?}"
    );

    // 3. Payload size limit
    let huge_payload = vec![b'N'; MAX_PAYLOAD_SIZE + 1];
    let res3 = decode(&huge_payload);
    assert!(
        matches!(res3, Err(CodecError::SecurityViolation(ref msg)) if msg.contains("payload size")),
        "Expected payload size violation, got: {res3:?}"
    );

    // 4. Arbitrary global execution rejection
    // Pickle stream for `import os; os.system('id')`
    let mut dangerous = vec![0x80, 2];
    dangerous.push(b'c');
    dangerous.extend_from_slice(b"os\nsystem\n");
    dangerous.push(b'.');
    let res4 = decode(&dangerous);
    assert!(
        matches!(
            res4,
            Err(CodecError::SecurityViolation(_) | CodecError::InvalidOpcode(_))
        ),
        "Arbitrary global must be rejected, got: {res4:?}"
    );
}
