//! Port of upstream `fail2ban/tests/sockettestcase.py`.

use std::sync::{Arc, Mutex};
use tempfile::tempdir;

use f2b_proto::{CSPROTO_CLOSE, CSPROTO_END, Value};
use f2b_server::{AsyncServer, Server};
use fast2ban_client::ClientSocket;

#[test]
fn test_socket_lifecycle_and_commands() {
    let tmp = tempdir().unwrap();
    let sock_path = tmp.path().join("f2b_sock_test.sock");
    let server = Arc::new(Mutex::new(Server::new()));

    let async_server = AsyncServer::bind(&sock_path, server).unwrap();
    let handle = async_server.start_background().unwrap();

    let mut csock = ClientSocket::new(&sock_path);
    assert!(csock.is_alive());

    // 1. Ping / pong
    let res = csock.send(&[Value::Str("ping".into())]).unwrap();
    assert_eq!(res, Value::Str("pong".into()));

    // 2. Echo message
    let echo_msg = vec![
        Value::Str("A".into()),
        Value::Str("test".into()),
        Value::Str("message".into()),
    ];
    let mut echo_cmd = vec![Value::Str("echo".into())];
    echo_cmd.extend(echo_msg.clone());
    let res = csock.send(&echo_cmd).unwrap();
    assert_eq!(res, Value::List(echo_msg));

    // 3. Client close and reconnect
    csock.close();
    let mut csock2 = ClientSocket::new(&sock_path);
    let res = csock2.send(&[Value::Str("ping".into())]).unwrap();
    assert_eq!(res, Value::Str("pong".into()));

    // 4. Server shutdown command
    let res = csock2.send(&[Value::Str("stop".into())]).unwrap();
    assert_eq!(res, Value::None);

    let _ = handle.join();
    assert!(
        !sock_path.exists(),
        "Socket file must be removed on server stop"
    );
}

#[test]
fn test_socket_framing_constants() {
    assert_eq!(CSPROTO_END, b"<F2B_END_COMMAND>");
    assert_eq!(CSPROTO_CLOSE, b"<F2B_CLOSE_COMMAND>");
}
