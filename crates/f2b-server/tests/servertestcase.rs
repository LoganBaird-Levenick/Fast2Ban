//! Port of upstream `fail2ban/tests/servertestcase.py` and `fail2banclienttestcase.py`.

use std::sync::{Arc, Mutex};
use tempfile::tempdir;

use f2b_proto::Value;
use f2b_server::{Server, Transmitter};

fn s(v: &str) -> Value {
    Value::Str(v.to_owned())
}

fn call(t: &Transmitter, args: Vec<Value>) -> Result<Value, String> {
    match t.proceed(Value::List(args)) {
        Value::Tuple(mut p) if p.len() == 2 => match (p.remove(0), p.remove(0)) {
            (Value::Int(0), ret) => Ok(ret),
            (Value::Int(1), Value::Exception(e)) => Err(e),
            other => panic!("unexpected reply {other:?}"),
        },
        other => panic!("unexpected reply {other:?}"),
    }
}

#[test]
fn test_server_jail_lifecycle_and_validation() {
    let t = Transmitter::new(Arc::new(Mutex::new(Server::new())));

    // Reserved jail name rejection
    assert!(call(&t, vec![s("add"), s("--all")]).is_err());

    // Add jail
    assert_eq!(
        call(&t, vec![s("add"), s("ssh"), s("polling")]),
        Ok(s("ssh"))
    );

    // Re-adding existing jail fails
    assert!(call(&t, vec![s("add"), s("ssh"), s("polling")]).is_err());

    // Start jail
    assert_eq!(call(&t, vec![s("start"), s("ssh")]), Ok(Value::None));

    // Stop jail
    assert_eq!(call(&t, vec![s("stop"), s("ssh")]), Ok(Value::None));

    // Stop all
    assert_eq!(call(&t, vec![s("stop"), s("--all")]), Ok(Value::None));
}

#[test]
fn test_database_configuration_commands() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("servertest.db");
    let db_str = db_path.to_str().unwrap();

    let t = Transmitter::new(Arc::new(Mutex::new(Server::new())));

    // Initial state: no db
    assert_eq!(call(&t, vec![s("get"), s("dbfile")]), Ok(Value::None));

    // Set database
    assert_eq!(
        call(&t, vec![s("set"), s("dbfile"), s(db_str)]),
        Ok(s(db_str))
    );
    assert_eq!(call(&t, vec![s("get"), s("dbfile")]), Ok(s(db_str)));

    // Set dbmaxmatches
    assert_eq!(
        call(&t, vec![s("set"), s("dbmaxmatches"), Value::Int(25)]),
        Ok(Value::Int(25))
    );
    assert_eq!(
        call(&t, vec![s("get"), s("dbmaxmatches")]),
        Ok(Value::Int(25))
    );

    // Set dbpurgeage
    assert_eq!(
        call(&t, vec![s("set"), s("dbpurgeage"), s("2d")]),
        Ok(Value::Int(172800))
    );
    assert_eq!(
        call(&t, vec![s("get"), s("dbpurgeage")]),
        Ok(Value::Int(172800))
    );
}

#[test]
fn test_unban_and_banned_queries() {
    let t = Transmitter::new(Arc::new(Mutex::new(Server::new())));

    assert_eq!(call(&t, vec![s("add"), s("j1"), s("polling")]), Ok(s("j1")));
    assert_eq!(call(&t, vec![s("start"), s("j1")]), Ok(Value::None));
    assert_eq!(
        call(
            &t,
            vec![
                s("set"),
                s("j1"),
                s("banip"),
                s("192.0.2.10"),
                s("192.0.2.20")
            ]
        ),
        Ok(Value::Int(2))
    );

    // Banned check single IP
    assert_eq!(
        call(&t, vec![s("get"), s("j1"), s("banned"), s("192.0.2.10")]),
        Ok(Value::Int(1))
    );
    assert_eq!(
        call(&t, vec![s("get"), s("j1"), s("banned"), s("192.0.2.99")]),
        Ok(Value::Int(0))
    );

    // Banned check multiple IPs
    assert_eq!(
        call(
            &t,
            vec![
                s("get"),
                s("j1"),
                s("banned"),
                s("192.0.2.10"),
                s("192.0.2.99")
            ]
        ),
        Ok(Value::List(vec![Value::Int(1), Value::Int(0)]))
    );

    // Unban single IP
    assert_eq!(
        call(&t, vec![s("set"), s("j1"), s("unbanip"), s("192.0.2.10")]),
        Ok(Value::Int(1))
    );

    // Unban absent IP with --report-absent errors
    assert!(
        call(
            &t,
            vec![
                s("set"),
                s("j1"),
                s("unbanip"),
                s("--report-absent"),
                s("192.0.2.10")
            ]
        )
        .is_err()
    );

    // Unban absent IP without --report-absent returns 0
    assert_eq!(
        call(&t, vec![s("set"), s("j1"), s("unbanip"), s("192.0.2.10")]),
        Ok(Value::Int(0))
    );

    // Unban all
    assert_eq!(call(&t, vec![s("unban"), s("--all")]), Ok(Value::Int(1)));
}

#[test]
fn test_server_stream_batch_execution() {
    let t = Transmitter::new(Arc::new(Mutex::new(Server::new())));

    let batch = Value::List(vec![
        Value::List(vec![s("add"), s("stream_jail"), s("polling")]),
        Value::List(vec![
            s("set"),
            s("stream_jail"),
            s("maxretry"),
            Value::Int(4),
        ]),
        Value::List(vec![s("start"), s("stream_jail")]),
    ]);

    assert_eq!(call(&t, vec![s("server-stream"), batch]), Ok(Value::None));

    // Verify commands took effect
    assert_eq!(
        call(&t, vec![s("get"), s("stream_jail"), s("maxretry")]),
        Ok(Value::Int(4))
    );
}
