//! Port of upstream `fail2ban/tests/clientbeautifiertestcase.py`.

use f2b_proto::{Beautifier, Value};

fn cmd(c: &[&str]) -> Vec<String> {
    c.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn test_ping_beautify() {
    assert_eq!(
        Beautifier::beautify(&cmd(&["ping"]), &Value::Str("pong".into())),
        "Server replied: pong"
    );
}

#[test]
fn test_version_beautify() {
    assert_eq!(
        Beautifier::beautify(&cmd(&["version"]), &Value::Str("1.1.2".into())),
        "1.1.2"
    );
}

#[test]
fn test_add_jail_beautify() {
    assert_eq!(
        Beautifier::beautify(&cmd(&["add", "ssh"]), &Value::Str("ssh".into())),
        "Added jail ssh"
    );
}

#[test]
fn test_start_jail_beautify() {
    assert_eq!(
        Beautifier::beautify(&cmd(&["start", "ssh"]), &Value::None),
        "Jail started"
    );
}

#[test]
fn test_stop_jail_beautify() {
    assert_eq!(
        Beautifier::beautify(&cmd(&["stop", "ssh"]), &Value::None),
        "Jail stopped"
    );
}

#[test]
fn test_shutdown_beautify() {
    assert_eq!(
        Beautifier::beautify(&cmd(&["stop"]), &Value::None),
        "Shutdown successful"
    );
}

#[test]
fn test_flushlogs_beautify() {
    assert_eq!(
        Beautifier::beautify(&cmd(&["flushlogs"]), &Value::Str("flushed".into())),
        "logs: flushed"
    );
}

#[test]
fn test_echo_beautify() {
    assert_eq!(
        Beautifier::beautify(
            &cmd(&["echo", "hello", "world"]),
            &Value::List(vec![Value::Str("hello".into()), Value::Str("world".into())])
        ),
        "hello world"
    );
}

#[test]
fn test_status_overall_beautify() {
    let response = Value::List(vec![
        Value::Tuple(vec![Value::Str("Number of jail".into()), Value::Int(2)]),
        Value::Tuple(vec![
            Value::Str("Jail list".into()),
            Value::Str("ssh, exim4".into()),
        ]),
    ]);
    let output = "Status\n|- Number of jail:\t2\n`- Jail list:\tssh, exim4";
    assert_eq!(Beautifier::beautify(&cmd(&["status"]), &response), output);
}

#[test]
fn test_status_jail_beautify() {
    let response = Value::List(vec![
        Value::Tuple(vec![
            Value::Str("Filter".into()),
            Value::List(vec![
                Value::Tuple(vec![Value::Str("Currently failed".into()), Value::Int(0)]),
                Value::Tuple(vec![Value::Str("Total failed".into()), Value::Int(0)]),
                Value::Tuple(vec![
                    Value::Str("File list".into()),
                    Value::List(vec![Value::Str("/var/log/auth.log".into())]),
                ]),
            ]),
        ]),
        Value::Tuple(vec![
            Value::Str("Actions".into()),
            Value::List(vec![
                Value::Tuple(vec![Value::Str("Currently banned".into()), Value::Int(3)]),
                Value::Tuple(vec![Value::Str("Total banned".into()), Value::Int(3)]),
                Value::Tuple(vec![
                    Value::Str("Banned IP list".into()),
                    Value::List(vec![
                        Value::Str("192.168.0.1".into()),
                        Value::Str("10.2.2.1".into()),
                        Value::Str("2001:db8::1".into()),
                    ]),
                ]),
            ]),
        ]),
    ]);

    let expected = "\
Status for the jail: ssh
|- Filter
|  |- Currently failed:\t0
|  |- Total failed:\t0
|  `- File list:\t/var/log/auth.log
`- Actions
   |- Currently banned:\t3
   |- Total banned:\t3
   `- Banned IP list:\t192.168.0.1 10.2.2.1 2001:db8::1";

    assert_eq!(
        Beautifier::beautify(&cmd(&["status", "ssh"]), &response),
        expected
    );
}
