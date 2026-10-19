use f2b_proto::{
    CodecError, Frame, MessageBuffer, Value, close_message, decode, encode, frame_message,
};
use std::process::Command;

#[test]
fn test_pickle_round_trip_with_python() {
    let test_objects = vec![
        Value::None,
        Value::Bool(true),
        Value::Bool(false),
        Value::Int(0),
        Value::Int(42),
        Value::Int(255),
        Value::Int(1000),
        Value::Int(100_000),
        Value::Int(-500),
        Value::Float(std::f64::consts::PI),
        Value::Str("hello world".into()),
        Value::List(vec![Value::Str("ping".into())]),
        Value::Tuple(vec![Value::Int(0), Value::Str("pong".into())]),
        Value::Dict(vec![
            (Value::Str("key".into()), Value::Int(123)),
            (
                Value::Str("list".into()),
                Value::List(vec![Value::Bool(true), Value::None]),
            ),
        ]),
        Value::Set(vec![Value::Str("a".into()), Value::Str("b".into())]),
        Value::Exception("test failure message".into()),
    ];

    for (i, val) in test_objects.iter().enumerate() {
        let encoded = encode(val);
        let hex_bytes: String = encoded.iter().map(|b| format!("{b:02x}")).collect();

        // 1. Python decodes what Rust encoded
        let py_script = format!(
            r#"import pickle
data = bytes.fromhex('{hex_bytes}')
obj = pickle.loads(data)
if isinstance(obj, Exception):
    assert str(obj) == 'test failure message'
print('OK')
"#
        );
        let out = Command::new("python3")
            .arg("-c")
            .arg(&py_script)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "Python failed to decode case {i}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );

        // 2. Python encodes, Rust decodes
        let py_roundtrip_script = format!(
            r#"import pickle
data = bytes.fromhex('{hex_bytes}')
obj = pickle.loads(data)
out = pickle.dumps(obj, protocol=5)
print(out.hex())
"#
        );
        let out2 = Command::new("python3")
            .arg("-c")
            .arg(&py_roundtrip_script)
            .output()
            .unwrap();
        assert!(out2.status.success());
        let py_hex = String::from_utf8_lossy(&out2.stdout).trim().to_owned();
        let py_bytes = (0..py_hex.len())
            .step_by(2)
            .map(|j| u8::from_str_radix(&py_hex[j..j + 2], 16).unwrap())
            .collect::<Vec<u8>>();

        let decoded = decode(&py_bytes).unwrap();
        if let (Value::Set(mut l1), Value::Set(mut l2)) = (decoded.clone(), val.clone()) {
            l1.sort_by_key(|v| v.to_string());
            l2.sort_by_key(|v| v.to_string());
            assert_eq!(l1, l2);
        } else {
            assert_eq!(&decoded, val, "Rust decode mismatch for case {i}");
        }
    }
}

#[test]
fn test_security_rejection_of_arbitrary_globals() {
    // Generated with: pickle.dumps(os.system)
    let dangerous_py_script = "\
import pickle, os\n\
b = pickle.dumps(os.system, protocol=5)\n\
print(b.hex())\n";

    let out = Command::new("python3")
        .arg("-c")
        .arg(dangerous_py_script)
        .output()
        .unwrap();
    let hex = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|j| u8::from_str_radix(&hex[j..j + 2], 16).unwrap())
        .collect::<Vec<u8>>();

    let res = decode(&bytes);
    assert!(res.is_err());
    match res.unwrap_err() {
        CodecError::SecurityViolation(msg) => {
            assert!(
                msg.contains("arbitrary global posix.system disallowed")
                    || msg.contains("os.system disallowed")
            );
        }
        other => panic!("expected SecurityViolation, got: {other:?}"),
    }
}

#[test]
fn test_message_framing() {
    let mut buf = MessageBuffer::new();

    let msg1 = b"hello";
    let framed1 = frame_message(msg1);

    // Feed in partial chunks
    buf.feed(&framed1[..5]);
    assert_eq!(buf.next_frame(), None);

    buf.feed(&framed1[5..]);
    assert_eq!(buf.next_frame(), Some(Frame::Message(b"hello".to_vec())));
    assert_eq!(buf.next_frame(), None);

    // Close frame
    let close = close_message();
    buf.feed(&close);
    assert_eq!(buf.next_frame(), Some(Frame::Close));
    assert_eq!(buf.next_frame(), None);
}
