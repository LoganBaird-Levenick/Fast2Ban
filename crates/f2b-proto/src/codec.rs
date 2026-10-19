//! Restricted Python pickle decoder and encoder supporting protocols 2 to 5.
//!
//! Specifically implements the security policy in PLAN.md §3.2:
//! - Only data primitives are decoded (`None`, `bool`, `int`, `float`, `str`, `list`, `tuple`, `dict`, `set`).
//! - Arbitrary code execution opcodes (`GLOBAL`, `REDUCE`, `BUILD`, `NEWOBJ`) are strictly rejected,
//!   with the single permitted exception of `builtins.Exception` for server error reporting.

use std::collections::HashMap;
use std::fmt;

use crate::value::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    UnexpectedEof,
    InvalidProtocol(u8),
    InvalidOpcode(u8),
    SecurityViolation(String),
    BadUtf8,
    StackUnderflow,
    TrailingBytes,
    InvalidValue(String),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected EOF while parsing pickle stream"),
            Self::InvalidProtocol(p) => write!(f, "unsupported pickle protocol version {p}"),
            Self::InvalidOpcode(op) => write!(f, "invalid or disallowed pickle opcode 0x{op:02x}"),
            Self::SecurityViolation(s) => write!(f, "security violation: {s}"),
            Self::BadUtf8 => write!(f, "invalid UTF-8 string in pickle"),
            Self::StackUnderflow => write!(f, "pickle stack underflow"),
            Self::TrailingBytes => write!(f, "unexpected trailing bytes after STOP opcode"),
            Self::InvalidValue(v) => write!(f, "invalid value in pickle: {v}"),
        }
    }
}

impl std::error::Error for CodecError {}

#[derive(Debug)]
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    stack: Vec<StackItem>,
    marks: Vec<usize>,
    memo: HashMap<usize, Value>,
}

#[derive(Debug)]
enum StackItem {
    Val(Value),
    Global(String, String), // (module, name)
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            stack: Vec::new(),
            marks: Vec::new(),
            memo: HashMap::new(),
        }
    }

    fn read_byte(&mut self) -> Result<u8, CodecError> {
        if self.pos >= self.data.len() {
            return Err(CodecError::UnexpectedEof);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.pos + n > self.data.len() {
            return Err(CodecError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_line(&mut self) -> Result<&'a str, CodecError> {
        let start = self.pos;
        while self.pos < self.data.len() {
            if self.data[self.pos] == b'\n' {
                let slice = &self.data[start..self.pos];
                self.pos += 1;
                return std::str::from_utf8(slice).map_err(|_| CodecError::BadUtf8);
            }
            self.pos += 1;
        }
        Err(CodecError::UnexpectedEof)
    }

    fn pop_val(&mut self) -> Result<Value, CodecError> {
        match self.stack.pop() {
            Some(StackItem::Val(v)) => Ok(v),
            Some(_) => Err(CodecError::InvalidValue("expected value on stack".into())),
            None => Err(CodecError::StackUnderflow),
        }
    }

    fn pop_mark_items(&mut self) -> Result<Vec<Value>, CodecError> {
        let mark = self.marks.pop().ok_or(CodecError::StackUnderflow)?;
        if mark > self.stack.len() {
            return Err(CodecError::StackUnderflow);
        }
        let items: Vec<Value> = self
            .stack
            .drain(mark..)
            .map(|item| match item {
                StackItem::Val(v) => Ok(v),
                _ => Err(CodecError::InvalidValue("expected value in items".into())),
            })
            .collect::<Result<_, _>>()?;
        Ok(items)
    }

    pub fn decode(mut self) -> Result<Value, CodecError> {
        let mut final_val = None;

        while self.pos < self.data.len() {
            let opcode = self.read_byte()?;
            match opcode {
                // PROTO
                0x80 => {
                    let proto = self.read_byte()?;
                    if !(2..=5).contains(&proto) {
                        return Err(CodecError::InvalidProtocol(proto));
                    }
                }
                // FRAME (protocol 4/5 8-byte frame length prefix)
                0x95 => {
                    let _ = self.read_bytes(8)?;
                }
                // STOP
                b'.' => {
                    final_val = Some(self.pop_val()?);
                    break;
                }
                // NONE
                b'N' => self.stack.push(StackItem::Val(Value::None)),
                // NEWTRUE / NEWFALSE
                0x88 => self.stack.push(StackItem::Val(Value::Bool(true))),
                0x89 => self.stack.push(StackItem::Val(Value::Bool(false))),
                // BININT1
                b'K' => {
                    let b = self.read_byte()?;
                    self.stack.push(StackItem::Val(Value::Int(b as i64)));
                }
                // BININT2
                b'M' => {
                    let b = self.read_bytes(2)?;
                    let v = u16::from_le_bytes([b[0], b[1]]);
                    self.stack.push(StackItem::Val(Value::Int(v as i64)));
                }
                // BININT
                b'J' => {
                    let b = self.read_bytes(4)?;
                    let v = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                    self.stack.push(StackItem::Val(Value::Int(v as i64)));
                }
                // LONG1
                0x8a => {
                    let len = self.read_byte()? as usize;
                    let bytes = self.read_bytes(len)?;
                    let v = decode_long_le(bytes)?;
                    self.stack.push(StackItem::Val(Value::Int(v)));
                }
                // LONG4
                0x8b => {
                    let b = self.read_bytes(4)?;
                    let len = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
                    let bytes = self.read_bytes(len)?;
                    let v = decode_long_le(bytes)?;
                    self.stack.push(StackItem::Val(Value::Int(v)));
                }
                // INT (ascii)
                b'I' => {
                    let line = self.read_line()?;
                    let v: i64 = line
                        .trim()
                        .parse()
                        .map_err(|_| CodecError::InvalidValue(line.into()))?;
                    self.stack.push(StackItem::Val(Value::Int(v)));
                }
                // BINFLOAT
                b'G' => {
                    let b = self.read_bytes(8)?;
                    let v = f64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                    self.stack.push(StackItem::Val(Value::Float(v)));
                }
                // SHORT_BINUNICODE
                0x8c => {
                    let len = self.read_byte()? as usize;
                    let bytes = self.read_bytes(len)?;
                    let s = std::str::from_utf8(bytes).map_err(|_| CodecError::BadUtf8)?;
                    self.stack.push(StackItem::Val(Value::Str(s.to_owned())));
                }
                // BINUNICODE
                b'X' => {
                    let b = self.read_bytes(4)?;
                    let len = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
                    let bytes = self.read_bytes(len)?;
                    let s = std::str::from_utf8(bytes).map_err(|_| CodecError::BadUtf8)?;
                    self.stack.push(StackItem::Val(Value::Str(s.to_owned())));
                }
                // SHORT_BINBYTES
                b'C' => {
                    let len = self.read_byte()? as usize;
                    let bytes = self.read_bytes(len)?;
                    self.stack
                        .push(StackItem::Val(Value::Bytes(bytes.to_vec())));
                }
                // BINBYTES
                b'B' => {
                    let b = self.read_bytes(4)?;
                    let len = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
                    let bytes = self.read_bytes(len)?;
                    self.stack
                        .push(StackItem::Val(Value::Bytes(bytes.to_vec())));
                }
                // MARK
                b'(' => {
                    self.marks.push(self.stack.len());
                }
                // EMPTY_LIST
                b']' => {
                    self.stack.push(StackItem::Val(Value::List(Vec::new())));
                }
                // APPEND
                b'a' => {
                    let item = self.pop_val()?;
                    match self.stack.last_mut() {
                        Some(StackItem::Val(Value::List(l))) => l.push(item),
                        _ => return Err(CodecError::StackUnderflow),
                    }
                }
                // APPENDS
                b'e' => {
                    let items = self.pop_mark_items()?;
                    match self.stack.last_mut() {
                        Some(StackItem::Val(Value::List(l))) => l.extend(items),
                        _ => return Err(CodecError::StackUnderflow),
                    }
                }
                // EMPTY_DICT
                b'}' => {
                    self.stack.push(StackItem::Val(Value::Dict(Vec::new())));
                }
                // SETITEM
                b's' => {
                    let v = self.pop_val()?;
                    let k = self.pop_val()?;
                    match self.stack.last_mut() {
                        Some(StackItem::Val(Value::Dict(d))) => d.push((k, v)),
                        _ => return Err(CodecError::StackUnderflow),
                    }
                }
                // SETITEMS
                b'u' => {
                    let items = self.pop_mark_items()?;
                    if items.len() % 2 != 0 {
                        return Err(CodecError::InvalidValue("odd number of dict items".into()));
                    }
                    match self.stack.last_mut() {
                        Some(StackItem::Val(Value::Dict(d))) => {
                            for chunk in items.chunks_exact(2) {
                                d.push((chunk[0].clone(), chunk[1].clone()));
                            }
                        }
                        _ => return Err(CodecError::StackUnderflow),
                    }
                }
                // EMPTY_SET
                0x8f => {
                    self.stack.push(StackItem::Val(Value::Set(Vec::new())));
                }
                // ADDITEMS
                0x90 => {
                    let items = self.pop_mark_items()?;
                    match self.stack.last_mut() {
                        Some(StackItem::Val(Value::Set(s))) => s.extend(items),
                        _ => return Err(CodecError::StackUnderflow),
                    }
                }
                // TUPLE1
                0x85 => {
                    let v = self.pop_val()?;
                    self.stack.push(StackItem::Val(Value::Tuple(vec![v])));
                }
                // TUPLE2
                0x86 => {
                    let v2 = self.pop_val()?;
                    let v1 = self.pop_val()?;
                    self.stack.push(StackItem::Val(Value::Tuple(vec![v1, v2])));
                }
                // TUPLE3
                0x87 => {
                    let v3 = self.pop_val()?;
                    let v2 = self.pop_val()?;
                    let v1 = self.pop_val()?;
                    self.stack
                        .push(StackItem::Val(Value::Tuple(vec![v1, v2, v3])));
                }
                // TUPLE (from mark)
                b't' => {
                    let items = self.pop_mark_items()?;
                    self.stack.push(StackItem::Val(Value::Tuple(items)));
                }
                // MEMOIZE
                0x94 => {
                    if let Some(StackItem::Val(v)) = self.stack.last() {
                        let idx = self.memo.len();
                        self.memo.insert(idx, v.clone());
                    }
                }
                // BINGET
                b'h' => {
                    let idx = self.read_byte()? as usize;
                    let v = self
                        .memo
                        .get(&idx)
                        .ok_or_else(|| CodecError::InvalidValue("memo not found".into()))?;
                    self.stack.push(StackItem::Val(v.clone()));
                }
                // LONG_BINGET
                b'j' => {
                    let b = self.read_bytes(4)?;
                    let idx = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
                    let v = self
                        .memo
                        .get(&idx)
                        .ok_or_else(|| CodecError::InvalidValue("memo not found".into()))?;
                    self.stack.push(StackItem::Val(v.clone()));
                }
                // BINPUT
                b'q' => {
                    let idx = self.read_byte()? as usize;
                    if let Some(StackItem::Val(v)) = self.stack.last() {
                        self.memo.insert(idx, v.clone());
                    }
                }
                // LONG_BINPUT
                b'r' => {
                    let b = self.read_bytes(4)?;
                    let idx = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
                    if let Some(StackItem::Val(v)) = self.stack.last() {
                        self.memo.insert(idx, v.clone());
                    }
                }
                // STACK_GLOBAL (\x93): only permitted for builtins.Exception
                0x93 => {
                    let name = self.pop_val()?.into_string();
                    let module = self.pop_val()?.into_string();
                    if module == "builtins" && name == "Exception" {
                        self.stack.push(StackItem::Global(module, name));
                    } else {
                        return Err(CodecError::SecurityViolation(format!(
                            "arbitrary global {module}.{name} disallowed"
                        )));
                    }
                }
                // REDUCE (R): only permitted for builtins.Exception
                b'R' => {
                    let arg = self.pop_val()?;
                    let target = self.stack.pop().ok_or(CodecError::StackUnderflow)?;
                    match target {
                        StackItem::Global(m, n) if m == "builtins" && n == "Exception" => {
                            let msg = match arg {
                                Value::Tuple(mut t) if !t.is_empty() => t.remove(0).into_string(),
                                Value::Str(s) => s,
                                _ => String::new(),
                            };
                            self.stack.push(StackItem::Val(Value::Exception(msg)));
                        }
                        _ => {
                            return Err(CodecError::SecurityViolation(
                                "arbitrary reduce disallowed".into(),
                            ));
                        }
                    }
                }
                other => {
                    return Err(CodecError::InvalidOpcode(other));
                }
            }
        }

        final_val.ok_or(CodecError::UnexpectedEof)
    }
}

fn decode_long_le(bytes: &[u8]) -> Result<i64, CodecError> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 8 {
        return Err(CodecError::InvalidValue(
            "integer out of 64-bit range".into(),
        ));
    }
    let mut buf = if bytes.last().unwrap() & 0x80 != 0 {
        [0xff; 8]
    } else {
        [0x00; 8]
    };
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(i64::from_le_bytes(buf))
}

/// Encodes a value to Protocol 5 pickle bytecode.
pub fn encode(val: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    // Protocol 5 header
    buf.extend_from_slice(&[0x80, 0x05]);
    encode_item(val, &mut buf);
    buf.push(b'.');
    buf
}

fn encode_item(val: &Value, buf: &mut Vec<u8>) {
    match val {
        Value::None => buf.push(b'N'),
        Value::Bool(true) => buf.push(0x88),
        Value::Bool(false) => buf.push(0x89),
        Value::Int(i) => encode_int(*i, buf),
        Value::Float(f) => {
            buf.push(b'G');
            buf.extend_from_slice(&f.to_be_bytes());
        }
        Value::Str(s) => encode_str(s, buf),
        Value::Bytes(b) => {
            if b.len() <= 255 {
                buf.push(b'C');
                buf.push(b.len() as u8);
            } else {
                buf.push(b'B');
                buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
            }
            buf.extend_from_slice(b);
        }
        Value::List(l) => {
            buf.extend_from_slice(b"](");
            for item in l {
                encode_item(item, buf);
            }
            buf.push(b'e');
        }
        Value::Tuple(t) => match t.len() {
            0 => buf.extend_from_slice(b")\x85"),
            1 => {
                encode_item(&t[0], buf);
                buf.push(0x85);
            }
            2 => {
                encode_item(&t[0], buf);
                encode_item(&t[1], buf);
                buf.push(0x86);
            }
            3 => {
                encode_item(&t[0], buf);
                encode_item(&t[1], buf);
                encode_item(&t[2], buf);
                buf.push(0x87);
            }
            _ => {
                buf.push(b'(');
                for item in t {
                    encode_item(item, buf);
                }
                buf.push(b't');
            }
        },
        Value::Dict(d) => {
            buf.extend_from_slice(b"}(");
            for (k, v) in d {
                encode_item(k, buf);
                encode_item(v, buf);
            }
            buf.push(b'u');
        }
        Value::Set(s) => {
            buf.extend_from_slice(b"\x8f(");
            for item in s {
                encode_item(item, buf);
            }
            buf.push(0x90);
        }
        Value::Exception(msg) => {
            // Emits builtins.Exception(msg)
            // builtins.Exception
            encode_str("builtins", buf);
            encode_str("Exception", buf);
            buf.push(0x93); // STACK_GLOBAL
            // argument tuple (msg,)
            encode_str(msg, buf);
            buf.push(0x85); // TUPLE1
            buf.push(b'R'); // REDUCE
        }
    }
}

fn encode_int(i: i64, buf: &mut Vec<u8>) {
    if (0..=255).contains(&i) {
        buf.push(b'K');
        buf.push(i as u8);
    } else if (0..=65535).contains(&i) {
        buf.push(b'M');
        buf.extend_from_slice(&(i as u16).to_le_bytes());
    } else if i32::MIN as i64 <= i && i <= i32::MAX as i64 {
        buf.push(b'J');
        buf.extend_from_slice(&(i as i32).to_le_bytes());
    } else {
        buf.push(0x8a);
        buf.push(8);
        buf.extend_from_slice(&i.to_le_bytes());
    }
}

fn encode_str(s: &str, buf: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    if bytes.len() <= 255 {
        buf.push(0x8c);
        buf.push(bytes.len() as u8);
    } else {
        buf.push(b'X');
        buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    }
    buf.extend_from_slice(bytes);
}

pub fn decode(bytes: &[u8]) -> Result<Value, CodecError> {
    Decoder::new(bytes).decode()
}
