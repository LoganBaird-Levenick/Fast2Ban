//! Minimal JSON reader for the oracle fixtures (the crate may not depend on serde).

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub fn str(&self) -> &str {
        match self {
            Value::Str(s) => s,
            v => panic!("expected string, got {v:?}"),
        }
    }

    pub fn arr(&self) -> &[Value] {
        match self {
            Value::Arr(a) => a,
            v => panic!("expected array, got {v:?}"),
        }
    }

    pub fn bool(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            v => panic!("expected bool, got {v:?}"),
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(o) => o.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            v => panic!("expected object, got {v:?}"),
        }
    }

    pub fn field(&self, key: &str) -> &Value {
        self.get(key)
            .unwrap_or_else(|| panic!("missing field {key}"))
    }

    pub fn strings(&self) -> Vec<String> {
        self.arr().iter().map(|v| v.str().to_owned()).collect()
    }

    /// `[[k, v], ...]` as ordered pairs.
    pub fn pairs(&self) -> Vec<(String, String)> {
        self.arr()
            .iter()
            .map(|p| (p.arr()[0].str().to_owned(), p.arr()[1].str().to_owned()))
            .collect()
    }
}

pub fn parse(text: &str) -> Value {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    let v = p.value();
    p.ws();
    assert_eq!(p.i, p.b.len(), "trailing data");
    v
}

pub fn load(name: &str) -> Value {
    let path = format!(
        "{}/../../testdata/f2b-helpers/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    parse(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}")))
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) {
        assert_eq!(self.b[self.i], c, "at {}", self.i);
        self.i += 1;
    }

    fn lit(&mut self, s: &str, v: Value) -> Value {
        assert!(self.b[self.i..].starts_with(s.as_bytes()));
        self.i += s.len();
        v
    }

    fn value(&mut self) -> Value {
        self.ws();
        match self.b[self.i] {
            b'n' => self.lit("null", Value::Null),
            b't' => self.lit("true", Value::Bool(true)),
            b'f' => self.lit("false", Value::Bool(false)),
            b'"' => Value::Str(self.string()),
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.b[self.i] == b']' {
                    self.i += 1;
                    return Value::Arr(a);
                }
                loop {
                    a.push(self.value());
                    self.ws();
                    match self.b[self.i] {
                        b',' => self.i += 1,
                        b']' => {
                            self.i += 1;
                            return Value::Arr(a);
                        }
                        c => panic!("unexpected {}", c as char),
                    }
                }
            }
            b'{' => {
                self.i += 1;
                let mut o = Vec::new();
                self.ws();
                if self.b[self.i] == b'}' {
                    self.i += 1;
                    return Value::Obj(o);
                }
                loop {
                    self.ws();
                    let k = self.string();
                    self.ws();
                    self.eat(b':');
                    o.push((k, self.value()));
                    self.ws();
                    match self.b[self.i] {
                        b',' => self.i += 1,
                        b'}' => {
                            self.i += 1;
                            return Value::Obj(o);
                        }
                        c => panic!("unexpected {}", c as char),
                    }
                }
            }
            _ => {
                let start = self.i;
                while self.i < self.b.len()
                    && matches!(
                        self.b[self.i],
                        b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
                    )
                {
                    self.i += 1;
                }
                Value::Num(
                    std::str::from_utf8(&self.b[start..self.i])
                        .unwrap()
                        .parse()
                        .unwrap(),
                )
            }
        }
    }

    fn hex4(&mut self) -> u32 {
        let s = std::str::from_utf8(&self.b[self.i..self.i + 4]).unwrap();
        self.i += 4;
        u32::from_str_radix(s, 16).unwrap()
    }

    fn string(&mut self) -> String {
        self.eat(b'"');
        let mut out = String::new();
        loop {
            let start = self.i;
            while self.b[self.i] != b'"' && self.b[self.i] != b'\\' {
                self.i += 1;
            }
            out.push_str(std::str::from_utf8(&self.b[start..self.i]).unwrap());
            if self.b[self.i] == b'"' {
                self.i += 1;
                return out;
            }
            self.i += 1;
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{8}'),
                b'f' => out.push('\u{c}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => {
                    let hi = self.hex4();
                    let cp = if (0xd800..0xdc00).contains(&hi) {
                        self.eat(b'\\');
                        self.eat(b'u');
                        let lo = self.hex4();
                        0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                    } else {
                        hi
                    };
                    out.push(char::from_u32(cp).expect("lone surrogate in fixture"));
                }
                c => panic!("bad escape {}", c as char),
            }
        }
    }
}
