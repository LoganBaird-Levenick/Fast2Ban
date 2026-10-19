//! Values of the client command stream (`['set', 'jail', 'maxretry', 5]`).

/// One element of a command, mirroring the Python objects upstream puts in the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    /// Python `None` (e.g. an unset action option).
    None,
    Str(String),
    Int(i64),
    Bool(bool),
    List(Vec<Arg>),
    /// Ordered mapping (e.g. the `thread` options dict).
    Map(Vec<(String, Arg)>),
}

/// A client command, e.g. `["set", "sshd", "maxretry", 5]`.
pub type Command = Vec<Arg>;

impl From<&str> for Arg {
    fn from(s: &str) -> Self {
        Self::Str(s.to_owned())
    }
}

impl From<String> for Arg {
    fn from(s: String) -> Self {
        Self::Str(s)
    }
}

/// A typed option value (after `bool`/`int` conversion) or the absent marker
/// (`None` in Python: a failed conversion falls back to a `None` default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Val {
    Str(String),
    Int(i64),
    Bool(bool),
    None,
}

impl Val {
    /// `str(value)` as Python would render it (used when option values act as
    /// interpolation variables).
    pub fn py_str(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            Self::Int(i) => i.to_string(),
            Self::Bool(true) => "True".to_owned(),
            Self::Bool(false) => "False".to_owned(),
            Self::None => "None".to_owned(),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            Self::Str(s) => !s.is_empty(),
            Self::Int(i) => *i != 0,
            Self::Bool(b) => *b,
            Self::None => false,
        }
    }
}

impl Val {
    /// Stream element for this value.
    pub fn into_arg(self) -> Arg {
        match self {
            Self::Str(s) => Arg::Str(s),
            Self::Int(i) => Arg::Int(i),
            Self::Bool(b) => Arg::Bool(b),
            Self::None => Arg::None,
        }
    }
}
