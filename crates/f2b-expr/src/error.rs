use std::error::Error;
use std::fmt;

/// Failure to compile or evaluate an expression.
///
/// Every variant corresponds to a place where upstream Python would raise
/// (`SyntaxError`, `NameError`, `ZeroDivisionError`, ...) or to a deliberate
/// restriction of this crate (documented in the crate docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExprError {
    /// The text is not a valid expression (Python `SyntaxError`, `IndentationError`).
    Syntax(String),
    /// Valid Python, but outside the accepted language: unknown names,
    /// strings, tuples, `is`/`in`, bignum-only constructs, ...
    Unsupported(String),
    /// Operand types do not fit the operator or function (Python `TypeError`).
    Type(String),
    /// Value outside the function's domain (Python `ValueError`).
    Value(&'static str),
    /// Python `ZeroDivisionError`.
    ZeroDivision(&'static str),
    /// Python `OverflowError`, or an integer that does not fit `i64`
    /// (Python integers are unbounded; this crate's are not).
    Overflow(&'static str),
}

impl fmt::Display for ExprError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(m) => write!(f, "invalid syntax: {m}"),
            Self::Unsupported(m) => write!(f, "unsupported expression: {m}"),
            Self::Type(m) => write!(f, "type error: {m}"),
            Self::Value(m) => write!(f, "value error: {m}"),
            Self::ZeroDivision(m) => write!(f, "zero division: {m}"),
            Self::Overflow(m) => write!(f, "overflow: {m}"),
        }
    }
}

impl Error for ExprError {}
