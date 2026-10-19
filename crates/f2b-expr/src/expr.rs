//! Lexer, parser and evaluator for the Python expression subset.

use crate::error::ExprError;
use crate::num::{Num, f64_to_i64, float_pow, int_lshift, int_rshift, round_float, round_int};
use std::cmp::Ordering;

/// Maximum number of tokens in one expression (bounds tree depth and so recursion).
const MAX_TOKENS: usize = 512;
/// Maximum nesting of parentheses / unary operators / conditionals.
const MAX_DEPTH: usize = 100;

/// A Python value as far as this subset is concerned (`bool` is an `int` subclass).
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Value {
    Int(i64),
    Float(f64),
    Bool(bool),
}

impl Value {
    pub(crate) fn num(self) -> Num {
        match self {
            Self::Int(i) => Num::Int(i),
            Self::Float(f) => Num::Float(f),
            Self::Bool(b) => Num::Int(i64::from(b)),
        }
    }

    pub(crate) fn from_num(n: Num) -> Self {
        match n {
            Num::Int(i) => Self::Int(i),
            Num::Float(f) => Self::Float(f),
        }
    }

    fn truthy(self) -> bool {
        match self {
            Self::Bool(b) => b,
            _ => self.num().is_truthy(),
        }
    }

    /// `Some` for `int` and `bool` operands (those that support bitwise ops and shifts).
    fn int_like(self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(i),
            Self::Bool(b) => Some(i64::from(b)),
            Self::Float(_) => None,
        }
    }

    fn type_name(self) -> &'static str {
        match self {
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Bool(_) => "bool",
        }
    }

    pub(crate) fn cmp(self, o: Self) -> Option<Ordering> {
        self.num().py_cmp(o.num())
    }
}

/// Values of the names available to a ban-time formula.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Env {
    pub(crate) ban_time: Value,
    pub(crate) ban_count: i64,
    pub(crate) ban_factor: Value,
}

impl Env {
    pub(crate) const EMPTY: Self = Self {
        ban_time: Value::Int(0),
        ban_count: 0,
        ban_factor: Value::Int(1),
    };
}

/// Which names an expression may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Literals and operators only (`str2seconds`).
    Pure,
    /// Plus calls to the builtin and `math` functions (`bantime.factor`).
    Calls,
    /// Plus `ban.Time`, `ban.Count`, `banFactor` (`bantime.formula`).
    Formula,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Mod,
    Pow,
    Shl,
    Shr,
    BitAnd,
    BitOr,
    BitXor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CmpOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MathFn {
    Exp,
    Log,
    Log2,
    Log10,
    Sqrt,
    Fabs,
    Floor,
    Ceil,
    Trunc,
    Pow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Func {
    Min,
    Max,
    Abs,
    Int,
    Float,
    Round,
    Pow,
    Math(MathFn),
}

/// Compiled expression tree.
#[derive(Clone, Debug)]
pub(crate) enum Expr {
    Const(Value),
    BanTime,
    BanCount,
    BanFactor,
    Neg(Box<Expr>),
    Pos(Box<Expr>),
    Invert(Box<Expr>),
    Not(Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Cmp(Box<Expr>, Vec<(CmpOp, Expr)>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    /// `then if cond else otherwise`, stored as `(cond, then, otherwise)`.
    IfElse(Box<Expr>, Box<Expr>, Box<Expr>),
    Call(Func, Vec<Expr>),
}

// ---------------------------------------------------------------- lexer ----

#[derive(Clone, Copy, Debug, PartialEq)]
enum Tok<'a> {
    Num(Value),
    Name(&'a str),
    Bin(BinOp),
    Cmp(CmpOp),
    Invert,
    LParen,
    RParen,
    Dot,
    Comma,
    Newline,
    End,
}

fn describe(t: Tok<'_>) -> String {
    match t {
        Tok::Num(_) => "number".into(),
        Tok::Name(n) => format!("name '{n}'"),
        Tok::Bin(op) => format!("operator {op:?}"),
        Tok::Cmp(op) => format!("operator {op:?}"),
        Tok::Invert => "'~'".into(),
        Tok::LParen => "'('".into(),
        Tok::RParen => "')'".into(),
        Tok::Dot => "'.'".into(),
        Tok::Comma => "','".into(),
        Tok::Newline => "end of line".into(),
        Tok::End => "end of expression".into(),
    }
}

fn syntax<T>(msg: impl Into<String>) -> Result<T, ExprError> {
    Err(ExprError::Syntax(msg.into()))
}

fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

/// Reads `digit (_? digit)*`, `b[i]` being a digit; returns the end index.
fn digitpart(b: &[u8], mut i: usize, ok: fn(u8) -> bool) -> Result<usize, ExprError> {
    loop {
        while i < b.len() && ok(b[i]) {
            i += 1;
        }
        if i < b.len() && b[i] == b'_' {
            if i + 1 < b.len() && ok(b[i + 1]) {
                i += 1;
            } else {
                return syntax("invalid underscore in numeric literal");
            }
        } else {
            return Ok(i);
        }
    }
}

/// CPython `verify_end_of_number`: a number may be followed by a keyword
/// (`1if x else 2`) but not by other identifier characters.
fn verify_end_of_number(b: &[u8], i: usize) -> Result<(), ExprError> {
    let Some(&c) = b.get(i) else { return Ok(()) };
    let rest = &b[i + 1..];
    let keyword = match c {
        b'a' => rest.starts_with(b"nd"),
        b'e' => rest.starts_with(b"lse"),
        b'f' => rest.starts_with(b"or"),
        b'i' => matches!(rest.first(), Some(b'f' | b'n' | b's')),
        b'o' => rest.starts_with(b"r"),
        b'n' => rest.starts_with(b"ot"),
        _ => false,
    };
    if !keyword && (c.is_ascii_alphanumeric() || c == b'_' || c >= 128) {
        return syntax("invalid numeric literal");
    }
    Ok(())
}

fn strip_underscores(b: &[u8]) -> String {
    b.iter()
        .filter(|&&c| c != b'_')
        .map(|&c| char::from(c))
        .collect()
}

fn lex_number(b: &[u8], start: usize) -> Result<(Value, usize), ExprError> {
    let mut i = start;
    if b[i] == b'0' && matches!(b.get(i + 1), Some(b'x' | b'X' | b'o' | b'O' | b'b' | b'B')) {
        let (radix, ok): (u32, fn(u8) -> bool) = match b[i + 1] {
            b'x' | b'X' => (16, |c| c.is_ascii_hexdigit()),
            b'o' | b'O' => (8, |c| (b'0'..=b'7').contains(&c)),
            _ => (2, |c| c == b'0' || c == b'1'),
        };
        i += 2;
        if b.get(i) == Some(&b'_') {
            i += 1;
        }
        if !b.get(i).is_some_and(|&c| ok(c)) {
            return syntax("invalid digit in prefixed integer literal");
        }
        let end = digitpart(b, i, ok)?;
        verify_end_of_number(b, end)?;
        let v = i64::from_str_radix(&strip_underscores(&b[i..end]), radix)
            .map_err(|_| ExprError::Overflow("integer literal does not fit in 64 bits"))?;
        return Ok((Value::Int(v), end));
    }
    let mut is_float = false;
    if b[i] == b'.' {
        i = digitpart(b, i + 1, is_digit)?;
        is_float = true;
    } else {
        i = digitpart(b, i, is_digit)?;
        if b.get(i) == Some(&b'.') {
            i += 1;
            is_float = true;
            if b.get(i).is_some_and(|&c| is_digit(c)) {
                i = digitpart(b, i, is_digit)?;
            } else if b.get(i) == Some(&b'_') {
                return syntax("invalid underscore in numeric literal");
            }
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        let j = i + 1;
        if b.get(j).is_some_and(|&c| is_digit(c)) {
            i = digitpart(b, j, is_digit)?;
            is_float = true;
        } else if matches!(b.get(j), Some(b'+' | b'-')) {
            if b.get(j + 1).is_some_and(|&c| is_digit(c)) {
                i = digitpart(b, j + 1, is_digit)?;
                is_float = true;
            } else {
                return syntax("invalid decimal literal");
            }
        }
        // otherwise not an exponent: `verify_end_of_number` below decides.
    }
    if matches!(b.get(i), Some(b'j' | b'J')) {
        return Err(ExprError::Unsupported("complex number literal".into()));
    }
    verify_end_of_number(b, i)?;
    let text = strip_underscores(&b[start..i]);
    if is_float {
        let f = text
            .parse::<f64>()
            .map_err(|_| ExprError::Syntax("invalid float literal".into()))?;
        Ok((Value::Float(f), i))
    } else {
        if text.starts_with('0') && text.bytes().any(|c| c != b'0') {
            return syntax("leading zeros in decimal integer literals are not permitted");
        }
        let v = text
            .parse::<i64>()
            .map_err(|_| ExprError::Overflow("integer literal does not fit in 64 bits"))?;
        Ok((Value::Int(v), i))
    }
}

fn lex(src: &str) -> Result<Vec<Tok<'_>>, ExprError> {
    if src.contains('\0') {
        return syntax("source code cannot contain null bytes");
    }
    let b = src.as_bytes();
    let mut toks: Vec<Tok<'_>> = Vec::new();
    let (mut i, mut depth, mut col) = (0usize, 0usize, 0usize);
    let mut line_start = true;
    let mut line_has_tokens = false;
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' => {
                col += 1;
                i += 1;
            }
            b'\t' => {
                col = (col / 8 + 1) * 8;
                i += 1;
            }
            0x0c => {
                col = 0;
                i += 1;
            }
            b'\n' | b'\r' => {
                i += if c == b'\r' && b.get(i + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                if depth == 0 {
                    if line_has_tokens {
                        toks.push(Tok::Newline);
                        line_has_tokens = false;
                    }
                    line_start = true;
                }
                col = 0;
            }
            b'#' => {
                while i < b.len() && b[i] != b'\n' && b[i] != b'\r' {
                    i += 1;
                }
            }
            _ => {
                if line_start && depth == 0 && col > 0 {
                    return syntax("unexpected indent");
                }
                line_start = false;
                if c == b'\\' {
                    // explicit line continuation
                    i += 1;
                    match b.get(i) {
                        Some(b'\n') => i += 1,
                        Some(b'\r') => i += if b.get(i + 1) == Some(&b'\n') { 2 } else { 1 },
                        _ => {
                            return syntax(
                                "unexpected character after line continuation character",
                            );
                        }
                    }
                    if i >= b.len() {
                        return syntax("unexpected EOF after line continuation character");
                    }
                    continue;
                }
                line_has_tokens = true;
                let two = b.get(i + 1).copied();
                let (tok, len) = match c {
                    b'0'..=b'9' => {
                        let (v, end) = lex_number(b, i)?;
                        (Tok::Num(v), end - i)
                    }
                    b'.' if two.is_some_and(is_digit) => {
                        let (v, end) = lex_number(b, i)?;
                        (Tok::Num(v), end - i)
                    }
                    b'.' => (Tok::Dot, 1),
                    b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                        let mut j = i + 1;
                        while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                            j += 1;
                        }
                        if b.get(j).is_some_and(|&x| x >= 128) {
                            return syntax("non-ASCII character in identifier");
                        }
                        (Tok::Name(&src[i..j]), j - i)
                    }
                    b'(' => {
                        depth += 1;
                        if depth > 200 {
                            return syntax("too many nested parentheses");
                        }
                        (Tok::LParen, 1)
                    }
                    b')' => {
                        if depth == 0 {
                            return syntax("unmatched ')'");
                        }
                        depth -= 1;
                        (Tok::RParen, 1)
                    }
                    b',' => (Tok::Comma, 1),
                    b'+' => (Tok::Bin(BinOp::Add), 1),
                    b'-' => (Tok::Bin(BinOp::Sub), 1),
                    b'*' if two == Some(b'*') => (Tok::Bin(BinOp::Pow), 2),
                    b'*' => (Tok::Bin(BinOp::Mul), 1),
                    b'/' if two == Some(b'/') => (Tok::Bin(BinOp::FloorDiv), 2),
                    b'/' => (Tok::Bin(BinOp::Div), 1),
                    b'%' => (Tok::Bin(BinOp::Mod), 1),
                    b'&' => (Tok::Bin(BinOp::BitAnd), 1),
                    b'|' => (Tok::Bin(BinOp::BitOr), 1),
                    b'^' => (Tok::Bin(BinOp::BitXor), 1),
                    b'~' => (Tok::Invert, 1),
                    b'<' if two == Some(b'<') => (Tok::Bin(BinOp::Shl), 2),
                    b'<' if two == Some(b'=') => (Tok::Cmp(CmpOp::Le), 2),
                    b'<' => (Tok::Cmp(CmpOp::Lt), 1),
                    b'>' if two == Some(b'>') => (Tok::Bin(BinOp::Shr), 2),
                    b'>' if two == Some(b'=') => (Tok::Cmp(CmpOp::Ge), 2),
                    b'>' => (Tok::Cmp(CmpOp::Gt), 1),
                    b'=' if two == Some(b'=') => (Tok::Cmp(CmpOp::Eq), 2),
                    b'!' if two == Some(b'=') => (Tok::Cmp(CmpOp::Ne), 2),
                    b'\'' | b'"' => {
                        return Err(ExprError::Unsupported("string literal".into()));
                    }
                    c if c >= 128 => return syntax("invalid non-ASCII character"),
                    c => return syntax(format!("invalid character '{}'", char::from(c))),
                };
                toks.push(tok);
                i += len;
                if toks.len() > MAX_TOKENS {
                    return Err(ExprError::Unsupported(format!(
                        "expression longer than {MAX_TOKENS} tokens"
                    )));
                }
            }
        }
    }
    if depth != 0 {
        return syntax("'(' was never closed");
    }
    toks.push(Tok::End);
    Ok(toks)
}

// --------------------------------------------------------------- parser ----

struct Parser<'a> {
    toks: Vec<Tok<'a>>,
    pos: usize,
    depth: usize,
    scope: Scope,
}

type PResult = Result<Expr, ExprError>;

impl<'a> Parser<'a> {
    fn peek(&self) -> Tok<'a> {
        self.toks[self.pos]
    }

    fn next(&mut self) -> Tok<'a> {
        let t = self.toks[self.pos];
        if !matches!(t, Tok::End) {
            self.pos += 1;
        }
        t
    }

    fn peek_name(&self, kw: &str) -> bool {
        matches!(self.peek(), Tok::Name(n) if n == kw)
    }

    fn unexpected<T>(&self, t: Tok<'_>) -> Result<T, ExprError> {
        syntax(format!("unexpected {}", describe(t)))
    }

    fn enter(&mut self) -> Result<(), ExprError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ExprError::Unsupported(format!(
                "expression nested deeper than {MAX_DEPTH} levels"
            )));
        }
        Ok(())
    }

    fn test(&mut self) -> PResult {
        self.enter()?;
        let body = self.or_test()?;
        let e = if self.peek_name("if") {
            self.next();
            let cond = self.or_test()?;
            if !self.peek_name("else") {
                let t = self.peek();
                return self.unexpected(t);
            }
            self.next();
            let other = self.test()?;
            Expr::IfElse(Box::new(cond), Box::new(body), Box::new(other))
        } else {
            body
        };
        self.depth -= 1;
        Ok(e)
    }

    fn or_test(&mut self) -> PResult {
        let mut e = self.and_test()?;
        while self.peek_name("or") {
            self.next();
            e = Expr::Or(Box::new(e), Box::new(self.and_test()?));
        }
        Ok(e)
    }

    fn and_test(&mut self) -> PResult {
        let mut e = self.not_test()?;
        while self.peek_name("and") {
            self.next();
            e = Expr::And(Box::new(e), Box::new(self.not_test()?));
        }
        Ok(e)
    }

    fn not_test(&mut self) -> PResult {
        if self.peek_name("not") {
            self.next();
            self.enter()?;
            let e = self.not_test()?;
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(e)));
        }
        self.comparison()
    }

    fn comparison(&mut self) -> PResult {
        let first = self.bit_or()?;
        let mut rest = Vec::new();
        loop {
            match self.peek() {
                Tok::Cmp(op) => {
                    self.next();
                    rest.push((op, self.bit_or()?));
                }
                Tok::Name("in" | "is") => {
                    return Err(ExprError::Unsupported("`in` / `is` comparisons".into()));
                }
                Tok::Name("not") => {
                    return Err(ExprError::Unsupported("`not in` comparison".into()));
                }
                _ => break,
            }
        }
        if rest.is_empty() {
            Ok(first)
        } else {
            Ok(Expr::Cmp(Box::new(first), rest))
        }
    }

    fn binary_level(&mut self, ops: &[BinOp], sub: fn(&mut Self) -> PResult) -> PResult {
        let mut e = sub(self)?;
        while let Tok::Bin(op) = self.peek() {
            if !ops.contains(&op) {
                break;
            }
            self.next();
            e = Expr::Bin(op, Box::new(e), Box::new(sub(self)?));
        }
        Ok(e)
    }

    fn bit_or(&mut self) -> PResult {
        self.binary_level(&[BinOp::BitOr], Self::bit_xor)
    }

    fn bit_xor(&mut self) -> PResult {
        self.binary_level(&[BinOp::BitXor], Self::bit_and)
    }

    fn bit_and(&mut self) -> PResult {
        self.binary_level(&[BinOp::BitAnd], Self::shift)
    }

    fn shift(&mut self) -> PResult {
        self.binary_level(&[BinOp::Shl, BinOp::Shr], Self::arith)
    }

    fn arith(&mut self) -> PResult {
        self.binary_level(&[BinOp::Add, BinOp::Sub], Self::term)
    }

    fn term(&mut self) -> PResult {
        self.binary_level(
            &[BinOp::Mul, BinOp::Div, BinOp::FloorDiv, BinOp::Mod],
            Self::factor,
        )
    }

    fn factor(&mut self) -> PResult {
        match self.peek() {
            Tok::Bin(op @ (BinOp::Add | BinOp::Sub)) => {
                self.next();
                self.enter()?;
                let e = Box::new(self.factor()?);
                self.depth -= 1;
                Ok(if op == BinOp::Add {
                    Expr::Pos(e)
                } else {
                    Expr::Neg(e)
                })
            }
            Tok::Invert => {
                self.next();
                self.enter()?;
                let e = Box::new(self.factor()?);
                self.depth -= 1;
                Ok(Expr::Invert(e))
            }
            _ => self.power(),
        }
    }

    fn power(&mut self) -> PResult {
        let base = self.primary()?;
        if matches!(self.peek(), Tok::LParen | Tok::Dot) {
            return Err(ExprError::Unsupported(
                "call, attribute access or subscript on this value".into(),
            ));
        }
        if self.peek() == Tok::Bin(BinOp::Pow) {
            self.next();
            self.enter()?;
            let exp = self.factor()?;
            self.depth -= 1;
            return Ok(Expr::Bin(BinOp::Pow, Box::new(base), Box::new(exp)));
        }
        Ok(base)
    }

    fn primary(&mut self) -> PResult {
        match self.next() {
            Tok::Num(v) => Ok(Expr::Const(v)),
            Tok::LParen => {
                if self.peek() == Tok::RParen {
                    return Err(ExprError::Unsupported("empty tuple".into()));
                }
                let e = self.test()?;
                match self.next() {
                    Tok::RParen => Ok(e),
                    Tok::Comma => Err(ExprError::Unsupported("tuple".into())),
                    t => self.unexpected(t),
                }
            }
            Tok::Name(n) => self.name(n),
            t => self.unexpected(t),
        }
    }

    fn name(&mut self, n: &str) -> PResult {
        let calls = self.scope != Scope::Pure;
        let ban = self.scope == Scope::Formula;
        match n {
            "True" => return Ok(Expr::Const(Value::Bool(true))),
            "False" => return Ok(Expr::Const(Value::Bool(false))),
            "ban" if ban => {
                return match (self.next(), self.next()) {
                    (Tok::Dot, Tok::Name("Time")) => Ok(Expr::BanTime),
                    (Tok::Dot, Tok::Name("Count")) => Ok(Expr::BanCount),
                    _ => Err(ExprError::Unsupported(
                        "`ban` is only usable as `ban.Time` or `ban.Count`".into(),
                    )),
                };
            }
            "banFactor" if ban => return Ok(Expr::BanFactor),
            "math" if calls => return self.math_attr(),
            _ => {}
        }
        let func = match n {
            "min" => Func::Min,
            "max" => Func::Max,
            "abs" => Func::Abs,
            "int" => Func::Int,
            "float" => Func::Float,
            "round" => Func::Round,
            "pow" => Func::Pow,
            _ => {
                return Err(ExprError::Unsupported(format!(
                    "name '{n}' is not available here"
                )));
            }
        };
        if !calls {
            return Err(ExprError::Unsupported(format!(
                "function '{n}' is not available here"
            )));
        }
        self.call(n, func)
    }

    fn math_attr(&mut self) -> PResult {
        if self.next() != Tok::Dot {
            return Err(ExprError::Unsupported("bare `math` module".into()));
        }
        let Tok::Name(attr) = self.next() else {
            return syntax("expected attribute name after 'math.'");
        };
        let func = match attr {
            "exp" => MathFn::Exp,
            "log" => MathFn::Log,
            "log2" => MathFn::Log2,
            "log10" => MathFn::Log10,
            "sqrt" => MathFn::Sqrt,
            "fabs" => MathFn::Fabs,
            "floor" => MathFn::Floor,
            "ceil" => MathFn::Ceil,
            "trunc" => MathFn::Trunc,
            "pow" => MathFn::Pow,
            "pi" => return Ok(Expr::Const(Value::Float(std::f64::consts::PI))),
            "e" => return Ok(Expr::Const(Value::Float(std::f64::consts::E))),
            "tau" => return Ok(Expr::Const(Value::Float(std::f64::consts::TAU))),
            "inf" => return Ok(Expr::Const(Value::Float(f64::INFINITY))),
            "nan" => return Ok(Expr::Const(Value::Float(f64::NAN))),
            _ => {
                return Err(ExprError::Unsupported(format!(
                    "math.{attr} is not available"
                )));
            }
        };
        self.call(&format!("math.{attr}"), Func::Math(func))
    }

    fn call(&mut self, name: &str, func: Func) -> PResult {
        if self.next() != Tok::LParen {
            return Err(ExprError::Unsupported(format!(
                "function '{name}' used as a value"
            )));
        }
        let mut args = Vec::new();
        if self.peek() == Tok::RParen {
            self.next();
        } else {
            loop {
                args.push(self.test()?);
                match self.next() {
                    Tok::Comma if self.peek() == Tok::RParen => {
                        self.next();
                        break;
                    }
                    Tok::Comma => {}
                    Tok::RParen => break,
                    t => return self.unexpected(t),
                }
            }
        }
        let (lo, hi) = match func {
            Func::Min | Func::Max => (2, usize::MAX),
            Func::Abs
            | Func::Math(
                MathFn::Exp
                | MathFn::Log2
                | MathFn::Log10
                | MathFn::Sqrt
                | MathFn::Fabs
                | MathFn::Floor
                | MathFn::Ceil
                | MathFn::Trunc,
            ) => (1, 1),
            Func::Int | Func::Float => (0, 1),
            Func::Round | Func::Math(MathFn::Log) => (1, 2),
            Func::Pow | Func::Math(MathFn::Pow) => (2, 2),
        };
        if args.len() < lo || args.len() > hi {
            return Err(ExprError::Type(format!(
                "{name}() does not accept {} argument(s) here (expected {lo}..{})",
                args.len(),
                if hi == usize::MAX {
                    "n".into()
                } else {
                    hi.to_string()
                }
            )));
        }
        Ok(Expr::Call(func, args))
    }
}

/// Compile `src`. With `strip_leading`, leading spaces/tabs are dropped first,
/// as `eval(str)` does (but `compile()` does not).
pub(crate) fn parse(src: &str, scope: Scope, strip_leading: bool) -> Result<Expr, ExprError> {
    let src = if strip_leading {
        src.trim_start_matches([' ', '\t'])
    } else {
        src
    };
    let toks = lex(src)?;
    let mut p = Parser {
        toks,
        pos: 0,
        depth: 0,
        scope,
    };
    let e = p.test()?;
    if p.peek() == Tok::Newline {
        p.next();
    }
    match p.peek() {
        Tok::End => Ok(e),
        t => p.unexpected(t),
    }
}

// ------------------------------------------------------------ evaluator ----

fn type_err<T>(op: &str, a: Value, b: Value) -> Result<T, ExprError> {
    Err(ExprError::Type(format!(
        "unsupported operand type(s) for {op}: '{}' and '{}'",
        a.type_name(),
        b.type_name()
    )))
}

fn binary(op: BinOp, a: Value, b: Value) -> Result<Value, ExprError> {
    let (x, y) = (a.num(), b.num());
    let n = match op {
        BinOp::Add => x.add(y)?,
        BinOp::Sub => x.sub(y)?,
        BinOp::Mul => x.mul(y)?,
        BinOp::Div => x.truediv(y)?,
        BinOp::FloorDiv => x.floordiv(y)?,
        BinOp::Mod => x.modulo(y)?,
        BinOp::Pow => x.pow(y)?,
        BinOp::Shl | BinOp::Shr | BinOp::BitAnd | BinOp::BitOr | BinOp::BitXor => {
            let (Some(i), Some(j)) = (a.int_like(), b.int_like()) else {
                return type_err(&format!("{op:?}"), a, b);
            };
            return Ok(match op {
                BinOp::Shl => Value::Int(int_lshift(i, j)?),
                BinOp::Shr => Value::Int(int_rshift(i, j)?),
                _ => {
                    let r = match op {
                        BinOp::BitAnd => i & j,
                        BinOp::BitOr => i | j,
                        _ => i ^ j,
                    };
                    if matches!((a, b), (Value::Bool(_), Value::Bool(_))) {
                        Value::Bool(r != 0)
                    } else {
                        Value::Int(r)
                    }
                }
            });
        }
    };
    Ok(Value::from_num(n))
}

fn compare(op: CmpOp, a: Value, b: Value) -> bool {
    let o = a.cmp(b);
    match op {
        CmpOp::Lt => o == Some(Ordering::Less),
        CmpOp::Le => matches!(o, Some(Ordering::Less | Ordering::Equal)),
        CmpOp::Gt => o == Some(Ordering::Greater),
        CmpOp::Ge => matches!(o, Some(Ordering::Greater | Ordering::Equal)),
        CmpOp::Eq => o == Some(Ordering::Equal),
        CmpOp::Ne => o != Some(Ordering::Equal),
    }
}

fn to_f64_checked(v: Value) -> f64 {
    v.num().as_f64()
}

/// CPython `math_1`-style wrapper: domain/range errors from the C result.
fn math_1(x: f64, r: f64, can_overflow: bool) -> Result<Value, ExprError> {
    if r.is_nan() && !x.is_nan() {
        return Err(ExprError::Value("math domain error"));
    }
    if r.is_infinite() && x.is_finite() {
        return Err(if can_overflow {
            ExprError::Overflow("math range error")
        } else {
            ExprError::Value("math domain error")
        });
    }
    Ok(Value::Float(r))
}

fn m_log(x: f64, f: fn(f64) -> f64) -> Result<f64, ExprError> {
    if x.is_nan() {
        return Ok(x);
    }
    if x > 0.0 {
        return Ok(f(x));
    }
    Err(ExprError::Value("math domain error"))
}

fn math_call(f: MathFn, a: Value, b: Option<Value>) -> Result<Value, ExprError> {
    let x = to_f64_checked(a);
    match f {
        MathFn::Exp => math_1(x, x.exp(), true),
        MathFn::Sqrt => {
            if x < 0.0 {
                Err(ExprError::Value("math domain error"))
            } else {
                Ok(Value::Float(x.sqrt()))
            }
        }
        MathFn::Log => {
            let num = m_log(x, f64::ln)?;
            match b {
                None => Ok(Value::Float(num)),
                Some(base) => {
                    let den = m_log(to_f64_checked(base), f64::ln)?;
                    Ok(Value::from_num(Num::Float(num).truediv(Num::Float(den))?))
                }
            }
        }
        MathFn::Log2 => Ok(Value::Float(m_log(x, f64::log2)?)),
        MathFn::Log10 => Ok(Value::Float(m_log(x, f64::log10)?)),
        MathFn::Fabs => Ok(Value::Float(x.abs())),
        MathFn::Floor | MathFn::Ceil | MathFn::Trunc => match a {
            Value::Float(f64v) => {
                let r = match f {
                    MathFn::Floor => f64v.floor(),
                    MathFn::Ceil => f64v.ceil(),
                    _ => f64v.trunc(),
                };
                Ok(Value::Int(f64_to_i64(r)?))
            }
            _ => Ok(Value::Int(a.num().as_i64()?)),
        },
        MathFn::Pow => {
            let y = b.map_or(0.0, to_f64_checked);
            Ok(Value::Float(float_pow(x, y)?))
        }
    }
}

fn round_value(a: Value, nd: Option<Value>) -> Result<Value, ExprError> {
    let nd = match nd {
        None => None,
        Some(v) => match v.int_like() {
            Some(n) => Some(n),
            None => {
                return Err(ExprError::Type("round() ndigits must be an integer".into()));
            }
        },
    };
    Ok(match (a.num(), nd) {
        (Num::Int(i), None) => Value::Int(i),
        (Num::Int(i), Some(n)) => Value::Int(round_int(i, n)?),
        (Num::Float(f), None) => Value::Int(f64_to_i64(f.round_ties_even())?),
        (Num::Float(f), Some(n)) => Value::Float(round_float(f, n)?),
    })
}

impl Expr {
    pub(crate) fn eval(&self, env: &Env) -> Result<Value, ExprError> {
        Ok(match self {
            Self::Const(v) => *v,
            Self::BanTime => env.ban_time,
            Self::BanCount => Value::Int(env.ban_count),
            Self::BanFactor => env.ban_factor,
            Self::Neg(e) => Value::from_num(e.eval(env)?.num().neg()?),
            Self::Pos(e) => Value::from_num(e.eval(env)?.num()),
            Self::Invert(e) => match e.eval(env)? {
                Value::Float(_) => {
                    return Err(ExprError::Type(
                        "bad operand type for unary ~: 'float'".into(),
                    ));
                }
                v => Value::Int(!v.int_like().unwrap_or(0)),
            },
            Self::Not(e) => Value::Bool(!e.eval(env)?.truthy()),
            Self::Bin(op, l, r) => {
                let a = l.eval(env)?;
                binary(*op, a, r.eval(env)?)?
            }
            Self::Cmp(first, rest) => {
                let mut left = first.eval(env)?;
                let mut result = true;
                for (op, e) in rest {
                    let right = e.eval(env)?;
                    result = compare(*op, left, right);
                    if !result {
                        break;
                    }
                    left = right;
                }
                Value::Bool(result)
            }
            Self::And(l, r) => {
                let a = l.eval(env)?;
                if a.truthy() { r.eval(env)? } else { a }
            }
            Self::Or(l, r) => {
                let a = l.eval(env)?;
                if a.truthy() { a } else { r.eval(env)? }
            }
            Self::IfElse(c, t, o) => {
                if c.eval(env)?.truthy() {
                    t.eval(env)?
                } else {
                    o.eval(env)?
                }
            }
            Self::Call(f, args) => call(*f, args, env)?,
        })
    }
}

fn call(f: Func, args: &[Expr], env: &Env) -> Result<Value, ExprError> {
    match f {
        Func::Min | Func::Max => {
            let mut it = args.iter();
            let mut best = match it.next() {
                Some(e) => e.eval(env)?,
                None => return Err(ExprError::Type("min/max expected arguments".into())),
            };
            let want = if f == Func::Min {
                Ordering::Less
            } else {
                Ordering::Greater
            };
            for e in it {
                let v = e.eval(env)?;
                if v.cmp(best) == Some(want) {
                    best = v;
                }
            }
            Ok(best)
        }
        Func::Abs => match args[0].eval(env)?.num() {
            Num::Int(i) => i
                .checked_abs()
                .map(Value::Int)
                .ok_or(ExprError::Overflow("abs() of the minimum integer")),
            Num::Float(x) => Ok(Value::Float(x.abs())),
        },
        Func::Int => match args.first() {
            None => Ok(Value::Int(0)),
            Some(e) => Ok(Value::Int(e.eval(env)?.num().as_i64()?)),
        },
        Func::Float => match args.first() {
            None => Ok(Value::Float(0.0)),
            Some(e) => Ok(Value::Float(e.eval(env)?.num().as_f64())),
        },
        Func::Round => {
            let a = args[0].eval(env)?;
            let nd = match args.get(1) {
                Some(e) => Some(e.eval(env)?),
                None => None,
            };
            round_value(a, nd)
        }
        Func::Pow => {
            let a = args[0].eval(env)?;
            binary(BinOp::Pow, a, args[1].eval(env)?)
        }
        Func::Math(m) => {
            let a = args[0].eval(env)?;
            let b = match args.get(1) {
                Some(e) => Some(e.eval(env)?),
                None => None,
            };
            math_call(m, a, b)
        }
    }
}
