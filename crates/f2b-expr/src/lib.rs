//! Safe replacement for the three places where upstream Fail2Ban runs Python
//! `eval()` on configuration text.
//!
//! | upstream | here |
//! |---|---|
//! | `MyTime.str2seconds` (`mytime.py`) | [`str2seconds`] |
//! | `MyTime.seconds2str` (`mytime.py`) | [`seconds2str`] |
//! | `Jail.setBanTimeExtra` lambdas, `eval(factor)`, `compile(formula)` (`jail.py`) + `BanTimeIncr`/`calcBanTime` (`observer.py`) | [`BanTimeIncrement`] |
//!
//! No Python is embedded: a purpose-built lexer/parser/evaluator implements a
//! subset of Python 3.14 expression syntax with Python's numeric semantics
//! (`int` vs `float` results, floor division/modulo signs, correctly rounded
//! `int / int`, `float` repr in [`Num`]'s `Display`, ...). Behaviour is proven
//! against the real upstream functions by the fixtures generated with
//! `tools/gen_f2b_expr_fixtures.py`.
//!
//! # Accepted language
//!
//! ```text
//! test      := or_test [ "if" or_test "else" test ]
//! or_test   := and_test ("or" and_test)*          -- returns an operand, like Python
//! and_test  := not_test ("and" not_test)*
//! not_test  := "not" not_test | comparison
//! comparison:= bit_or (("<"|"<="|">"|">="|"=="|"!=") bit_or)*   -- chained
//! bit_or    := bit_xor ("|" bit_xor)*   bit_xor := bit_and ("^" bit_and)*
//! bit_and   := shift ("&" shift)*       shift   := arith (("<<"|">>") arith)*
//! arith     := term (("+"|"-") term)*   term    := factor (("*"|"/"|"//"|"%") factor)*
//! factor    := ("+"|"-"|"~") factor | power
//! power     := primary ["**" factor]
//! primary   := NUMBER | "True" | "False" | "(" test ")" | name | call
//! ```
//!
//! * Numbers: decimal/hex/octal/binary integers, floats with exponent,
//!   `_` separators, Python's leading-zero rules. Imaginary literals are
//!   rejected.
//! * Surrounding syntax follows the tokenizer: `# comments`, backslash line
//!   continuation, newlines inside parentheses, trailing blank lines;
//!   indentation or a second logical line is an error.
//! * Names depend on the scope:
//!   * `str2seconds`: none (pure arithmetic; boolean results are rejected).
//!   * `bantime.factor`: calls of the builtins and `math` functions below.
//!   * `bantime.formula`: additionally `ban.Time`, `ban.Count`, `banFactor`
//!     (`ban` only as those two attributes).
//! * Builtins: `min(a, b, ...)`, `max(a, b, ...)` (two or more arguments),
//!   `abs`, `int([x])`, `float([x])`, `round(x[, ndigits])`, `pow(x, y)`.
//! * `math` (available in upstream's formula globals; the shipped
//!   `jail.conf` documents `math.exp`): `exp`, `log(x[, base])`, `log2`,
//!   `log10`, `sqrt`, `fabs`, `floor`, `ceil`, `trunc`, `pow`, and the
//!   constants `pi`, `e`, `tau`, `inf`, `nan`.
//!
//! # Deliberate differences from upstream
//!
//! * **Integers are `i64`.** Python ints are unbounded; any literal, result
//!   or conversion outside `i64` is an [`ExprError::Overflow`] instead of a
//!   bignum. Real ban times are far below this.
//! * The literal `-9223372036854775808` is rejected (the positive literal is
//!   out of range before the minus is applied); `i64::MIN` is still reachable
//!   as `-9223372036854775807-1`. Likewise, any expression whose evaluation
//!   needs an out-of-range intermediate is an error even if the final value
//!   would fit (`0 * 2**100`).
//! * **Unsupported Python** is an error rather than evaluated: strings,
//!   tuples/lists/dicts, subscripts, `lambda`, comprehensions, `is`/`in`,
//!   `@`, assignment expressions, complex numbers, keyword arguments,
//!   `pow(a, b, mod)`, the `random` module and any other global of
//!   `jail.py`. `1 < 2` etc. as a `str2seconds` *result* is rejected because
//!   [`Num`] has no boolean.
//! * Unknown names and wrong call arities in a formula are rejected when the
//!   [`BanTimeIncrement`] is built; Python only fails when evaluating the
//!   offending branch.
//! * Non-ASCII decimal digits are not treated as digits by the unit-rewrite
//!   regexes (Python would see them as digits but then fail to tokenize them
//!   in expressions anyway). `bantime.multipliers` entries with non-ASCII
//!   digits (accepted by Python's `int()`) are rejected. Non-ASCII text is
//!   fine inside `#` comments.
//! * Expressions are limited to 512 tokens and 100 nesting levels so that
//!   recursion depth is bounded.
//! * `seconds2str` of a finite float whose rounded unit count exceeds `i64`
//!   is an error (Python prints a bignum).

mod bantime;
mod error;
mod expr;
mod mytime;
mod num;

pub use bantime::{BanTimeIncrement, BanTimeOptions, DEFAULT_FORMULA};
pub use error::ExprError;
pub use mytime::{seconds2str, str2seconds};
pub use num::Num;
