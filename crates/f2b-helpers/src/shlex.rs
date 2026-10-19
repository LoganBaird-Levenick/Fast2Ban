//! Python's `shlex.split(s)` (POSIX mode, no comment handling).

use std::fmt;

/// Error of [`shlex_split`]; `Display` is the message of Python's `ValueError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShlexError {
    /// `No closing quotation`
    NoClosingQuotation,
    /// `No escaped character` (input ends right after a backslash)
    NoEscapedCharacter,
}

impl fmt::Display for ShlexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoClosingQuotation => "No closing quotation",
            Self::NoEscapedCharacter => "No escaped character",
        })
    }
}

impl std::error::Error for ShlexError {}

#[derive(Clone, Copy)]
enum State {
    /// Between tokens.
    Space,
    /// Inside a token, outside quotes.
    Word,
    /// Inside the given quote character.
    Quote(char),
    /// After a backslash; `Some(q)` when it appeared inside the double quote `q`.
    Escape(Option<char>),
}

/// `shlex.split(s)` as used for `journalmatch`: `shlex(s, posix=True)` with
/// `whitespace_split=True` and `commenters=''`.
///
/// Tokens are separated by space, tab, CR and LF only. Outside quotes a backslash
/// escapes the next character (including a newline, which is kept). Inside single
/// quotes everything is literal; inside double quotes a backslash only escapes `"`
/// and `\`, otherwise it is kept. A quoted empty string yields an empty token.
///
/// The `shlex` crate is deliberately not used: it differs from Python (it treats `#`
/// as a comment, drops backslash-newline and removes backslashes before arbitrary
/// characters in double quotes).
///
/// # Errors
/// [`ShlexError`] for an unterminated quote or a trailing backslash.
pub fn shlex_split(s: &str) -> Result<Vec<String>, ShlexError> {
    let mut out = Vec::new();
    let mut token = String::new();
    let mut state = State::Space;
    for c in s.chars() {
        state = match state {
            State::Space | State::Word => match c {
                ' ' | '\t' | '\r' | '\n' => {
                    if matches!(state, State::Word) {
                        out.push(std::mem::take(&mut token));
                    }
                    State::Space
                }
                '\\' => State::Escape(None),
                '\'' | '"' => State::Quote(c),
                _ => {
                    token.push(c);
                    State::Word
                }
            },
            State::Quote(q) => {
                if c == q {
                    State::Word
                } else if c == '\\' && q == '"' {
                    State::Escape(Some(q))
                } else {
                    token.push(c);
                    state
                }
            }
            State::Escape(None) => {
                token.push(c);
                State::Word
            }
            State::Escape(Some(q)) => {
                // Only the quote itself and the backslash can be escaped in quotes.
                if c != '\\' && c != q {
                    token.push('\\');
                }
                token.push(c);
                State::Quote(q)
            }
        };
    }
    match state {
        State::Space => {}
        State::Word => out.push(token),
        State::Quote(_) => return Err(ShlexError::NoClosingQuotation),
        State::Escape(_) => return Err(ShlexError::NoEscapedCharacter),
    }
    Ok(out)
}
