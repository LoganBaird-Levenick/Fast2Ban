//! Error type mirroring the Python exceptions raised by upstream's config stack.
//!
//! `Display` output equals Python's `str(exception)` so that messages match
//! upstream's "Failed during configuration: ..." text.

use std::fmt;

use crate::pyutil::py_repr;

/// Maximum nesting of `%(name)s` interpolation (`configparser.MAX_INTERPOLATION_DEPTH`).
pub const MAX_INTERPOLATION_DEPTH: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// `configparser.NoSectionError`
    NoSection(String),
    /// `configparser.NoOptionError`
    NoOption { option: String, section: String },
    /// `configparser.InterpolationMissingOptionError`
    InterpolationMissingOption {
        option: String,
        section: String,
        rawval: String,
        reference: String,
    },
    /// `configparser.InterpolationDepthError`
    InterpolationDepth {
        option: String,
        section: String,
        rawval: String,
    },
    /// `configparser.InterpolationSyntaxError`
    InterpolationSyntax {
        option: String,
        section: String,
        msg: String,
    },
    /// `configparser.ParsingError` (collected, raised at end of file)
    Parsing {
        source: String,
        errors: Vec<(usize, String)>,
    },
    /// `configparser.MissingSectionHeaderError`
    MissingSectionHeader {
        source: String,
        lineno: usize,
        line: String,
    },
    /// `configparser.DuplicateSectionError`
    DuplicateSection {
        section: String,
        source: String,
        lineno: usize,
    },
    /// `configparser.DuplicateOptionError`
    DuplicateOption {
        section: String,
        option: String,
        source: String,
        lineno: usize,
    },
    /// `UnicodeDecodeError` while reading a config file.
    Decode { path: String },
    /// `ValueError` (also stands in for upstream `LookupError` messages).
    Value(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSection(s) => write!(f, "No section: {}", py_repr(s)),
            Self::NoOption { option, section } => {
                write!(
                    f,
                    "No option {} in section: {}",
                    py_repr(option),
                    py_repr(section)
                )
            }
            Self::InterpolationMissingOption {
                option,
                section,
                rawval,
                reference,
            } => write!(
                f,
                "Bad value substitution: option {} in section {} contains an interpolation key {} which is not a valid option name. Raw value: {}",
                py_repr(option),
                py_repr(section),
                py_repr(reference),
                py_repr(rawval)
            ),
            Self::InterpolationDepth {
                option,
                section,
                rawval,
            } => write!(
                f,
                "Recursion limit exceeded in value substitution: option {} in section {} contains an interpolation key which cannot be substituted in {} steps. Raw value: {}",
                py_repr(option),
                py_repr(section),
                MAX_INTERPOLATION_DEPTH,
                py_repr(rawval)
            ),
            Self::InterpolationSyntax { msg, .. } => f.write_str(msg),
            Self::Parsing { source, errors } => {
                write!(f, "Source contains parsing errors: {}", py_repr(source))?;
                for (n, line) in errors {
                    write!(f, "\n\t[line {n:2}]: {}", py_repr(line))?;
                }
                Ok(())
            }
            Self::MissingSectionHeader {
                source,
                lineno,
                line,
            } => write!(
                f,
                "File contains no section headers.\nfile: {}, line: {}\n{}",
                py_repr(source),
                lineno,
                py_repr(line)
            ),
            Self::DuplicateSection {
                section,
                source,
                lineno,
            } => write!(
                f,
                "While reading from {} [line {:2}]: section {} already exists",
                py_repr(source),
                lineno,
                py_repr(section)
            ),
            Self::DuplicateOption {
                section,
                option,
                source,
                lineno,
            } => write!(
                f,
                "While reading from {} [line {:2}]: option {} in section {} already exists",
                py_repr(source),
                lineno,
                py_repr(option),
                py_repr(section)
            ),
            Self::Decode { path } => write!(f, "Error decoding config file {}", py_repr(path)),
            Self::Value(m) => f.write_str(m),
        }
    }
}

impl ConfigError {
    /// Name of the Python exception class upstream raises for this error.
    pub fn py_class(&self) -> &'static str {
        match self {
            Self::NoSection(_) => "NoSectionError",
            Self::NoOption { .. } => "NoOptionError",
            Self::InterpolationMissingOption { .. } => "InterpolationMissingOptionError",
            Self::InterpolationDepth { .. } => "InterpolationDepthError",
            Self::InterpolationSyntax { .. } => "InterpolationSyntaxError",
            Self::Parsing { .. } => "ParsingError",
            Self::MissingSectionHeader { .. } => "MissingSectionHeaderError",
            Self::DuplicateSection { .. } => "DuplicateSectionError",
            Self::DuplicateOption { .. } => "DuplicateOptionError",
            Self::Decode { .. } => "UnicodeDecodeError",
            Self::Value(_) => "ValueError",
        }
    }

    /// Python `repr(exception)`: configparser errors repr to their message,
    /// a plain `ValueError` shows its class.
    pub fn py_repr(&self) -> String {
        match self {
            Self::Value(m) => format!("ValueError({})", py_repr(m)),
            other => other.to_string(),
        }
    }
}

impl std::error::Error for ConfigError {}

pub type Result<T> = std::result::Result<T, ConfigError>;
