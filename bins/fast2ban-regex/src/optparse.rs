//! A port of the parts of Python's `optparse` that upstream's `fail2ban-regex`
//! relies on: option strings, abbreviations of long options, combined short
//! flags, `--opt=value`, interspersed positionals, typed (`int`) values with
//! `optparse`'s radix guessing, built-in `--version`/`-h`, error messages and
//! the `IndentedHelpFormatter` help layout.

use std::collections::HashMap;

use crate::pyrepr::repr;
use crate::textwrap::wrap;

/// What an option does when seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// `store` (takes a value of the option's type).
    Store,
    StoreTrue,
    StoreFalse,
    Count,
    /// `-h/--help`: print the full help and exit 0.
    Help,
    /// `--version`: print `<prog> <version>` and exit 0.
    Version,
    /// `-V`: print the machine-readable version and exit 0.
    NormVersion,
}

/// Value type of a `Store` option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty {
    Str,
    Int,
}

/// A stored option value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
}

/// One option definition.
#[derive(Clone, Debug)]
pub struct Spec {
    pub short: Vec<&'static str>,
    pub long: Vec<&'static str>,
    pub action: Action,
    pub ty: Option<Ty>,
    pub dest: Option<&'static str>,
    pub default: Option<Value>,
    pub help: &'static str,
}

impl Spec {
    fn takes_value(&self) -> bool {
        self.ty.is_some()
    }

    fn metavar(&self) -> String {
        self.dest.unwrap_or_default().to_uppercase()
    }
}

/// Parsed option values by `dest`.
#[derive(Clone, Debug, Default)]
pub struct Values(HashMap<&'static str, Value>);

impl Values {
    pub fn str(&self, dest: &str) -> Option<&str> {
        match self.0.get(dest) {
            Some(Value::Str(s)) => Some(s),
            _ => None,
        }
    }

    pub fn int(&self, dest: &str) -> Option<i64> {
        match self.0.get(dest) {
            Some(Value::Int(i)) => Some(*i),
            _ => None,
        }
    }

    /// Truthiness of a boolean (`store_true`/`store_false`) option.
    pub fn flag(&self, dest: &str) -> bool {
        matches!(self.0.get(dest), Some(Value::Bool(true)))
    }
}

/// Result of parsing a command line.
#[derive(Debug)]
pub enum Parsed {
    /// Parsing went through: values and positional arguments.
    Run(Values, Vec<String>),
    /// Parsing ended the program (help, version, usage error).
    Exit {
        code: i32,
        stdout: String,
        stderr: String,
    },
}

/// The parser: option table plus program texts.
pub struct Parser {
    specs: Vec<Spec>,
    /// `argv[0]` as given (appears in the usage line).
    argv0: String,
    version: String,
    norm_version: String,
    /// Complete help text for `-h` (upstream's overridden `format_help`).
    help: Box<dyn Fn(&Parser) -> String>,
    usage_line: String,
    long_index: Vec<(&'static str, usize)>,
    short_index: Vec<(&'static str, usize)>,
}
impl std::fmt::Debug for Parser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parser")
            .field("specs", &self.specs)
            .field("argv0", &self.argv0)
            .finish_non_exhaustive()
    }
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

impl Parser {
    pub fn new(
        specs: Vec<Spec>,
        argv0: &str,
        usage_line: String,
        version: &str,
        norm_version: &str,
        help: Box<dyn Fn(&Parser) -> String>,
    ) -> Self {
        let mut long_index = Vec::new();
        let mut short_index = Vec::new();
        for (i, s) in specs.iter().enumerate() {
            long_index.extend(s.long.iter().map(|l| (*l, i)));
            short_index.extend(s.short.iter().map(|l| (*l, i)));
        }
        Self {
            specs,
            argv0: argv0.to_owned(),
            version: version.to_owned(),
            norm_version: norm_version.to_owned(),
            help,
            usage_line,
            long_index,
            short_index,
        }
    }

    /// `os.path.basename(sys.argv[0])`.
    pub fn prog(&self) -> &str {
        basename(&self.argv0)
    }

    /// `Option` table (for help rendering).
    pub fn specs(&self) -> &[Spec] {
        &self.specs
    }
    /// `format_help()`
    pub fn format_help(&self) -> String {
        (self.help)(self)
    }

    fn error(&self, msg: &str) -> Parsed {
        Parsed::Exit {
            code: 2,
            stdout: String::new(),
            stderr: format!(
                "Usage: {}\n\n{}: error: {}\n",
                self.usage_line,
                self.prog(),
                msg
            ),
        }
    }

    fn defaults(&self) -> Values {
        let mut v = Values::default();
        for s in &self.specs {
            if let (Some(dest), Some(d)) = (s.dest, &s.default) {
                v.0.insert(dest, d.clone());
            }
        }
        v
    }

    fn match_long(&self, s: &str) -> Result<usize, String> {
        if let Some((_, i)) = self.long_index.iter().find(|(l, _)| *l == s) {
            return Ok(*i);
        }
        let mut poss: Vec<&str> = self
            .long_index
            .iter()
            .filter(|(l, _)| l.starts_with(s))
            .map(|(l, _)| *l)
            .collect();
        match poss.len() {
            0 => Err(format!("no such option: {s}")),
            1 => Ok(self
                .long_index
                .iter()
                .find(|(l, _)| *l == poss[0])
                .map_or(0, |(_, i)| *i)),
            _ => {
                poss.sort_unstable();
                Err(format!("ambiguous option: {s} ({}?)", poss.join(", ")))
            }
        }
    }

    /// Applies one option occurrence. `Err` carries a parse-ending result.
    fn process(
        &self,
        idx: usize,
        opt: &str,
        value: Option<String>,
        values: &mut Values,
    ) -> Result<(), Parsed> {
        let spec = &self.specs[idx];
        let dest = spec.dest.unwrap_or_default();
        match spec.action {
            Action::Store => {
                let raw = value.unwrap_or_default();
                let v = match spec.ty {
                    Some(Ty::Int) => match parse_int(&raw) {
                        Some(i) => Value::Int(i),
                        None => {
                            return Err(self.error(&format!(
                                "option {opt}: invalid integer value: {}",
                                repr(&raw)
                            )));
                        }
                    },
                    _ => Value::Str(raw),
                };
                values.0.insert(dest, v);
            }
            Action::StoreTrue => {
                values.0.insert(dest, Value::Bool(true));
            }
            Action::StoreFalse => {
                values.0.insert(dest, Value::Bool(false));
            }
            Action::Count => {
                let n = values.int(dest).unwrap_or(0);
                values.0.insert(dest, Value::Int(n.saturating_add(1)));
            }
            Action::Help => {
                return Err(Parsed::Exit {
                    code: 0,
                    stdout: (self.help)(self),
                    stderr: String::new(),
                });
            }
            Action::Version => {
                return Err(Parsed::Exit {
                    code: 0,
                    stdout: format!("{} {}\n", self.prog(), self.version),
                    stderr: String::new(),
                });
            }
            Action::NormVersion => {
                return Err(Parsed::Exit {
                    code: 0,
                    stdout: format!("{}\n", self.norm_version),
                    stderr: String::new(),
                });
            }
        }
        Ok(())
    }

    /// `OptionParser.parse_args(args)`.
    pub fn parse(&self, args: &[String]) -> Parsed {
        let mut values = self.defaults();
        let mut largs: Vec<String> = Vec::new();
        let mut rargs: std::collections::VecDeque<String> = args.iter().cloned().collect();
        let res: Result<(), Parsed> = (|| {
            while let Some(arg) = rargs.front() {
                if arg == "--" {
                    rargs.pop_front();
                    return Ok(());
                } else if arg.starts_with("--") {
                    self.process_long(&mut rargs, &mut values)?;
                } else if arg.starts_with('-') && arg.chars().count() > 1 {
                    self.process_short(&mut rargs, &mut values)?;
                } else if let Some(a) = rargs.pop_front() {
                    largs.push(a);
                }
            }
            Ok(())
        })();
        if let Err(p) = res {
            return p;
        }
        largs.extend(rargs);
        Parsed::Run(values, largs)
    }

    fn requires_arg(&self, opt: &str) -> Parsed {
        self.error(&format!("{opt} option requires 1 argument"))
    }

    fn process_long(
        &self,
        rargs: &mut std::collections::VecDeque<String>,
        values: &mut Values,
    ) -> Result<(), Parsed> {
        let arg = rargs.pop_front().unwrap_or_default();
        let (opt, had_value) = match arg.split_once('=') {
            Some((o, rest)) => {
                rargs.push_front(rest.to_owned());
                (o.to_owned(), true)
            }
            None => (arg, false),
        };
        let idx = self.match_long(&opt).map_err(|m| self.error(&m))?;
        let canon = self
            .long_index
            .iter()
            .find(|(_, i)| *i == idx && (opt == **l_of(self, idx, &opt) || true))
            .map_or("", |(l, _)| *l);
        // the canonical long option string the abbreviation matched
        let canon = self.canonical(&opt, canon);
        let spec = &self.specs[idx];
        let value = if spec.takes_value() {
            match rargs.pop_front() {
                Some(v) => Some(v),
                None => return Err(self.requires_arg(&canon)),
            }
        } else if had_value {
            return Err(self.error(&format!("{canon} option does not take a value")));
        } else {
            None
        };
        self.process(idx, &canon, value, values)
    }

    /// The registered long option string `opt` stands for.
    fn canonical(&self, opt: &str, _fallback: &str) -> String {
        if let Some((l, _)) = self.long_index.iter().find(|(l, _)| *l == opt) {
            return (*l).to_owned();
        }
        self.long_index
            .iter()
            .find(|(l, _)| l.starts_with(opt))
            .map_or_else(|| opt.to_owned(), |(l, _)| (*l).to_owned())
    }

    fn process_short(
        &self,
        rargs: &mut std::collections::VecDeque<String>,
        values: &mut Values,
    ) -> Result<(), Parsed> {
        let arg = rargs.pop_front().unwrap_or_default();
        let chars: Vec<char> = arg.chars().collect();
        let mut i = 1;
        let mut stop = false;
        for ch in &chars[1..] {
            let opt = format!("-{ch}");
            i += 1;
            let Some((_, idx)) = self.short_index.iter().find(|(s, _)| *s == opt) else {
                return Err(self.error(&format!("no such option: {opt}")));
            };
            let spec = &self.specs[*idx];
            let value = if spec.takes_value() {
                if i < chars.len() {
                    rargs.push_front(chars[i..].iter().collect());
                    stop = true;
                }
                match rargs.pop_front() {
                    Some(v) => Some(v),
                    None => return Err(self.requires_arg(&opt)),
                }
            } else {
                None
            };
            self.process(*idx, &opt, value, values)?;
            if stop {
                break;
            }
        }
        Ok(())
    }

    /// `HelpFormatter` width: `$COLUMNS - 2`, default 78.
    fn width(columns: Option<&str>) -> usize {
        let c = columns
            .and_then(|c| parse_int_radix(c, 10))
            .map_or(80, |c| c.max(i64::MIN / 2));
        usize::try_from(c - 2).unwrap_or(0)
    }

    /// `OptionParser.format_option_help` (the `Options:` block).
    pub fn format_option_help(&self, columns: Option<&str>) -> String {
        let width = Self::width(columns);
        let indent = 2usize;
        let max_help_position = 24.min(width.saturating_sub(20).max(indent * 2));
        let strings: Vec<String> = self.specs.iter().map(option_strings).collect();
        let max_len = strings
            .iter()
            .map(|s| s.chars().count() + indent)
            .max()
            .unwrap_or(0);
        let help_position = (max_len + 2).min(max_help_position);
        let help_width = width.saturating_sub(help_position).max(11);
        let mut out = String::from("Options:\n");
        let opt_width = help_position.saturating_sub(indent + 2);
        for (spec, opts) in self.specs.iter().zip(&strings) {
            let mut line = String::new();
            let indent_first = if opts.chars().count() > opt_width {
                line.push_str(&format!("{:indent$}{opts}\n", ""));
                help_position
            } else {
                line.push_str(&format!("{:indent$}{opts:<opt_width$}  ", ""));
                0
            };
            if spec.help.is_empty() {
                if !line.ends_with('\n') {
                    line.push('\n');
                }
            } else {
                let lines = wrap(spec.help, help_width);
                if let Some(first) = lines.first() {
                    line.push_str(&format!("{:indent_first$}{first}\n", ""));
                }
                for l in lines.iter().skip(1) {
                    line.push_str(&format!("{:help_position$}{l}\n", ""));
                }
            }
            out.push_str(&line);
        }
        out
    }
}

fn l_of<'a>(_p: &'a Parser, _idx: usize, opt: &'a str) -> &'a &'a str {
    // helper kept trivial: canonical string is resolved in `canonical`
    &*Box::leak(Box::new(opt))
}

/// `HelpFormatter.format_option_strings`.
fn option_strings(spec: &Spec) -> String {
    let mut opts: Vec<String> = Vec::new();
    if spec.takes_value() {
        let mv = spec.metavar();
        opts.extend(spec.short.iter().map(|s| format!("{s} {mv}")));
        opts.extend(spec.long.iter().map(|l| format!("{l}={mv}")));
    } else {
        opts.extend(spec.short.iter().map(|s| (*s).to_owned()));
        opts.extend(spec.long.iter().map(|l| (*l).to_owned()));
    }
    opts.join(", ")
}

/// Python `int(text, radix)` (whitespace, sign, `_` separators, matching
/// radix prefix).
pub fn parse_int_radix(text: &str, radix: u32) -> Option<i64> {
    let t = text.trim_matches(f2b_helpers::pychar::is_space);
    let (neg, rest) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let lower = rest.to_ascii_lowercase();
    let prefix = match radix {
        16 => "0x",
        8 => "0o",
        2 => "0b",
        _ => "",
    };
    let mut digits = rest;
    if !prefix.is_empty() && lower.starts_with(prefix) {
        digits = &rest[2..];
        // a prefix must be followed by a digit (an `_` may separate them)
        digits = digits.strip_prefix('_').unwrap_or(digits);
    }
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return None;
    }
    let mut v: i128 = 0;
    for c in digits.chars().filter(|c| *c != '_') {
        let d = c.to_digit(radix)?;
        v = v * i128::from(radix) + i128::from(d);
        if v > i128::from(i64::MAX) + 1 {
            return None;
        }
    }
    let v = if neg { -v } else { v };
    i64::try_from(v).ok()
}

/// `optparse._parse_int`: guesses the radix from the prefix.
pub fn parse_int(val: &str) -> Option<i64> {
    let l2: String = val.chars().take(2).collect::<String>().to_lowercase();
    if l2 == "0x" {
        parse_int_radix(val, 16)
    } else if l2 == "0b" {
        let rest: String = val.chars().skip(2).collect();
        let rest = if rest.is_empty() {
            "0".to_owned()
        } else {
            rest
        };
        parse_int_radix(&rest, 2)
    } else if val.starts_with('0') {
        parse_int_radix(val, 8)
    } else {
        parse_int_radix(val, 10)
    }
}
