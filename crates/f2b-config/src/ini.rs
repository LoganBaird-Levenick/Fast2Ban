//! Port of Python 3.14 `configparser.ConfigParser` as configured by upstream's
//! `SafeConfigParserWithIncludes` (`fail2ban/client/configparserinc.py`):
//!
//! * `strict=True`, `empty_lines_in_values=True`, delimiters `=` and `:`,
//!   full-line comments `#`/`;`, inline comments `;` (after whitespace),
//!   option names lowercased, section names case sensitive;
//! * `BasicInterpolation` (`%(name)s`, `%%`) extended with `__name__` and
//!   `%(section/option)s` / `%(known/option)s` lookups;
//! * `[INCLUDES] before/after`, automatic `.local` overrides, conditional
//!   sections (`[Init?family=inet6]` => options `key?family=inet6`) and the
//!   `KNOWN/<section>` shadow sections remembering overridden values.

use std::collections::HashSet;
use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::Regex;

use crate::error::{ConfigError, MAX_INTERPOLATION_DEPTH, Result};
use crate::fs::Fs;
use crate::pyutil::{
    dirname, is_py_space, isabs, join, py_repr, py_rstrip, py_strip, splitext_root,
};

pub type Section = IndexMap<String, String>;

pub const DEFAULT_SECTION: &str = "DEFAULT";
/// Name of the include section.
pub const INCLUDES_SECTION: &str = "INCLUDES";

/// `SECTION_OPTNAME_CRE`
static SECTION_OPTNAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([\w\-]+)/([^\s>]+)$").expect("static regex"));
/// `SECTION_OPTSUBST_CRE`
static SECTION_OPTSUBST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"%\(([\w\-]+/([^\)]+))\)s").expect("static regex"));
/// `CONDITIONAL_RE`
static CONDITIONAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\w+)(\?.+)$").expect("static regex"));
/// `BasicInterpolation._KEYCRE`
static KEYCRE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^%\(([^)]+)\)s").expect("static regex"));

/// Splits `name?cond` option/section names: `("name", "?cond")`.
pub fn split_conditional(name: &str) -> Option<(&str, &str)> {
    let m = CONDITIONAL.captures(name)?;
    Some((m.get(1)?.as_str(), m.get(2)?.as_str()))
}

/// A parsed (and possibly merged) configuration.
#[derive(Debug, Default, Clone)]
pub struct Ini {
    defaults: Section,
    sections: IndexMap<String, Section>,
}

enum Cur {
    None,
    Default,
    Named(String),
}

impl Ini {
    pub fn new() -> Self {
        Self::default()
    }

    // ---------------------------------------------------------------- parsing

    /// Parse one file's text (`ConfigParser._read`).
    pub fn parse(source: &str, text: &str) -> Result<Self> {
        let mut raw_defaults: IndexMap<String, Vec<String>> = IndexMap::new();
        let mut raw_sections: IndexMap<String, IndexMap<String, Vec<String>>> = IndexMap::new();
        let mut added_sections: HashSet<String> = HashSet::new();
        let mut added_options: HashSet<(String, String)> = HashSet::new();
        let mut cursect = Cur::None;
        let mut sectname = String::new();
        let mut optname = String::new(); // empty == Python falsy/None
        let mut indent_level = 0usize;
        let mut errors: Vec<(usize, String)> = Vec::new();

        for (idx, (raw, had_nl)) in split_universal(text).into_iter().enumerate() {
            let lineno = idx + 1;
            let trimmed = py_strip(raw);
            let clean = strip_comments(trimmed);
            let has_comments = trimmed != clean;

            if clean.is_empty() {
                if !has_comments && !optname.is_empty() {
                    if let Some(list) =
                        current_list(&cursect, &mut raw_defaults, &mut raw_sections, &optname)
                    {
                        list.push(String::new());
                    }
                }
                continue;
            }

            let cur_indent = raw.chars().take_while(|&c| is_py_space(c)).count();

            // continuation line?
            if !matches!(cursect, Cur::None) && !optname.is_empty() && cur_indent > indent_level {
                if let Some(list) =
                    current_list(&cursect, &mut raw_defaults, &mut raw_sections, &optname)
                {
                    list.push(clean.to_owned());
                }
                continue;
            }

            let raw_line = if had_nl {
                format!("{raw}\n")
            } else {
                raw.to_owned()
            };
            indent_level = cur_indent;

            if let Some(header) = section_header(clean) {
                sectname = header.to_owned();
                if raw_sections.contains_key(&sectname) {
                    if added_sections.contains(&sectname) {
                        return Err(ConfigError::DuplicateSection {
                            section: sectname,
                            source: source.to_owned(),
                            lineno,
                        });
                    }
                    cursect = Cur::Named(sectname.clone());
                    added_sections.insert(sectname.clone());
                } else if sectname == DEFAULT_SECTION {
                    cursect = Cur::Default;
                } else {
                    raw_sections.insert(sectname.clone(), IndexMap::new());
                    cursect = Cur::Named(sectname.clone());
                    added_sections.insert(sectname.clone());
                }
                optname.clear();
                continue;
            }
            if matches!(cursect, Cur::None) {
                return Err(ConfigError::MissingSectionHeader {
                    source: source.to_owned(),
                    lineno,
                    line: raw_line,
                });
            }

            // option line
            let Some((name, value)) = split_option(clean) else {
                errors.push((lineno, raw_line));
                continue;
            };
            if name.is_empty() {
                errors.push((lineno, raw_line));
            }
            optname = name.to_lowercase();
            let key = (sectname.clone(), optname.clone());
            if added_options.contains(&key) {
                return Err(ConfigError::DuplicateOption {
                    section: sectname,
                    option: optname,
                    source: source.to_owned(),
                    lineno,
                });
            }
            added_options.insert(key);
            let list = vec![value.to_owned()];
            match &cursect {
                Cur::Default => {
                    raw_defaults.insert(optname.clone(), list);
                }
                Cur::Named(n) => {
                    if let Some(sec) = raw_sections.get_mut(n) {
                        sec.insert(optname.clone(), list);
                    }
                }
                Cur::None => {}
            }
        }

        if !errors.is_empty() {
            return Err(ConfigError::Parsing {
                source: source.to_owned(),
                errors,
            });
        }

        let join_vals = |m: IndexMap<String, Vec<String>>| -> Section {
            m.into_iter()
                .map(|(k, v)| (k, py_rstrip(&v.join("\n")).to_owned()))
                .collect()
        };
        Ok(Self {
            defaults: join_vals(raw_defaults),
            sections: raw_sections
                .into_iter()
                .map(|(k, v)| (k, join_vals(v)))
                .collect(),
        })
    }

    // -------------------------------------------------------------- accessors

    /// `sections()`, including internal `KNOWN/...` sections.
    pub fn sections(&self) -> impl Iterator<Item = &str> {
        self.sections.keys().map(String::as_str)
    }

    pub fn has_section(&self, name: &str) -> bool {
        self.sections.contains_key(name)
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.get(name)
    }

    pub fn defaults(&self) -> &Section {
        &self.defaults
    }

    pub fn defaults_mut(&mut self) -> &mut Section {
        &mut self.defaults
    }

    /// Own option names of a section (`options(section, withDefault=False)`).
    pub fn options_own(&self, section: &str) -> Result<Vec<String>> {
        self.sections
            .get(section)
            .map(|s| s.keys().cloned().collect())
            .ok_or_else(|| ConfigError::NoSection(section.to_owned()))
    }

    /// `has_option(section, option)` (option lowercased, DEFAULT considered).
    pub fn has_option(&self, section: &str, option: &str) -> bool {
        let opt = option.to_lowercase();
        if section.is_empty() || section == DEFAULT_SECTION {
            self.defaults.contains_key(&opt)
        } else if let Some(s) = self.sections.get(section) {
            s.contains_key(&opt) || self.defaults.contains_key(&opt)
        } else {
            false
        }
    }

    /// `merge_section(section, options, pref)`: update (creating) a section.
    /// With a non-empty `pref`, option names are prefixed (except `__name__`
    /// and names already carrying the prefix).
    pub fn merge_section<'a>(
        &mut self,
        section: &str,
        options: impl IntoIterator<Item = (&'a str, &'a str)>,
        pref: &str,
    ) {
        let sec = self.sections.entry(section.to_owned()).or_default();
        for (k, v) in options {
            if pref.is_empty() {
                sec.insert(k.to_owned(), v.to_owned());
            } else if !k.starts_with(pref) && k != "__name__" {
                sec.insert(format!("{pref}{k}"), v.to_owned());
            }
        }
    }

    // ----------------------------------------------------------------- get

    /// `ConfigParser.get(section, option, vars=vars)` with upstream's
    /// interpolation. `vars` take priority over the section, which takes
    /// priority over `[DEFAULT]`; keys are lowercased like `_unify_values`.
    pub fn get(&self, section: &str, option: &str, raw: bool, vars: &Section) -> Result<String> {
        let chain = self.unify(section, vars)?;
        let option = option.to_lowercase();
        let Some(value) = chain.lookup(&option) else {
            return Err(ConfigError::NoOption {
                option,
                section: section.to_owned(),
            });
        };
        let value = value.clone();
        if raw {
            return Ok(value);
        }
        let mut out = String::new();
        self.interpolate_some(&option, &mut out, &value, section, &chain, 1)?;
        Ok(out)
    }

    /// `get_ex`: like [`Ini::get`], additionally resolving `section/option`
    /// names (`known/...` and `default/...` included).
    pub fn get_ex(&self, section: &str, option: &str, raw: bool, vars: &Section) -> Result<String> {
        if option.contains('/') {
            if let Some(m) = SECTION_OPTNAME.captures(option) {
                let (sec, opt) = (&m[1], &m[2]);
                let lwr = sec.to_lowercase();
                let candidates: Vec<String> = if lwr == "known" {
                    vec![format!("KNOWN/{section}"), section.to_owned()]
                } else if lwr == "default" {
                    vec![DEFAULT_SECTION.to_owned()]
                } else {
                    vec![sec.to_owned()]
                };
                for sec in candidates {
                    match self.get(&sec, opt, raw, &Section::new()) {
                        Ok(v) => return Ok(v),
                        Err(ConfigError::NoSection(_) | ConfigError::NoOption { .. }) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        self.get(section, option, raw, vars)
    }

    fn unify<'a>(&'a self, section: &str, vars: &Section) -> Result<Chain<'a>> {
        let sect = match self.sections.get(section) {
            Some(s) => Some(s),
            None if section == DEFAULT_SECTION => None,
            None => return Err(ConfigError::NoSection(section.to_owned())),
        };
        Ok(Chain {
            first: vars
                .iter()
                .map(|(k, v)| (k.to_lowercase(), v.clone()))
                .collect(),
            sect,
            defaults: &self.defaults,
        })
    }

    /// `parser.get(section, option, raw=True, fallback=rest)` (error text only).
    fn raw_or(&self, section: &str, option: &str, fallback: &str) -> String {
        let opt = option.to_lowercase();
        self.sections
            .get(section)
            .and_then(|s| s.get(&opt))
            .or_else(|| self.defaults.get(&opt))
            .cloned()
            .unwrap_or_else(|| fallback.to_owned())
    }

    /// `BasicInterpolationWithName._interpolate_some` over
    /// `BasicInterpolation._interpolate_some`.
    fn interpolate_some(
        &self,
        option: &str,
        accum: &mut String,
        rest: &str,
        section: &str,
        map: &Chain<'_>,
        depth: usize,
    ) -> Result<()> {
        // Work on a copy of the lookup chain, extended like upstream does.
        let mut map = map.clone();
        map.first.insert("__name__".to_owned(), section.to_owned());
        self.map_section_options(section, rest, &mut map);

        let rawval = self.raw_or(section, option, rest);
        if depth > MAX_INTERPOLATION_DEPTH {
            return Err(ConfigError::InterpolationDepth {
                option: option.to_owned(),
                section: section.to_owned(),
                rawval,
            });
        }
        let mut rest = rest;
        while !rest.is_empty() {
            let Some(p) = rest.find('%') else {
                accum.push_str(rest);
                return Ok(());
            };
            if p > 0 {
                accum.push_str(&rest[..p]);
                rest = &rest[p..];
            }
            match rest.as_bytes().get(1) {
                Some(b'%') => {
                    accum.push('%');
                    rest = &rest[2..];
                }
                Some(b'(') => {
                    let Some(m) = KEYCRE.captures(rest) else {
                        return Err(ConfigError::InterpolationSyntax {
                            option: option.to_owned(),
                            section: section.to_owned(),
                            msg: format!("bad interpolation variable reference {}", py_repr(rest)),
                        });
                    };
                    let var = m[1].to_lowercase();
                    let end = m.get(0).map_or(0, |g| g.end());
                    rest = &rest[end..];
                    let Some(v) = map.lookup(&var) else {
                        return Err(ConfigError::InterpolationMissingOption {
                            option: option.to_owned(),
                            section: section.to_owned(),
                            rawval,
                            reference: var,
                        });
                    };
                    if v.contains('%') {
                        let v = v.clone();
                        self.interpolate_some(option, accum, &v, section, &map, depth + 1)?;
                    } else {
                        accum.push_str(v);
                    }
                }
                _ => {
                    return Err(ConfigError::InterpolationSyntax {
                        option: option.to_owned(),
                        section: section.to_owned(),
                        msg: format!(
                            "'%' must be followed by '%' or '(', found: {}",
                            py_repr(rest)
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// `_map_section_options`: make `%(section/option)s` references resolvable
    /// by copying the *raw* referenced values into the lookup chain.
    fn map_section_options(&self, section: &str, rest: &str, map: &mut Chain<'_>) {
        if !rest.contains('/') || !rest.contains("%(") {
            return;
        }
        for m in SECTION_OPTSUBST.captures_iter(rest) {
            let (sopt, opt) = (&m[1], &m[2]);
            if map.contains(sopt) {
                continue;
            }
            let sec = &sopt[..sopt.len() - opt.len() - 1];
            let seclwr = sec.to_lowercase();
            let mut usedef = false;
            let mut v: Option<&String> = None;
            if seclwr == "default" {
                usedef = true;
            } else if seclwr == "known" {
                match self
                    .sections
                    .get(&format!("KNOWN/{section}"))
                    .and_then(|s| s.get(opt))
                {
                    Some(x) => v = Some(x),
                    None => usedef = true,
                }
            } else {
                // a missing section is ignored (no replacement at all)
                let Some(secmap) = self.sections.get(sec) else {
                    continue;
                };
                match secmap.get(opt) {
                    Some(x) => v = Some(x),
                    None => usedef = true,
                }
            }
            if usedef {
                match self.defaults.get(opt) {
                    Some(x) => v = Some(x),
                    None => continue,
                }
            }
            if let Some(v) = v {
                map.first.insert(sopt.to_owned(), v.clone());
            }
        }
    }

    // ------------------------------------------------------- reading + includes

    /// `SafeConfigParserWithIncludes.read(filenames)`: resolve includes and
    /// `.local` overrides, then merge every file in order. Returns the files
    /// that were read.
    pub fn read(&mut self, fs: &dyn Fs, filenames: &[String]) -> Result<Vec<String>> {
        let full = get_includes(fs, filenames, &[])?;
        let mut ret = Vec::new();
        for filename in full {
            let Some(cfg) = read_single(fs, &filename)? else {
                continue;
            };
            ret.push(filename);
            self.merge(cfg);
        }
        Ok(ret)
    }

    fn merge(&mut self, cfg: Ini) {
        for (k, v) in cfg.defaults {
            self.defaults.insert(k, v);
        }
        for (n, s) in cfg.sections {
            let (n, s) = match split_conditional(&n) {
                Some((base, cond)) => {
                    let renamed: Section = s
                        .into_iter()
                        .filter(|(k, _)| k != "__name__")
                        .map(|(k, v)| (format!("{k}{cond}"), v))
                        .collect();
                    (base.to_owned(), renamed)
                }
                None => (n, s),
            };
            if let Some(existing) = self.sections.get(&n) {
                // remember values about to be overridden, for `known/...` lookups
                let known: Vec<(String, String)> = existing
                    .iter()
                    .filter(|(k, _)| s.contains_key(*k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let ksec = self.sections.entry(format!("KNOWN/{n}")).or_default();
                for (k, v) in known {
                    ksec.insert(k, v);
                }
                if let Some(existing) = self.sections.get_mut(&n) {
                    for (k, v) in s {
                        existing.insert(k, v);
                    }
                }
            } else {
                self.sections.insert(n, s);
            }
        }
    }
}

/// Lookup chain `ChainMap(vars+extras, section, defaults)`.
#[derive(Clone)]
struct Chain<'a> {
    first: Section,
    sect: Option<&'a Section>,
    defaults: &'a Section,
}

impl Chain<'_> {
    fn lookup(&self, key: &str) -> Option<&String> {
        self.first
            .get(key)
            .or_else(|| self.sect.and_then(|s| s.get(key)))
            .or_else(|| self.defaults.get(key))
    }

    fn contains(&self, key: &str) -> bool {
        self.lookup(key).is_some()
    }
}

fn current_list<'a>(
    cur: &Cur,
    defaults: &'a mut IndexMap<String, Vec<String>>,
    sections: &'a mut IndexMap<String, IndexMap<String, Vec<String>>>,
    optname: &str,
) -> Option<&'a mut Vec<String>> {
    match cur {
        Cur::None => None,
        Cur::Default => defaults.get_mut(optname),
        Cur::Named(n) => sections.get_mut(n).and_then(|s| s.get_mut(optname)),
    }
}

/// Lines with universal-newline translation (`\n`, `\r\n`, `\r`), each paired
/// with whether a terminator followed it.
fn split_universal(text: &str) -> Vec<(&str, bool)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                out.push((&text[start..i], true));
                i += 1;
                start = i;
            }
            b'\r' => {
                out.push((&text[start..i], true));
                i += if bytes.get(i + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < text.len() {
        out.push((&text[start..], false));
    }
    out
}

/// `_CommentSpec.strip` for full prefixes `#`/`;` and inline prefix `;`
/// (input already stripped).
fn strip_comments(trimmed: &str) -> &str {
    if trimmed.starts_with('#') || trimmed.starts_with(';') {
        return "";
    }
    let mut prev_space = false;
    for (i, c) in trimmed.char_indices() {
        if c == ';' && prev_space {
            // the whitespace char before ';' is consumed by the pattern too
            let cut = trimmed[..i]
                .char_indices()
                .next_back()
                .map_or(0, |(j, _)| j);
            return py_rstrip(&trimmed[..cut]);
        }
        prev_space = is_py_space(c);
    }
    py_rstrip(trimmed)
}

/// `SECTCRE.match`: `[` + anything + the *last* `]` (at least one char between).
fn section_header(clean: &str) -> Option<&str> {
    let rest = clean.strip_prefix('[')?;
    let close = rest.rfind(']')?;
    (close > 0).then(|| &rest[..close])
}

/// `OPTCRE.match`: `(option)\s*[=:]\s*(value)` with the earliest delimiter.
fn split_option(clean: &str) -> Option<(&str, &str)> {
    let p = clean.find(['=', ':'])?;
    Some((py_rstrip(&clean[..p]), py_strip(&clean[p + 1..])))
}

/// Parse a single file into a fresh `Ini`. `Ok(None)` when the file cannot be
/// opened (upstream silently skips those).
fn read_single(fs: &dyn Fs, path: &str) -> Result<Option<Ini>> {
    match fs.read_to_string(path) {
        Ok(text) => Ini::parse(path, &text).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => Err(ConfigError::Decode {
            path: path.to_owned(),
        }),
        Err(_) => Ok(None),
    }
}

/// `_expandConfFilesWithLocal`
fn expand_with_local(fs: &dyn Fs, filenames: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for f in filenames {
        out.push(f.clone());
        let local = format!("{}.local", splitext_root(f));
        if !filenames.contains(&local) && fs.is_file(&local) {
            out.push(local);
        }
    }
    out
}

/// `_getIncludes`
fn get_includes(fs: &dyn Fs, filenames: &[String], seen: &[String]) -> Result<Vec<String>> {
    let mut full = Vec::new();
    for f in expand_with_local(fs, filenames) {
        full.extend(includes_of(fs, &f, seen)?);
    }
    Ok(full)
}

/// `__getIncludesUncached`: the file with its `before`/`after` includes.
fn includes_of(fs: &dyn Fs, resource: &str, seen: &[String]) -> Result<Vec<String>> {
    let parser = match read_single(fs, resource) {
        Ok(Some(p)) => p,
        // unreadable, or undecodable (upstream logs and returns [])
        Ok(None) | Err(ConfigError::Decode { .. }) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let dir = dirname(resource);
    let mut before = Vec::new();
    let mut after = Vec::new();
    if parser.has_section(INCLUDES_SECTION) {
        for (name, list) in [("before", &mut before), ("after", &mut after)] {
            let has = parser
                .section(INCLUDES_SECTION)
                .is_some_and(|s| s.contains_key(name))
                || parser.defaults.contains_key(name);
            if !has {
                continue;
            }
            let resources = parser.get(INCLUDES_SECTION, name, false, &Section::new())?;
            for new in resources.split('\n') {
                let r = if isabs(new) {
                    new.to_owned()
                } else {
                    join(dir, new)
                };
                if seen.contains(&r) {
                    continue;
                }
                let mut s = seen.to_vec();
                s.push(resource.to_owned());
                list.extend(get_includes(fs, &[r], &s)?);
            }
        }
    }
    let mut out = before;
    out.push(resource.to_owned());
    out.extend(after);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> Ini {
        Ini::parse("t.conf", text).expect("parse")
    }

    fn get(i: &Ini, s: &str, o: &str) -> String {
        i.get(s, o, false, &Section::new()).expect("get")
    }

    #[test]
    fn multiline_values_comments_and_blank_lines() {
        let i = p("[S]\na = x ; inline\n  # skipped\n  y\n\n  z\nb: 1\nc=http://h;x\n");
        assert_eq!(get(&i, "S", "a"), "x\ny\n\nz");
        assert_eq!(get(&i, "S", "b"), "1");
        // `;` not preceded by whitespace is part of the value
        assert_eq!(get(&i, "S", "c"), "http://h;x");
    }

    #[test]
    fn strict_duplicates_are_errors() {
        assert!(matches!(
            Ini::parse("t", "[S]\na=1\na=2\n"),
            Err(ConfigError::DuplicateOption { .. })
        ));
        assert!(matches!(
            Ini::parse("t", "[S]\n[S]\n"),
            Err(ConfigError::DuplicateSection { .. })
        ));
    }

    #[test]
    fn interpolation_defaults_escapes_and_depth() {
        let i = p("[DEFAULT]\nd = D\n[S]\na = %(d)s-%%-%(b)s\nb = B%(d)s\nr = %(r)s\n");
        assert_eq!(get(&i, "S", "a"), "D-%-BD");
        assert!(matches!(
            i.get("S", "r", false, &Section::new()),
            Err(ConfigError::InterpolationDepth { .. })
        ));
        assert!(matches!(
            p("[S]\na = %(nope)s\n").get("S", "a", false, &Section::new()),
            Err(ConfigError::InterpolationMissingOption { .. })
        ));
    }

    #[test]
    fn section_slash_option_reference() {
        let i = p("[lt_file]\nd = X\n[S]\na = %(lt_file/d)s!\n");
        assert_eq!(get(&i, "S", "a"), "X!");
    }

    #[test]
    fn vars_override_section() {
        let i = p("[S]\na = %(v)s\nv = sec\n");
        let mut vars = Section::new();
        vars.insert("V".into(), "var".into());
        assert_eq!(i.get("S", "a", false, &vars).unwrap(), "var");
    }

    #[test]
    fn universal_newlines() {
        let i = p("[S]\r\na = 1\rb = 2\r\n");
        assert_eq!(get(&i, "S", "a"), "1");
        assert_eq!(get(&i, "S", "b"), "2");
    }

    #[test]
    fn conditional_sections_and_known_shadow() {
        let mut m = Ini::new();
        m.merge(p("[Init]\nchain = INPUT\n"));
        m.merge(p(
            "[Init?family=inet6]\nchain = X\n[Init]\nchain = OUTPUT\n",
        ));
        let s = m.section("Init").unwrap();
        assert_eq!(s["chain"], "OUTPUT");
        assert_eq!(s["chain?family=inet6"], "X");
        assert_eq!(m.section("KNOWN/Init").unwrap()["chain"], "INPUT");
    }
}
