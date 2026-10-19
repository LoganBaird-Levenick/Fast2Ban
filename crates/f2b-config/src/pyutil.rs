//! Small helpers reproducing Python string/path semantics the config stack relies on.

/// `str.isspace` for a single char (Python's `\s` class).
pub fn is_py_space(c: char) -> bool {
    f2b_helpers::pychar::is_space(c)
}

/// `str.strip()`.
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

/// `str.rstrip()`.
pub fn py_rstrip(s: &str) -> &str {
    s.trim_end_matches(is_py_space)
}

/// `str.lstrip()`.
pub fn py_lstrip(s: &str) -> &str {
    s.trim_start_matches(is_py_space)
}

/// `repr(str)`.
pub fn py_repr(s: &str) -> String {
    f2b_helpers::pychar::repr_str(s)
}

/// Python `int(str)` for the forms a config can contain (surrounding
/// whitespace, optional sign, ASCII digits with single `_` separators).
pub fn py_int(s: &str) -> Option<i64> {
    let t = py_strip(s);
    let (neg, digits) = match t.as_bytes().first()? {
        b'+' => (false, &t[1..]),
        b'-' => (true, &t[1..]),
        _ => (false, t),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return None;
    }
    let mut v: i64 = 0;
    for b in digits.bytes() {
        if b == b'_' {
            continue;
        }
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add(i64::from(b - b'0'))?;
    }
    Some(if neg { -v } else { v })
}

/// `os.path.isabs` (POSIX).
pub fn isabs(p: &str) -> bool {
    p.starts_with('/')
}

/// `os.path.join(a, b)` (POSIX, two arguments).
pub fn join(a: &str, b: &str) -> String {
    if b.starts_with('/') || a.is_empty() {
        b.to_owned()
    } else if a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

/// `os.path.dirname` (POSIX).
pub fn dirname(p: &str) -> &str {
    let i = p.rfind('/').map_or(0, |i| i + 1);
    let head = &p[..i];
    if !head.is_empty() && head.bytes().any(|b| b != b'/') {
        head.trim_end_matches('/')
    } else {
        head
    }
}

/// `os.path.splitext(p)[0]` (POSIX): drops the last extension of the final
/// path component; a leading dot of the component is not an extension.
pub fn splitext_root(p: &str) -> &str {
    let sep = p.rfind('/').map_or(0, |i| i + 1);
    let base = &p[sep..];
    let Some(dot) = base.rfind('.') else {
        return p;
    };
    // only dots at the start of the component ("..x", ".x") do not count
    if base[..dot].bytes().all(|b| b == b'.') {
        return p;
    }
    &p[..sep + dot]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repr_escapes_non_printable_like_python() {
        // BOM (U+FEFF) is not printable: Python shows it as \ufeff
        assert_eq!(py_repr("\u{feff}[x]\n"), "'\\ufeff[x]\\n'");
    }

    #[test]
    fn splitext_semantics() {
        assert_eq!(splitext_root("jail.d/a.conf"), "jail.d/a");
        assert_eq!(splitext_root("a.b.conf"), "a.b");
        assert_eq!(splitext_root("dir.x/file"), "dir.x/file");
        assert_eq!(splitext_root(".hidden"), ".hidden");
        assert_eq!(splitext_root("x"), "x");
    }

    #[test]
    fn int_forms() {
        assert_eq!(py_int(" 5 "), Some(5));
        assert_eq!(py_int("1_0"), Some(10));
        assert_eq!(py_int("-3"), Some(-3));
        assert_eq!(py_int("1__0"), None);
        assert_eq!(py_int("x"), None);
        assert_eq!(py_int(""), None);
    }

    #[test]
    fn dirname_semantics() {
        assert_eq!(dirname("/etc/fail2ban/jail.conf"), "/etc/fail2ban");
        assert_eq!(dirname("jail.conf"), "");
        assert_eq!(dirname("/jail.conf"), "/");
    }
}
