//! `json.dumps` of a flat string mapping with Python's defaults
//! (`ensure_ascii=True`, `", "` / `": "` separators).

use indexmap::IndexMap;

pub fn dumps_str_map(map: &IndexMap<String, String>) -> String {
    let mut out = String::from("{");
    for (i, (k, v)) in map.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        dumps_str(k, &mut out);
        out.push_str(": ");
        dumps_str(v, &mut out);
    }
    out.push('}');
    out
}

fn dumps_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_python_json_dumps() {
        let mut m = IndexMap::new();
        m.insert("a".to_owned(), "é\u{2603}\n\u{1}\u{7f}\"\\".to_owned());
        m.insert("b".to_owned(), "\u{1F600}".to_owned());
        assert_eq!(
            dumps_str_map(&m),
            r#"{"a": "\u00e9\u2603\n\u0001\u007f\"\\", "b": "\ud83d\ude00"}"#
        );
        assert_eq!(dumps_str_map(&IndexMap::new()), "{}");
    }
}
