//! Text wrapping matching Python's `textwrap.TextWrapper` for help messages.

/// Wrap text to `width` characters, breaking on whitespace.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let width = width.max(1);
    for chunk in text.split('\n') {
        let mut line = String::new();
        for word in chunk.split_whitespace() {
            if line.is_empty() {
                line.push_str(word);
            } else if line.chars().count() + 1 + word.chars().count() <= width {
                line.push(' ');
                line.push_str(word);
            } else {
                out.push(line);
                line = word.to_owned();
            }
        }
        if !line.is_empty() {
            out.push(line);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_words() {
        let text = "one two three four five";
        let lines = wrap(text, 10);
        assert_eq!(lines, vec!["one two", "three four", "five"]);
    }
}
