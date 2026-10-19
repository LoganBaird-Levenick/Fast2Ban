//! Formats server responses for display (`fail2ban/client/beautifier.py`).

use crate::value::Value;

#[derive(Debug, Clone, Copy)]
pub struct Beautifier;

impl Beautifier {
    pub fn beautify(cmd: &[String], response: &Value) -> String {
        if cmd.is_empty() {
            return response.to_string();
        }

        let first = cmd[0].as_str();
        match first {
            "ping" => match response {
                Value::Str(s) => format!("Server replied: {s}"),
                other => format!("Server replied: {other}"),
            },
            "version" => match response {
                Value::Str(s) => s.clone(),
                other => other.to_string(),
            },
            "start" => "Jail started".to_owned(),
            "stop" => {
                if cmd.len() == 1 {
                    "Shutdown successful".to_owned()
                } else {
                    "Jail stopped".to_owned()
                }
            }
            "add" => match response {
                Value::Str(s) => format!("Added jail {s}"),
                other => format!("Added jail {other}"),
            },
            "flushlogs" => match response {
                Value::Str(s) => format!("logs: {s}"),
                other => format!("logs: {other}"),
            },
            "echo" => match response {
                Value::List(l) => l.iter().map(Value::to_string).collect::<Vec<_>>().join(" "),
                other => other.to_string(),
            },
            "status" => Self::beautify_status(cmd, response),
            _ => response.to_string(),
        }
    }

    fn beautify_status(cmd: &[String], response: &Value) -> String {
        let mut out = Vec::new();

        if cmd.len() > 1 && cmd[1] != "--all" {
            out.push(format!("Status for the jail: {}", cmd[1]));
            Self::format_jail_stat(response, "", &mut out);
        } else {
            out.push("Status".to_owned());
            if let Value::List(pairs) = response {
                for (n, pair) in pairs.iter().enumerate() {
                    let is_last = n == pairs.len() - 1;
                    let prefix = if is_last { "`-" } else { "|-" };
                    if let Value::Tuple(kv) = pair {
                        if kv.len() == 2 {
                            let k = &kv[0];
                            let v = &kv[1];
                            out.push(format!("{prefix} {k}:\t{v}"));
                        }
                    }
                }
            }
        }

        out.join("\n")
    }

    fn format_jail_stat(response: &Value, pref: &str, out: &mut Vec<String>) {
        if let Value::List(sections) = response {
            for (n, sec) in sections.iter().enumerate() {
                let is_sec_last = n == sections.len() - 1;
                let sec_pref = if is_sec_last { "`-" } else { "|-" };
                let child_pref = if is_sec_last { "   " } else { "|  " };

                if let Value::Tuple(sec_pair) = sec {
                    if sec_pair.len() == 2 {
                        let sec_name = &sec_pair[0];
                        out.push(format!("{pref}{sec_pref} {sec_name}"));

                        if let Value::List(items) = &sec_pair[1] {
                            for (m, item) in items.iter().enumerate() {
                                let is_item_last = m == items.len() - 1;
                                let item_pref = if is_item_last { "`-" } else { "|-" };
                                if let Value::Tuple(kv) = item {
                                    if kv.len() == 2 {
                                        let k = &kv[0];
                                        let v_str = match &kv[1] {
                                            Value::List(l) => l
                                                .iter()
                                                .map(Value::to_string)
                                                .collect::<Vec<_>>()
                                                .join(" "),
                                            other => other.to_string(),
                                        };
                                        out.push(format!(
                                            "{pref}{child_pref}{item_pref} {k}:\t{v_str}"
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
