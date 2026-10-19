//! Dynamic and recursive tag replacement for action commands.

use f2b_helpers::substitute_recursive_tags;
use f2b_regex::map_tag_to_option;
use f2b_types::BanTicket;
use indexmap::IndexMap;
use regex::Regex;
use std::sync::LazyLock;

static TAG_CRE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<([^ <>]+)>").unwrap());
static FCUSTAG_CRE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<F-([A-Z0-9_\-]+)>").unwrap());
static ESCAPE_CRE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[\\#&;`|*?~<>\^\(\)\[\]{}$'"\n\r]"#).unwrap());
static ESCAPE_VN_CRE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\W").unwrap());

/// Information provided to an action during execution.
#[derive(Clone, Debug)]
pub struct ActionInfo {
    pub ip: String,
    pub fid: String,
    pub failures: i64,
    pub time: f64,
    pub bantime: i64,
    pub bancount: i64,
    pub matches: Vec<String>,
    pub family: String,
    pub ip_rev: String,
    pub jail_name: String,
    pub custom_tags: IndexMap<String, String>,
}

impl ActionInfo {
    pub fn from_ticket(ticket: &BanTicket, jail_name: &str, default_bt: i64) -> Self {
        let ip_obj = ticket.ticket().ip();
        let ip_str = ip_obj.ntoa().to_string();
        let fid_str = ticket.id().ntoa().to_string();
        let family_str = if ip_obj.is_ipv6() {
            "inet6".to_owned()
        } else {
            "inet4".to_owned()
        };
        let ip_rev = ip_obj.get_ptr(Some(""));

        let mut custom = IndexMap::new();
        for (k, v) in ticket.ticket().data() {
            custom.insert(k.to_lowercase(), v.clone());
        }

        Self {
            ip: ip_str,
            fid: fid_str,
            failures: ticket.ticket().failures(),
            time: ticket.time(),
            bantime: ticket.ticket().ban_time(default_bt),
            bancount: ticket.ticket().ban_count(),
            matches: ticket.ticket().matches().to_vec(),
            family: family_str,
            ip_rev,
            jail_name: jail_name.to_owned(),
            custom_tags: custom,
        }
    }
}

/// Dynamic tag replacer for command actions.
#[derive(Debug, Clone, Copy)]
pub struct TagReplacer;
impl TagReplacer {
    /// Escape characters which may be used for command injection (`escapeTag` in upstream).
    pub fn escape_tag(value: &str) -> String {
        let mut out = String::with_capacity(value.len() * 2);
        for c in value.chars() {
            match c {
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\\' | '#' | '&' | ';' | '`' | '|' | '*' | '?' | '~' | '<' | '>' | '^' | '('
                | ')' | '[' | ']' | '{' | '}' | '$' | '\'' | '"' => {
                    out.push('\\');
                    out.push(c);
                }
                other => out.push(other),
            }
        }
        out
    }

    /// Recursively resolve static action properties (`replaceTag`).
    pub fn resolve_properties(
        props: &IndexMap<String, String>,
        conditional: &str,
    ) -> Result<IndexMap<String, String>, String> {
        let mut ignore = std::collections::HashSet::new();
        ignore.insert("matches".to_owned());
        ignore.insert("ipmatches".to_owned());
        ignore.insert("ipjailmatches".to_owned());
        substitute_recursive_tags(props, conditional, &ignore, None).map_err(|e| e.to_string())
    }

    /// Replaces dynamic and foreign tags in a command template (`replaceDynamicTags`).
    ///
    /// Escapes untrusted input via shell variables if metacharacters are present.
    pub fn replace_dynamic_tags(
        cmd: &str,
        ainfo: Option<&ActionInfo>,
        props: &IndexMap<String, String>,
    ) -> (String, Vec<(String, String)>) {
        let mut vars_dict: IndexMap<String, String> = IndexMap::new();
        let mut real_cmd = cmd.to_owned();

        let get_tag_val = |tag: &str| -> Option<String> {
            match tag {
                "br" => Some("\n".to_owned()),
                "sp" => Some(" ".to_owned()),
                "family" => ainfo.map(|a| a.family.clone()),
                "ip" => ainfo.map(|a| a.ip.clone()),
                "fid" => ainfo.map(|a| a.fid.clone()),
                "failures" => ainfo.map(|a| a.failures.to_string()),
                "time" => ainfo.map(|a| a.time.to_string()),
                "bantime" => ainfo.map(|a| a.bantime.to_string()),
                "bancount" => ainfo.map(|a| a.bancount.to_string()),
                "matches" => ainfo.map(|a| a.matches.join("\n")),
                "ipmatches" | "ipjailmatches" => ainfo.map(|a| a.matches.join("\n")),
                "ipfailures" | "ipjailfailures" => ainfo.map(|a| a.failures.to_string()),
                "ip-rev" => ainfo.map(|a| a.ip_rev.clone()),
                "jail.name" => ainfo.map(|a| a.jail_name.clone()),
                _ => props.get(tag).cloned(),
            }
        };

        // First pass: replace <tag>
        real_cmd = TAG_CRE
            .replace_all(&real_cmd, |caps: &regex::Captures<'_>| {
                let tag = &caps[1];
                if let Some(val) = get_tag_val(tag) {
                    if ESCAPE_CRE.is_match(&val) {
                        let clean_name = ESCAPE_VN_CRE.replace_all(tag, "_");
                        let var_name = format!("f2bV_{clean_name}");
                        vars_dict.insert(var_name.clone(), val);
                        format!("${var_name}")
                    } else {
                        val
                    }
                } else {
                    caps[0].to_owned()
                }
            })
            .into_owned();

        // Second pass: replace custom filter tags <F-*>
        if real_cmd.contains("<F-") {
            real_cmd = FCUSTAG_CRE
                .replace_all(&real_cmd, |caps: &regex::Captures<'_>| {
                    let tag = map_tag_to_option(&caps[1]);
                    let val = ainfo
                        .and_then(|a| a.custom_tags.get(&tag).cloned())
                        .unwrap_or_default();
                    if ESCAPE_CRE.is_match(&val) {
                        let var_name = format!("f2bV_F_{tag}");
                        vars_dict.insert(var_name.clone(), val);
                        format!("${var_name}")
                    } else {
                        val
                    }
                })
                .into_owned();
        }

        let vars: Vec<(String, String)> = vars_dict.into_iter().collect();
        (real_cmd, vars)
    }
}
