//! Phase 7 gate: stock jails end-to-end smoke matrix.
//!
//! Every case runs the real daemon pieces in-process (`Server` + `AsyncServer`
//! on a temp unix socket + the runner thread), configured from an unmodified
//! copy of the stock tree `fail2ban/config` plus a generated `jail.local`,
//! streamed exactly like `fast2ban-client start` does (`read_config` ->
//! `server-stream`). Canned log lines from the upstream sample corpus
//! (`testdata/samples/stock/*.json`, see `tools/extract_samples.py`) are
//! appended to the jail's log file; the test then checks through client
//! commands (`get <jail> banip`, `set <jail> unbanip`, `unban --all`) and the
//! `dummy` action's output file that exactly the addresses the upstream daemon
//! bans for the same log (oracle: `testdata/smoke-oracle/stock.json`, made by
//! `tools/gen_smoke_oracle.py` from the real Python daemon; the `match: true`
//! sample hosts must be a subset of it) were banned, and that unbanning ran
//! the unban command.
//!
//! There is NO real firewall here (no docker daemon / root / iptables / nft in
//! the sandbox): the action is `dummy`, which appends `+<ip>` / `-<ip>` lines
//! to a file.
//!
//! Environment knobs: `F2B_SMOKE_FILTER=<substring>` runs only matching case
//! ids, `F2B_SMOKE_JOBS=<n>` sets the worker count (default 4).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use f2b_config::{Arg, RealFs, read_config};
use f2b_proto::{Beautifier, Value};
use f2b_server::{AsyncServer, Server};
use f2b_types::IPAddr;
use fast2ban_client::ClientSocket;
use indexmap::IndexMap;
use serde_json::Value as Json;
use tempfile::TempDir;

/// Per-case wall clock budget for every polling phase together.
const CASE_DEADLINE: Duration = Duration::from_secs(10);
/// Time the runner gets to (wrongly) ban more after the expected set is reached.
const SETTLE: Duration = Duration::from_millis(350);
const SETTLE_EMPTY: Duration = Duration::from_millis(700);

/// Cases that fail because of a daemon bug, with the finding id from
/// `smoke-findings.md`. Listed cases still run with unchanged assertions; a
/// pass is reported as `XPASS` (not a failure) so the list can be pruned.
const KNOWN_FAILING: &[(&str, &str)] = &[];

// ---------------------------------------------------------------------------
// case generation
// ---------------------------------------------------------------------------

/// A stock jail of `jail.conf` that is exercised with the stock definition.
struct StockJail {
    jail: &'static str,
    filter: &'static str,
    /// Filter options the stock definition passes (`filter = postfix[mode=rbl]`).
    base: &'static [(&'static str, &'static str)],
    /// The stock `filter = %(__name__)s[mode=%(mode)s]` is in effect, so
    /// `mode = X` in the jail section selects the sample group `{mode: X}`.
    mode_selectable: bool,
}

const fn stock(jail: &'static str) -> StockJail {
    StockJail {
        jail,
        filter: jail,
        base: &[],
        mode_selectable: true,
    }
}

const STOCK_JAILS: &[StockJail] = &[
    stock("sshd"),
    stock("apache-auth"),
    stock("apache-badbots"),
    stock("apache-noscript"),
    stock("apache-overflows"),
    stock("apache-nohome"),
    stock("apache-botsearch"),
    stock("apache-fakegooglebot"),
    stock("apache-modsecurity"),
    stock("apache-shellshock"),
    stock("nginx-http-auth"),
    stock("nginx-limit-req"),
    stock("nginx-botsearch"),
    stock("nginx-bad-request"),
    stock("nginx-forbidden"),
    stock("postfix"),
    StockJail {
        jail: "postfix-rbl",
        filter: "postfix",
        base: &[("mode", "rbl")],
        mode_selectable: false,
    },
    StockJail {
        jail: "postfix-sasl",
        filter: "postfix",
        base: &[("mode", "auth")],
        mode_selectable: false,
    },
    stock("dovecot"),
    stock("recidive"),
];

#[derive(Debug)]
struct Case {
    id: String,
    jail: String,
    /// `filter = ...` override for synthetic jails; `None` keeps the stock one.
    filter_override: Option<String>,
    /// Extra jail options (`mode = aggressive`).
    extra: Vec<(String, String)>,
    lines: Vec<String>,
    /// Addresses the upstream daemon bans for these lines (oracle fixture).
    expected: BTreeSet<String>,
    /// `match: true` samples whose host is not an IP address (kept in the
    /// log; upstream's own result decides whether they ban anything).
    name_host_lines: usize,
    /// Fixture problem found while building the case (fails the case).
    setup_error: Option<String>,
}

#[derive(Debug)]
struct Skipped {
    id: String,
    reason: String,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

/// One (filter, options) sample group: all records upstream checks with
/// identical filter options, in file order.
struct Group {
    filter: String,
    opts: BTreeMap<String, String>,
    journal: bool,
    records: Vec<Json>,
}

fn opt_text(v: &Json) -> String {
    match v {
        Json::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn load_groups() -> Vec<Group> {
    let dir = root().join("testdata/samples/stock");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("sample fixtures {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let mut groups = Vec::new();
    for f in files {
        let data: Json = serde_json::from_str(&fs::read_to_string(&f).unwrap()).unwrap();
        let filter = data["filter"].as_str().unwrap().to_owned();
        let mut by_key: Vec<(String, Group)> = Vec::new();
        for r in data["records"].as_array().unwrap() {
            let opts: BTreeMap<String, String> = r["filter_options"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), opt_text(v)))
                .collect();
            let key = format!("{opts:?}");
            let pos = if let Some(p) = by_key.iter().position(|(k, _)| *k == key) {
                p
            } else {
                by_key.push((
                    key,
                    Group {
                        filter: filter.clone(),
                        opts,
                        journal: false,
                        records: Vec::new(),
                    },
                ));
                by_key.len() - 1
            };
            let g = &mut by_key[pos].1;
            g.journal |= r["logtype"].as_str() == Some("journal");
            g.records.push(r.clone());
        }
        groups.extend(by_key.into_iter().map(|(_, g)| g));
    }
    groups
}

fn normalize_ip(s: &str) -> Option<String> {
    let ip = IPAddr::new(s).ok()?;
    ip.is_valid().then(|| ip.ntoa().into_owned())
}

/// Log lines of a group, the valid-address hosts its samples expect and the
/// number of `match: true` samples with a non-address host.
fn lines_and_hosts(g: &Group) -> (Vec<String>, BTreeSet<String>, usize) {
    let mut lines = Vec::new();
    let mut expected = BTreeSet::new();
    let mut name_hosts = 0;
    for r in &g.records {
        lines.push(r["line"].as_str().unwrap().to_owned());
        let e = &r["expect"];
        if e["match"].as_bool() != Some(true) {
            continue;
        }
        match e["host"].as_str().and_then(normalize_ip) {
            Some(ip) => {
                expected.insert(ip);
            }
            None => name_hosts += 1,
        }
    }
    (lines, expected, name_hosts)
}

/// Value of a filter option in `filter = name[k=v, ...]` syntax.
fn quote_opt(v: &str) -> String {
    if !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        v.to_owned()
    } else {
        format!("\"{}\"", v.replace('"', "\\\""))
    }
}

fn filter_spec(name: &str, opts: &BTreeMap<String, String>) -> String {
    if opts.is_empty() {
        return name.to_owned();
    }
    let o: Vec<String> = opts
        .iter()
        .map(|(k, v)| format!("{k}={}", quote_opt(v)))
        .collect();
    format!("{name}[{}]", o.join(", "))
}

fn load_oracle() -> BTreeMap<(String, BTreeMap<String, String>), BTreeSet<String>> {
    let path = root().join("testdata/smoke-oracle/stock.json");
    let data: Json = serde_json::from_str(
        &fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
    )
    .unwrap();
    data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let opts = c["filter_options"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), opt_text(v)))
                .collect();
            let bans = c["expected_bans"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| {
                    let b = b.as_str().unwrap();
                    normalize_ip(b).unwrap_or_else(|| b.to_owned())
                })
                .collect();
            ((c["filter"].as_str().unwrap().to_owned(), opts), bans)
        })
        .collect()
}

/// Builds a case for a sample group, taking the expectation from the oracle.
fn make_case(
    oracle: &BTreeMap<(String, BTreeMap<String, String>), BTreeSet<String>>,
    g: &Group,
    id: String,
    jail: String,
    filter_override: Option<String>,
    extra: Vec<(String, String)>,
) -> Case {
    let (lines, sample_hosts, name_host_lines) = lines_and_hosts(g);
    let (expected, setup_error) = match oracle.get(&(g.filter.clone(), g.opts.clone())) {
        Some(e) => (e.clone(), None),
        None => (
            BTreeSet::new(),
            Some(
                "no entry in testdata/smoke-oracle/stock.json (run tools/gen_smoke_oracle.py)"
                    .to_owned(),
            ),
        ),
    };
    let setup_error = setup_error.or_else(|| {
        let missing: Vec<_> = sample_hosts.difference(&expected).collect();
        (!missing.is_empty())
            .then(|| format!("oracle (upstream daemon) does not ban sample hosts {missing:?}"))
    });
    Case {
        id,
        jail,
        filter_override,
        extra,
        lines,
        expected,
        name_host_lines,
        setup_error,
    }
}

fn build_cases(groups: &[Group]) -> (Vec<Case>, Vec<Skipped>) {
    let oracle = load_oracle();
    let mut cases = Vec::new();
    let mut skipped = Vec::new();
    // Stock jails with their stock filter definition.
    for sj in STOCK_JAILS {
        let base: BTreeMap<String, String> = sj
            .base
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let mut matched = false;
        for g in groups
            .iter()
            .filter(|g| g.filter == sj.filter && !g.journal)
        {
            let mut extra = Vec::new();
            let label;
            if g.opts == base {
                label = String::new();
            } else if sj.mode_selectable
                && base.is_empty()
                && g.opts.len() == 1
                && g.opts.contains_key("mode")
            {
                let mode = g.opts["mode"].clone();
                label = format!("[mode={mode}]");
                extra.push(("mode".to_owned(), mode));
            } else {
                continue;
            }
            matched = true;
            cases.push(make_case(
                &oracle,
                g,
                format!("stock:{}{label}", sj.jail),
                sj.jail.to_owned(),
                None,
                extra,
            ));
        }
        assert!(matched, "stock jail {} has no sample group", sj.jail);
    }
    // Every filter x option group, as a synthetic jail.
    for g in groups {
        let spec = filter_spec(&g.filter, &g.opts);
        let id = format!("smoke:{spec}");
        if g.journal {
            skipped.push(Skipped {
                id,
                reason: "journal-only samples (file backend only)".to_owned(),
            });
            continue;
        }
        cases.push(make_case(
            &oracle,
            g,
            id,
            format!("smoke-{}", g.filter),
            Some(spec),
            Vec::new(),
        ));
    }
    (cases, skipped)
}

// ---------------------------------------------------------------------------
// daemon harness
// ---------------------------------------------------------------------------

/// Owns the in-process daemon of one case; stops it (and joins its threads)
/// on drop, also when the case panics. Field order: the temp dir goes last.
struct Daemon {
    async_server: AsyncServer,
    handle: Option<JoinHandle<()>>,
    sock: PathBuf,
    _tmp: TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Graceful stop (runs the jail/action stop commands) ...
        let mut c = ClientSocket::new(&self.sock);
        let _ = c.send(&[Value::Str("stop".to_owned())]);
        c.close();
        // ... and make sure the loops end even if that failed.
        self.async_server.stop();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for e in fs::read_dir(src)? {
        let e = e?;
        let to = dst.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_tree(&e.path(), &to)?;
        } else {
            fs::copy(e.path(), to)?;
        }
    }
    Ok(())
}

fn arg_to_value(a: Arg) -> Value {
    match a {
        Arg::None => Value::None,
        Arg::Str(s) => Value::Str(s),
        Arg::Int(i) => Value::Int(i),
        Arg::Bool(b) => Value::Bool(b),
        Arg::List(l) => Value::List(l.into_iter().map(arg_to_value).collect()),
        Arg::Map(m) => Value::Dict(
            m.into_iter()
                .map(|(k, v)| (Value::Str(k), arg_to_value(v)))
                .collect(),
        ),
    }
}

fn jail_local(case: &Case, log: &Path, out: &Path) -> String {
    let mut s = format!("[{}]\n", case.jail);
    let mut kv = |k: &str, v: &str| {
        let _ = writeln!(s, "{k} = {v}");
    };
    kv("enabled", "true");
    kv("backend", "polling");
    kv("logpath", &log.display().to_string());
    kv("maxretry", "1");
    kv("findtime", "100y");
    kv("bantime", "-1");
    kv("ignoreself", "false");
    kv("ignoreip", "");
    kv("ignorecommand", "");
    kv("usedns", "no");
    kv("action", &format!("dummy[target=\"{}\"]", out.display()));
    if let Some(f) = &case.filter_override {
        kv("filter", f);
    }
    for (k, v) in &case.extra {
        kv(k, v);
    }
    s
}

struct Running {
    client: ClientSocket,
    log: PathBuf,
    out: PathBuf,
    _daemon: Daemon,
}

/// Prepares the config tree, starts the daemon and streams the config like
/// `fast2ban-client start`.
fn start(case: &Case) -> Result<Running, String> {
    let tmp = tempfile::Builder::new()
        .prefix("f2b-smoke-")
        .tempdir()
        .map_err(|e| format!("tempdir: {e}"))?;
    let conf = tmp.path().join("conf");
    copy_tree(&root().join("fail2ban/config"), &conf).map_err(|e| format!("copy config: {e}"))?;
    fs::write(
        conf.join("fail2ban.local"),
        "[Definition]\nlogtarget = STDERR\ndbfile = None\n",
    )
    .map_err(|e| e.to_string())?;
    let log = tmp.path().join("jail.log");
    let out = tmp.path().join("action.out");
    fs::write(&log, "").map_err(|e| e.to_string())?;
    fs::write(conf.join("jail.local"), jail_local(case, &log, &out)).map_err(|e| e.to_string())?;

    let sock = tmp.path().join("f2b.sock");
    let server = Arc::new(Mutex::new(Server::new()));
    let async_server =
        AsyncServer::bind(&sock, server).map_err(|e| format!("bind {}: {e}", sock.display()))?;
    let handle = async_server
        .start_background()
        .map_err(|e| format!("start_background: {e}"))?;
    let daemon = Daemon {
        async_server,
        handle: Some(handle),
        sock: sock.clone(),
        _tmp: tmp,
    };

    let res = read_config(
        Rc::new(RealFs),
        conf.to_str().unwrap(),
        None,
        &IndexMap::new(),
        true,
        false,
    );
    let Some(stream) = res.stream else {
        return Err(format!("read_config failed: {:?}", res.error));
    };
    let rows: Vec<Value> = stream
        .into_iter()
        .map(|c| Value::List(c.into_iter().map(arg_to_value).collect()))
        .collect();
    let mut client = ClientSocket::new(&sock);
    client
        .send(&[Value::Str("server-stream".to_owned()), Value::List(rows)])
        .map_err(|e| format!("server-stream: {e}"))?;
    Ok(Running {
        client,
        log,
        out,
        _daemon: daemon,
    })
}

fn cmd(args: &[&str]) -> Vec<Value> {
    args.iter().map(|a| Value::Str((*a).to_owned())).collect()
}

fn list_of_strings(v: &Value) -> Result<Vec<String>, String> {
    match v.as_list() {
        Some(l) => Ok(l.iter().cloned().map(Value::into_string).collect()),
        None => Err(format!("expected a list, got {v:?}")),
    }
}

/// Parsed `dummy` action output: `+<ip>` ban lines and `-<ip>` unban lines.
#[derive(Default, Debug)]
struct ActionOut {
    bans: Vec<String>,
    unbans: Vec<String>,
}

fn read_action_out(path: &Path) -> ActionOut {
    let mut o = ActionOut::default();
    for l in fs::read_to_string(path).unwrap_or_default().lines() {
        let norm = |s: &str| normalize_ip(s.trim()).unwrap_or_else(|| s.trim().to_owned());
        if let Some(ip) = l.strip_prefix('+') {
            o.bans.push(norm(ip));
        } else if let Some(ip) = l.strip_prefix('-') {
            o.unbans.push(norm(ip));
        }
    }
    o
}

impl Running {
    fn banned(&mut self, jail: &str) -> Result<BTreeSet<String>, String> {
        let v = self
            .client
            .send(&cmd(&["get", jail, "banip"]))
            .map_err(|e| format!("get {jail} banip: {e}"))?;
        Ok(list_of_strings(&v)?
            .into_iter()
            .map(|s| normalize_ip(&s).unwrap_or(s))
            .collect())
    }
}

impl Running {
    /// One field of the client's `status <jail>` text, e.g. `Currently banned`.
    fn status_field(&mut self, jail: &str, field: &str) -> Result<String, String> {
        let args = ["status", jail];
        let v = self
            .client
            .send(&cmd(&args))
            .map_err(|e| format!("status {jail}: {e}"))?;
        let owned: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let text = Beautifier::beautify(&owned, &v);
        let key = format!("{field}:");
        text.lines()
            .find_map(|l| {
                let l = l.trim_start_matches(['|', '`', '-', ' ']);
                l.strip_prefix(&key).map(|r| r.trim().to_owned())
            })
            .ok_or_else(|| format!("no '{field}' in status: {text:?}"))
    }

    fn expect_status(&mut self, jail: &str, field: &str, want: usize) -> Result<(), String> {
        let got = self.status_field(jail, field)?;
        if got == want.to_string() {
            Ok(())
        } else {
            Err(format!("status '{field}' is {got:?}, expected {want}"))
        }
    }
}

fn diff(want: &BTreeSet<String>, got: &BTreeSet<String>) -> String {
    let missing: Vec<_> = want.difference(got).collect();
    let extra: Vec<_> = got.difference(want).collect();
    format!("missing {missing:?}, unexpected {extra:?}")
}

/// Polls `f` until it returns `Ok(true)` or the deadline passes; returns the
/// last error text on timeout.
fn wait_until(
    deadline: Instant,
    what: &str,
    mut f: impl FnMut() -> Result<Option<String>, String>,
) -> Result<(), String> {
    let mut last;
    loop {
        last = f()?;
        match &last {
            None => return Ok(()),
            Some(_) if Instant::now() >= deadline => break,
            Some(_) => thread::sleep(Duration::from_millis(25)),
        }
    }
    Err(format!("timeout waiting for {what}: {}", last.unwrap()))
}

fn run_case(case: &Case) -> Result<(), String> {
    if let Some(e) = &case.setup_error {
        return Err(e.clone());
    }
    let deadline = Instant::now() + CASE_DEADLINE;
    let mut rt = start(case)?;
    let jail = case.jail.as_str();

    let initially = rt.banned(jail)?;
    if !initially.is_empty() {
        return Err(format!("bans before any log line: {initially:?}"));
    }

    // Append the canned log in one write, as a daemon would see a live log.
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(&rt.log)
        .map_err(|e| e.to_string())?;
    let mut text = case.lines.join("\n");
    text.push('\n');
    f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    drop(f);

    // 1. exactly the expected addresses get banned (client view) ...
    let expected = &case.expected;
    wait_until(deadline, "bans", || {
        let got = rt.banned(jail)?;
        Ok((got != *expected).then(|| diff(expected, &got)))
    })?;
    // ... and nothing else is banned later.
    thread::sleep(if expected.is_empty() {
        SETTLE_EMPTY
    } else {
        SETTLE
    });
    let got = rt.banned(jail)?;
    if got != *expected {
        return Err(format!("after settling: {}", diff(expected, &got)));
    }

    rt.expect_status(jail, "Currently banned", expected.len())?;
    rt.expect_status(jail, "Total banned", expected.len())?;

    // 2. the ban action ran once per address (action-output view).
    let out = rt.out.clone();
    wait_until(deadline, "ban actions", || {
        let o = read_action_out(&out);
        let set: BTreeSet<String> = o.bans.iter().cloned().collect();
        Ok((set != *expected || o.bans.len() != expected.len())
            .then(|| format!("{} (ban lines {:?})", diff(expected, &set), o.bans)))
    })?;

    if expected.is_empty() {
        return Ok(());
    }

    // 3. unban one address explicitly ...
    let first = expected.iter().next().unwrap().clone();
    rt.client
        .send(&cmd(&["set", jail, "unbanip", &first]))
        .map_err(|e| format!("set unbanip {first}: {e}"))?;
    let mut rest = expected.clone();
    rest.remove(&first);
    let got = rt.banned(jail)?;
    if got != rest {
        return Err(format!("after unbanip {first}: {}", diff(&rest, &got)));
    }
    wait_until(deadline, "unban action of the single address", || {
        let o = read_action_out(&out);
        Ok((!o.unbans.contains(&first)).then(|| format!("no '-{first}' in {:?}", o.unbans)))
    })?;

    // 4. ... then everything else.
    let n = rt
        .client
        .send(&cmd(&["unban", "--all"]))
        .map_err(|e| format!("unban --all: {e}"))?;
    if n.as_i64() != Some(i64::try_from(rest.len()).unwrap()) {
        return Err(format!(
            "unban --all returned {n:?}, expected {}",
            rest.len()
        ));
    }
    let got = rt.banned(jail)?;
    if !got.is_empty() {
        return Err(format!("still banned after unban --all: {got:?}"));
    }
    rt.expect_status(jail, "Currently banned", 0)?;
    // Upstream `unban --all` runs the action's `actionflush` (dummy: `-*`)
    // instead of one unban per address; accept per-address unbans too.
    wait_until(deadline, "unban actions", || {
        let o = read_action_out(&out);
        let flushed = o.unbans.iter().any(|u| u == "*");
        let each = rest.iter().all(|ip| o.unbans.contains(ip));
        Ok((!flushed && !each).then(|| {
            format!(
                "neither flush ('-*') nor unban of {:?}: unban lines {:?}",
                rest, o.unbans
            )
        }))
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// matrix driver
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Outcome {
    Pass,
    Fail(String),
    KnownFail(&'static str, String),
    Xpass(&'static str),
}

fn run_guarded(case: &Case) -> Outcome {
    let res = catch_unwind(AssertUnwindSafe(|| run_case(case))).unwrap_or_else(|p| {
        let msg = p
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_else(|| "panic".to_owned());
        Err(format!("panic: {msg}"))
    });
    let known = KNOWN_FAILING
        .iter()
        .find(|(id, _)| *id == case.id)
        .map(|(_, f)| *f);
    match (res, known) {
        (Ok(()), None) => Outcome::Pass,
        (Ok(()), Some(f)) => Outcome::Xpass(f),
        (Err(e), None) => Outcome::Fail(e),
        (Err(e), Some(f)) => Outcome::KnownFail(f, e),
    }
}

#[test]
fn stock_jails_smoke_matrix() {
    let groups = load_groups();
    let (mut cases, skipped) = build_cases(&groups);
    if let Ok(f) = std::env::var("F2B_SMOKE_FILTER") {
        cases.retain(|c| c.id.contains(&f));
    }
    let jobs = std::env::var("F2B_SMOKE_JOBS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4)
        .max(1);

    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(usize, Outcome, Duration)>> = Mutex::new(Vec::new());
    let started = Instant::now();
    thread::scope(|s| {
        for _ in 0..jobs {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(case) = cases.get(i) else { break };
                    let t = Instant::now();
                    let o = run_guarded(case);
                    results.lock().unwrap().push((i, o, t.elapsed()));
                }
            });
        }
    });
    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|(i, ..)| *i);

    let (mut pass, mut fail, mut known, mut xpass) = (0, 0, 0, 0);
    let mut table = String::new();
    let mut failures = String::new();
    for (i, o, dur) in &results {
        let c = &cases[*i];
        let status = match o {
            Outcome::Pass => {
                pass += 1;
                "PASS".to_owned()
            }
            Outcome::Fail(e) => {
                fail += 1;
                let _ = writeln!(failures, "FAIL {}: {e}", c.id);
                "FAIL".to_owned()
            }
            Outcome::KnownFail(f, _) => {
                known += 1;
                format!("known failing: {f}")
            }
            Outcome::Xpass(f) => {
                xpass += 1;
                format!("XPASS (listed as known failing: {f})")
            }
        };
        let _ = writeln!(
            table,
            "{status:<28} {:<48} lines={:<4} ban={:<3} name-host-lines={:<2} {:>5}ms",
            c.id,
            c.lines.len(),
            c.expected.len(),
            c.name_host_lines,
            dur.as_millis()
        );
        if let Outcome::KnownFail(_, e) = o {
            let _ = writeln!(table, "    {e}");
        }
    }
    for s in &skipped {
        let _ = writeln!(table, "{:<28} {:<48} {}", "SKIPPED", s.id, s.reason);
    }
    println!("{table}");
    println!(
        "smoke matrix: {} run, {pass} passed, {known} known failing, {xpass} xpass, {fail} failed, {} skipped, {} workers, {:.1}s",
        results.len(),
        skipped.len(),
        jobs,
        started.elapsed().as_secs_f64()
    );
    assert!(
        fail == 0,
        "{fail} of {} smoke cases failed:\n{failures}\n(full table above; known-failing cases are in smoke-findings.md)",
        results.len()
    );
}
