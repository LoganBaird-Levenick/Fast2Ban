//! Client commands against a [`Transmitter`] (no socket): option round trips,
//! status shapes, ban/unban commands and reload semantics.

use std::fs;
use std::sync::{Arc, Mutex};

use tempfile::tempdir;

use f2b_proto::Value;
use f2b_server::{Server, Transmitter};

fn s(v: &str) -> Value {
    Value::Str(v.to_owned())
}

fn list(items: &[&str]) -> Value {
    Value::List(items.iter().map(|i| s(i)).collect())
}

/// Send one command; `Ok(result)` or `Err(exception text)`.
fn call(t: &Transmitter, args: Vec<Value>) -> Result<Value, String> {
    match t.proceed(Value::List(args)) {
        Value::Tuple(mut p) if p.len() == 2 => match (p.remove(0), p.remove(0)) {
            (Value::Int(0), ret) => Ok(ret),
            (Value::Int(1), Value::Exception(e)) => Err(e),
            other => panic!("unexpected reply {other:?}"),
        },
        other => panic!("unexpected reply {other:?}"),
    }
}

fn transmitter() -> Transmitter {
    Transmitter::new(Arc::new(Mutex::new(Server::new())))
}

fn jail(t: &Transmitter, name: &str) {
    assert_eq!(call(t, vec![s("add"), s(name), s("polling")]), Ok(s(name)));
}

fn set(t: &Transmitter, args: &[&str]) -> Result<Value, String> {
    let mut v = vec![s("set")];
    v.extend(args.iter().map(|a| s(a)));
    call(t, v)
}

fn get(t: &Transmitter, args: &[&str]) -> Result<Value, String> {
    let mut v = vec![s("get")];
    v.extend(args.iter().map(|a| s(a)));
    call(t, v)
}

#[test]
fn server_level_commands() {
    let t = transmitter();
    assert_eq!(call(&t, vec![s("ping")]), Ok(s("pong")));
    assert_eq!(
        call(&t, vec![s("echo"), s("a"), s("b")]),
        Ok(list(&["a", "b"]))
    );
    assert_eq!(call(&t, vec![s("version")]), Ok(s("1.1.2.dev1")));
    assert_eq!(call(&t, vec![s("server-status")]), Ok(s("Server ready")));
    assert!(call(&t, vec![s("bogus")]).is_err());
    assert!(
        call(&t, vec![s("add"), s("--all")]).is_err(),
        "reserved name"
    );
    assert_eq!(set(&t, &["allowipv6", "yes"]), Ok(s("yes")));
    // no database yet: settings of it are accepted but have no effect
    assert_eq!(set(&t, &["dbmaxmatches", "3"]), Ok(Value::None));
    assert_eq!(get(&t, &["dbfile"]), Ok(Value::None));
}

#[test]
fn jail_options_round_trip_like_upstream() {
    let t = transmitter();
    jail(&t, "sshd");
    // setters answer with what the getter reports afterwards
    assert_eq!(set(&t, &["sshd", "maxretry", "7"]), Ok(Value::Int(7)));
    assert_eq!(get(&t, &["sshd", "maxretry"]), Ok(Value::Int(7)));
    assert_eq!(set(&t, &["sshd", "findtime", "10m"]), Ok(Value::Int(600)));
    assert_eq!(set(&t, &["sshd", "bantime", "1h"]), Ok(Value::Int(3600)));
    assert_eq!(set(&t, &["sshd", "bantime", "-1"]), Ok(Value::Int(-1)));
    assert_eq!(set(&t, &["sshd", "maxlines", "3"]), Ok(Value::Int(3)));
    assert_eq!(set(&t, &["sshd", "maxmatches", "9"]), Ok(Value::Int(9)));
    assert_eq!(set(&t, &["sshd", "usedns", "no"]), Ok(s("no")));
    assert_eq!(
        set(&t, &["sshd", "ignorecommand", "/bin/true"]),
        Ok(s("/bin/true"))
    );
    assert_eq!(set(&t, &["sshd", "idle", "on"]), Ok(Value::Bool(true)));
    assert!(set(&t, &["sshd", "idle", "maybe"]).is_err());
    assert_eq!(
        set(&t, &["sshd", "ignoreself", "no"]),
        Ok(Value::Bool(false))
    );
    assert_eq!(
        set(&t, &["sshd", "addignoreip", "192.0.2.0/24", "198.51.100.1"]),
        Ok(list(&["192.0.2.0/24", "198.51.100.1"]))
    );
    assert_eq!(
        set(&t, &["sshd", "delignoreip", "198.51.100.1"]),
        Ok(list(&["192.0.2.0/24"]))
    );
    assert_eq!(set(&t, &["sshd", "logencoding", "auto"]), Ok(s("UTF-8")));
    assert!(set(&t, &["sshd", "logencoding", "klingon"]).is_err());
    // getters return the expanded regular expression, like upstream's getRegex()
    assert_eq!(
        set(&t, &["sshd", "prefregex", r"^<F-CONTENT>.+</F-CONTENT>$"]),
        Ok(s(r"^(?P<content>.+)$"))
    );

    // regex lists: add one by one, delete by index; bad ones are refused
    let regexes = |t: &Transmitter| match get(t, &["sshd", "failregex"]).unwrap() {
        Value::List(l) => l,
        other => panic!("{other:?}"),
    };
    let Ok(Value::List(first)) = set(&t, &["sshd", "addfailregex", r"^bad from <HOST>$"]) else {
        panic!("addfailregex");
    };
    assert_eq!(first.len(), 1);
    assert!(set(&t, &["sshd", "addfailregex", r"^no failure id$"]).is_err());
    assert_eq!(
        call(
            &t,
            vec![
                s("multi-set"),
                s("sshd"),
                s("addfailregex"),
                list(&[r"^x from <HOST>$"])
            ]
        ),
        Ok(Value::Bool(true))
    );
    let both = regexes(&t);
    assert_eq!(both.len(), 2);
    assert_eq!(both[0], first[0]);
    assert_eq!(
        set(&t, &["sshd", "delfailregex", "0"]),
        Ok(Value::List(vec![both[1].clone()]))
    );
    assert!(set(&t, &["sshd", "delfailregex", "5"]).is_err());

    assert_eq!(
        set(&t, &["sshd", "bantime.increment", "true"]),
        Ok(s("true"))
    );
    assert!(
        set(
            &t,
            &["sshd", "bantime.formula", "ban.Time * os.system('x')"]
        )
        .is_err()
    );

    // unknown jail / option
    assert!(set(&t, &["nope", "maxretry", "1"]).is_err());
    assert!(set(&t, &["sshd", "nosuchoption", "1"]).is_err());
    assert!(get(&t, &["sshd", "nosuchoption"]).is_err());
    // Python actions are not supported
    assert!(set(&t, &["sshd", "addaction", "smtp", "/x/smtp.py", "{}"]).is_err());
}

#[test]
fn log_paths_and_journal_matches() {
    let tmp = tempdir().unwrap();
    let log = tmp.path().join("a.log");
    fs::write(&log, "").unwrap();
    let log = log.to_str().unwrap();
    let t = transmitter();
    jail(&t, "sshd");
    assert_eq!(
        set(&t, &["sshd", "addlogpath", log, "tail"]),
        Ok(list(&[log]))
    );
    assert!(set(&t, &["sshd", "addlogpath", log, "middle"]).is_err());
    assert!(set(&t, &["sshd", "addlogpath", "/nonexistent/x.log"]).is_err());
    assert_eq!(set(&t, &["sshd", "dellogpath", log]), Ok(list(&[])));
    // a file backend ignores journal matches but accepts the commands
    assert_eq!(
        set(&t, &["sshd", "addjournalmatch", "_COMM=sshd"]),
        Ok(list(&[]))
    );
    assert_eq!(get(&t, &["sshd", "journalmatch"]), Ok(list(&[])));

    // a systemd jail keeps them
    assert_eq!(
        call(&t, vec![s("add"), s("jrn"), s("systemd")]),
        Ok(s("jrn"))
    );
    assert_eq!(
        set(
            &t,
            &[
                "jrn",
                "addjournalmatch",
                "_SYSTEMD_UNIT=sshd.service",
                "+",
                "_COMM=sshd"
            ]
        ),
        Ok(Value::List(vec![
            list(&["_SYSTEMD_UNIT=sshd.service"]),
            list(&["_COMM=sshd"])
        ]))
    );
    assert_eq!(
        set(&t, &["jrn", "addjournalmatch", "no equals sign"]),
        Err("Invalid match".to_owned())
    );
    assert!(
        set(&t, &["jrn", "addlogpath", log]).is_err(),
        "no log files for the systemd backend"
    );
}

#[test]
fn ban_commands_and_status_shapes() {
    let tmp = tempdir().unwrap();
    let acts = tmp.path().join("acts");
    let t = transmitter();
    jail(&t, "a");
    jail(&t, "b");
    for j in ["a", "b"] {
        assert_eq!(set(&t, &[j, "addaction", "rec"]), Ok(s("rec")));
        let ban = format!("echo '{j} ban <ip>' >> {}", acts.display());
        let unban = format!("echo '{j} unban <ip>' >> {}", acts.display());
        assert_eq!(
            call(
                &t,
                vec![
                    s("multi-set"),
                    s(j),
                    s("action"),
                    s("rec"),
                    Value::List(vec![
                        Value::List(vec![s("actionban"), s(&ban)]),
                        Value::List(vec![s("actionunban"), s(&unban)]),
                    ])
                ]
            ),
            Ok(Value::Bool(true))
        );
        assert_eq!(call(&t, vec![s("start"), s(j)]), Ok(Value::None));
    }
    assert_eq!(get(&t, &["a", "actions"]), Ok(list(&["rec"])));
    assert!(get(&t, &["a", "action", "rec", "actionban"]).unwrap() != Value::None);
    assert!(get(&t, &["a", "action", "nope", "actionban"]).is_err());

    assert_eq!(
        set(&t, &["a", "banip", "192.0.2.1", "192.0.2.2"]),
        Ok(Value::Int(2))
    );
    assert_eq!(set(&t, &["b", "banip", "192.0.2.1"]), Ok(Value::Int(1)));
    assert_eq!(
        get(&t, &["a", "banip"]),
        Ok(list(&["192.0.2.1", "192.0.2.2"]))
    );
    assert_eq!(get(&t, &["a", "banned", "192.0.2.1"]), Ok(Value::Int(1)));
    assert_eq!(
        get(&t, &["a", "banned", "192.0.2.1", "203.0.113.1"]),
        Ok(Value::List(vec![Value::Int(1), Value::Int(0)]))
    );
    assert_eq!(
        call(&t, vec![s("banned"), s("192.0.2.1"), s("192.0.2.2")]),
        Ok(Value::List(vec![list(&["a", "b"]), list(&["a"])]))
    );

    // status: overview, one jail, all jails, stats
    let status = call(&t, vec![s("status")]).unwrap();
    assert_eq!(
        status,
        Value::List(vec![
            Value::Tuple(vec![s("Number of jail"), Value::Int(2)]),
            Value::Tuple(vec![s("Jail list"), s("a, b")]),
        ])
    );
    let one = call(&t, vec![s("status"), s("a")]).unwrap();
    let Value::List(parts) = &one else {
        panic!("{one:?}")
    };
    let Value::Tuple(actions) = &parts[1] else {
        panic!("{one:?}")
    };
    let Value::List(items) = &actions[1] else {
        panic!("{one:?}")
    };
    assert_eq!(
        items[0],
        Value::Tuple(vec![s("Currently banned"), Value::Int(2)])
    );
    assert_eq!(
        items[1],
        Value::Tuple(vec![s("Total banned"), Value::Int(2)])
    );
    assert_eq!(
        items[2],
        Value::Tuple(vec![s("Banned IP list"), list(&["192.0.2.1", "192.0.2.2"])])
    );
    let stats = call(&t, vec![s("stats")]).unwrap();
    let Value::Dict(d) = stats else { panic!() };
    assert_eq!(d.len(), 2);
    assert_eq!(
        d[0].1,
        Value::List(vec![
            s("polling"),
            Value::Tuple(vec![Value::Int(0), Value::Int(0)]),
            Value::Tuple(vec![Value::Int(2), Value::Int(2)]),
        ])
    );
    assert!(call(&t, vec![s("status"), s("a"), s("cymru")]).is_err());
    assert!(call(&t, vec![s("status"), s("zzz")]).is_err());

    // unban: one address in one jail, a missing one is an error there, everywhere is lenient
    assert_eq!(set(&t, &["a", "unbanip", "192.0.2.2"]), Ok(Value::Int(1)));
    assert!(set(&t, &["a", "unbanip", "--report-absent", "192.0.2.2"]).is_err());
    assert_eq!(set(&t, &["a", "unbanip", "192.0.2.2"]), Ok(Value::Int(0)));
    assert_eq!(
        call(&t, vec![s("unban"), s("192.0.2.1")]),
        Ok(Value::Int(2))
    );
    assert_eq!(set(&t, &["a", "banip", "192.0.2.5"]), Ok(Value::Int(1)));
    assert_eq!(call(&t, vec![s("unban"), s("--all")]), Ok(Value::Int(1)));
    let log = fs::read_to_string(&acts).unwrap();
    assert_eq!(
        log.lines().filter(|l| l.contains(" unban ")).count(),
        4,
        "{log}"
    );
}

#[test]
fn reload_removes_untouched_jails_and_keeps_bans() {
    let t = transmitter();
    jail(&t, "keep");
    jail(&t, "drop");
    assert_eq!(set(&t, &["keep", "banip", "192.0.2.9"]), Ok(Value::Int(1)));
    assert_eq!(call(&t, vec![s("start"), s("keep")]), Ok(Value::None));

    // the stream names only `keep` (as the client does for the reloaded config)
    let stream = Value::List(vec![
        list(&["add", "keep", "polling"]),
        list(&["set", "keep", "maxretry", "9"]),
        list(&["start", "keep"]),
    ]);
    assert_eq!(
        call(&t, vec![s("reload"), s("--all"), list(&[]), stream]),
        Ok(s("OK"))
    );
    assert_eq!(get(&t, &["keep", "maxretry"]), Ok(Value::Int(9)));
    assert_eq!(
        get(&t, &["keep", "banip"]),
        Ok(list(&["192.0.2.9"])),
        "bans survive a reload"
    );
    assert!(
        get(&t, &["drop", "maxretry"]).is_err(),
        "jail not in the new config is removed"
    );

    // a failing stream still finishes the reload (a second one may start)
    let bad = Value::List(vec![list(&["set", "keep", "nosuchoption", "1"])]);
    assert!(call(&t, vec![s("reload"), s("--all"), list(&[]), bad]).is_err());
    let ok = Value::List(vec![
        list(&["add", "keep", "polling"]),
        list(&["start", "keep"]),
    ]);
    assert_eq!(
        call(&t, vec![s("reload"), s("--all"), list(&[]), ok]),
        Ok(s("OK"))
    );

    // unknown jail: error unless --if-exists
    assert!(
        call(
            &t,
            vec![s("reload"), s("nope"), list(&[]), Value::List(vec![])]
        )
        .is_err()
    );
    assert_eq!(
        call(
            &t,
            vec![
                s("reload"),
                s("nope"),
                list(&["--if-exists"]),
                Value::List(vec![])
            ]
        ),
        Ok(s("OK"))
    );

    // --unban empties the ban list before the new configuration is applied
    let ok = Value::List(vec![
        list(&["add", "keep", "polling"]),
        list(&["start", "keep"]),
    ]);
    assert_eq!(
        call(&t, vec![s("reload"), s("keep"), list(&["--unban"]), ok]),
        Ok(s("OK"))
    );
    assert_eq!(get(&t, &["keep", "banip"]), Ok(list(&[])));
}
