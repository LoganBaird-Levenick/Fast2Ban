//! Runtime behaviour of a jail: journal backend, persisted read positions,
//! restored bans, unban/ban by address, reload.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::tempdir;

use f2b_action::{CommandAction, Jail};
use f2b_backend::journal::JournalOptions;
use f2b_backend::{Backend, JournalBackend};
use f2b_date::LocalZone;
use f2b_db::Fail2BanDb;
use f2b_filter::Filter;
use f2b_types::{DnsUtils, FixedClock, IPAddr, SharedClock};

const NOW: f64 = 2_000_000_000.0;
/// The journal entry is formatted as a syslog line `host sshd[pid]: message`.
const JOURNAL_REGEX: &str = r"^\S+ sshd\[\d+\]: Failed password for .* from <HOST>$";

fn jail_with(backend: Backend, name: &str) -> Jail {
    jail_with_regex(backend, name, r"^Failed password for .* from <HOST>$")
}

fn jail_with_regex(backend: Backend, name: &str, regex: &str) -> Jail {
    let clock: SharedClock = Arc::new(FixedClock::new(NOW));
    let dns = Arc::new(DnsUtils::system(clock.clone()));
    let mut filter = Filter::new(clock.clone(), dns, LocalZone::utc());
    filter.add_fail_regex(regex).unwrap();
    let mut jail = Jail::new(name, filter, backend, clock);
    jail.ignore_self = false;
    jail.fail_manager.set_max_retry(3);
    jail.actions.ban_manager.set_ban_time(600);
    jail
}

fn recording_action(jail: &str, path: &Path) -> CommandAction {
    let p = path.display();
    let mut a = CommandAction::new(jail, "rec");
    a.actionban = format!("echo 'ban <ip>' >> {p}");
    a.actionunban = format!("echo 'unban <ip>' >> {p}");
    a
}

fn lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// A `journalctl` stand-in: logs its arguments, prints `count` failed logins of
/// 203.0.113.9 (one per second before `NOW`), then keeps running when
/// following.
fn fake_journalctl(dir: &Path, count: u32) -> std::path::PathBuf {
    let script = dir.join("journalctl");
    let body = format!(
        r#"#!/bin/sh
echo "$@" >> "{argv}"
i=0
while [ $i -lt {count} ]; do
  ts=$(( ({now} - 30 + i) * 1000000 + 250000 ))
  printf '__CURSOR=c%d\n__REALTIME_TIMESTAMP=%d\n__MONOTONIC_TIMESTAMP=%d\n_BOOT_ID=0123456789abcdef0123456789abcdef\n_HOSTNAME=host\nSYSLOG_IDENTIFIER=sshd\n_PID=77\nMESSAGE=Failed password for root from 203.0.113.9\n\n' $i $ts $((1000+i))
  i=$((i+1))
done
case "$*" in *--follow*) sleep 600 ;; esac
"#,
        argv = dir.join("argv.log").display(),
        now = NOW as i64,
    );
    fs::write(&script, body).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    script
}

fn journal_backend(journalctl: &Path, matches: &[&str]) -> Backend {
    let opts = JournalOptions {
        journalctl: Some(journalctl.to_path_buf()),
        ..JournalOptions::default()
    };
    let mut j = JournalBackend::new(opts);
    j.add_match(matches).unwrap();
    Backend::Journal(j)
}

/// The lines of `path` once there are at least `n` of them (the fake
/// journalctl runs asynchronously to the jail).
fn wait_for_lines(path: &Path, n: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let l = lines(path);
        if l.len() >= n {
            return l;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {n} lines in {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn step_until(jail: &mut Jail, what: &str, mut done: impl FnMut(&Jail) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done(jail) {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        jail.step(NOW).unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn journal_jail_bans_from_entries_and_resumes_behind_the_stored_position() {
    let tmp = tempdir().unwrap();
    let ctl = fake_journalctl(tmp.path(), 3);
    let acts = tmp.path().join("acts");
    let db = Arc::new(Fail2BanDb::open(tmp.path().join("f2b.db"), 86400).unwrap());
    let ip = IPAddr::new("203.0.113.9").unwrap();

    let mut jail = jail_with_regex(
        journal_backend(&ctl, &["_SYSTEMD_UNIT=sshd.service", "+", "_COMM=sshd"]),
        "sshd",
        JOURNAL_REGEX,
    );
    jail.set_database(Some(db.clone()));
    db.add_jail("sshd").unwrap();
    jail.actions.add_action(recording_action("sshd", &acts));
    jail.start().unwrap();
    step_until(&mut jail, "the ban", |j| {
        j.actions.ban_manager.in_ban_list(&ip)
    });
    assert_eq!(lines(&acts), ["ban 203.0.113.9"]);

    // the reader was started at now - findtime, following, with the matches
    let argv = lines(&tmp.path().join("argv.log"));
    assert_eq!(argv.len(), 1);
    let since = NOW - 600.0;
    assert!(
        argv[0].starts_with("--output=export --no-pager --quiet")
            && argv[0].ends_with(&format!(
                "--since=@{since} --no-tail --follow _SYSTEMD_UNIT=sshd.service + _COMM=sshd"
            )),
        "unexpected argv[0]: {}",
        argv[0]
    );

    // the position of the last entry (NOW - 28 + 0.25) went to the database
    let stored = db.get_journal_pos("sshd", "systemd-journal").unwrap();
    assert_eq!(stored, Some(NOW as i64 - 28));
    jail.stop().unwrap();

    // a restarted jail reads on behind the stored position, not findtime ago
    let mut again = jail_with(journal_backend(&ctl, &["_COMM=sshd"]), "sshd");
    again.set_database(Some(db));
    again.start().unwrap();
    let argv = wait_for_lines(&tmp.path().join("argv.log"), 2);
    assert!(
        argv[1].starts_with("--output=export --no-pager --quiet")
            && argv[1].ends_with(&format!(
                "--since=@{} --no-tail --follow _COMM=sshd",
                NOW as i64 - 28
            )),
        "unexpected argv[1]: {}",
        argv[1]
    );
}

#[test]
fn journal_matches_are_exposed_and_restart_a_running_reader() {
    let tmp = tempdir().unwrap();
    let ctl = fake_journalctl(tmp.path(), 0);
    let argv_log = tmp.path().join("argv.log");
    let mut jail = jail_with(journal_backend(&ctl, &["_COMM=sshd"]), "sshd");
    jail.start().unwrap();
    wait_for_lines(&argv_log, 1);
    assert_eq!(jail.journal_matches(), vec![vec!["_COMM=sshd".to_owned()]]);

    // every successful change restarts journalctl (one at a time: the fake
    // logs its arguments asynchronously)
    jail.add_journal_match(&["_COMM=sudo".to_owned()]).unwrap();
    assert_eq!(jail.journal_matches().len(), 2);
    let argv = wait_for_lines(&argv_log, 2);
    assert!(argv[1].ends_with("_COMM=sshd + _COMM=sudo"), "{}", argv[1]);

    let err = jail.add_journal_match(&["lowercase=bad".to_owned()]);
    assert!(err.is_err());
    assert_eq!(
        jail.journal_matches().len(),
        2,
        "invalid match changes nothing"
    );

    jail.del_journal_match(&["_COMM=sudo".to_owned()]).unwrap();
    let argv = wait_for_lines(&argv_log, 3);
    assert!(argv[2].ends_with("--follow _COMM=sshd"), "{}", argv[2]);
    assert!(jail.del_journal_match(&["_COMM=sudo".to_owned()]).is_err());

    jail.del_journal_match(&[]).unwrap();
    assert!(jail.journal_matches().is_empty());
    let argv = wait_for_lines(&argv_log, 4);
    assert!(argv[3].ends_with("--follow"), "{}", argv[3]);
    assert_eq!(argv.len(), 4, "failed changes start no reader: {argv:?}");
}

#[test]
fn file_jail_resumes_behind_the_stored_position() {
    let tmp = tempdir().unwrap();
    let log = tmp.path().join("auth.log");
    let acts = tmp.path().join("acts");
    let db = Arc::new(Fail2BanDb::open(tmp.path().join("f2b.db"), 86400).unwrap());
    fs::write(
        &log,
        "Failed password for root from 192.0.2.1\nFailed password for root from 192.0.2.1\n",
    )
    .unwrap();
    let make = |db: &Arc<Fail2BanDb>| {
        let mut jail = jail_with(Backend::create("polling"), "sshd");
        jail.filter.check_find_time = false;
        jail.set_database(Some(db.clone()));
        db.add_jail("sshd").unwrap();
        jail.actions.add_action(recording_action("sshd", &acts));
        jail.add_log_path(log.to_str().unwrap(), false).unwrap();
        jail.start().unwrap();
        jail
    };

    let mut jail = make(&db);
    jail.step(NOW).unwrap();
    assert_eq!(jail.filter_counts(), (1, 2), "two failures read");
    jail.stop().unwrap();

    // a new process: the two old lines are not read again, a third one is
    fs::write(
        &log,
        "Failed password for root from 192.0.2.1\nFailed password for root from 192.0.2.1\n\
         Failed password for root from 192.0.2.1\n",
    )
    .unwrap();
    let mut jail = make(&db);
    jail.step(NOW).unwrap();
    assert_eq!(jail.filter_counts(), (1, 1), "only the new line counted");
    assert!(jail.actions.ban_manager.size() == 0);
}

#[test]
fn restored_bans_run_the_ban_action() {
    let tmp = tempdir().unwrap();
    let acts = tmp.path().join("acts");
    let db = Arc::new(Fail2BanDb::open(tmp.path().join("f2b.db"), 86400).unwrap());
    let ip = IPAddr::new("192.0.2.7").unwrap();

    let mut first = jail_with(Backend::create("polling"), "sshd");
    first.set_database(Some(db.clone()));
    db.add_jail("sshd").unwrap();
    assert_eq!(first.ban_ips(&["192.0.2.7"], NOW).unwrap(), 1);
    assert!(first.actions.ban_manager.in_ban_list(&ip));

    // a restarted jail takes the ban over from the database and re-applies it
    let mut second = jail_with(Backend::create("polling"), "sshd");
    second.set_database(Some(db));
    second.actions.add_action(recording_action("sshd", &acts));
    assert_eq!(second.restore_current_bans(true, NOW).unwrap(), 1);
    assert!(second.actions.ban_manager.in_ban_list(&ip));
    assert_eq!(lines(&acts), ["ban 192.0.2.7"]);
}

#[test]
fn unban_by_address_subnet_and_all() {
    let tmp = tempdir().unwrap();
    let acts = tmp.path().join("acts");
    let mut jail = jail_with(Backend::create("polling"), "sshd");
    jail.actions.add_action(recording_action("sshd", &acts));
    jail.ban_ips(&["192.0.2.1", "192.0.2.2", "198.51.100.5"], NOW)
        .unwrap();
    assert_eq!(jail.ban_list(false).len(), 3);

    // unknown address: an error unless `if_exists`
    let err = jail.unban_ips(Some(&["203.0.113.1"]), false).unwrap_err();
    assert!(err.contains("203.0.113.1"), "{err}");
    assert_eq!(jail.unban_ips(Some(&["203.0.113.1"]), true), Ok(0));

    // a subnet unbans every banned address inside it
    assert_eq!(jail.unban_ips(Some(&["192.0.2.0/24"]), false), Ok(2));
    assert_eq!(jail.ban_list(false), ["198.51.100.5"]);
    assert_eq!(jail.unban_ips(None, true), Ok(1));
    assert!(jail.ban_list(false).is_empty());
    assert_eq!(
        lines(&acts)
            .iter()
            .filter(|l| l.starts_with("unban"))
            .count(),
        3
    );
}

#[test]
fn reload_keeps_known_logs_and_actions_and_drops_the_rest() {
    let tmp = tempdir().unwrap();
    let keep = tmp.path().join("keep.log");
    let gone = tmp.path().join("gone.log");
    let acts = tmp.path().join("acts");
    fs::write(&keep, "x\n").unwrap();
    fs::write(&gone, "x\n").unwrap();
    let mut jail = jail_with(Backend::create("polling"), "sshd");
    jail.add_log_path(keep.to_str().unwrap(), false).unwrap();
    jail.add_log_path(gone.to_str().unwrap(), false).unwrap();
    jail.add_action("old");
    jail.add_action("kept");
    jail.actions.get_action_mut("old").unwrap().set_property(
        "actionunban",
        format!("echo 'old unban <ip>' >> {}", acts.display()),
    );
    jail.actions.get_action_mut("kept").unwrap().set_property(
        "actionreload",
        format!("echo reloaded >> {}", acts.display()),
    );
    jail.start().unwrap();
    jail.ban_ips(&["192.0.2.1"], NOW).unwrap();

    jail.reload_begin();
    assert!(jail.idle);
    // the new configuration mentions only `keep.log` and `kept`
    jail.add_log_path(keep.to_str().unwrap(), false).unwrap();
    jail.add_action("kept");
    jail.reload_end();

    assert_eq!(jail.log_paths(), [keep.to_str().unwrap()]);
    assert_eq!(jail.actions.names(), ["kept"]);
    assert_eq!(
        lines(&acts),
        ["old unban 192.0.2.1", "reloaded"],
        "removed action unbans its tickets, kept action is reloaded"
    );
    assert_eq!(jail.ban_list(false), ["192.0.2.1"], "the ban itself stays");
}

#[test]
fn idle_and_inactive_jails_do_not_read() {
    let tmp = tempdir().unwrap();
    let log = tmp.path().join("auth.log");
    fs::write(&log, "").unwrap();
    let mut jail = jail_with(Backend::create("polling"), "sshd");
    jail.filter.check_find_time = false;
    jail.add_log_path(log.to_str().unwrap(), false).unwrap();
    fs::write(&log, "Failed password for root from 192.0.2.1\n").unwrap();

    jail.step(NOW).unwrap(); // not started
    assert_eq!(jail.filter_counts(), (0, 0));
    jail.start().unwrap();
    jail.idle = true;
    jail.step(NOW).unwrap();
    assert_eq!(jail.filter_counts(), (0, 0));
    jail.idle = false;
    jail.step(NOW).unwrap();
    assert_eq!(jail.filter_counts(), (1, 1));
}
