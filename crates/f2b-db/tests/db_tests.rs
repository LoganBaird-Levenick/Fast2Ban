use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::NamedTempFile;

use f2b_db::Fail2BanDb;
use f2b_types::{BanTicket, IPAddr};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn test_open_and_migrate_database_v1() {
    let root_dir = root();
    let v1_fixture = root_dir.join("fail2ban/fail2ban/tests/files/database_v1.db");
    if !v1_fixture.exists() {
        eprintln!("database_v1.db missing; skipping");
        return;
    }

    let tmp = NamedTempFile::new().unwrap();
    fs::copy(&v1_fixture, tmp.path()).unwrap();

    let db =
        Fail2BanDb::open(tmp.path(), 86400).expect("failed to open and migrate database_v1.db");

    // Check jail name
    let jails = db.get_jail_names(None).unwrap();
    assert!(jails.contains("DummyJail #29162448 with 0 tickets"));

    // Check log paths
    let logs = db.get_log_paths(None).unwrap();
    assert!(logs.contains("/tmp/Fail2BanDb_pUlZJh.log"));

    // Check bans
    let bans = db.get_bans(None, None, None, 1388009242.0).unwrap();
    assert_eq!(bans.len(), 1);
    let t = &bans[0];
    assert_eq!(t.id().ntoa(), "127.0.0.1");
    assert!((t.time() - 1388009242.25932).abs() < 0.01);
    assert_eq!(t.ticket().matches(), &["abc\n"]);

    // Check current bans (upgrade v1 -> v4 backfills bips with unknown ban-time corrected to 123456)
    let current = db
        .get_current_bans(None, None, Some(1388009242.0), Some(123456), None)
        .unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].ticket().raw_ban_time(), Some(123456));
}

#[test]
fn test_open_and_migrate_database_v2() {
    let root_dir = root();
    let v2_fixture = root_dir.join("fail2ban/fail2ban/tests/files/database_v2.db");
    if !v2_fixture.exists() {
        eprintln!("database_v2.db missing; skipping");
        return;
    }

    let tmp = NamedTempFile::new().unwrap();
    fs::copy(&v2_fixture, tmp.path()).unwrap();

    let db =
        Fail2BanDb::open(tmp.path(), 86400).expect("failed to open and migrate database_v2.db");

    // Check jail name
    let jails = db.get_jail_names(None).unwrap();
    assert!(jails.contains("pam-generic"));

    // Check log paths
    let logs = db.get_log_paths(None).unwrap();
    assert!(logs.contains("/var/log/auth.log"));

    // Check bans
    let bans = db.get_bans(None, None, None, 1417596235.0).unwrap();
    assert_eq!(bans[0].id().ntoa(), "1.2.3.7");
    assert_eq!(bans[1].id().ntoa(), "1.2.3.8");

    assert_eq!(bans[1].ticket().failures(), 3);
    assert_eq!(bans[1].ticket().matches().len(), 3);

    // Current bans restored from bips
    let current = db
        .get_current_bans(
            Some("pam-generic"),
            None,
            Some(1417595494.0),
            Some(600),
            None,
        )
        .unwrap();
    assert_eq!(current.len(), 2);
    assert_eq!(current[0].ticket().raw_ban_time(), Some(600));
}

#[test]
fn test_crud_log_resume_and_purge() {
    let db = Fail2BanDb::open_in_memory().unwrap();

    // Jails
    db.add_jail("sshd").unwrap();
    db.add_jail("nginx").unwrap();
    let names = db.get_jail_names(Some(true)).unwrap();
    assert!(names.contains("sshd"));
    assert!(names.contains("nginx"));

    db.del_jail("nginx").unwrap();
    let enabled = db.get_jail_names(Some(true)).unwrap();
    assert!(!enabled.contains("nginx"));

    // Logs resume
    let log_path = "/var/log/auth.log";
    // First time log added: returns None (no previous pos)
    let pos0 = db.add_log("sshd", log_path, 100, Some("md5_init")).unwrap();
    assert_eq!(pos0, None);

    // Reconnect with same MD5: resumes pos 100
    let pos1 = db.add_log("sshd", log_path, 100, Some("md5_init")).unwrap();
    assert_eq!(pos1, Some(100));

    // Reconnect with changed MD5 (rotation): resumes None (start from 0)
    let pos_rot = db
        .add_log("sshd", log_path, 0, Some("md5_rotated"))
        .unwrap();
    assert_eq!(pos_rot, None);

    // Update log position
    db.update_log("sshd", log_path, 500, Some("md5_rotated"))
        .unwrap();
    let pos_updated = db
        .add_log("sshd", log_path, 500, Some("md5_rotated"))
        .unwrap();
    assert_eq!(pos_updated, Some(500));

    // Bans
    let ip = IPAddr::new("192.0.2.77").unwrap();
    let mut ticket = BanTicket::new(ip.clone(), 1000.0);
    ticket.ticket_mut().set_ban_time(600);
    ticket.ticket_mut().set_matches(vec!["failure line".into()]);

    db.add_ban("sshd", &ticket, 600).unwrap();

    let active = db
        .get_current_bans(Some("sshd"), None, Some(1200.0), None, None)
        .unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id(), &ip);

    // Purge at t = 1000 + 86400 + 1: expired bips are purged
    db.purge(100_000.0).unwrap();
    let active_after = db
        .get_current_bans(Some("sshd"), None, Some(100_000.0), None, None)
        .unwrap();
    assert_eq!(active_after.len(), 0);
}

#[test]
fn test_python_round_trip() {
    let tmp = NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_owned();

    // 1. Rust creates database, adds a jail and a ban
    {
        let db = Fail2BanDb::open(&db_path, 86400).unwrap();
        db.add_jail("roundtrip-jail").unwrap();

        let ip = IPAddr::new("203.0.113.19").unwrap();
        let mut ticket = BanTicket::new(ip, 2000.0);
        ticket.ticket_mut().set_ban_time(3600);
        ticket
            .ticket_mut()
            .set_matches(vec!["rust failure match".into()]);
        db.add_ban("roundtrip-jail", &ticket, 3600).unwrap();
    }

    // 2. Python opens the database, verifies Rust's data, and adds a Python ban
    let root_dir = root();
    let root_str = root_dir.display();
    if !root_dir.join("fail2ban/fail2ban/server").is_dir() {
        eprintln!("fail2ban missing; skipping python roundtrip test");
        return;
    }
    let py_script = format!(
        r#"import sys
sys.path.insert(0, '{root_str}/fail2ban')
from fail2ban.server.database import Fail2BanDb
from fail2ban.server.ticket import BanTicket

db = Fail2BanDb('{db_path}')
jails = db.getJailNames()
assert 'roundtrip-jail' in jails, f'jails: {{jails}}'

bans = db.getCurrentBans(fromtime=2000)
assert len(bans) == 1, f'bans: {{bans}}'
assert str(bans[0].getID()) == '203.0.113.19'
assert bans[0].getBanTime() == 3600
assert bans[0].getMatches() == ['rust failure match']

class DummyJail:
    name = 'roundtrip-jail'
    class actions:
        @staticmethod
        def getBanTime(): return 1800

t2 = BanTicket('198.51.100.99', 2500, ['python failure match'])
t2.setBanTime(1800)
db.addBan(DummyJail(), t2)
db.close()
"#
    );

    let output = Command::new("python3")
        .arg("-c")
        .arg(&py_script)
        .output()
        .expect("python execution failed");

    assert!(
        output.status.success(),
        "Python script failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // 3. Rust reopens database and verifies Python's ban
    {
        let db = Fail2BanDb::open(&db_path, 86400).unwrap();
        let bans = db
            .get_current_bans(Some("roundtrip-jail"), None, Some(2500.0), None, None)
            .unwrap();
        assert_eq!(bans.len(), 2);

        let py_ban = bans
            .iter()
            .find(|b| b.id().ntoa() == "198.51.100.99")
            .expect("Python ban found");
        assert_eq!(py_ban.ticket().raw_ban_time(), Some(1800));
        assert_eq!(py_ban.ticket().matches(), &["python failure match"]);
    }
}
