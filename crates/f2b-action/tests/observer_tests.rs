//! Differential oracle tests porting Fail2Ban's `observertestcase.py`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;

use f2b_action::{BanExtra, Jail, Observer};
use f2b_backend::Backend;
use f2b_date::LocalZone;
use f2b_db::Fail2BanDb;
use f2b_filter::Filter;
use f2b_types::{BanTicket, DnsUtils, FailTicket, IPAddr, system_clock};

fn make_test_jail(name: &str) -> Jail {
    let clock = system_clock();
    let dns = Arc::new(DnsUtils::system(clock.clone()));
    let zone = LocalZone::system();
    let filter = Filter::new(clock.clone(), dns, zone);
    let backend = Backend::create("polling");
    Jail::new(name, filter, backend, clock)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// Verify calculation matches exact numbers from upstream `testDefault`.
#[test]
fn test_default_formula_and_options() {
    let mut extra = BanExtra::new();
    extra.set_opt("increment", Some("true")).unwrap();
    assert!(extra.increment);

    extra.set_opt("maxtime", Some("1d")).unwrap();
    assert_eq!(extra.maxtime, Some(24 * 3600));

    extra.set_opt("rndtime", None).unwrap();
    extra.set_opt("factor", None).unwrap();
    extra.set_opt("multipliers", None).unwrap();

    // 1. algorithm and max time 24 hours:
    let expected_24h = [
        1200, 2400, 4800, 9600, 19200, 38400, 76800, 86400, 86400, 86400,
    ];
    for (i, &exp) in expected_24h.iter().enumerate() {
        let count = (i + 1) as i64;
        let res = extra.calc_ban_time(600.0, count, || 0.0).unwrap();
        assert_eq!(res.as_i64().unwrap(), exp, "failed at count {count}");
    }

    // 2. extra large max time (30 days):
    extra.set_opt("maxtime", Some("30d")).unwrap();
    let expected_30d = [
        1200, 2400, 4800, 9600, 19200, 38400, 76800, 153600, 307200, 614400,
    ];
    for (i, &exp) in expected_30d.iter().enumerate() {
        let count = (i + 1) as i64;
        let res = extra.calc_ban_time(600.0, count, || 0.0).unwrap();
        assert_eq!(
            res.as_i64().unwrap(),
            exp,
            "failed at count {count} with 30d"
        );
    }

    // 3. factor 2:
    extra.set_opt("maxtime", Some("1d")).unwrap();
    extra.set_opt("factor", Some("2")).unwrap();
    let expected_factor2 = [
        2400, 4800, 9600, 19200, 38400, 76800, 86400, 86400, 86400, 86400,
    ];
    for (i, &exp) in expected_factor2.iter().enumerate() {
        let count = (i + 1) as i64;
        let res = extra.calc_ban_time(600.0, count, || 0.0).unwrap();
        assert_eq!(
            res.as_i64().unwrap(),
            exp,
            "failed at count {count} with factor 2"
        );
    }

    // 4. factor float 1.33:
    extra.set_opt("factor", Some("1.33")).unwrap();
    let expected_factor_float = [
        1596, 3192, 6384, 12768, 25536, 51072, 86400, 86400, 86400, 86400,
    ];
    for (i, &exp) in expected_factor_float.iter().enumerate() {
        let count = (i + 1) as i64;
        let res = extra.calc_ban_time(600.0, count, || 0.0).unwrap();
        assert_eq!(
            res.as_f64().floor() as i64,
            exp,
            "failed at count {count} with factor 1.33"
        );
    }

    // 5. max time 12 hours:
    extra.set_opt("factor", None).unwrap();
    extra.set_opt("maxtime", Some("12h")).unwrap();
    let expected_12h = [
        1200, 2400, 4800, 9600, 19200, 38400, 43200, 43200, 43200, 43200,
    ];
    for (i, &exp) in expected_12h.iter().enumerate() {
        let count = (i + 1) as i64;
        let res = extra.calc_ban_time(600.0, count, || 0.0).unwrap();
        assert_eq!(
            res.as_i64().unwrap(),
            exp,
            "failed at count {count} with 12h"
        );
    }

    // 6. randomization (rndtime = 5m):
    extra.set_opt("maxtime", Some("24h")).unwrap();
    extra.set_opt("rndtime", Some("5m")).unwrap();
    let with_rnd = extra.calc_ban_time(600.0, 1, || 0.5).unwrap();
    // 600 * 2 = 1200 + 0.5 * 300 = 1350
    assert_eq!(with_rnd.as_f64(), 1350.0);
}

/// Port of `testMultipliers`.
#[test]
fn test_multipliers() {
    let mut extra = BanExtra::new();
    extra.set_opt("increment", Some("true")).unwrap();
    extra.set_opt("maxtime", Some("30d")).unwrap();
    extra
        .set_opt("multipliers", Some("1 2 4 8 16 32 64 128 256"))
        .unwrap();

    // Multipliers stop growing after count 8 (length 9):
    let expected = [
        1200, 2400, 4800, 9600, 19200, 38400, 76800, 153600, 153600, 153600,
    ];
    for (i, &exp) in expected.iter().enumerate() {
        let count = (i + 1) as i64;
        let res = extra.calc_ban_time(600.0, count, || 0.0).unwrap();
        assert_eq!(
            res.as_i64().unwrap(),
            exp,
            "failed at count {count} with multipliers"
        );
    }
}

/// Port of `testFormula` with exponential formula.
#[test]
fn test_custom_formula() {
    let mut extra = BanExtra::new();
    extra.set_opt("increment", Some("true")).unwrap();
    extra.set_opt("maxtime", Some("24h")).unwrap();
    extra
        .set_opt(
            "formula",
            Some("ban.Time * math.exp(float(ban.Count+1)*banFactor)/math.exp(1*banFactor)"),
        )
        .unwrap();
    extra.set_opt("factor", Some("2.0 / 2.885385")).unwrap();

    let expected_24h = [
        1200, 2400, 4800, 9600, 19200, 38400, 76800, 86400, 86400, 86400,
    ];
    for (i, &exp) in expected_24h.iter().enumerate() {
        let count = (i + 1) as i64;
        let res = extra.calc_ban_time(600.0, count, || 0.0).unwrap();
        assert_eq!(res.as_f64() as i64, exp, "failed formula at count {count}");
    }

    extra.set_opt("maxtime", Some("30d")).unwrap();
    let expected_30d = [
        1200, 2400, 4800, 9600, 19200, 38400, 76800, 153601, 307203, 614407,
    ];
    for (i, &exp) in expected_30d.iter().enumerate() {
        let count = (i + 1) as i64;
        let res = extra.calc_ban_time(600.0, count, || 0.0).unwrap();
        assert_eq!(
            res.as_f64() as i64,
            exp,
            "failed formula at count {count} with 30d"
        );
    }
}

/// Port of `BanTimeIncrDB::testBanTimeIncr`.
#[test]
fn test_database_bantime_increment() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("f2b_test_observer.db");
    let db = Arc::new(Fail2BanDb::open(&db_path, 86400).unwrap());

    let mut jail = make_test_jail("test_jail");
    jail.actions.ban_manager.set_ban_time(10);
    jail.set_ban_time_extra("increment", Some("true")).unwrap();
    jail.set_ban_time_extra(
        "multipliers",
        Some("1 2 4 8 16 32 64 128 256 512 1024 2048"),
    )
    .unwrap();
    jail.set_database(Some(db.clone()));
    db.add_jail(&jail.name).unwrap();

    let ip = IPAddr::new("192.0.2.1").unwrap();
    let stime = 1000.0;
    let mut ticket = BanTicket::new(ip.clone(), stime);

    // 1. Ticket not yet found in database -> returns base ban time 10
    let b1 = Observer::incr_ban_time(
        &jail.name,
        &jail.ban_extra,
        Some(&db),
        10,
        &mut ticket,
        stime,
    );
    assert_eq!(b1, 10);

    // 2. Add first ban to database
    ticket.ticket_mut().set_ban_count(1, true);
    ticket.ticket_mut().set_ban_time(10);
    db.add_ban(&jail.name, &ticket, 10).unwrap();

    let queried = db
        .get_ban("192.0.2.1", Some(&jail.name), false, None, None, stime)
        .unwrap();
    assert_eq!(queried, Some((1, stime, 10)));

    // 3. Second ban for same IP -> increment to 20
    let mut ticket2 = BanTicket::new(ip.clone(), stime + 15.0);
    let b2 = Observer::incr_ban_time(
        &jail.name,
        &jail.ban_extra,
        Some(&db),
        10,
        &mut ticket2,
        stime + 15.0,
    );
    assert_eq!(b2, 20);
    assert_eq!(ticket2.ticket().ban_count(), 2);
    db.add_ban(&jail.name, &ticket2, 20).unwrap();

    let queried2 = db
        .get_ban(
            "192.0.2.1",
            Some(&jail.name),
            false,
            None,
            None,
            stime + 15.0,
        )
        .unwrap();
    assert_eq!(queried2, Some((2, stime + 15.0, 20)));

    // 4. Successive increments doubling each time
    let mut last_ban_time = 20i64;
    let mut current_time = stime + 15.0;
    for _ in 0..10 {
        current_time += last_ban_time as f64 + 5.0;
        let mut t = BanTicket::new(ip.clone(), current_time);
        let bt = Observer::incr_ban_time(
            &jail.name,
            &jail.ban_extra,
            Some(&db),
            10,
            &mut t,
            current_time,
        );
        assert_eq!(bt, last_ban_time * 2);
        db.add_ban(&jail.name, &t, bt).unwrap();
        last_ban_time = bt;
    }

    // 5. Test overalljails across two jails
    let mut jail2 = make_test_jail("test_jail_2");
    jail2.set_ban_time_extra("increment", Some("true")).unwrap();
    jail2
        .set_ban_time_extra("overalljails", Some("true"))
        .unwrap();
    jail2.set_database(Some(db.clone()));
    db.add_jail(&jail2.name).unwrap();

    // Query across all jails
    let overall = db
        .get_ban("192.0.2.1", None, true, None, None, current_time)
        .unwrap();
    assert!(overall.is_some());
    let (total_count, max_tob, _) = overall.unwrap();
    assert_eq!(total_count, 12);
    assert_eq!(max_tob, current_time);
}

/// Port of `BanTimeIncrDB::testObserver` testing bad IP acceleration.
#[test]
fn test_observer_failure_found_bad_ip_acceleration() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("f2b_bad_ip.db");
    let db = Arc::new(Fail2BanDb::open(&db_path, 86400).unwrap());

    let mut jail = make_test_jail("sshd");
    jail.actions.ban_manager.set_ban_time(10);
    jail.set_ban_time_extra("increment", Some("true")).unwrap();
    jail.set_database(Some(db.clone()));
    db.add_jail(&jail.name).unwrap();

    let ip = IPAddr::new("192.0.2.1").unwrap();
    let stime = 1000.0;
    let mut ticket = FailTicket::new(ip.clone(), stime);

    // Initial failures: 3 failures needed for maxretry=3
    jail.fail_manager.set_max_retry(3);
    let attempts1 = jail.fail_manager.add_failure(ticket.clone(), 1);
    Observer::failure_found(
        &jail.name,
        &jail.ban_extra,
        Some(&db),
        &mut jail.fail_manager,
        &mut jail.actions,
        &mut ticket,
        stime,
    );
    assert_eq!(attempts1, 1);
    assert_eq!(ticket.ticket().ban_count(), 0);

    // Manually register that this IP was previously banned 4 times in the DB (making it a bad IP)
    let mut prev_ban = BanTicket::new(ip.clone(), stime - 100.0);
    prev_ban.ticket_mut().set_ban_count(4, true);
    prev_ban.ticket_mut().set_ban_time(160);
    db.add_ban(&jail.name, &prev_ban, 160).unwrap();

    // Now test a new failure arriving for this bad IP at stime + 10.0:
    let mut bad_ticket = FailTicket::new(ip.clone(), stime + 10.0);
    jail.fail_manager.del_failure(&ip); // Reset failmanager attempts

    let initial_attempt = jail.fail_manager.add_failure(bad_ticket.clone(), 1);
    assert_eq!(initial_attempt, 1);

    Observer::failure_found(
        &jail.name,
        &jail.ban_extra,
        Some(&db),
        &mut jail.fail_manager,
        &mut jail.actions,
        &mut bad_ticket,
        stime + 10.0,
    );

    // Because the IP was banned 4 times, retryCount = (1 << 4) / 2 + 1 = 9, capped at max_retry = 3
    // It added (3 - 1) = 2 retries, immediately bringing attempts to 3 (>= max_retry)!
    // And triggered a ban!
    assert!(jail.actions.ban_manager.in_ban_list(&ip));
    let banned_ticket = jail.actions.ban_manager.get_ticket(&ip).unwrap();
    assert_eq!(banned_ticket.ticket().ban_count(), 5);
}

/// Differential oracle test: compares Rust calculations directly against Python `fail2ban.server.observer`.
#[test]
fn test_python_differential_observer() {
    let root = repo_root();
    let python_script = r#"
import sys
from fail2ban.server.observer import ObserverThread
from fail2ban.tests.dummyjail import DummyJail

jail = DummyJail()
jail.setBanTimeExtra('increment', 'true')
jail.setBanTimeExtra('maxtime', '24h')
obs = ObserverThread()

results = []
for factor in ['1', '2', '1.33']:
    jail.setBanTimeExtra('factor', factor)
    for c in range(1, 11):
        results.append(int(obs.calcBanTime(jail, 600, c)))

print(','.join(map(str, results)))
"#;

    let output = Command::new("python3")
        .env("PYTHONPATH", root.join("fail2ban"))
        .arg("-c")
        .arg(python_script)
        .output()
        .expect("failed to run python observer");

    assert!(output.status.success(), "python failed: {:?}", output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let py_values: Vec<i64> = stdout
        .trim()
        .split(',')
        .map(|s| s.parse().unwrap())
        .collect();

    let mut rust_values = Vec::new();
    let mut extra = BanExtra::new();
    extra.set_opt("increment", Some("true")).unwrap();
    extra.set_opt("maxtime", Some("24h")).unwrap();

    for factor in ["1", "2", "1.33"] {
        extra.set_opt("factor", Some(factor)).unwrap();
        for c in 1..=10 {
            let res = extra.calc_ban_time(600.0, c, || 0.0).unwrap();
            rust_values.push(res.as_f64().floor() as i64);
        }
    }

    assert_eq!(
        rust_values, py_values,
        "Rust observer calculations differ from Python!"
    );
}

/// Boundary condition test verifying formula stops growing at Count >= 20.
#[test]
fn test_boundary_count_20_21() {
    let mut extra = BanExtra::new();
    extra.set_opt("increment", Some("true")).unwrap();
    extra.set_opt("maxtime", None).unwrap(); // no clamping

    let at_19 = extra.calc_ban_time(600.0, 19, || 0.0).unwrap();
    let at_20 = extra.calc_ban_time(600.0, 20, || 0.0).unwrap();
    let at_21 = extra.calc_ban_time(600.0, 21, || 0.0).unwrap();
    let at_25 = extra.calc_ban_time(600.0, 25, || 0.0).unwrap();

    assert_eq!(at_19.as_i64().unwrap(), 600 * (1 << 19));
    assert_eq!(at_20.as_i64().unwrap(), 600 * (1 << 20));
    assert_eq!(at_21.as_i64().unwrap(), 600 * (1 << 20)); // Stops growing!
    assert_eq!(at_25.as_i64().unwrap(), 600 * (1 << 20));
}
