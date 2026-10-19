use std::sync::Arc;
use tempfile::NamedTempFile;

use f2b_action::{CommandAction, Jail};
use f2b_backend::Backend;
use f2b_date::LocalZone;
use f2b_filter::Filter;
use f2b_types::{DnsUtils, FixedClock, IPAddr, SharedClock};
#[test]
fn test_jail_end_to_end_monitoring_and_banning() {
    let clock: SharedClock = Arc::new(FixedClock::new(1000.0));
    let dns = Arc::new(DnsUtils::system(clock.clone()));
    let zone = LocalZone::utc();

    let mut filter = Filter::new(clock.clone(), dns, zone);
    filter
        .add_fail_regex(r"^Failed password for .* from <HOST>$")
        .unwrap();
    filter.check_find_time = false;

    let backend = Backend::create("polling");
    let mut jail = Jail::new("ssh-jail", filter, backend, clock.clone());
    jail.fail_manager.set_max_retry(3);
    jail.actions.ban_manager.set_ban_time(600);

    // Mock action recording executed commands to a temporary file
    let log_file = NamedTempFile::new().unwrap();
    let log_path = log_file.path().to_str().unwrap().to_owned();

    let mut action = CommandAction::new("ssh-jail", "mock-action");
    action.actionstart = format!("echo 'START' >> {log_path}");
    action.actionstop = format!("echo 'STOP' >> {log_path}");
    action.actionban = format!("echo 'BAN <ip>' >> {log_path}");
    action.actionunban = format!("echo 'UNBAN <ip>' >> {log_path}");

    jail.actions.add_action(action);
    jail.start().unwrap();

    // 1st failure: attempt 1, 0 bans
    let b1 = jail
        .process_line("Failed password for root from 192.0.2.1", 1000.0)
        .unwrap();
    assert_eq!(b1, 0);
    assert_eq!(jail.fail_manager.size(), 1);
    assert_eq!(jail.actions.ban_manager.size(), 0);

    // 2nd failure: attempt 2, 0 bans
    let b2 = jail
        .process_line("Failed password for root from 192.0.2.1", 1010.0)
        .unwrap();
    assert_eq!(b2, 0);

    // 3rd failure: reaches maxretry (3) -> BAN!
    let b3 = jail
        .process_line("Failed password for root from 192.0.2.1", 1020.0)
        .unwrap();
    assert_eq!(b3, 1);
    assert_eq!(jail.actions.ban_manager.size(), 1);
    assert!(
        jail.actions
            .ban_manager
            .in_ban_list(&IPAddr::new("192.0.2.1").unwrap())
    );

    // Check actions file content
    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(content.contains("START"));
    assert!(content.contains("BAN 192.0.2.1"));

    // Step at t = 1500 (still banned, eob is 1020 + 600 = 1620)
    jail.step(1500.0).unwrap();
    assert_eq!(jail.actions.ban_manager.size(), 1);

    // Step at t = 1625 -> UNBAN!
    jail.step(1625.0).unwrap();
    assert_eq!(jail.actions.ban_manager.size(), 0);

    let content_after = std::fs::read_to_string(&log_path).unwrap();
    assert!(content_after.contains("UNBAN 192.0.2.1"));

    // Stop jail
    jail.stop().unwrap();
    let content_final = std::fs::read_to_string(&log_path).unwrap();
    assert!(content_final.contains("STOP"));
}

#[test]
fn test_jail_ignore_ip_and_ignore_command() {
    let clock: SharedClock = Arc::new(FixedClock::new(1000.0));
    let dns = Arc::new(DnsUtils::system(clock.clone()));
    let zone = LocalZone::utc();

    let mut filter = Filter::new(clock.clone(), dns, zone);
    filter
        .add_fail_regex(r"^Failed password for .* from <HOST>$")
        .unwrap();
    filter.check_find_time = false;

    let backend = Backend::create("polling");
    let mut jail = Jail::new("ssh-jail-ignore", filter, backend, clock);
    jail.fail_manager.set_max_retry(1); // 1 attempt bans if not ignored

    // Ignore subnet
    jail.add_ignore_ip("192.0.2.0/24").unwrap();

    // Line from ignored IP should not register any failure
    let bans = jail
        .process_line("Failed password for root from 192.0.2.55", 1000.0)
        .unwrap();
    assert_eq!(bans, 0);
    assert_eq!(jail.fail_manager.size(), 0);

    // Test external ignorecommand: ignore 10.0.0.99
    jail.set_ignore_command(Some("/bin/sh -c 'test \"<ip>\" = \"10.0.0.99\"'".into()));

    let bans2 = jail
        .process_line("Failed password for root from 10.0.0.99", 1000.0)
        .unwrap();
    assert_eq!(bans2, 0);
    assert_eq!(jail.fail_manager.size(), 0);

    // Non-ignored IP gets banned
    let bans3 = jail
        .process_line("Failed password for root from 10.0.0.1", 1000.0)
        .unwrap();
    assert_eq!(bans3, 1);
    assert_eq!(jail.actions.ban_manager.size(), 1);
}
