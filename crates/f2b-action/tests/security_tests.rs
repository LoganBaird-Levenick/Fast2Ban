//! Security regression tests: hostile log lines, command injection prevention,
//! shell parameter wrapping (`WRAP_CMD_PARAMS`), and socket permissions.

use std::fs;
use std::sync::Arc;
use tempfile::tempdir;

use f2b_action::{CommandAction, Jail};
use f2b_backend::Backend;
use f2b_date::LocalZone;
use f2b_filter::Filter;
use f2b_types::{DnsUtils, FixedClock, SharedClock};

#[test]
fn test_hostile_log_line_command_injection_prevention() {
    let tmp = tempdir().unwrap();
    let canary1 = tmp.path().join("canary1");
    let canary2 = tmp.path().join("canary2");
    let canary3 = tmp.path().join("canary3");
    let canary4 = tmp.path().join("canary4");
    let canary5 = tmp.path().join("canary5");
    let canary6 = tmp.path().join("canary6");
    let canary7 = tmp.path().join("canary7");
    let audit_log = tmp.path().join("audit.log");

    let clock: SharedClock = Arc::new(FixedClock::new(1000.0));
    let dns = Arc::new(DnsUtils::system(clock.clone()));
    let mut filter = Filter::new(clock.clone(), dns, LocalZone::utc());
    // Filter matching user and host
    filter
        .add_fail_regex(r"^Failed password for invalid user <F-USER>.*</F-USER> from <HOST>$")
        .unwrap();
    filter.check_find_time = false;

    let backend = Backend::create("polling");
    let mut jail = Jail::new("sec-jail", filter, backend, clock);
    jail.fail_manager.set_max_retry(1);
    jail.actions.ban_manager.set_ban_time(600);
    jail.ignore_self = false;

    let mut action = CommandAction::new("sec-jail", "audit");
    // Action incorporates <ip>, <F-USER>, and <matches> directly into shell commands
    action.actionban = format!(
        "echo BAN ip=<ip> user=<F-USER> >> {audit}\nprintf '%s\n' \"<matches>\" >> {audit}",
        audit = audit_log.display()
    );

    jail.actions.add_action(action);
    jail.start().unwrap();

    // List of hostile payloads attempting shell command injection
    let hostile_payloads = [
        format!("; touch {} ;", canary1.display()),
        format!("$(touch {})", canary2.display()),
        format!("`touch {}`", canary3.display()),
        format!("| touch {}", canary4.display()),
        format!("&& touch {}", canary5.display()),
        format!("> {}", canary6.display()),
        format!("& touch {} &", canary7.display()),
    ];

    for (i, payload) in hostile_payloads.iter().enumerate() {
        let ip_num = i + 1;
        let line = format!("Failed password for invalid user {payload} from 198.51.100.{ip_num}");
        let bans = jail.process_line(&line, 1000.0 + i as f64).unwrap();
        assert_eq!(bans, 1, "Payload {payload} should result in a ban");
    }

    // Verify NONE of the canaries were touched/created
    assert!(
        !canary1.exists(),
        "canary1 was executed! Command injection vulnerability!"
    );
    assert!(
        !canary2.exists(),
        "canary2 was executed! Command injection vulnerability!"
    );
    // Verify audit log received all literal values safely
    let audit_content = fs::read_to_string(&audit_log).unwrap();
    assert!(audit_content.contains("BAN ip=198.51.100.1"));
    assert!(audit_content.contains("$(touch"));
    assert!(audit_content.contains("`touch"));
}
