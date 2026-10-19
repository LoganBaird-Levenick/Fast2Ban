use f2b_action::{ActionInfo, Actions, CommandAction, TagReplacer, build_shell_cmd, execute_cmd};
use f2b_types::{BanTicket, IPAddr};
use indexmap::IndexMap;
use std::time::Duration;

#[test]
fn test_build_shell_cmd_and_execute() {
    let vars = vec![
        ("f2bV_ip".to_owned(), "192.0.2.1; rm -rf /".to_owned()),
        ("f2bV_user".to_owned(), "admin$(whoami)".to_owned()),
    ];
    let (script, args) = build_shell_cmd("echo IP=$f2bV_ip USER=$f2bV_user", &vars);
    assert_eq!(args, vec!["192.0.2.1; rm -rf /", "admin$(whoami)"]);
    assert!(script.starts_with("f2bV_ip=$0 f2bV_user=$1 \n"));

    let res = execute_cmd(&script, Duration::from_secs(5), &vars).unwrap();
    assert!(res.success);
    assert_eq!(res.status, 0);
    assert_eq!(
        res.stdout.trim(),
        "IP=192.0.2.1; rm -rf / USER=admin$(whoami)"
    );
}

#[test]
fn test_execute_timeout() {
    let res = execute_cmd("sleep 10", Duration::from_millis(50), &[]);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("timed out"));
}

#[test]
fn test_dynamic_tag_replacement_and_injection_defense() {
    let ip = IPAddr::new("192.0.2.5").unwrap();
    let mut ticket = BanTicket::new(ip, 123456.0);
    ticket.ticket_mut().set_failures(4);
    ticket.ticket_mut().set_ban_time(3600);
    ticket.ticket_mut().set_ban_count(2, true);
    ticket
        .ticket_mut()
        .set_matches(vec!["malicious; `cat /etc/passwd`".into()]);
    ticket
        .ticket_mut()
        .data_mut()
        .insert("user".into(), "guest' OR 1=1".into());

    let ainfo = ActionInfo::from_ticket(&ticket, "sshd", 600);

    let mut props = IndexMap::new();
    props.insert("port".to_owned(), "22".to_owned());
    props.insert("name".to_owned(), "sshd".to_owned());

    let template = "iptables -A f2b-<name> -p tcp --dport <port> -s <ip> -m comment --comment '<matches>' -j DROP; echo <F-USER>";
    let (cmd, vars) = TagReplacer::replace_dynamic_tags(template, Some(&ainfo), &props);

    // Verified: untrusted <matches> and <F-USER> were replaced by safe shell variables
    assert!(cmd.contains("$f2bV_matches"));
    assert!(cmd.contains("$f2bV_F_user"));
    assert!(cmd.contains("-s 192.0.2.5"));
    assert!(cmd.contains("--dport 22"));

    let var_map: std::collections::HashMap<_, _> = vars.into_iter().collect();
    assert_eq!(var_map["f2bV_matches"], "malicious; `cat /etc/passwd`");
    assert_eq!(var_map["f2bV_F_user"], "guest' OR 1=1");
}

#[test]
fn test_action_lifecycle_and_actions_coordinator() {
    let mut actions = Actions::new("testjail");
    actions.ban_manager.set_ban_time(600);

    let mut act = CommandAction::new("testjail", "dummy");
    act.actionstart = "echo start".to_owned();
    act.actionstop = "echo stop".to_owned();
    act.actionban = "echo ban <ip>".to_owned();
    act.actionunban = "echo unban <ip>".to_owned();
    act.actionflush = "echo flush".to_owned();

    actions.add_action(act);

    // Initial start
    actions.start().unwrap();
    assert!(actions.get_action("dummy").unwrap().is_started("inet4"));

    // Ban
    let ip = IPAddr::new("192.0.2.100").unwrap();
    let mut ticket = BanTicket::new(ip.clone(), 1000.0);
    let banned = actions.ban(&mut ticket, 1000.0).unwrap();
    assert!(banned);
    assert!(ticket.ticket().is_banned());
    assert_eq!(actions.ban_manager.size(), 1);

    // Duplicate ban while active returns false
    let mut ticket_dup = BanTicket::new(ip.clone(), 1000.0);
    let banned_again = actions.ban(&mut ticket_dup, 1000.0).unwrap();
    assert!(!banned_again);

    // Unban
    let unbanned_count = actions.check_unban(1700.0, None).unwrap();
    assert_eq!(unbanned_count, 1);
    assert_eq!(actions.ban_manager.size(), 0);

    // Stop
    actions.stop().unwrap();
    assert!(!actions.get_action("dummy").unwrap().is_started("inet4"));
}
