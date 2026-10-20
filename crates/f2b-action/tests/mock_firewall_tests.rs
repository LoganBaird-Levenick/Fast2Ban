use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::rc::Rc;
use tempfile::tempdir;

use f2b_action::{Actions, CommandAction};
use f2b_config::{Arg, ConfigReader, DefinitionReader, RealFs};
use f2b_types::{BanTicket, IPAddr};
use indexmap::IndexMap;

#[test]
fn test_stock_dummy_action_from_config() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let basedir = root.join("fail2ban/config");
    if !basedir.is_dir() {
        eprintln!("fail2ban/config missing; skipping test");
        return;
    }

    let tmp = tempdir().unwrap();
    let dummy_target = tmp.path().join("dummy.target");

    let mut init = IndexMap::new();
    init.insert(
        "target".to_owned(),
        dummy_target.to_str().unwrap().to_owned(),
    );

    let share = Rc::new(std::cell::RefCell::new(std::collections::HashMap::new()));
    let mut reader = DefinitionReader::action(
        "dummy",
        "myjail",
        init,
        ConfigReader::with_share(
            Rc::new(RealFs),
            share,
            Some(basedir.to_str().unwrap().to_owned()),
        ),
    );
    assert!(reader.read().unwrap());
    reader.get_options(&IndexMap::new(), false).unwrap();
    let cmds = reader.convert().unwrap();

    let mut action = CommandAction::new("myjail", "dummy");
    for cmd in cmds {
        if cmd.get(2) == Some(&Arg::Str("action".to_owned())) {
            if let Some(Arg::List(pairs)) = cmd.get(4) {
                for pair in pairs {
                    if let Arg::List(p) = pair {
                        if let (Some(Arg::Str(k)), Some(Arg::Str(v))) = (p.first(), p.get(1)) {
                            action.set_property(k.clone(), v.clone());
                        }
                    }
                }
            }
        }
    }

    assert!(action.actionstart.contains("touch "));
    assert!(action.actionban.contains("+<ip>"));
    assert!(action.actionunban.contains("-<ip>"));

    let mut actions = Actions::new("myjail");
    actions.ban_manager.set_ban_time(600);
    actions.add_action(action);

    // Start creates target file with init value 123
    actions.start().unwrap();
    assert!(dummy_target.exists());
    let content = fs::read_to_string(&dummy_target).unwrap();
    assert!(content.contains("123"));

    // Ban adds +<ip>
    let ip = IPAddr::new("192.0.2.1").unwrap();
    let mut ticket = BanTicket::new(ip.clone(), 1000.0);
    actions.ban(&mut ticket, 1000.0).unwrap();
    let content = fs::read_to_string(&dummy_target).unwrap();
    assert!(content.contains("+192.0.2.1"));

    // Unban adds -<ip>
    actions.unban(&ticket).unwrap();
    let content = fs::read_to_string(&dummy_target).unwrap();
    assert!(content.contains("-192.0.2.1"));

    // Stop removes target file
    actions.stop().unwrap();
    assert!(!dummy_target.exists());
}

#[test]
fn test_mock_iptables_firewall_command_sequence() {
    // Set up a mock `iptables` binary in a temporary directory
    let tmp = tempdir().unwrap();
    let mock_log = tmp.path().join("iptables.log");
    let mock_iptables = tmp.path().join("iptables");

    let script = format!(
        "#!/bin/sh\n\
         echo \"$@\" >> \"{}\"\n\
         exit 0\n",
        mock_log.display()
    );
    fs::write(&mock_iptables, script).unwrap();
    let mut perms = fs::metadata(&mock_iptables).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&mock_iptables, perms).unwrap();

    // Read stock iptables-multiport action
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let basedir = root.join("fail2ban/config");
    if !basedir.is_dir() {
        eprintln!("fail2ban/config missing; skipping test");
        return;
    }

    let mut init = IndexMap::new();
    init.insert("name".to_owned(), "SSH".to_owned());
    init.insert("port".to_owned(), "22".to_owned());
    init.insert("protocol".to_owned(), "tcp".to_owned());

    let share = Rc::new(std::cell::RefCell::new(std::collections::HashMap::new()));
    let mut reader = DefinitionReader::action(
        "iptables-multiport",
        "ssh-jail",
        init,
        ConfigReader::with_share(
            Rc::new(RealFs),
            share,
            Some(basedir.to_str().unwrap().to_owned()),
        ),
    );
    assert!(reader.read().unwrap());
    reader.get_options(&IndexMap::new(), false).unwrap();
    let cmds = reader.convert().unwrap();

    let mut action = CommandAction::new("ssh-jail", "iptables-multiport");
    for cmd in cmds {
        if cmd.get(2) == Some(&Arg::Str("action".to_owned())) {
            if let Some(Arg::List(pairs)) = cmd.get(4) {
                for pair in pairs {
                    if let Arg::List(p) = pair {
                        if let (Some(Arg::Str(k)), Some(Arg::Str(v))) = (p.first(), p.get(1)) {
                            action.set_property(k.clone(), v.clone());
                        }
                    }
                }
            }
        }
    }

    // Set property iptables command to mock path
    action.set_property("iptables", mock_iptables.to_str().unwrap());

    let mut actions = Actions::new("ssh-jail");
    actions.ban_manager.set_ban_time(600);
    actions.add_action(action);

    // Lifecycle
    actions.start().unwrap();

    let ip = IPAddr::new("198.51.100.42").unwrap();
    let mut ticket = BanTicket::new(ip.clone(), 1000.0);
    actions.ban(&mut ticket, 1000.0).unwrap();

    actions.unban(&ticket).unwrap();

    actions.stop().unwrap();

    // Verify commands recorded by mock iptables
    let log_content = fs::read_to_string(&mock_log).unwrap();
    let invocations: Vec<&str> = log_content.trim().split('\n').collect();

    // Check key iptables arguments
    assert!(invocations.iter().any(|line| line.contains("-N f2b-SSH")
        || line.contains("-A f2b-SSH")
        || line.contains("-C f2b-SSH")));
    assert!(
        invocations
            .iter()
            .any(|line| line.contains("-I f2b-SSH") && line.contains("-s 198.51.100.42"))
    );
    assert!(
        invocations
            .iter()
            .any(|line| line.contains("-D f2b-SSH") && line.contains("-s 198.51.100.42"))
    );
    assert!(
        invocations
            .iter()
            .any(|line| line.contains("-F f2b-SSH") || line.contains("-X f2b-SSH"))
    );
}
