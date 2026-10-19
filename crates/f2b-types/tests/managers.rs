use f2b_types::{BanManager, BanReason, BanTicket, FailManager, FailTicket, IPAddr};

#[test]
fn test_failmanager_and_ticket() {
    let mut fm = FailManager::new();
    fm.set_max_retry(3);
    fm.set_max_time(600.0);
    fm.set_max_matches(2);

    let ip = IPAddr::new("192.0.2.1").unwrap();
    let mut t1 = FailTicket::new(ip.clone(), 1000.0);
    t1.ticket_mut().set_matches(vec!["match 1".into()]);

    assert_eq!(fm.add_failure(t1, 1), 1);
    assert_eq!(fm.size(), 1);
    assert_eq!(fm.fail_total(), 1);

    // Second failure
    let mut t2 = FailTicket::new(ip.clone(), 1050.0);
    t2.ticket_mut().set_matches(vec!["match 2".into()]);
    assert_eq!(fm.add_failure(t2, 1), 2);
    assert_eq!(fm.fail_total(), 2);

    // Third failure -> ready to ban
    let mut t3 = FailTicket::new(ip.clone(), 1100.0);
    t3.ticket_mut().set_matches(vec!["match 3".into()]);
    assert_eq!(fm.add_failure(t3, 1), 3);

    let to_ban = fm.to_ban(None).expect("ready to ban");
    assert_eq!(to_ban.id(), &ip);
    assert_eq!(to_ban.retry(), 3);
    // Truncated to max_matches = 2
    assert_eq!(to_ban.ticket().matches(), &["match 2", "match 3"]);
    assert_eq!(fm.size(), 0);

    // Cleanup removes old
    let ip2 = IPAddr::new("192.0.2.2").unwrap();
    let t4 = FailTicket::new(ip2.clone(), 500.0);
    fm.add_failure(t4, 1);
    assert_eq!(fm.size(), 1);
    fm.cleanup(1200.0); // 1200 - 600 = 600 cutoff, 500 is older
    assert_eq!(fm.size(), 0);
}

#[test]
fn test_banmanager() {
    let mut bm = BanManager::new();
    bm.set_ban_time(600);

    let ip1 = IPAddr::new("192.0.2.10").unwrap();
    let t1 = BanTicket::new(ip1.clone(), 1000.0);

    let (added, reason) = bm.add_ban_ticket(t1, 1000.0);
    assert!(added);
    assert_eq!(reason, BanReason::Ok);
    assert_eq!(bm.size(), 1);
    assert_eq!(bm.ban_total(), 1);

    // Duplicate ticket with same time: not prolonged
    let t1_same = BanTicket::new(ip1.clone(), 1000.0);
    let (added, reason) = bm.add_ban_ticket(t1_same, 1000.0);
    assert!(!added);
    assert_eq!(reason, BanReason::AlreadyBanned { prolonged: false });

    // Duplicate ticket with later time: prolonged
    let t1_later = BanTicket::new(ip1.clone(), 1050.0);
    let (added, reason) = bm.add_ban_ticket(t1_later, 1050.0);
    assert!(!added);
    assert_eq!(reason, BanReason::AlreadyBanned { prolonged: true });
    // Expired ticket should not be added
    let ip2 = IPAddr::new("192.0.2.20").unwrap();
    let t2 = BanTicket::new(ip2.clone(), 100.0);
    let (added, reason) = bm.add_ban_ticket(t2, 1000.0); // eob is 700 < 1000
    assert!(!added);
    assert_eq!(reason, BanReason::Expired);

    // Unbanning
    // At t = 1500, ip1 (eob = 1600) is not yet unbanned
    let unbanned = bm.unban_list(1500.0, None);
    assert!(unbanned.is_empty());
    assert_eq!(bm.size(), 1);

    // At t = 1651, ip1 is unbanned (prolonged eob was 1650)
    let unbanned = bm.unban_list(1651.0, None);
    assert_eq!(unbanned.len(), 1);
    assert_eq!(unbanned[0].id(), &ip1);
    assert_eq!(bm.size(), 0);
}

#[test]
fn test_permanent_ban() {
    let mut bm = BanManager::new();
    bm.set_ban_time(-1);

    let ip = IPAddr::new("192.0.2.99").unwrap();
    let t = BanTicket::new(ip.clone(), 1000.0);

    let (added, _) = bm.add_ban_ticket(t, 1000.0);
    assert!(added);

    // Far in the future
    let unbanned = bm.unban_list(1_000_000_000.0, None);
    assert!(unbanned.is_empty());
    assert_eq!(bm.size(), 1);
}
