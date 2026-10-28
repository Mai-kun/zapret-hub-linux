//! Live routing through a real proxy: every test needs root (the nftables table) and
//! `ROUTER_SOCKS5` set to a working local SOCKS5 proxy.
use router::rules::{self, Protocol, Rule};
use router::{Router, RouterState, Setup, parse_proxy};
use std::net::UdpSocket;
use std::time::Duration;

/// A router running one rule. The traffic under test comes from child processes: the router
/// leaves this process's own sockets alone (`Loop`).
fn running(rule: Rule) -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().unwrap();
    let r = Router::new(dir.path().join("routes.toml"));
    r.edit(|list| rules::add(list, rule)).unwrap();
    let proxy = parse_proxy(std::env::var("ROUTER_SOCKS5").ok().as_deref()).unwrap();
    r.start(Setup { proxy }).unwrap();
    assert_eq!(r.status().state, RouterState::Running);
    (dir, r)
}

/// `curl` fetches `http://<ip>/`; returns its output.
fn curl(ip: &str, host: &str) -> String {
    let out = std::process::Command::new("curl")
        .args(["-s", "-i", "--http1.1", "--max-time", "10", "-H"])
        .arg(format!("Host: {host}"))
        .args(["-H", "Connection: close"])
        .arg(format!("http://{ip}/"))
        .output()
        .expect("curl runs");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
#[ignore = "needs root and ROUTER_SOCKS5 (a working proxy) set"]
fn a_running_router_carries_tcp_through_the_proxy() {
    use router::flows::Via;

    let (_dir, r) = running(Rule {
        name: "web".into(),
        enabled: true,
        protocol: Protocol::Tcp,
        ports: vec!["80".into()],
        ips: vec!["1.1.1.1/32".into()],
        domains: vec![],
        apps: vec![],
    });
    let reply = curl("1.1.1.1", "1.1.1.1");
    assert!(reply.starts_with("HTTP/1.1"), "{reply}");
    let rows = r.flows(false);
    let row = rows
        .iter()
        .find(|f| f.protocol == "tcp" && f.destination == "1.1.1.1:80")
        .unwrap_or_else(|| panic!("no flow row: {rows:?}"));
    assert_eq!(row.via, Via::Proxy, "{row:?}");
    assert!(row.down > 0.0, "{row:?}");
    r.stop();
    assert_eq!(r.status().state, RouterState::Off);
}

#[test]
#[ignore = "needs root and ROUTER_SOCKS5 (a working proxy) set"]
fn a_domain_rule_follows_dns() {
    use router::flows::Via;

    let (_dir, r) = running(Rule {
        name: "one".into(),
        enabled: true,
        protocol: Protocol::Both,
        ports: vec!["80".into()],
        ips: vec![],
        domains: vec!["one.one.one.one".into()],
        apps: vec![],
    });
    // Our own query, not the system resolver's cache: the sniffer watches the wire.
    let mut query = vec![0x43, 0x21, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for _ in 0..4 {
        query.extend_from_slice(b"\x03one");
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.send_to(&query, "1.1.1.1:53").unwrap();
    let mut buf = [0u8; 1500];
    let (n, _) = s.recv_from(&mut buf).expect("no DNS answer");
    let answer = router::dns::parse(&buf[..n]).expect("a DNS answer");
    let ip = answer.ips.first().expect("an A record").0.to_string();
    std::thread::sleep(Duration::from_millis(1500)); // the table re-applies with the new address

    let reply = curl(&ip, "one.one.one.one");
    assert!(reply.starts_with("HTTP/1.1"), "{reply}");
    let rows = r.flows(false);
    let row = rows
        .iter()
        .find(|f| f.protocol == "tcp" && f.destination == format!("{ip}:80"))
        .unwrap_or_else(|| panic!("no flow row: {rows:?}"));
    assert_eq!(row.domain.as_deref(), Some("one.one.one.one"), "{row:?}");
    assert_eq!(row.via, Via::Proxy, "{row:?}");
    r.stop();
}

#[test]
#[ignore = "needs root and ROUTER_SOCKS5 (a working proxy) set"]
fn an_app_rule_follows_curl() {
    use router::flows::Via;

    let (_dir, r) = running(Rule {
        name: "curl".into(),
        enabled: true,
        protocol: Protocol::Tcp,
        ports: vec!["80".into()],
        ips: vec!["1.1.1.1/32".into()],
        domains: vec![],
        apps: vec!["curl".into()],
    });
    let is_curl = |p: &Option<String>| p.as_deref().is_some_and(|p| p.ends_with("curl"));
    let reply = curl("1.1.1.1", "1.1.1.1");
    assert!(reply.starts_with("HTTP/1.1"), "{reply}");
    let rows = r.flows(false);
    let row = rows
        .iter()
        .find(|f| f.protocol == "tcp" && f.destination == "1.1.1.1:80")
        .unwrap_or_else(|| panic!("no flow row: {rows:?}"));
    assert_eq!(row.via, Via::Proxy, "{row:?}");
    assert!(is_curl(&row.program), "{row:?}");

    r.edit(|list| {
        list[0].apps = vec!["nothing-here".into()];
        Ok(())
    })
    .unwrap();
    let ruled = r.flows(false).len();
    let reply = curl("1.1.1.1", "1.1.1.1");
    assert!(reply.starts_with("HTTP/1.1"), "{reply}");
    let rows = r.flows(true);
    assert!(
        rows.iter()
            .any(|f| f.destination == "1.1.1.1:80" && f.rule.is_none() && is_curl(&f.program)),
        "no rule-less row: {rows:?}"
    );
    assert_eq!(r.flows(false).len(), ruled, "no new ruled rows");
    r.stop();
}
