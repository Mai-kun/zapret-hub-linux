//! The nftables `redirect` table of the router: rule generation, applying and removal (the live
//! part runs `nft` under root rights, directly or through `sudo -n`).

use crate::rules::{Protocol, Table};
use anyhow::{Context, Result, bail};
use std::io::Write;
use std::net::{SocketAddrV4, TcpStream};
use std::os::unix::io::AsRawFd as _;

/// The router's own table; nothing else touches it, so a full replace is safe.
pub const TABLE: &str = "inet zapret_router";
/// The mark of the acceptor's own sockets: packets carrying it are never redirected back
/// (loop protection for the hub's own connections and, through the acceptor, for the proxy's).
pub const MARK: u32 = 0x40000000;

/// Marks `stream` so the router's nftables table lets its packets pass. Needs
/// `CAP_NET_ADMIN`: the same rights applying the table needs.
pub fn mark(stream: &TcpStream) -> bool {
    set_mark(stream.as_raw_fd())
}

/// Whether sockets of this process may carry the mark at all (a rights probe).
pub fn mark_probe() -> bool {
    // SAFETY: a plain socket() call; the fd is closed on every way out.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return false;
    }
    let ok = set_mark(fd);
    // SAFETY: `fd` is owned and no longer used.
    unsafe { libc::close(fd) };
    ok
}

fn set_mark(fd: i32) -> bool {
    let mark: libc::c_uint = MARK;
    // SAFETY: `fd` is a live socket for the call; the pointer covers exactly the bytes of
    // `mark`. A failure only means the caller falls back to the loop-safe behaviour.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&raw const mark).cast(),
            size_of::<libc::c_uint>() as u32,
        ) == 0
    }
}

fn ranges(sets: &[(u32, u32)]) -> String {
    sets.iter()
        .map(|&(a, b)| {
            let (a, b) = (std::net::Ipv4Addr::from(a), std::net::Ipv4Addr::from(b));
            if a == b {
                a.to_string()
            } else {
                format!("{a}-{b}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn ports(sets: &[(u16, u16)]) -> String {
    sets.iter()
        .map(|&(a, b)| if a == b { a.to_string() } else { format!("{a}-{b}") })
        .collect::<Vec<_>>()
        .join(", ")
}

/// One TCP redirect line of a rule: `ip daddr {…} tcp dport {…} redirect to :acceptor`.
/// A rule with neither ranges nor ports redirects nothing. A domains-only rule waits for its
/// names to resolve (`with_names` adds them to the ranges); a ports-only rule (its targets are
/// the ports themselves) takes every destination.
fn redirect(rule: &crate::rules::Compiled, acceptor: u16) -> Option<String> {
    if rule.protocol == Protocol::Udp || (rule.ranges.is_empty() && rule.ports.is_empty()) {
        return None;
    }
    if rule.ranges.is_empty() && !rule.domains.is_empty() {
        return None;
    }
    let mut line = String::new();
    if !rule.ranges.is_empty() {
        line.push_str(&format!("ip daddr {{ {} }}", ranges(&rule.ranges)));
    }
    if !rule.ports.is_empty() {
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(&format!("tcp dport {{ {} }}", ports(&rule.ports)));
    }
    Some(format!("{line} redirect to :{acceptor}"))
}

/// The whole script `nft -f -` applies: the old table goes away, the new one replaces it in one
/// transaction, so live connections keep their redirections (conntrack holds them) and no packet
/// is redirected to a port nobody listens on.
pub fn script(table: &Table, proxy: SocketAddrV4, acceptor: u16) -> String {
    let mut out = format!(
        "table {TABLE}\ndelete table {TABLE}\ntable {TABLE} {{\n    chain output {{\n        \
         type nat hook output priority dstnat; policy accept;\n        \
         oifname \"lo\" accept\n        \
         meta mark & {MARK:#x} != 0 return\n"
    );
    let proxy_line = |proto: &str| {
        format!("        ip daddr {} {proto} dport {} return\n", proxy.ip(), proxy.port())
    };
    out.push_str(&proxy_line("tcp"));
    out.push_str(&proxy_line("udp"));
    for rule in &table.rules {
        if let Some(line) = redirect(rule, acceptor) {
            out.push_str("        ");
            out.push_str(&line);
            out.push('\n');
        }
    }
    out.push_str("    }\n}\n");
    out
}

/// The root-rights command to run: directly as root, else through `sudo -n`.
fn command(args: &[&str]) -> Result<std::process::Command> {
    if libc_matches_root() {
        let mut cmd = std::process::Command::new("nft");
        cmd.args(args);
        return Ok(cmd);
    }
    for wrapper in ["/usr/bin/sudo", "/usr/bin/pkexec"] {
        if std::fs::metadata(wrapper).is_ok() {
            let mut cmd = std::process::Command::new(wrapper);
            if wrapper.ends_with("sudo") {
                cmd.arg("-n");
            }
            cmd.arg("nft");
            cmd.args(args);
            return Ok(cmd);
        }
    }
    bail!("`nft` needs root rights: run Zapret Hub as root (sudo -E) or set up polkit/sudoers for it")
}

fn libc_matches_root() -> bool {
    // SAFETY: `geteuid` is a plain syscall without invariants.
    (unsafe { libc::geteuid() }) == 0
}

/// Feeds `script` to `nft -f -`.
pub fn apply(script: &str) -> Result<()> {
    let mut cmd = command(&["-f", "-"])?;
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::null());
    let mut child = cmd
        .spawn()
        .context("cannot run nft: is nftables installed?")?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).context("writing the nft script")?;
    }
    let out = child.wait().context("waiting for nft")?;
    if !out.success() {
        bail!("nft refused the router table (code {})", out.code().unwrap_or(-1));
    }
    Ok(())
}

/// Whether `nft` answers at all under this process's rights: a start can only succeed when it does.
pub fn can_apply() -> bool {
    command(&["list", "tables"])
        .and_then(|mut cmd| {
            cmd.stdout(std::process::Stdio::null());
            cmd.stderr(std::process::Stdio::null());
            Ok(cmd.status().map(|s| s.success()).unwrap_or(false))
        })
        .unwrap_or(false)
}

/// Removes the table; a missing one (never applied, or the process before us did) is fine.
pub fn remove() {
    let script = format!("table {TABLE}\ndelete table {TABLE}\n");
    if let Err(e) = apply(&script) {
        log::debug!("cannot delete the {TABLE} table: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{self, Preset, Rule};

    fn rule(protocol: Protocol, ports: &[&str], ips: &[&str]) -> Rule {
        Rule {
            name: "r".into(),
            enabled: true,
            protocol,
            ports: ports.iter().map(|s| s.to_string()).collect(),
            ips: ips.iter().map(|s| s.to_string()).collect(),
            domains: vec![],
            apps: vec![],
        }
    }

    #[test]
    fn a_rule_makes_one_tcp_redirect_line() {
        let table = Table::new(&[rule(Protocol::Tcp, &["443"], &["1.1.1.1/32", "8.8.8.0/24"])]);
        let text = script(&table, "127.0.0.1:2080".parse().unwrap(), 45_000);
        assert!(text.contains("table inet zapret_router"), "{text}");
        assert!(text.contains("delete table inet zapret_router"), "{text}");
        assert!(text.contains("type nat hook output priority dstnat"), "{text}");
        assert!(text.contains("oifname \"lo\" accept"), "{text}");
        assert!(text.contains("meta mark & 0x40000000 != 0 return"), "{text}");
        assert!(
            text.contains("ip daddr 127.0.0.1 tcp dport 2080 return")
                && text.contains("ip daddr 127.0.0.1 udp dport 2080 return"),
            "{text}"
        );
        assert!(
            text.contains("ip daddr { 1.1.1.1, 8.8.8.0-8.8.8.255 } tcp dport { 443 } redirect to :45000"),
            "{text}"
        );
    }

    #[test]
    fn udp_rules_and_targetless_rules_redirect_nothing() {
        let table = Table::new(&[
            rule(Protocol::Udp, &["53"], &["1.1.1.1"]),
            rule(Protocol::Both, &[], &["2.2.2.2"]),
            rule(Protocol::Tcp, &[], &[]),
        ]);
        let text = script(&table, "127.0.0.1:2080".parse().unwrap(), 45_000);
        assert!(!text.contains("1.1.1.1"), "{text}");
        assert!(text.contains("ip daddr { 2.2.2.2 } redirect to :45000"), "{text}");
    }

    #[test]
    fn a_ports_only_rule_takes_every_destination() {
        let table = Table::new(&[rule(Protocol::Both, &["80", "443"], &[])]);
        let text = script(&table, "127.0.0.1:2080".parse().unwrap(), 45_000);
        assert!(
            text.contains("tcp dport { 80, 443 } redirect to :45000"),
            "{text}"
        );
    }

    #[test]
    fn a_domains_only_rule_waits_for_its_names() {
        let mut rule = rules::preset(Preset::Twitch);
        rule.ips = vec![];
        let table = Table::new(&[rule]);
        let text = script(&table, "127.0.0.1:2080".parse().unwrap(), 45_000);
        assert_eq!(text.matches("redirect to :45000").count(), 0, "{text}");
    }

    #[test]
    fn resolved_names_join_the_ranges() {
        use std::net::Ipv4Addr;
        let discord = rules::preset(Preset::Discord);
        let table = Table::new(&[discord])
            .with_names(&[(Ipv4Addr::new(162, 159, 128, 1), "discord.com".into())]);
        let text = script(&table, "127.0.0.1:2080".parse().unwrap(), 45_000);
        assert!(text.contains("162.159.128.1"), "{text}");
    }

    #[test]
    fn the_mark_function_reports_what_it_could() {
        // The answer depends on the rights of this process; either way it must not panic.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _ = mark(&stream);
    }
}
