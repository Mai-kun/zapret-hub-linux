//! The port filters `nfqws2` cannot do itself: `--wf-tcp-out`/`--wf-udp-out` are WinDivert
//! options, and on Linux the nfqueue takes its packets from an nftables table instead (zapret2
//! readme, «Механика обработки трафика»). The table applies the port lists the strategies name
//! and sends everything into queue `nfqws2 --qnum=200`. nfqws2's own generated packets carry mark
//! `0x40000000`, which the table leaves alone and the matched return stops the loop.
//!
//! Rights: `nft` and the table file live under root, so `zapret::root` runs them through `sudo`.

use anyhow::Context as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// The queue the table fills and `nfqws2 --qnum=` reads; `nfqws2`'s own examples use 200.
pub const QNUM: u32 = 200;

/// NFQWS2_COMPAT: the mark `nfqws2` puts on its own packets (its default), kept out of the queue.
const FWMARK: &str = "0x40000000";

/// The group the table lets through whole: any process started in it (`sg {BYPASS} "<program>"`)
/// leaves the queue alone. `nft` names a group of `/etc/group`, so it has to exist.
pub const GROUP: &str = "zapret-bypass";

/// The cgroup v2 whose processes' sockets leave the queue whole on the very first SYN — the
/// dynamic port sets alone cannot catch a new connection that sends its ClientHello in the
/// first milliseconds. The monitor writes the excluded processes' own PIDs here and evicts
/// anything else back to the root cgroup: cgroup v2 passes to every child at fork, so an
/// excluded agent or launcher would otherwise carry the mark onto everything it ever starts.
pub const CGROUP: &str = "/sys/fs/cgroup/zapret_bypass";

/// The table file the `zapret2` service's `ExecStartPre` applies and `ExecStopPost` deletes.
pub const CONFIG: &str = "/etc/zapret-hub/nfqws2.nft";

/// `tail` as `nfqws2` reads it: the `--wf-*` options (WinDivert's whole filter family) come out,
/// the `--wf-tcp-out=`/`--wf-udp-out=` port lists going into the answer, and `--qnum=200` takes
/// the filtering over. Returns the arguments and `(tcp, udp)` port lists.
pub fn translate(tail: &str) -> (String, String, String) {
    let mut tcp = Vec::new();
    let mut udp = Vec::new();
    let mut kept: Vec<String> = Vec::new();
    for token in zapret::quoted_tokens(tail) {
        let plain = token.replace('"', "");
        if let Some(ports) = plain.strip_prefix("--wf-tcp-out=") {
            tcp.push(ports.to_owned());
        } else if let Some(ports) = plain.strip_prefix("--wf-udp-out=") {
            udp.push(ports.to_owned());
        } else if plain.starts_with("--wf-") {
            // `--wf-l3=`, `--wf-raw-part=`, `--wf-dup-check=0`: nfqws2 has no windivert at all.
        } else if plain.starts_with("--qnum=") {
            // The strategy named one already: it wins.
            kept.push(token);
        } else {
            kept.push(token);
        }
    }
    if !kept.iter().any(|token| token.starts_with("--qnum=")) {
        kept.push(format!("--qnum={QNUM}"));
    }
    (kept.join(" "), tcp.join(","), udp.join(","))
}

/// The table as `nft` takes it, from a file (the queue's port lists are fixed per apply). The
/// `table` before `delete` makes the removal not fail on the first ever apply; the final `table`
/// builds the queue's rules again for the `mark`-kept packets to pass, the matched ones entering
/// queue 200 while the connection is young. Loopback stays out: queued loopback packets stall
/// local connections, and no DPI lives there.
///
/// `with_cgroupv2` adds `socket cgroupv2 level 1 "zapret_bypass" return`: the sockets of the
/// processes the monitor put into `/sys/fs/cgroup/zapret_bypass` leave the queue on the very
/// first SYN. Kernels without `socket cgroupv2` in nft call it a syntax error, so `apply` retries
/// without it instead of failing. The excluded programs also leave through the dynamic
/// `@bypass_*_ports` sets of their own open ports, for the sockets they opened before the tick.
pub fn table(
    tcp_ports: &str,
    udp_ports: &str,
    excluded_ports: &str,
    with_cgroupv2: bool,
) -> String {
    // Before the queue rules: the group, the cgroup and the excluded ports go through
    // untouched, and only the rest of the traffic reaches the queue.
    let mut rules = format!("        meta skgid {GROUP} return\n");
    if with_cgroupv2 {
        rules.push_str(&format!(
            "        socket cgroupv2 level 1 \"{}\" return\n",
            CGROUP.rsplit('/').next().unwrap_or("zapret_bypass")
        ));
    }

    if !excluded_ports.is_empty() {
        rules.push_str(&format!("        th dport {{ {excluded_ports} }} return\n"));
        rules.push_str(&format!("        th sport {{ {excluded_ports} }} return\n"));
    }
    
    // Dynamic sets
    rules.push_str("        tcp sport @bypass_tcp_ports return\n");
    rules.push_str("        udp sport @bypass_udp_ports return\n");

    if !tcp_ports.is_empty() {
        rules.push_str(&format!(
            "        tcp dport {{ {tcp_ports} }} ct original packets 1-12 counter queue num {QNUM} bypass\n"
        ));
    }
    if !udp_ports.is_empty() {
        rules.push_str(&format!(
            "        udp dport {{ {udp_ports} }} ct original packets 1-8 counter queue num {QNUM} bypass\n"
        ));
    }
    format!(
        "table inet zapret_hub\n\
         delete table inet zapret_hub\n\
         table inet zapret_hub {{\n\
         \x20   set bypass_tcp_ports {{ type inet_service; flags interval; }}\n\
         \x20   set bypass_udp_ports {{ type inet_service; flags interval; }}\n\
         \x20   chain output {{\n\
         \x20       type filter hook output priority mangle; policy accept;\n\
         \x20       meta mark & {FWMARK} != 0 return\n\
         \x20       oifname \"lo\" accept\n\
         {rules}    }}\n\
         }}"
    )
}

/// `nft` by its absolute path: `which` first, then the sbin folders a user `PATH` does not hold
/// (Debian/Ubuntu put `nft` into `/usr/sbin`), for systemd's unit lines.
pub fn nft_path() -> anyhow::Result<PathBuf> {
    let path = zapret::root::which("nft").with_context(|| {
        "nftables was not found on this system: install nftables, nfqws2 needs it"
    })?;
    Ok(PathBuf::from(path))
}

/// The `{GROUP}` entry missing from `/etc/group`: created once as a system group, best effort —
/// a rights refusal is logged and the next `nft -f` names the missing group in its own error.
fn ensure_group() {
    let known = exec::run(
        Command::new("getent").args(["group", GROUP]),
        Duration::from_secs(10),
        None,
    )
    .ok()
    .map(|out| out.success());
    if known != Some(false) {
        return; // exists, or `getent` said nothing: nft will name the problem itself
    }
    if let Err(err) = zapret::root::run("groupadd", &["--system", GROUP]) {
        log::warn!("the {GROUP} group was not created: {err:#}");
    }
}

/// Makes `/sys/fs/cgroup/zapret_bypass` exist so `socket cgroupv2 level 1 "zapret_bypass"` can
/// match the processes the monitor puts there.
pub fn ensure_cgroup() {
    if let Err(err) = zapret::root::run("mkdir", &["-p", CGROUP]) {
        log::warn!("cannot create {CGROUP}: {err:#}");
    }
}

/// The processes of the legacy or stale cgroup go back to the root one: a pid the monitor no
/// longer matches (the app itself, a test `curl` inherited at fork) must not keep the mark.
/// Best effort — a mount without cgroup v2 or a gone directory is fine.
pub fn evacuate_cgroup() {
    let procs = std::path::Path::new(CGROUP).join("cgroup.procs");
    if let Ok(list) = std::fs::read_to_string(&procs) {
        let list = list.split_whitespace().collect::<Vec<_>>().join(" ");
        if !list.is_empty() {
            // The root cgroup takes every pid back; its own `cgroup.procs` accepts the list.
            let _ = zapret::root::run(
                "sh",
                &[
                    "-c",
                    &format!("printf '%s\\n' {list} > /sys/fs/cgroup/cgroup.procs"),
                ],
            );
            log::info!("the processes of {CGROUP} are back in the root cgroup");
        }
    }
}

/// Writes the table to {CONFIG} under root: the service can apply it at every start.
pub fn write_config(tcp_ports: &str, udp_ports: &str, excluded_ports: &str) -> anyhow::Result<()> {
    ensure_cgroup();
    let text = table(tcp_ports, udp_ports, excluded_ports, true);
    ensure_group();
    zapret::root::write(std::path::Path::new(CONFIG), &text)
}

/// Applies the table now (the tests run `nfqws2` without a service): the file is a temp one,
/// `nft -f` reads and keeps it. `socket cgroupv2` is tried first; on a kernel or an `nft` that
/// does not know it, `nft -f` is retried without the bypass rule instead of failing.
pub fn apply(tcp_ports: &str, udp_ports: &str, excluded_ports: &str) -> anyhow::Result<()> {
    ensure_cgroup();
    ensure_group();
    let applied = apply_text(&table(tcp_ports, udp_ports, excluded_ports, true));
    if applied.is_err() {
        // Older kernel/nft: `socket cgroupv2` is a syntax error. The cgroup itself still works
        // through the port sets, so retry without the rule and keep the table alive.
        return apply_text(&table(tcp_ports, udp_ports, excluded_ports, false));
    }
    applied
}

/// Applies one rendered table text through `nft -f`.
fn apply_text(text: &str) -> anyhow::Result<()> {
    let file = std::env::temp_dir().join(format!("zapret-hub-nft-{}", std::process::id()));
    std::fs::write(&file, text)?;
    let applied = zapret::root::run("nft", &["-f", file.display().to_string().as_str()])?;
    let _ = std::fs::remove_file(&file);
    applied.check()?;
    Ok(())
}

/// The table gone, best effort: a first ever apply leaves no table to delete.
pub fn clear() {
    let _ = zapret::root::run("nft", &["delete", "table", "inet", "zapret_hub"]);
}

/// Active rules in nftables: checks table `zapret_hub`, fallback `zapretunix`.
pub fn rules() -> String {
    let check = |table: &str| -> Option<String> {
        if let Ok(out) = exec::run(
            Command::new("nft").args(["list", "table", "inet", table]),
            Duration::from_secs(10),
            None,
        ) {
            if out.success() && !out.stdout.trim().is_empty() {
                return Some(out.stdout.trim().to_string());
            }
        }
        if let Ok(out) = zapret::root::run("nft", &["list", "table", "inet", table]) {
            if out.success() && !out.stdout.trim().is_empty() {
                return Some(out.stdout.trim().to_string());
            }
        }
        None
    };

    check("zapret_hub")
        .or_else(|| check("zapretunix"))
        .unwrap_or_else(|| "Таблица nftables не активна".to_string())
}

/// The `ExecStartPre` and `ExecStopPost` lines a `zapret2` service that runs `nfqws2` gets: the
/// table comes up before the engine, and steps down after it, whatever the exit.
pub fn unit_hooks() -> Option<String> {
    let nft = nft_path().ok()?;
    let shown = nft.display();
    Some(format!(
        "ExecStartPre=+{shown} -f {CONFIG}\nExecStopPost=+{shown} delete table inet zapret_hub\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filter_options_become_a_queue_and_port_lists() {
        let (args, tcp, udp) =
            translate(r#"--chdir="/tmp/z" --wf-tcp-out=443 --wf-udp-out=53,69 --lua-desync=fake"#);
        assert_eq!(
            args,
            format!(r#"--chdir="/tmp/z" --lua-desync=fake --qnum={QNUM}"#)
        );
        assert_eq!(tcp, "443");
        assert_eq!(udp, "53,69");
    }

    #[test]
    fn every_windivert_option_is_out_but_nothing_else_is() {
        let (args, tcp, udp) = translate(
            r#"--wf-l3=ipv4 --wf-raw-part=@"x\part.txt" --wf-dup-check=0 --wf-tcp-out=443 --intercept=0 --new --lua-desync=fake"#,
        );
        assert_eq!(
            args,
            format!(r#"--intercept=0 --new --lua-desync=fake --qnum={QNUM}"#)
        );
        assert_eq!(tcp, "443");
        assert_eq!(udp, "");
    }

    #[test]
    fn a_strategy_that_named_a_queue_keeps_it() {
        let (args, tcp, udp) = translate("--wf-tcp-out=443 --qnum=207 --lua-desync=fake");
        assert_eq!(args, "--qnum=207 --lua-desync=fake");
        assert_eq!(tcp, "443");
        assert_eq!(udp, "");
    }

    #[test]
    fn a_strategy_without_filters_gets_the_queue_anyway() {
        let (args, tcp, udp) = translate("--lua-desync=fake");
        assert_eq!(args, format!("--lua-desync=fake --qnum={QNUM}"));
        assert_eq!((tcp.as_str(), udp.as_str()), ("", ""));
    }

    #[test]
    fn the_table_matches_the_readme_shape() {
        let text = table("443,80", "443", "51413, 6881-6889", true);
        for part in [
            "table inet zapret_hub",
            "delete table inet zapret_hub",
            "chain output {",
            "type filter hook output priority mangle; policy accept;",
            "meta mark & 0x40000000 != 0 return",
            "oifname \"lo\" accept",
            "meta skgid zapret-bypass return",
            "th dport { 51413, 6881-6889 } return",
            "th sport { 51413, 6881-6889 } return",
            "tcp dport { 443,80 } ct original packets 1-12 counter queue num 200 bypass",
            "udp dport { 443 } ct original packets 1-8 counter queue num 200 bypass",
        ] {
            assert!(text.contains(part), "{part}: {text}");
        }
        // The exclusions sit before the queue rules: they leave it, the rest reaches it.
        let skgid = text.find("meta skgid").unwrap();
        let queue = text.find("queue num").unwrap();
        assert!(skgid < queue);
        let empty = table("", "", "", true);
        assert!(empty.contains("policy accept;") && !empty.contains("queue num"));
        assert!(empty.contains("meta skgid") && !empty.contains("th dport"));
        // The cgroup rule sits before the excluded ports and the queue: a socket of the bypass
        // cgroup leaves on the first SYN, the port sets cover the sockets opened before the tick.
        let cgroup = text.find("socket cgroupv2").unwrap();
        let ports = text.find("@bypass_tcp_ports").unwrap();
        let queue = text.find("queue num").unwrap();
        assert!(cgroup < ports && ports < queue);
        // A kernel without `socket cgroupv2` gets the table without the bypass rule.
        let without = table("443,80", "443", "", false);
        assert!(!without.contains("socket cgroupv2"));
        assert!(without.contains("meta skgid zapret-bypass return"));
    }

    #[test]
    fn nft_rules_answers_listing_or_inactive_message() {
        let text = rules();
        assert!(!text.is_empty());
    }
}
