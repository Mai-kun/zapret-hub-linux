//! The port filters `nfqws2` cannot do itself: `--wf-tcp-out`/`--wf-udp-out` are WinDivert
//! options, and on Linux the nfqueue takes its packets from an nftables table instead (zapret2
//! readme, «Механика обработки трафика»). The table applies the port lists the strategies name
//! and sends everything into queue `nfqws2 --qnum=200`. nfqws2's own generated packets carry mark
//! `0x40000000`, which the table leaves alone and the matched return stops the loop.
//!
//! Rights: `nft` and the table file live under root, so `zapret::root` runs them through `sudo`.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// The queue the table fills and `nfqws2 --qnum=` reads; `nfqws2`'s own examples use 200.
pub const QNUM: u32 = 200;

/// NFQWS2_COMPAT: the mark `nfqws2` puts on its own packets (its default), kept out of the queue.
const FWMARK: &str = "0x40000000";

/// The table file the `zapret2` service's `ExecStartPre` applies and `ExecStopPost` deletes.
pub const CONFIG: &str = "/etc/zapret-hub/nfqws2.nft";

/// `tail` as `nfqws2` reads it: the `--wf-*` options (WinDivert's whole filter family) come out,
/// the `--wf-tcp-out=`/`--wf-udp-out=` port lists going into the answer, and `--qnum=200` takes
/// the filtering over. Returns the arguments and `(tcp, udp)` port lists.
pub fn translate(tail: &str) -> (String, String, String) {
    let mut tcp = Vec::new();
    let mut udp = Vec::new();
    let mut kept: Vec<String> = Vec::new();
    for token in zapret::custom::quoted_tokens(tail) {
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
pub fn table(tcp_ports: &str, udp_ports: &str) -> String {
    let mut rules = String::new();
    if !tcp_ports.is_empty() {
        rules.push_str(&format!(
            "        tcp dport {{ {tcp_ports} }} ct original packets 1-12 queue num {QNUM} bypass\n"
        ));
    }
    if !udp_ports.is_empty() {
        rules.push_str(&format!(
            "        udp dport {{ {udp_ports} }} ct original packets 1-8 queue num {QNUM} bypass\n"
        ));
    }
    format!(
        "table inet zapret_hub\n\
         delete table inet zapret_hub\n\
         table inet zapret_hub {{\n\
         \x20   chain output {{\n\
         \x20       type filter hook output priority mangle; policy accept;\n\
         \x20       meta mark & {FWMARK} != 0 return\n\
         \x20       oifname \"lo\" accept\n\
         {rules}    }}\n\
         }}"
    )
}

/// `nft` on the PATH (`which`), for absolute paths systemd's ExecStart needs.
pub fn nft_path() -> anyhow::Result<PathBuf> {
    let which = exec::run(Command::new("which").arg("nft"), Duration::from_secs(10), None)?;
    anyhow::ensure!(
        which.success(),
        "nftables was not found on this system: install nftables, nfqws2 needs it"
    );
    let path = which.stdout.trim();
    anyhow::ensure!(path.starts_with('/'), "which answered with a relative nft: {path}");
    Ok(PathBuf::from(path))
}

/// Writes the table to {CONFIG} under root: the service can apply it at every start.
pub fn write_config(tcp_ports: &str, udp_ports: &str) -> anyhow::Result<()> {
    let text = table(tcp_ports, udp_ports);
    zapret::root::write(std::path::Path::new(CONFIG), &text)
}

/// Applies the table now (the tests run `nfqws2` without a service): the file is a temp one,
/// `nft -f` reads and keeps it.
pub fn apply(tcp_ports: &str, udp_ports: &str) -> anyhow::Result<()> {
    let text = table(tcp_ports, udp_ports);
    let file = std::env::temp_dir().join(format!("zapret-hub-nft-{}", std::process::id()));
    std::fs::write(&file, text)?;
    let applied = zapret::root::run("nft", &["-f", file.display().to_string().as_str()]);
    let _ = std::fs::remove_file(&file);
    applied?.check()?;
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
        let text = table("443,80", "443");
        for part in [
            "table inet zapret_hub",
            "delete table inet zapret_hub",
            "chain output {",
            "type filter hook output priority mangle; policy accept;",
            "meta mark & 0x40000000 != 0 return",
            "oifname \"lo\" accept",
            "tcp dport { 443,80 } ct original packets 1-12 queue num 200 bypass",
            "udp dport { 443 } ct original packets 1-8 queue num 200 bypass",
        ] {
            assert!(text.contains(part), "{part}: {text}");
        }
        let empty = table("", "");
        assert!(empty.contains("policy accept;") && !empty.contains("queue num"));
    }

    #[test]
    fn nft_rules_answers_listing_or_inactive_message() {
        let text = rules();
        assert!(!text.is_empty());
    }
}
