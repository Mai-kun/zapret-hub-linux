//! Flushing the Linux DNS cache after a hosts change.

/// Flushes whatever cache the system actually runs: `systemd-resolved` (`resolvectl` or
/// `systemd-resolve`), NetworkManager, `nscd`, `dnsmasq`. Any single success counts. On a box with
/// no local cache at all — `/etc/resolv.conf` points straight at a real nameserver — there is
/// nothing to flush, and that is success too.
pub fn flush_dns() -> anyhow::Result<()> {
    let run = |cmd_name: &str, args: &[&str]| {
        if let Ok(out) = exec::run(
            std::process::Command::new(cmd_name).args(args),
            std::time::Duration::from_secs(15),
            None,
        ) {
            if out.success() {
                return true;
            }
        }
        if let Ok(out) = crate::root::run(cmd_name, args) {
            if out.success() {
                return true;
            }
        }
        false
    };

    if run("resolvectl", &["flush-caches"])
        || run("systemd-resolve", &["--flush-caches"])
        || run("nmcli", &["general", "reload", "dns-full"])
        || run("nscd", &["-i", "hosts"])
        // `pkill` exits 1 when no `dnsmasq` runs: the tool guards itself.
        || run("pkill", &["-HUP", "dnsmasq"])
    {
        return Ok(());
    }
    // Every tool failed or is missing: on a system without any local stub the lookups go straight
    // to the nameserver in `/etc/resolv.conf`, there is no cache and nothing to complain about.
    if !local_stub_configured() {
        return Ok(());
    }

    anyhow::bail!("failed to flush DNS cache: none of systemd-resolved, NetworkManager, nscd, dnsmasq worked")
}

/// Does `/etc/resolv.conf` send lookups at a local stub (127.0.0.53 of systemd-resolved, 127.0.0.1
/// of dnsmasq or nscd)? False means the system resolves directly and keeps no cache.
fn local_stub_configured() -> bool {
    std::fs::read_to_string("/etc/resolv.conf").is_ok_and(|text| {
        // `starts_with` never matches a `#nameserver …` comment line.
        text.lines().any(|line| line.trim().starts_with("nameserver 127."))
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn flush_dns_runs_without_panic() {
        let _ = super::flush_dns();
        // `local_stub_configured` must never trip on reading the file.
        let _ = super::local_stub_configured();
    }
}
