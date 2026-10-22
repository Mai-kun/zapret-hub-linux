//! Flushing the Linux DNS cache after a hosts change.

/// Flushes the Linux DNS cache using `resolvectl flush-caches` (fallback: `systemd-resolve --flush-caches`).
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

    if run("resolvectl", &["flush-caches"]) {
        return Ok(());
    }
    if run("systemd-resolve", &["--flush-caches"]) {
        return Ok(());
    }
    anyhow::bail!("failed to flush DNS cache via resolvectl or systemd-resolve")
}

#[cfg(test)]
mod tests {
    #[test]
    fn flush_dns_runs_without_panic() {
        let _ = super::flush_dns();
    }
}
