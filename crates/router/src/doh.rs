//! Whether the system itself resolves names over encrypted DNS, or how close it can get on Linux:
//! then the DNS sniffer sees no answers and domain rules match nothing. Read-only file lookups.

/// True when systemd-resolved has encrypted DNS on (`DNSOverTLS=yes` in `/etc/systemd/resolved.conf`
/// or in any of its drop-ins), and always false when the file says nothing or does not exist.
pub fn system_doh() -> bool {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/etc/systemd/resolved.conf.d") {
        files.extend(entries.flatten().map(|entry| entry.path()));
    }
    files.push("/etc/systemd/resolved.conf".into());
    files.iter().any(|file| {
        std::fs::read_to_string(file)
            .is_ok_and(|text| {
                text.lines().any(|line| {
                    let line = line.split('#').next().unwrap_or("").trim();
                    line.eq_ignore_ascii_case("DNSOverTLS=yes")
                })
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_this_machine_without_failing() {
        // The answer depends on the machine; the walk must finish and a missing file reads as off.
        let _ = system_doh();
    }
}
