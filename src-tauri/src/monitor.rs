//! Background watch of the excluded programs. Every 1–2 s (and right after exclusions are saved)
//! it scans `/proc`, matches processes against the enabled groups' `apps`, puts the matches' own
//! PIDs into the `zapret_bypass` cgroup v2 — their sockets leave the nftables queue on the very
//! first SYN — and fills the nftables bypass sets `bypass_tcp_ports`/`bypass_udp_ports` with
//! their open local ports, for the sockets opened before the tick.
//!
//! Two guards keep the cgroup from poisoning anyone else: only a process whose own name matches
//! an app enters it (never a parent, a terminal or a launcher), and every tick evicts anything
//! found inside whose own name matches no app — an excluded agent's children (the app itself, a
//! test `curl`) inherited the mark at fork and come back to the root cgroup at once.
//!
//! Everything here is best effort: a missing root, an absent table or a gone process is logged
//! and retried on the next tick — the watch must never take the app down.

use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use tauri::AppHandle;
use zapret2::nft::CGROUP;

use crate::actions;
use crate::exclusions;
use crate::state::AppState;

/// The processes the watch never touches, matched exactly against the process name: the app's
/// own machinery, and the shells and builders an excluded agent spawns — their traffic must
/// never bypass nfqws2, whatever their parent is.
pub const PROTECTED: &[&str] = &[
    "zapret-hub",
    "zapret-hub-cli",
    "nfqws2",
    "nfq",
    "curl",
    "sh",
    "bash",
    "fish",
    "zsh",
    "cargo",
    "rustc",
];

/// The tick when nothing wakes the watch up.
const TICK: Duration = Duration::from_secs(2);
/// `nft` needs the table before `add element` works on its sets.
const TABLE: &str = "inet zapret_hub";

/// Starts the watch and returns the wake-up sender: `save_exclusion_rules` pokes it so the change
/// applies without waiting for the next tick.
pub fn start_monitor(handle: AppHandle, state: &AppState) -> mpsc::Sender<()> {
    let (tx, rx) = mpsc::channel();
    *state.monitor_wake.lock().unwrap() = Some(tx.clone());
    std::thread::spawn(move || {
        log::info!(
            "exclusions monitor: watching the enabled groups' apps into {} and the nftables sets",
            CGROUP
        );
        // True until the first empty tick: the sets may still hold the ports of a run before
        // this one, so the first tick must flush even when nothing matches.
        let mut populated = true;
        loop {
            let _ = rx.recv_timeout(TICK);
            if let Err(err) = sync_once(&handle, &mut populated) {
                log::warn!("exclusions monitor: {err:#}");
            }
        }
    });
    tx
}

/// At the app's start: this very process must not keep the bypass mark it inherited at fork from
/// an excluded agent (the app started from such an agent's terminal). The move goes through
/// `sudo` — a plain user cannot write the root cgroup's `cgroup.procs`; a refusal is logged and
/// the watch's first tick evicts this pid the same way.
pub fn evict_self() {
    let Ok(self_cgroup) = std::fs::read_to_string("/proc/self/cgroup") else {
        return;
    };
    if !self_cgroup.contains("zapret_bypass") {
        return;
    }
    match zapret::root::run(
        "sh",
        &[
            "-c",
            &format!("echo {} > /sys/fs/cgroup/cgroup.procs", std::process::id()),
        ],
    ) {
        Ok(_) => log::info!("this process left the zapret_bypass cgroup"),
        Err(err) => log::warn!("cannot leave zapret_bypass: {err:#}"),
    }
}

/// One tick: evict the inherited strangers, move the matches' own PIDs into the cgroup, refresh
/// the port sets. Nothing runs the `/proc` scan or a single `nft` while the groups hold no apps.
fn sync_once(handle: &AppHandle, populated: &mut bool) -> anyhow::Result<()> {
    let state = actions::state(handle);
    let saved = exclusions::ExclusionRules::load(&state.paths)?;
    let apps: Vec<String> = saved.enabled_apps();
    evict_foreign(&apps);
    if apps.is_empty() {
        // The groups went away: what their ports left in the sets is flushed once, then silence.
        update_port_sets(&[], populated);
        return Ok(());
    }
    let pids = find_pids(&apps)?;
    if !pids.is_empty() {
        // The cgroup appears with the table, but the watch may tick first: create it here too.
        zapret2::nft::ensure_cgroup();
        let list = pids
            .iter()
            .map(|pid| pid.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        // `echo` is a shell builtin, so `sh -c` moves every matched pid at once.
        let _ = zapret::root::run(
            "sh",
            &["-c", &format!("printf '%s\\n' {list} > {CGROUP}/cgroup.procs")],
        );
    }
    update_port_sets(&pids, populated);
    Ok(())
}

/// Anything inside the bypass cgroup whose own name matches none of the active apps goes back to
/// the root cgroup at once: cgroup v2 hands the mark to every forked child, and an excluded
/// agent's `bash` → `zapret-hub` → `curl` chain must never keep it.
pub fn evict_foreign(apps: &[String]) {
    let Ok(list) = std::fs::read_to_string(format!("{CGROUP}/cgroup.procs")) else {
        return; // no cgroup, no cgroup v2: nothing to watch
    };
    let strangers: Vec<String> = list
        .split_whitespace()
        .filter(|pid| {
            let name = process_name(&pid.parse::<u32>().unwrap_or(0));
            !PROTECTED.contains(&name.as_str())
                && !apps.iter().any(|app| exclusions::app_matches(&name, app))
        })
        .map(|pid| pid.to_owned())
        .collect();
    if strangers.is_empty() {
        return;
    }
    let _ = zapret::root::run(
        "sh",
        &[
            "-c",
            &format!(
                "printf '%s\\n' {} > /sys/fs/cgroup/cgroup.procs",
                strangers.join(" ")
            ),
        ],
    );
    log::info!(
        "evicted from {CGROUP}: {}",
        strangers
            .iter()
            .map(|pid| format!("{pid} ({})", process_name(&pid.parse().unwrap_or(0))))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// The PIDs of the processes whose own name matches an exclusion app — and nobody else's: a
/// matched process's children inherit the cgroup at fork and are evicted back by `evict_foreign`
/// instead of ever being matched here. The name is `comm`, the executable's file name, or the
/// first command-line word (`/usr/bin/opencode`), case-insensitively, as a substring — so
/// `opencode` catches `opencode-cli` too. The app's own machinery (`PROTECTED`) never lands
/// here, whatever started it.
fn find_pids(apps: &[String]) -> anyhow::Result<Vec<u32>> {
    let entries: Vec<u32> = std::fs::read_dir("/proc")?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .parse::<u32>()
                .ok()
        })
        .collect();

    Ok(entries
        .into_iter()
        .map(|pid| {
            let name = process_name(&pid);
            (pid, name)
        })
        .filter(|(_, name)| !PROTECTED.contains(&name.as_str()))
        .filter(|(_, name)| {
            apps.iter()
                .any(|app| exclusions::app_matches(name, app))
        })
        .map(|(pid, _)| pid)
        .collect())
}

/// `comm`, then the file name of `exe` and of `cmdline[0]` — whatever is readable.
pub(crate) fn process_name(pid: &u32) -> String {
    if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        let name = comm.trim();
        if !name.is_empty() {
            return name.to_owned();
        }
    }
    if let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) {
        if let Some(first) = cmdline.split(|byte| *byte == b'\0').next() {
            if let Ok(text) = std::str::from_utf8(&first) {
                if let Some(name) = Path::new(text).file_name().and_then(|name| name.to_str()) {
                    return name.to_owned();
                }
            }
        }
    }
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.to_owned())
        })
        .unwrap_or_default()
}

/// The open local TCP/UDP ports of the matched processes, as `(tcp, udp)`.
fn open_ports(pids: &[u32]) -> (Vec<u16>, Vec<u16>) {
    let (tcp_nodes, udp_nodes) = net_nodes();
    let mut tcp: Vec<u16> = Vec::new();
    let mut udp: Vec<u16> = Vec::new();
    for pid in pids {
        let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(link) = std::fs::read_link(entry.path()) else {
                continue;
            };
            let Some(inode) = link
                .to_string_lossy()
                .strip_prefix("socket:[")
                .and_then(|text| text.strip_suffix(']'))
                .and_then(|text| text.parse::<u64>().ok())
            else {
                continue;
            };
            if let Some(&port) = tcp_nodes.get(&inode) {
                tcp.push(port);
            } else if let Some(&port) = udp_nodes.get(&inode) {
                udp.push(port);
            }
        }
    }
    tcp.sort_unstable();
    tcp.dedup();
    udp.sort_unstable();
    udp.dedup();
    (tcp, udp)
}

/// `/proc/net/{tcp,tcp6,udp,udp6}` as `inode → local port`, one map per protocol family.
/// Parses one `/proc/net/<family>` file into `inode → local port`.
fn net_lines(text: &str, map: &mut HashMap<u64, u16>) {
    for line in text.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let Some(local) = fields.nth(1) else {
            continue;
        };
        let port = local
            .rsplit_once(':')
            .and_then(|(_, port)| u16::from_str_radix(port, 16).ok());
        let Some(inode) = fields.last().and_then(|text| text.parse::<u64>().ok()) else {
            continue;
        };
        if let Some(port) = port {
            map.insert(inode, port);
        }
    }
}

/// `/proc/net/{tcp,tcp6,udp,udp6}` as `inode → local port`, one map per protocol family.
fn net_nodes() -> (HashMap<u64, u16>, HashMap<u64, u16>) {
    let mut tcp: HashMap<u64, u16> = HashMap::new();
    let mut udp: HashMap<u64, u16> = HashMap::new();
    let read_net = |path: &str, map: &mut HashMap<u64, u16>| {
        if let Ok(text) = std::fs::read_to_string(path) {
            net_lines(&text, map);
        }
    };
    read_net("/proc/net/tcp", &mut tcp);
    read_net("/proc/net/tcp6", &mut tcp);
    read_net("/proc/net/udp", &mut udp);
    read_net("/proc/net/udp6", &mut udp);
    (tcp, udp)
}

/// Replaces the set's contents with `ports`; an empty list just flushes the set. A missing table
/// (zapret not applied yet) is silently skipped: the next tick tries again. `populated` says the
/// sets may still hold ports of an earlier tick: when nothing matched and they cannot, the two
/// `nft` spawns (and the `/proc/net` reads) are skipped too.
fn update_port_sets(pids: &[u32], populated: &mut bool) {
    if pids.is_empty() && !*populated {
        return;
    }
    let (tcp, udp) = open_ports(pids);
    *populated = !tcp.is_empty() || !udp.is_empty();
    set_elements("bypass_tcp_ports", &tcp);
    set_elements("bypass_udp_ports", &udp);
}

fn set_elements(set: &str, ports: &[u16]) {
    let flush = zapret::root::run("nft", &["flush", "set", TABLE, set]);
    if let Err(err) = &flush {
        log::debug!("cannot flush nftables set {set}: {err:#}");
    }
    if ports.is_empty() {
        return;
    }
    let list = ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let added = zapret::root::run(
        "nft",
        &["add", "element", TABLE, set, &format!("{{ {list} }}")],
    );
    if let Err(err) = &added {
        log::debug!("cannot add elements to nftables set {set}: {err:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake `/proc` tree in a temp dir.
    struct ProcRoot {
        dir: tempfile::TempDir,
    }

    impl ProcRoot {
        fn new() -> anyhow::Result<Self> {
            Ok(Self { dir: tempfile::tempdir()? })
        }

        fn proc(&self) -> std::path::PathBuf {
            self.dir.path().join("proc")
        }

        /// Adds `/proc/<pid>/` with `comm`, `cmdline`, `exe` symlink and an `fd` socket inode.
        fn add(
            &self,
            pid: u32,
            comm: &str,
            cmdline: &[&str],
            exe: Option<&str>,
            socket_inodes: &[u64],
        ) -> anyhow::Result<()> {
            let pid_dir = self.proc().join(pid.to_string());
            std::fs::create_dir_all(pid_dir.join("fd"))?;
            std::fs::write(pid_dir.join("comm"), comm)?;
            let mut cmdline_bytes = Vec::new();
            for word in cmdline {
                cmdline_bytes.extend_from_slice(word.as_bytes());
                cmdline_bytes.push(0);
            }
            std::fs::write(pid_dir.join("cmdline"), &cmdline_bytes)?;
            if let Some(exe) = exe {
                std::os::unix::fs::symlink(exe, pid_dir.join("exe"))?;
            }
            for (index, inode) in socket_inodes.iter().enumerate() {
                std::os::unix::fs::symlink(
                    format!("socket:[{inode}]"),
                    pid_dir.join("fd").join(index.to_string()),
                )?;
            }
            Ok(())
        }

        /// Adds `/proc/<pid>/status` with `PPid: <parent>`.
        fn status(&self, pid: u32, parent: u32) -> anyhow::Result<()> {
            std::fs::write(self.proc().join(pid.to_string()).join("status"), format!("PPid: {parent}\n"))?;
            Ok(())
        }

        /// `/proc/net/tcp` and friends: `local_address ... inode` lines.
        fn net(&self, family: &str, lines: &[&str]) -> anyhow::Result<()> {
            std::fs::create_dir_all(self.dir.path().join("proc/net"))?;
            let mut text =
                String::from("sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
            for line in lines {
                text.push_str(line);
                text.push('\n');
            }
            std::fs::write(self.dir.path().join(format!("proc/net/{family}")), &text)?;
            Ok(())
        }

        fn root(&self) -> &Path {
            self.dir.path()
        }
    }

    #[test]
    fn process_name_reads_comm_cmdline_and_exe() {
        let root = ProcRoot::new().unwrap();
        root.add(1, "opencode-cli", &["/usr/bin/opencode-cli", "--flag"], Some("/usr/bin/opencode-cli"), &[]).unwrap();
        root.add(2, "firefox", &["/usr/lib/firefox/firefox"], Some("/usr/lib/firefox/firefox"), &[]).unwrap();
        // comm is preferred over the path; cmdline[0] wins over exe only when comm is empty.
        assert_eq!(process_name_root(root.root(), 1), "opencode-cli");
        assert_eq!(process_name_root(root.root(), 2), "firefox");
    }

    #[test]
    fn matching_is_by_own_name_only_and_protected_never_matches() {
        let root = ProcRoot::new().unwrap();
        root.add(1, "init", &["/sbin/init"], Some("/sbin/init"), &[]).unwrap();
        root.add(10, "opencode", &["opencode"], Some("/usr/bin/opencode"), &[]).unwrap();
        root.add(11, "opencode-cli", &["/opt/OPAQUE/opencode-cli"], Some("/opt/x/opencode-cli"), &[]).unwrap();
        root.add(12, "firefox", &["firefox"], Some("/usr/lib/firefox"), &[]).unwrap();
        root.add(13, "node", &["node"], Some("/usr/bin/node"), &[]).unwrap(); // a child of 10
        root.add(14, "curl", &["curl"], Some("/usr/bin/curl"), &[]).unwrap(); // also a child of 10
        root.status(10, 1).unwrap();
        root.status(11, 10).unwrap();
        root.status(13, 11).unwrap();
        root.status(14, 11).unwrap();

        // The watch matches a process by its own name alone: the children an excluded app
        // spawned (`node`, `curl`) are matched no more — the cgroup mark they inherited at fork
        // is what `evict_foreign` takes back out.
        let apps = vec!["opencode".to_owned()];
        let matched: Vec<u32> = [1u32, 10, 11, 12, 13, 14]
            .into_iter()
            .map(|pid| (pid, process_name_root(root.root(), pid)))
            .filter(|(_, name)| !PROTECTED.contains(&name.as_str()))
            .filter(|(_, name)| {
                apps.iter()
                    .any(|app| exclusions::app_matches(name, app))
            })
            .map(|(pid, _)| pid)
            .collect();
        assert_eq!(matched, [10, 11]);
    }

    #[test]
    fn open_ports_reads_socket_inodes_from_proc_net() {
        let root = ProcRoot::new().unwrap();
        // Inodes in /proc are decimal; port fields are hex. Column 1 is the local address
        // (column 0 is the `sl` number the real /proc/net/tcp has).
        root.add(20, "opencode", &["opencode"], Some("/usr/bin/opencode"), &[4660, 22136]).unwrap();
        root.net(
            "tcp",
            &[
                "0: 00000000:1F90 00000000:0000 0A ... 0 0 4660",
                "0: 00000000:5035 00000000:0000 06 ... 0 0 22136",
            ],
        )
        .unwrap();
        root.net("udp", &[]).unwrap();

        // `open_ports` reads the real `/proc/net/*`; here we replicate its parsing over the fake files.
        let tcp_nodes = net_nodes_root(root.root(), "tcp");
        let udp_nodes = net_nodes_root(root.root(), "udp");
        let ports: Vec<u16> = [0x1234, 0x5678]
            .iter()
            .filter_map(|inode| tcp_nodes.get(inode).copied())
            .collect();
        assert_eq!(ports, [8080, 20533]);
        assert!(udp_nodes.is_empty());
    }

    #[test]
    fn app_matching_is_used_by_the_watch() {
        assert!(exclusions::app_matches("opencode-cli", "opencode"));
        assert!(exclusions::app_matches("/usr/bin/opencode", "opencode"));
        assert!(!exclusions::app_matches("firefox", "opencode"));
    }

    /// `comm` of `pid`, rooted at a fake tree root.
    fn process_name_root(root: &Path, pid: u32) -> String {
        let comm = root.join("proc").join(pid.to_string()).join("comm");
        std::fs::read_to_string(&comm)
            .ok()
            .and_then(|text| {
                let name = text.trim();
                if name.is_empty() {
                    None
                } else {
                    Some(name.to_owned())
                }
            })
            .unwrap_or_default()
    }

    /// Parsed `inode → local port` of one `/proc/net/<family>` file, rooted at a fake tree root.
    fn net_nodes_root(root: &Path, family: &str) -> HashMap<u64, u16> {
        let mut nodes: HashMap<u64, u16> = HashMap::new();
        let Ok(text) = std::fs::read_to_string(root.join("proc/net").join(family)) else {
            return nodes;
        };
        for line in text.lines().skip(1) {
            let mut fields = line.split_whitespace();
            let port = fields
                .nth(1)
                .and_then(|local| local.rsplit_once(':'))
                .and_then(|(_, port)| u16::from_str_radix(port, 16).ok());
            let inode = fields.last().and_then(|text| text.parse::<u64>().ok());
            if let (Some(port), Some(inode)) = (port, inode) {
                nodes.insert(inode, port);
            }
        }
        nodes
    }
}
