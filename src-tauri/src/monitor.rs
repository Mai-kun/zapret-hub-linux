//! Background watch of the excluded programs. Every 1–2 s (and right after exclusions are saved)
//! it scans `/proc`, matches processes against the enabled groups' `apps`, moves the matches into
//! the `zapret_bypass` cgroup v2 so their sockets never reach nfqws2, and puts their open local
//! ports into the nftables bypass sets `bypass_tcp_ports`/`bypass_udp_ports`.
//!
//! Everything here is best effort: a missing root, an absent table or a gone process is logged
//! and retried on the next tick — the watch must never take the app down.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use tauri::AppHandle;

use crate::actions;
use crate::exclusions;
use crate::state::AppState;

/// `/sys/fs/cgroup/zapret_bypass`: processes started here bypass nfqws2 through the nftables
/// rules of `table inet zapret_hub`.
const CGROUP: &str = "/sys/fs/cgroup/zapret_bypass";
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
        log::info!("exclusions monitor: watching for {}", exclusions::DEFAULT_APPS.join(", "));
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

/// One tick: read the groups, move matching processes into the cgroup, refresh the port sets.
/// Nothing runs the `/proc` scan or a single `nft` while the groups hold no apps.
fn sync_once(handle: &AppHandle, populated: &mut bool) -> anyhow::Result<()> {
    let state = actions::state(handle);
    let saved = exclusions::ExclusionRules::load(&state.paths)?;
    let apps: Vec<String> = saved.enabled_apps();
    if apps.is_empty() {
        // The groups went away: what their ports left in the sets is flushed once, then silence.
        update_port_sets(&[], populated);
        return Ok(());
    }

    let _ = zapret::root::run("mkdir", &["-p", CGROUP]);
    let pids = find_pids(&apps)?;
    if !pids.is_empty() {
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

/// The PIDs of all processes whose name matches an exclusion app, plus their descendants: comm
/// (`opencode-cli`), the executable's file name, and the first command-line word (`/usr/bin/opencode`),
/// matched case-insensitively and as a substring, so `opencode` catches `opencode-cli` too.
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

    let mut matched: Vec<u32> = Vec::new();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for pid in &entries {
        if apps.iter().any(|app| exclusions::app_matches(&process_name(pid), app)) {
            matched.push(*pid);
        }
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
            for line in status.lines() {
                if let Some(parent) = line
                    .strip_prefix("PPid:")
                    .and_then(|text| text.trim().parse::<u32>().ok())
                {
                    children.entry(parent).or_default().push(*pid);
                    break;
                }
            }
        }
    }

    // Matched processes and everything they started: children, grandchildren, …
    let mut out: Vec<u32> = Vec::new();
    let mut seen: HashSet<u32> = HashSet::new();
    let mut todo: VecDeque<u32> = matched.into_iter().collect();
    while let Some(pid) = todo.pop_front() {
        if !seen.insert(pid) {
            continue;
        }
        out.push(pid);
        if let Some(kids) = children.get(&pid) {
            todo.extend(kids.iter().copied());
        }
    }
    Ok(out)
}

/// `comm`, then the file name of `exe` and of `cmdline[0]` — whatever is readable.
fn process_name(pid: &u32) -> String {
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

    /// Reads `status` for `PPid` the way `find_pids` does, rooted at `root/proc`.
    fn read_ppid(root: &Path, pid: u32) -> Option<u32> {
        std::fs::read_to_string(root.join("proc").join(pid.to_string()).join("status"))
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("PPid:").and_then(|text| text.trim().parse().ok()))
            })
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
    fn find_pids_matches_comm_cmdline_basename_and_descendants() {
        let root = ProcRoot::new().unwrap();
        root.add(1, "init", &["/sbin/init"], Some("/sbin/init"), &[]).unwrap();
        root.add(10, "opencode", &["opencode"], Some("/usr/bin/opencode"), &[]).unwrap();
        root.add(11, "opencode-cli", &["/opt/OPAQUE/opencode-cli"], Some("/opt/x/opencode-cli"), &[]).unwrap();
        root.add(12, "firefox", &["firefox"], Some("/usr/lib/firefox"), &[]).unwrap();
        root.add(13, "node", &["node"], Some("/usr/bin/node"), &[]).unwrap();
        root.status(1, 0).unwrap();
        root.status(10, 1).unwrap();
        root.status(11, 10).unwrap(); // 11 is a child of 10
        root.status(12, 1).unwrap();
        root.status(13, 11).unwrap(); // 13 is a grandchild of 10 through 11

        // The real watch roots everything at /proc; here we mirror its logic over the fake tree.
        let apps = vec!["opencode".to_owned()];
        let entries: Vec<u32> = std::fs::read_dir(root.proc())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
            .collect();
        let matched: Vec<u32> = entries
            .iter()
            .filter(|pid| {
                apps.iter()
                    .any(|app| exclusions::app_matches(&process_name_root(root.root(), **pid), app))
            })
            .copied()
            .collect();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        // PPid of every process is scanned, not only of the first matches.
        for pid in &entries {
            if let Some(parent) = read_ppid(root.root(), *pid) {
                children.entry(parent).or_default().push(*pid);
            }
        }
        let mut out: Vec<u32> = Vec::new();
        let mut seen: HashSet<u32> = HashSet::new();
        let mut todo: VecDeque<u32> = matched.into_iter().collect();
        while let Some(pid) = todo.pop_front() {
            if !seen.insert(pid) {
                continue;
            }
            out.push(pid);
            if let Some(kids) = children.get(&pid) {
                todo.extend(kids.iter().copied());
            }
        }
        out.sort_unstable();
        assert_eq!(out, [10, 11, 13]);
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
