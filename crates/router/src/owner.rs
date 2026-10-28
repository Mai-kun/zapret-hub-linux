//! Which process owns a local port (socket events, then the /proc/net tables) and its image path.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::rules::Protocol;

pub const PID_WAIT: Duration = Duration::from_millis(50);

/// Local port -> PID, fed by socket events; `wait` covers an event that trails its packet.
/// `None` means "looked up, no owner found" and is not waited for again.
#[derive(Default)]
pub struct Owners {
    map: Mutex<HashMap<u16, Option<u32>>>,
    changed: Condvar,
}

impl Owners {
    pub fn record(&self, local_port: u16, pid: u32) {
        self.map.lock().unwrap().insert(local_port, Some(pid));
        self.changed.notify_all();
    }

    pub fn forget(&self, local_port: u16) {
        self.map.lock().unwrap().remove(&local_port);
    }

    /// Forgets every port: a new session knows nobody.
    pub fn clear(&self) {
        self.map.lock().unwrap().clear();
        self.changed.notify_all();
    }

    pub fn wait(&self, local_port: u16, timeout: Duration) -> Option<u32> {
        let guard = self.map.lock().unwrap();
        let (guard, _) = self
            .changed
            .wait_timeout_while(guard, timeout, |m| !m.contains_key(&local_port))
            .unwrap();
        guard.get(&local_port).copied().flatten()
    }

    /// Known entry, else `lookup` (the tables), else wait for an event; a miss is remembered.
    pub fn pid(
        &self,
        local_port: u16,
        timeout: Duration,
        lookup: impl FnOnce(u16) -> Option<u32>,
    ) -> Option<u32> {
        if let Some(known) = self.map.lock().unwrap().get(&local_port) {
            return *known;
        }
        if let Some(pid) = lookup(local_port) {
            self.record(local_port, pid);
            return Some(pid);
        }
        let found = self.wait(local_port, timeout);
        if found.is_none() {
            self.map.lock().unwrap().entry(local_port).or_insert(None);
        }
        found
    }
}

/// Port of a `MIB_TCPROW_OWNER_PID` (low 16 bits, network byte order).
pub fn port_of(dw_port: u32) -> u16 {
    u16::from_be(dw_port as u16)
}

/// Owner of a table row: TIME_WAIT and similar rows carry PID 0 and never count.
pub fn row_owner(dw_port: u32, pid: u32, port: u16) -> Option<u32> {
    (pid != 0 && port_of(dw_port) == port).then_some(pid)
}

/// The IPv4 and IPv6 table files of one protocol.
fn net_files(protocol: Protocol) -> &'static [&'static str] {
    match protocol {
        Protocol::Udp => &["/proc/net/udp", "/proc/net/udp6"],
        Protocol::Tcp | Protocol::Both => &["/proc/net/tcp", "/proc/net/tcp6"],
    }
}

/// Inodes of the sockets with `port` as their local port (`None` — every local port).
/// TCP rows keep the LISTEN state only (state column `0A`) when `listen_only`.
fn socket_inodes(protocol: Protocol, port: Option<u16>, listen_only: bool) -> Vec<u64> {
    let mut inodes = Vec::new();
    for file in net_files(protocol) {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // `sl local_address rem_address st ... inode ...`
            let Some(local) = fields.get(1).and_then(|f| f.split(':').nth(1)) else {
                continue;
            };
            // `local_port == port`; a `None` port keeps every row.
            let local_port = u16::from_str_radix(local, 16).ok();
            if port.is_some() && port != local_port {
                continue;
            }
            if listen_only && fields.get(3) != Some(&"0A") {
                continue;
            }
            if let Some(inode) = fields
                .get(9)
                .and_then(|i| i.parse::<u64>().ok())
                .filter(|inode| *inode != 0)
            {
                inodes.push(inode);
            }
        }
    }
    inodes
}

/// Which process holds a socket inode: every `/proc/[pid]/fd/*` link `socket:[inode]`.
fn inode_pid_map() -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return map;
    };
    let mut pids: Vec<u32> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| name.parse().ok())
        .collect();
    pids.sort_unstable();
    for pid in pids {
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(link) = std::fs::read_link(fd.path()) else {
                continue;
            };
            if let Some(inode) = link
                .to_string_lossy()
                .trim_start_matches("socket:[")
                .strip_suffix(']')
                .and_then(|inode| inode.parse().ok())
            {
                // A socket can be shared; the lowest PID wins.
                map.entry(inode).or_insert(pid);
            }
        }
    }
    map
}

/// A PID owning a local `port` per the socket tables, IPv4 first then IPv6 (`Both` is TCP).
fn table_pid_of(protocol: Protocol, local_port: u16) -> Option<u32> {
    // ponytail: port lookups take the first matching inode; several sockets can share a port,
    // fine for an owner guess
    let inodes = socket_inodes(protocol, Some(local_port), false);
    let map = inode_pid_map();
    inodes
        .iter()
        .filter_map(|inode| map.get(inode).copied())
        .find(|pid| *pid != 0)
}

fn tcp_pid(port: u16) -> Option<u32> {
    table_pid_of(Protocol::Tcp, port)
}

fn udp_pid(port: u16) -> Option<u32> {
    table_pid_of(Protocol::Udp, port)
}

/// PIDs owning UDP sockets now, IPv4 and IPv6 tables, sorted and without duplicates.
pub fn udp_pids() -> Vec<u32> {
    let inodes = socket_inodes(Protocol::Udp, None, false);
    let map = inode_pid_map();
    let mut pids: Vec<u32> = inodes
        .iter()
        .filter_map(|inode| map.get(inode).copied())
        .filter(|&p| p != 0)
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids
}

/// PID of the process listening on the TCP `port`.
pub fn listener_pid(port: u16) -> Option<u32> {
    let inodes = socket_inodes(Protocol::Tcp, Some(port), true);
    let map = inode_pid_map();
    inodes
        .iter()
        .filter_map(|inode| map.get(inode).copied())
        .find(|pid| *pid != 0)
}

/// PID owning the local `local_port` per the socket tables, IPv4 then IPv6 (`Both` is TCP).
pub fn table_pid(protocol: Protocol, local_port: u16) -> Option<u32> {
    match protocol {
        Protocol::Udp => udp_pid(local_port),
        Protocol::Tcp | Protocol::Both => tcp_pid(local_port),
    }
}

/// Start time in clock ticks since boot (stat field 22) of a running process; `None` if it does
/// not exist or is a zombie.
pub fn process_start(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name can hold anything, including `) `: everything after its close is safe.
    let after_comm = stat.rsplit(')').next()?;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    if fields.first() == Some(&"Z") {
        return None;
    }
    fields.get(19)?.parse().ok()
}

/// Full path of the process image.
pub fn image_path(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

/// PID -> (start time, image path); the start time tells a reused PID from the old process.
/// A failed image lookup is cached too (`None`), so System or unopenable processes cost one query.
#[derive(Default)]
pub struct Images(Mutex<HashMap<u32, Cached>>);

type Cached = (u64, Option<Arc<str>>);

impl Images {
    pub fn lookup(
        &self,
        pid: u32,
        start: u64,
        image: impl FnOnce() -> Option<String>,
    ) -> Option<Arc<str>> {
        if let Some((s, path)) = self.0.lock().unwrap().get(&pid)
            && *s == start
        {
            return path.clone();
        }
        let path: Option<Arc<str>> = image().map(Into::into); // outside the lock
        self.0.lock().unwrap().insert(pid, (start, path.clone()));
        path
    }

    pub fn get(&self, pid: u32) -> Option<Arc<str>> {
        let start = process_start(pid)?;
        self.lookup(pid, start, || image_path(pid))
    }

    /// Drops entries whose process is gone or whose PID now has another start time.
    pub fn prune(&self, alive: impl Fn(u32) -> Option<u64>) {
        let seen: Vec<(u32, u64)> = self
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|(pid, (start, _))| (*pid, *start))
            .collect();
        // The liveness checks run outside the lock: the capture thread reads the cache.
        let dead: Vec<(u32, u64)> = seen
            .into_iter()
            .filter(|(pid, start)| alive(*pid) != Some(*start))
            .collect();
        self.0
            .lock()
            .unwrap()
            .retain(|pid, (start, _)| !dead.contains(&(*pid, *start)));
    }

    pub fn paths(&self) -> Vec<Arc<str>> {
        self.0
            .lock()
            .unwrap()
            .values()
            .filter_map(|(_, p)| p.clone())
            .collect()
    }
}
