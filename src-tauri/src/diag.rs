//! `doctor` and `probe`: the whole state of every subsystem in one answer, and a live check of
//! one target — what an agent reads in one go instead of hunting through the window.

use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use probe::curl::{self, CheckKind, CheckResult, CheckStatus};
use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use zapret::service::{self, SvcState};
use zapret2::{Engine, strategies};

use crate::actions;
use crate::settings::Settings;
use crate::state::AppState;

/// NFQWS2_COMPAT: `nfqws2`'s own packets carry it and must not enter the queue again; the table
/// keeps the same mark (the constant is private to `zapret2::nft`).
const FWMARK: &str = "0x40000000";
/// The queue `zapret2::nft::table` fills and `nfqws2 --qnum=` binds.
const QNUM: u32 = zapret2::nft::QNUM;
const QUEUE_FILE: &str = "/proc/net/netfilter/nfnetlink_queue";

/// The system DNS gets this long to answer: a dead resolver would hang forever, and only hosts
/// whose resolution the bypass makes possible matter.
const DNS_BUDGET: Duration = Duration::from_millis(1500);
/// The domains a system resolver must answer for `doctor` to call it working: blocked targets
/// would not resolve either, so the check only asks for what any resolver answers.
const DNS_HOSTS: [&str; 2] = ["discord.com", "ya.ru"];
/// Public resolvers a direct UDP query still reaches while the system one does not: the fix's
/// config names them.
const DNS_SERVERS: [&str; 2] = ["77.88.8.8:53", "8.8.8.8:53"];
/// The drop-in the `FixSystemDns` fix writes: plain DNS, no failure of one server holds the rest.
const RESOLVED_CONF: &str = "/etc/systemd/resolved.conf.d/99-zapret-dns.conf";
const RESOLVED_CONFIG: &str =
    "[Resolve]\nDNS=77.88.8.8 77.88.8.1 8.8.8.8 1.1.1.1\nDomains=~.\nDNSOverTLS=no\n";

/// A `.bin` of the bin folder that holds nothing and its non-empty donor of the same content.
const BIN_DONORS: &[(&str, &[&str])] = &[
    ("stun2.bin", &["stun.bin"]),
    ("quic_initial_4pda_to.bin", &["quic_initial_www_google_com.bin"]),
    ("tls_clienthello_sochi_park.bin", &["tls_clienthello_max_ru.bin"]),
];

/// The engine: where it is, what it says, and whether the system lets it take packets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct EngineDiag {
    /// The engine file; `None` while the zapret2 folder is unset or does not open, `error`
    /// says why.
    pub path: Option<String>,
    pub error: Option<String>,
    /// `nfqws2 --version` as the overview shows it.
    pub version: Option<String>,
    /// The Unix exec bits of the engine file (true for a Windows build).
    pub executable: bool,
    /// What `getcap` says; both are checked only for a `nfqws2` build.
    pub cap_net_admin: bool,
    pub cap_net_raw: bool,
}

/// `doctor`'s `lists_and_bins`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct ListsAndBins {
    /// Non-empty, non-comment lines; `None` while zapret2 is unset.
    pub general_domains: Option<u32>,
    pub google_domains: Option<u32>,
    pub exclude_user_domains: Option<u32>,
    /// Every `.bin` of the engine's bin folder.
    pub bins: Vec<Bin>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct Bin {
    pub name: String,
    pub bytes: u32,
    /// The active strategy's text loads it.
    pub used_by_active: bool,
    /// 0 bytes while the strategy sends it as a fake or a blob: DPI would answer with an empty
    /// packet.
    pub empty_used: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct ServiceDiag {
    pub name: String,
    pub state: SvcState,
    pub strategy: Option<String>,
    pub game_filter: bool,
}

/// `/proc/net/netfilter/nfnetlink_queue`, in the kernel's own order: the queue number, the
/// listener's netlink port, then the packets waiting in the queue.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct NfQueueDiag {
    /// A line for queue 200 with a portid other than 0: something has the queue open.
    pub open: bool,
    /// The netlink port of the engine holding it; 0 means nobody is there.
    pub peer_portid: Option<u32>,
    /// Packets sitting in the queue.
    pub queue_total: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct NftDiag {
    /// `nft list table inet zapret_hub` answered with rules.
    pub active: bool,
    /// `oifname "lo"` accepts: queued loopback packets stall local connections.
    pub lo_skip: bool,
    /// The mark rule that keeps `nfqws2`'s own packets out of the queue.
    pub fwmark: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct Conflicts {
    /// Engine processes running that the service does not own: their handles take the packets
    /// the queue sends first.
    pub processes: Vec<String>,
    /// `zapretunix` and other third-party nftables with a zapret in the name.
    pub tables: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct SocksDiag {
    /// The setting holds an address.
    pub set: bool,
    /// It answered a SOCKS5 greeting now.
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct TgWsDiag {
    pub installed: bool,
    /// `systemctl --user is-active` answers «active».
    pub running: bool,
    /// The settings' port.
    pub port: u16,
    /// A TCP connection to the port got through.
    pub listening: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct ProxiesDiag {
    pub socks5: SocksDiag,
    pub tg_ws: TgWsDiag,
}

/// An automatic remedy of one problem `doctor` found: `fix_doctor_issue` runs it, `doctor --fix`
/// runs all of them, then the report is taken again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum FixAction {
    /// The system resolver does not answer while a plain UDP query of a public resolver does:
    /// `/etc/systemd/resolved.conf.d/99-zapret-dns.conf` is written and the caches are flushed.
    FixSystemDns,
    /// An unfinished operation (`pending.json`) or a set strategy without its service back:
    /// the snapshot is restored or the strategy applied again.
    RestoreService,
    /// Empty or missing `.bin` files of the bin folder: a non-empty donor is copied over them.
    RepairBins,
    /// Outside engine processes and foreign `zapret*` nftables: they take the queue's packets.
    KillConflicts,
}

/// One problem and its remedy: `text` is what is wrong, `fix` is what `[Исправить]` runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct Issue {
    pub text: String,
    pub fix: Option<FixAction>,
}

/// The system DNS against a public resolver: the resolver of `/etc/resolv.conf` answers, and a
/// plain UDP query of `DNS_SERVERS` does.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct SystemDnsDiag {
    /// The system resolver answered within the budget.
    pub system_ok: bool,
    /// Any public resolver answered directly over UDP 53.
    pub direct_ok: bool,
}

/// Everything at once; `issues` is what to fix and how, empty when it all looks healthy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct DoctorReport {
    pub system_dns: SystemDnsDiag,
    pub engine: EngineDiag,
    pub lists_and_bins: ListsAndBins,
    pub service: ServiceDiag,
    pub nfqueue: NfQueueDiag,
    pub nftables: NftDiag,
    pub conflicts: Conflicts,
    pub proxies: ProxiesDiag,
    pub issues: Vec<Issue>,
}

/// A domain (`discord.com`) or URL (`https://gateway.discord.gg`): where it goes, what the
/// zapret2 lists and the routing rules think of it, whether it answers through zapret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct ProbeResult {
    pub host: String,
    pub url: String,
    pub resolved_ips: Vec<String>,
    pub matching: Matchings,
    pub checks: Checks,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct Matchings {
    /// In `list-general.txt` or `list-general-user.txt`.
    pub in_list_general: bool,
    /// In `list-google.txt`.
    pub in_list_google: bool,
    /// In `list-exclude.txt` or `list-exclude-user.txt`: the exclusions let it through.
    pub excluded_domain: bool,
    /// One of the resolved IPs is in `ipset-exclude.txt` or `ipset-exclude-user.txt`.
    pub excluded_ip: bool,
    /// The first enabled rule of `routes.toml` whose domains cover the host or whose subnets
    /// hold one of the resolved IPs.
    pub matched_route_rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct Checks {
    pub http: CheckResult,
    pub tls12: CheckResult,
    pub tls13: CheckResult,
    /// ICMP round trip; `None` on timeout or a target that answers no pings.
    pub ping_ms: Option<u32>,
}

/// The whole report. Every issue carries its own remedy, so the answer is the state and the
/// fix in one JSON.
pub fn doctor(app: &AppHandle) -> DoctorReport {
    let state = actions::state(app);
    let settings = state.settings();
    let mut issues = Vec::new();

    let system_dns = system_dns(&mut issues);
    let opened = state.engine2();
    let service = service_diag(&settings, &mut issues);
    let (engine, opened) = engine_diag(opened, &mut issues);
    let lists_and_bins = lists_and_bins(&opened, &service, &mut issues);
    let nfqueue = nfqueue(&service, &mut issues);
    let nftables = nftables(&service, &mut issues);
    let conflicts = conflicts(&service, &mut issues);
    let proxies = proxies(app, &settings, &mut issues);
    restore_service(&state, &mut issues);
    DoctorReport {
        system_dns,
        engine,
        lists_and_bins,
        service,
        nfqueue,
        nftables,
        conflicts,
        proxies,
        issues,
    }
}

/// A helper that keeps the remedy attached to its text: `fix` is None for what only advice can
/// repair.
fn issue(issues: &mut Vec<Issue>, text: String, fix: Option<FixAction>) {
    issues.push(Issue { text, fix });
}

/// The system resolver now, and a public one the query reaches directly: when only the direct
/// answer comes, the `FixSystemDns` fix makes the system resolver plain again.
fn system_dns(issues: &mut Vec<Issue>) -> SystemDnsDiag {
    let hosts: Vec<String> = DNS_HOSTS.iter().map(|host| host.to_string()).collect();
    let system_ok = resolves(&hosts, DNS_BUDGET);
    let direct_ok = DNS_SERVERS.iter().any(|server| udp_dns_ok(server, DNS_BUDGET));
    if !system_ok && direct_ok {
        issue(
            issues,
            format!(
                "the system DNS resolver does not answer while a direct UDP query of a public \
                 resolver does: `fix` writes {RESOLVED_CONF} (the DNS servers above, plain no \
                 DoT) and restarts systemd-resolved"
            ),
            Some(FixAction::FixSystemDns),
        );
    }
    SystemDnsDiag {
        system_ok,
        direct_ok,
    }
}

/// Whether any host of `hosts` resolves within `budget`. `to_socket_addrs` cannot be timed out,
/// so the lookups are detached threads and the wait is bounded instead. One "yes" is one: the
/// resolver answers, and it does not owe the rest faster than the deadline.
fn resolves(hosts: &[String], budget: Duration) -> bool {
    use std::net::ToSocketAddrs as _;
    let (send, recv) = mpsc::channel::<bool>();
    for host in hosts {
        let send = send.clone();
        let host = host.clone(); // owned: the lookups are detached
        let _ = thread::Builder::new()
            .name("dns-check".into())
            .spawn(move || {
                let _ = send.send((host.as_str(), 443).to_socket_addrs().is_ok());
            });
    }
    drop(send); // a disconnect means every lookup finished
    let deadline = Instant::now() + budget;
    let mut ok = false;
    for _ in 0..hosts.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match recv.recv_timeout(left) {
            Ok(answered) if answered => {
                ok = true;
                break;
            }
            Ok(_) => {} // this host is unknown to nobody, the next one may come
            Err(_) => break, // all lookups done, or the budget ran out
        }
    }
    ok
}

/// A plain UDP DNS query (an A record) reaches `server` (`8.8.8.8:53`) and comes back answered.
/// The timeouts bound every step, so a hung network cannot hold the check longer than `2 × budget`.
fn udp_dns_ok(server: &str, budget: Duration) -> bool {
    thread::scope(|scope| {
        scope
            .spawn(move || {
                let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
                    return false;
                };
                let _ = socket.set_read_timeout(Some(budget));
                let _ = socket.set_write_timeout(Some(budget));
                if socket.connect(server).is_err() {
                    return false;
                }
                let query = dns_query(0x1234u16, "discord.com");
                let mut answer = [0u8; 512];
                socket.send(&query).is_ok()
                    && socket.recv(&mut answer).is_ok_and(|len| {
                        // The answer's id matches and it says NOERROR with at least one record.
                        len >= 12
                            && answer[0] == query[0]
                            && answer[1] == query[1]
                            && answer[3] & 0x0F == 0
                            && (answer[6], answer[7]) != (0, 0)
                    })
            })
            .join()
            .unwrap_or(false) // a panicked check did not reach the resolver either
    })
}

/// An A query of `name` framed as RFC 1035 says: the fixed id, one question, labels, A, IN.
fn dns_query(id: impl Into<u16>, name: &str) -> Vec<u8> {
    let id = id.into();
    let mut out = vec![0u8; 12];
    out[0] = (id >> 8) as u8;
    out[1] = id as u8;
    out[2] = 0x01; // RD: the answer may come from a cache
    out[5] = 1; // one question
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend(label.as_bytes());
    }
    out.push(0); // the root
    out.extend([0, 1, 0, 1]); // type A, class IN
    out
}

/// The `zapret2` service as the overview shows it, with its strategy and the game filter in force.
fn service_diag(settings: &Settings, issues: &mut Vec<Issue>) -> ServiceDiag {
    let (name, _) = service::active();
    let state = service::state(name);
    if state != SvcState::Running {
        // A strategy recorded but no service is what an interrupted test or apply leaves:
        // `RestoreService` applies it again; nothing set means only advice can repair it.
        let fix = service::strategy().map(|_| FixAction::RestoreService);
        let remedy = match fix {
            Some(_) => ": `fix` applies it again".to_owned(),
            None => format!(
                ": apply a strategy (`zapret-hub-cli apply <name>` or `zapret-hub-cli apply-best`)"
            ),
        };
        issue(
            issues,
            format!("the {name} service is {state:?}{remedy}"),
            fix,
        );
    }
    ServiceDiag {
        name: name.to_owned(),
        state,
        strategy: service::strategy(),
        game_filter: settings.game_filter,
    }
}

/// A `pending.json` left behind means an unfinished operation: only its restore (or a fresh
/// apply of the strategy) puts the state back. A set strategy without its service or table is
/// reported by `service_diag` and `nftables`, with the same fix.
fn restore_service(state: &AppState, issues: &mut Vec<Issue>) {
    let pending = zapret::snapshot::pending_path(&state.paths.data());
    match zapret::snapshot::Snapshot::load(&pending) {
        Ok(Some(_)) => issue(
            issues,
            format!(
                "{} holds an unfinished operation: its state was not put back — `fix` restores it",
                pending.display()
            ),
            Some(FixAction::RestoreService),
        ),
        Err(err) => issue(
            issues,
            format!("{err:#}"),
            None, // a broken pending.json cannot be auto-restored: a human decides (snapshot spec)
        ),
        Ok(None) => {}
    }
}

/// The engine, its rights and its capabilities; each refusal becomes the remedy next to it.
fn engine_diag(
    engine: anyhow::Result<Option<Engine>>,
    issues: &mut Vec<Issue>,
) -> (EngineDiag, Option<Engine>) {
    let engine = match engine {
        Ok(Some(engine)) => engine,
        Ok(None) => {
            issue(
                issues,
                "the zapret2 folder is not set: choose it in Zapret Hub → Settings".to_owned(),
                None,
            );
            return (empty_engine(None), None);
        }
        Err(err) => {
            issue(issues, format!("{err:#}"), None);
            return (empty_engine(Some(format!("{err:#}"))), None);
        }
    };
    let exe = engine.exe();
    let path = exe.display().to_string();
    let version = match engine.version() {
        Ok(version) => Some(version.text),
        Err(err) => {
            issue(issues, format!("{path}: {err:#}"), None);
            None
        }
    };
    if engine.is_nfqws() {
        let (executable, cap_net_admin, cap_net_raw) = rights(exe);
        if !executable {
            issue(
                issues,
                format!("{path} cannot be executed: `sudo chmod +x {path}`"),
                None,
            );
        } else if !(cap_net_admin && cap_net_raw) {
            issue(
                issues,
                format!(
                    "{path} misses capabilities (cap_net_admin {cap_net_admin}, cap_net_raw \
                     {cap_net_raw}): `sudo setcap 'cap_net_admin,cap_net_raw=eip' {path}`"
                ),
                None,
            );
        }
        (
            EngineDiag {
                path: Some(path),
                error: None,
                version,
                executable,
                cap_net_admin,
                cap_net_raw,
            },
            Some(engine),
        )
    } else {
        (
            EngineDiag {
                path: Some(path),
                error: None,
                version,
                executable: true,
                cap_net_admin: false,
                cap_net_raw: false,
            },
            Some(engine),
        )
    }
}

fn empty_engine(error: Option<String>) -> EngineDiag {
    EngineDiag {
        path: None,
        error,
        version: None,
        executable: false,
        cap_net_admin: false,
        cap_net_raw: false,
    }
}

/// The exec bits and `getcap`; on a Windows build nothing here is anybody's business.
fn rights(exe: &Path) -> (bool, bool, bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(exe)
            .map(|meta| meta.permissions().mode())
            .unwrap_or(0);
        let capabilities =
            exec::run(Command::new("getcap").arg(exe), Duration::from_secs(10), None)
                .map(|out| out.stdout)
                .unwrap_or_default();
        (
            mode & 0o111 != 0,
            capabilities.contains("cap_net_admin"),
            capabilities.contains("cap_net_raw"),
        )
    }
    #[cfg(not(unix))]
    let _ = exe;
    #[cfg(not(unix))]
    (true, false, false)
}

/// Non-empty, non-comment lines of one list file.
fn domains(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok().map(|text| {
        text.lines()
            .filter(|line| {
                let line = line.trim();
                !line.is_empty() && !line.starts_with('#')
            })
            .count() as u32
    })
}

/// The active strategy's text, when the service's strategy is a zapret2 one and the folder
/// holds it.
fn active_text(engine: &Engine, strategy: Option<&str>) -> Option<strategies::Strategy> {
    let short = strategy.and_then(zapret2::strip_prefix)?;
    strategies::find(engine.root(), short).ok()
}

/// `%BIN%` (any case) as a strategy writes it, up to what ends the token: the names the
/// strategy loads from the bin folder, in the bin folder's own case.
fn referenced_bins(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut names = Vec::new();
    let mut from = 0;
    while let Some(at) = lower[from..].find("%bin%") {
        let start = from + at + "%bin%".len();
        let tail = &lower[start..];
        let end = tail
            .find(['"', ' ', '\t', '(', ')', '\r', '\n', ','])
            .unwrap_or(tail.len());
        let name = &text[start..start + end];
        let name = name.trim_start_matches(['\\', '/']);
        if name.ends_with(".bin") {
            names.push(name.to_owned());
        }
        from = start;
    }
    names
}

/// The three counts and every `.bin` with its used-by mark; a `.bin` the active strategy sends
/// empty or misses, and a missing list, are problems the DPI check only hints at.
fn lists_and_bins(
    engine: &Option<Engine>,
    service: &ServiceDiag,
    issues: &mut Vec<Issue>,
) -> ListsAndBins {
    let Some(engine) = engine else {
        return ListsAndBins::default();
    };
    let lists = strategies::lists_dir(engine);
    let count = |file: &str| domains(&lists.join(file));
    for (file, count) in [
        ("list-general.txt", count("list-general.txt")),
        ("list-google.txt", count("list-google.txt")),
        ("list-exclude-user.txt", count("list-exclude-user.txt")),
    ] {
        if count.is_none() {
            issue(
                issues,
                format!(
                    "{} is missing: the strategy would read nothing from it",
                    lists.join(file).display()
                ),
                None,
            );
        }
    }
    let active = active_text(engine, service.strategy.as_deref());
    let referenced = active
        .as_ref()
        .map(|active| referenced_bins(&active.text))
        .unwrap_or_default();
    let mut bins = Vec::new();
    let bin = strategies::bin_dir(engine);
    {
        for entry in std::fs::read_dir(&bin)
            .map(|entries| entries.flatten().collect::<Vec<_>>())
            .unwrap_or_default()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".bin") {
                continue;
            }
            let bytes = entry.metadata().map_or(0u32, |meta| meta.len() as u32);
            let used_by_active = referenced.iter().any(|used| used == &name);
            if bytes == 0 {
                let for_active = used_by_active
                    .then(|| " and the active strategy sends it as a fake or a blob: DPI would \
                               answer with an empty packet".to_owned())
                    .unwrap_or_else(|| " and its donor can fill it in".to_owned());
                issue(
                    issues,
                    format!("{} of the bin folder is empty{for_active}", bin.join(&name).display()),
                    Some(FixAction::RepairBins),
                );
            }
            bins.push(Bin {
                name,
                bytes,
                used_by_active,
                empty_used: used_by_active && bytes == 0,
            });
        }
    }
    for used in &referenced {
        if !bins.iter().any(|bin: &Bin| bin.name == *used) {
            issue(
                issues,
                format!(
                    "the active strategy loads {} of the bin folder, which is missing",
                    strategies::bin_dir(engine).join(used).display()
                ),
                Some(FixAction::RepairBins),
            );
        }
    }
    ListsAndBins {
        general_domains: count("list-general.txt"),
        google_domains: count("list-google.txt"),
        exclude_user_domains: count("list-exclude-user.txt"),
        bins,
    }
}
/// The NFQUEUE: a line for our queue with an engine on it, or nobody there. Only a running
/// service owes the queue; stopped, silence is normal.
fn nfqueue(service: &ServiceDiag, issues: &mut Vec<Issue>) -> NfQueueDiag {
    let state = queue_text().as_deref().and_then(parse_queue);
    if service.state == SvcState::Running {
        match state {
            None => issue(
                issues,
                format!(
                    "queue {QNUM} is not in the kernel's queue list: the nft table did not apply \
                     it or the strategy named another --qnum"
                ),
                None,
            ),
            Some((0, _)) => issue(
                issues,
                "the service runs but nobody holds its queue: nfqws2 did not bind it — see the \
                 journal (`zapret-hub-cli service logs`)"
                    .to_owned(),
                None,
            ),
            _ => {}
        }
    }
    NfQueueDiag {
        open: state.is_some_and(|(portid, _)| portid != 0),
        peer_portid: state.map(|(portid, _)| portid),
        queue_total: state.map(|(_, total)| total),
    }
}

/// The `/proc` queue file; a kernel temp covers `cat` when the file is closed to us.
fn queue_text() -> Option<String> {
    #[cfg(unix)]
    {
        if let Ok(text) = std::fs::read_to_string(QUEUE_FILE) {
            return Some(text);
        }
        zapret::root::run("cat", &[QUEUE_FILE])
            .ok()
            .map(|out| out.stdout)
            .filter(|text| !text.trim().is_empty())
    }
    #[cfg(not(unix))]
    None
}

/// `(peer_portid, queue_total)` of the line of the queue `QNUM`, or `None` when it is absent.
/// The kernel writes: queue number, netlink port of the listener, packets waiting.
fn parse_queue(text: &str) -> Option<(u32, u32)> {
    let q = QNUM.to_string();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some(q.as_str()) {
            continue;
        }
        let portid = fields.next()?.parse().ok()?;
        let total = fields.next()?.parse().ok()?;
        return Some((portid, total));
    }
    None
}

/// The `inet zapret_hub` table as it is now: applied or not, and the two guards in place. A
/// missing table with a strategy applied (a service restart that lost its ExecStartPre) is what
/// `RestoreService` repairs.
fn nftables(service: &ServiceDiag, issues: &mut Vec<Issue>) -> NftDiag {
    #[cfg(unix)]
    {
        let text = table_text().unwrap_or_default();
        let lo_skip = text.contains(r#"oifname "lo""#);
        let fwmark = text.contains(FWMARK);
        let active = !text.trim().is_empty();
        if !active {
            let fix = (service.state == SvcState::Running && service.strategy.is_some())
                .then_some(FixAction::RestoreService);
            issue(
                issues,
                "the nft table inet zapret_hub is not applied: nfqws2 gets no packets — restart \
                 the service, its ExecStartPre applies the table"
                    .to_owned(),
                fix,
            );
        } else if !lo_skip || !fwmark {
            issue(
                issues,
                "the nft table misses the `oifname \"lo\" or the nfqws2-mark rule: apply the \
                 strategy again, the unit's table file holds both"
                    .to_owned(),
                service.strategy
                    .is_some()
                    .then_some(FixAction::RestoreService),
            );
        }
        return NftDiag {
            active,
            lo_skip,
            fwmark,
        };
    }
    // No nftables outside Unix; the queue does not exist there either.
    #[cfg(not(unix))]
    let _ = (service, issues);
    #[cfg(not(unix))]
    NftDiag {
        active: false,
        lo_skip: false,
        fwmark: false,
    }
}

/// `nft list table inet zapret_hub` as the user, then through `sudo`; `None` when nothing answers.
fn table_text() -> Option<String> {
    #[cfg(unix)]
    {
        let args = ["list", "table", "inet", "zapret_hub"];
        let mut cmd = Command::new("nft");
        cmd.args(args);
        if let Ok(out) = exec::run(&mut cmd, Duration::from_secs(10), None)
            && out.success()
            && !out.stdout.trim().is_empty()
        {
            return Some(out.stdout);
        }
        zapret::root::run("nft", &args)
            .ok()
            .filter(|out| out.success() && !out.stdout.trim().is_empty())
            .map(|out| out.stdout)
    }
    #[cfg(not(unix))]
    None
}

/// Outside engine processes and foreign zapret nftables: they each take the packets the queue
/// should keep, so one engine at a time is the rule.
fn conflicts(service: &ServiceDiag, issues: &mut Vec<Issue>) -> Conflicts {
    let own = std::process::id();
    let service_pid = service::status(&service.name).map_or(0, |(_, pid)| pid);
    let mut processes = Vec::new();
    for image in ["nfqws2", "nfqws", "winws2", "winws"] {
        for proc in zapret::procs::find(image) {
            if proc.pid == service_pid || proc.pid == own {
                continue; // the service's own engine, or this very app
            }
            issue(
                issues,
                format!(
                    "an outside {image} process runs, pid {}: it takes packets from the queue \
                     too — `kill-conflicts` ends it or its service does",
                    proc.pid
                ),
                Some(FixAction::KillConflicts),
            );
            processes.push(match &proc.exe {
                Some(exe) => format!("{} (pid {})", exe.display(), proc.pid),
                None => format!("{image} (pid {})", proc.pid),
            });
        }
    }
    let mut tables = Vec::new();
    if let Ok(out) = zapret::root::run("nft", &["list", "tables"]) {
        tables = out
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| line.contains("zapret") && !line.contains("zapret_hub"))
            .map(str::to_owned)
            .collect();
    }
    for table in &tables {
        issue(
            issues,
            format!(
                "the foreign nftables table {table} filters traffic together with Zapret Hub: \
                 `kill-conflicts` deletes it"
            ),
            Some(FixAction::KillConflicts),
        );
    }
    Conflicts { processes, tables }
}

/// The two proxies: does the SOCKS5 in the settings answer, and tg-ws take its port.
fn proxies(app: &AppHandle, settings: &Settings, issues: &mut Vec<Issue>) -> ProxiesDiag {
    let socks = match &settings.socks5 {
        Some(addr) => {
            let status = probe::socks::check(addr);
            if !status.ok {
                issue(
                    issues,
                    format!(
                        "the SOCKS5 proxy {addr} does not answer: {} — check that it runs and the \
                         address holds, or clear it in Settings",
                        status.error.as_deref().unwrap_or("no greeting")
                    ),
                    None,
                );
            }
            SocksDiag {
                set: true,
                ok: status.ok,
                error: status.error,
            }
        }
        None => SocksDiag {
            set: false,
            ok: false,
            error: None,
        },
    };
    let tg = crate::tgws::status(app);
    let listening = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], tg.port)),
        Duration::from_secs(1),
    )
    .is_ok();
    if tg.installed && tg.running && !listening {
        issue(
            issues,
            format!(
                "tg-ws-proxy runs but nothing listens on port {}: restart it (`zapret-hub-cli \
                 tg-ws on`)",
                tg.port
            ),
            None,
        );
    }
    ProxiesDiag {
        socks5: socks,
        tg_ws: TgWsDiag {
            installed: tg.installed,
            running: tg.running,
            port: tg.port,
            listening,
        },
    }
}

// --- fix -------------------------------------------------------------------------------------------------

/// One remedy of the report: what `[Исправить]` and `zapret-hub-cli fix <target>` run, answered
/// by a fresh `doctor`.
pub fn fix(app: &AppHandle, action: FixAction) -> anyhow::Result<()> {
    match action {
        FixAction::FixSystemDns => fix_system_dns(),
        FixAction::RestoreService => fix_restore_service(app),
        FixAction::RepairBins => fix_repair_bins(app),
        FixAction::KillConflicts => fix_kill_conflicts(),
    }
}

/// The system resolver goes plain and public: a drop-in config and a restart, then the caches go.
fn fix_system_dns() -> anyhow::Result<()> {
    zapret::root::write(Path::new(RESOLVED_CONF), RESOLVED_CONFIG)?;
    // Best effort: resolved may be absent or masked on a system whose stub works otherwise.
    if let Err(err) =
        zapret::root::run("systemctl", &["restart", "systemd-resolved"]).and_then(|out| out.check())
    {
        log::warn!("systemd-resolved did not restart: {err:#}");
    }
    zapret::hosts::flush_dns()?;
    Ok(())
}

/// The unfinished operation's state goes back, or a strategy recorded without its service is
/// applied again.
fn fix_restore_service(app: &AppHandle) -> anyhow::Result<()> {
    let state = actions::state(app);
    let pending = zapret::snapshot::pending_path(&state.paths.data());
    if let Some(snapshot) = zapret::snapshot::Snapshot::load(&pending)? {
        let operation = snapshot.operation.clone();
        state.change_safely(&format!("restore pending ({operation})"), || {
            snapshot.restore()?;
            zapret::snapshot::Snapshot::clear(&pending)?;
            Ok(())
        })?;
        return Ok(());
    }
    if let Some(strategy) = service::strategy() {
        actions::apply(app, &strategy)?;
        return Ok(());
    }
    anyhow::bail!("there is nothing to restore: no unfinished operation and no strategy applied");
}

/// Donor `.bin` names to copy from, table first, then the same stem without its trailing number
/// (`stun2.bin` → `stun.bin`).
fn donor_candidates(name: &str) -> Vec<String> {
    let mut donors: Vec<String> = BIN_DONORS
        .iter()
        .find(|(target, _)| *target == name)
        .map(|(_, donors)| donors.iter().map(|donor| donor.to_string()).collect())
        .unwrap_or_default();
    let Some(stem) = name.strip_suffix(".bin") else {
        return donors;
    };
    let cut = stem.trim_end_matches(|c: char| c.is_ascii_digit());
    let without = cut.trim_end_matches(['_', '-']);
    let fallback = format!("{without}.bin");
    if !without.is_empty() && without.len() != stem.len() && !donors.contains(&fallback) {
        donors.push(fallback);
    }
    donors
}

/// The `.bin` files to repair: every empty one of the bin folder, and names the active strategy
/// loads that it holds nothing under.
fn repairable(engine: &Engine, service_strategy: Option<&str>) -> Vec<String> {
    let bin = strategies::bin_dir(engine);
    let mut broken: Vec<String> = match std::fs::read_dir(&bin) {
        Ok(entries) => entries
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                name.ends_with(".bin")
                    && std::fs::metadata(bin.join(name)).is_ok_and(|meta| meta.len() == 0)
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    broken.sort();
    let referenced = active_text(engine, service_strategy)
        .map(|active| referenced_bins(&active.text))
        .unwrap_or_default();
    for used in referenced {
        if !std::fs::metadata(bin.join(&used)).is_ok_and(|meta| meta.len() > 0)
            && !broken.contains(&used)
        {
            broken.push(used);
        }
    }
    broken
}

/// Empty and missing `.bin` files are copied over from their non-empty donors.
fn fix_repair_bins(app: &AppHandle) -> anyhow::Result<()> {
    let state = actions::state(app);
    let engine = state.engine2_required()?;
    let bin = strategies::bin_dir(&engine);
    let broken = repairable(&engine, service::strategy().as_deref());
    anyhow::ensure!(!broken.is_empty(), "no empty or missing `.bin` to repair");
    let mut fixed = Vec::new();
    for name in broken {
        let donor = donor_candidates(&name)
            .into_iter()
            .find(|donor| {
                std::fs::metadata(bin.join(donor)).is_ok_and(|meta| meta.len() > 0)
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{name}: no non-empty donor `.bin` in {} — reinstall the engine release",
                    bin.display()
                )
            })?;
        std::fs::copy(bin.join(&donor), bin.join(&name))?;
        log::info!("{} ← {}", bin.join(&name).display(), donor);
        fixed.push(name);
    }
    log::info!("{}.bin files repaired: {}", fixed.len(), fixed.join(", "));
    Ok(())
}

/// Outside engine processes end, foreign `zapret*` tables go; the service's own engine and this
/// app stay.
fn fix_kill_conflicts() -> anyhow::Result<()> {
    let (name, _) = service::active();
    let service_pid = service::status(name).map_or(0, |(_, pid)| pid);
    let own = std::process::id();
    let mut killed: Vec<String> = Vec::new();
    for image in ["nfqws2", "nfqws", "winws2", "winws"] {
        for proc in zapret::procs::find(image) {
            if proc.pid == service_pid || proc.pid == own {
                continue; // the service's own engine, or this very app
            }
            zapret::procs::kill(proc.pid)?;
            killed.push(format!("{image} (pid {})", proc.pid));
        }
    }
    let mut removed: Vec<String> = Vec::new();
    if let Ok(out) = zapret::root::run("nft", &["list", "tables"]) {
        for table in out
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| line.contains("zapret") && !line.contains("zapret_hub"))
        {
            // `table inet zapretunix` → `nft delete table inet zapretunix`.
            let args: Vec<&str> = ["delete"]
                .iter()
                .copied()
                .chain(table.split_whitespace())
                .collect();
            match zapret::root::run("nft", &args) {
                Ok(out) if out.success() => removed.push(table.to_owned()),
                other => {
                    let err = match other {
                        Ok(out) => out.check().map(|_| ()).err(),
                        Err(err) => Some(err),
                    };
                    let err = err
                        .map(|err| err.to_string())
                        .unwrap_or_else(|| "nft answered nothing".into());
                    log::warn!("nft delete {table}: {err}");
                }
            }
        }
    }
    if killed.is_empty() && removed.is_empty() {
        anyhow::bail!("no outside engine process and no foreign table left");
    }
    log::info!(
        "the conflicts are gone: {} process(es), {} table(s)",
        killed.len(),
        removed.len()
    );
    Ok(())
}

// --- probe -----------------------------------------------------------------------------------------------

/// One probe: the host, what the lists and the routing rules do with it, and the live checks.
pub fn probe(app: &AppHandle, target: &str) -> ProbeResult {
    let (host, url) = url_and_host(target);
    let resolved_ips = resolve(&host);
    let matching = matching(&actions::state(app), &host, &resolved_ips);
    let checks = checks(&url, &host);
    ProbeResult {
        host,
        url,
        resolved_ips,
        matching,
        checks,
    }
}

/// The host behind a domain or URL and the URL itself: the scheme is https by default, userinfo
/// and a trailing dot leave the host; the URL keeps the port and a bracketed IPv6.
pub fn url_and_host(target: &str) -> (String, String) {
    let target = target.trim();
    let lower = target.to_ascii_lowercase();
    let (scheme, rest, had_scheme) = if lower.starts_with("http://") {
        ("http://", &target[7..], true)
    } else if lower.starts_with("https://") {
        ("https://", &target[8..], true)
    } else {
        ("https://", target, false)
    };
    // The authority is the piece before path or query; the userinfo stands before it.
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    let (host_raw, _) = split_port(authority);
    let host = host_raw
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let url = if had_scheme {
        target.to_owned()
    } else {
        format!("{scheme}{authority}")
    };
    (host, url)
}

/// The host part of an authority without the port: `example.com:8443`, `[::1]:9001` too.
fn split_port(authority: &str) -> (String, Option<u16>) {
    if authority.starts_with('[') {
        let (host, rest) = authority.split_once(']').unwrap_or((authority, ""));
        return (
            host.trim_start_matches('[').to_owned(),
            rest.strip_prefix(':').and_then(|port| port.parse().ok()),
        );
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => match port.parse() {
            Ok(port) => (host.to_owned(), Some(port)),
            Err(_) => (authority.to_owned(), None),
        },
        None => (authority.to_owned(), None),
    }
}

/// Every IPv4 the system DNS answers with, without doubles.
fn resolve(host: &str) -> Vec<String> {
    let mut ips: Vec<String> = match (host, 0).to_socket_addrs() {
        Ok(addrs) => addrs.map(|addr| addr.ip().to_string()).collect(),
        Err(_) => Vec::new(),
    };
    ips.sort_unstable();
    ips.dedup();
    ips
}

/// What the zapret2 lists and the routing rules say about the host and its addresses.
fn matching(state: &AppState, host: &str, ips: &[String]) -> Matchings {
    let engine = state.engine2().ok().flatten();
    let read = |file: &str| -> Vec<String> {
        engine
            .as_ref()
            .map(strategies::lists_dir)
            .and_then(|dir| std::fs::read_to_string(dir.join(file)).ok())
            .map(|text| {
                text.lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let in_list = |file: &str| read(file).iter().any(|entry| entry_covers(entry, host));
    let excluded_ips = [read("ipset-exclude.txt"), read("ipset-exclude-user.txt")].concat();
    let rule = |ip: Option<&String>| -> Option<String> {
        router::rules::load(&state.paths.routes())
            .ok()
            .filter(|rules| !rules.is_empty())
            .and_then(|rules| {
                router::rules::Table::new(&rules)
                    .rule_for(host, ip.and_then(|ip| ip.parse().ok()))
                    .map(str::to_owned)
            })
    };
    Matchings {
        in_list_general: in_list("list-general.txt") || in_list("list-general-user.txt"),
        in_list_google: in_list("list-google.txt"),
        excluded_domain: in_list("list-exclude.txt") || in_list("list-exclude-user.txt"),
        excluded_ip: ips
            .iter()
            .any(|ip| excluded_ips.iter().any(|entry| ip_entry_covers(entry, ip))),
        matched_route_rule: rule(None).or_else(|| ips.iter().find_map(|ip| rule(Some(ip)))),
    }
}

/// Whether a zapret2 list entry matches `host` (lowercase): it is a suffix compare, so a plain
/// name and its `*`/`+` forms all cover the domain and its subdomains; a subnet or a plain IP
/// never covers a host name.
pub fn entry_covers(entry: &str, host: &str) -> bool {
    let entry = entry.trim().to_ascii_lowercase();
    if entry.contains('/') || entry.parse::<Ipv4Addr>().is_ok() {
        return false; // that is the ipset side
    }
    let name = entry.strip_suffix('.').unwrap_or(&entry);
    let name = name.strip_prefix("+.").unwrap_or(name);
    let name = name.strip_prefix("*.").unwrap_or(name);
    let name = name.strip_prefix('.').unwrap_or(name); // a leading dot is the same suffix compare
    !name.is_empty() && router::rules::covers(name, host)
}

/// Whether a CIDR or a single-IP entry holds `ip` (an IPv6 answer never matches; the lists carry
/// IPv4 only).
fn ip_entry_covers(entry: &str, ip: &str) -> bool {
    let Ok(ip) = ip.trim().parse::<Ipv4Addr>() else {
        return false;
    };
    router::rules::parse_net(entry.trim()).is_some_and(|(a, b)| (a..=b).contains(&u32::from(ip)))
}

/// The four live checks at once: HTTP, TLS1.2 and TLS1.3 through curl, one ICMP ping.
fn checks(url: &str, host: &str) -> Checks {
    thread::scope(|s| {
        let http = s.spawn(|| curl::check(url, CheckKind::Http, None));
        let tls12 = s.spawn(|| curl::check(url, CheckKind::Tls12, None));
        let tls13 = s.spawn(|| curl::check(url, CheckKind::Tls13, None));
        let ping = s.spawn(|| probe::ping::ping(host, 1000));
        Checks {
            http: http.join().unwrap_or_else(|_| plain(CheckKind::Http)),
            tls12: tls12.join().unwrap_or_else(|_| plain(CheckKind::Tls12)),
            tls13: tls13.join().unwrap_or_else(|_| plain(CheckKind::Tls13)),
            ping_ms: ping.join().unwrap_or(None),
        }
    })
}

/// The answer of a check whose thread died, so the report keeps its shape.
fn plain(kind: CheckKind) -> CheckResult {
    CheckResult {
        kind,
        status: CheckStatus::Error,
        http_code: "000".to_owned(),
        time_ms: None,
        stderr: "the check did not finish".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_forms_end_in_a_host_and_a_url() {
        assert_eq!(
            url_and_host(" Discord.COM "),
            ("discord.com".to_owned(), "https://Discord.COM".to_owned())
        );
        assert_eq!(
            url_and_host("example.com:8443"),
            (
                "example.com".to_owned(),
                "https://example.com:8443".to_owned()
            )
        );
        assert_eq!(
            url_and_host("http://Example.COM/x?y=1"),
            (
                "example.com".to_owned(),
                "http://Example.COM/x?y=1".to_owned()
            )
        );
        assert_eq!(
            url_and_host("https://user:pw@example.com:443/p"),
            (
                "example.com".to_owned(),
                "https://user:pw@example.com:443/p".to_owned()
            )
        );
        assert_eq!(
            url_and_host("https://[::1]:9001/p"),
            ("::1".to_owned(), "https://[::1]:9001/p".to_owned())
        );
    }

    #[test]
    fn list_entries_match_a_host_by_suffix() {
        for entry in ["discord.com", "+.discord.com", "*.discord.com", ".discord.com"] {
            assert!(entry_covers(entry, "discord.com"), "{entry}");
            assert!(entry_covers(entry, "gw.discord.com"), "{entry}");
        }
        assert!(entry_covers(" *.DISCORD.com ", "gw.discord.com"));
        assert!(!entry_covers("discord.com", "discord.com.evil.io"));
        assert!(!entry_covers("# comment", "discord.com"));
        assert!(!entry_covers("", "discord.com"));
        // The IP side stays out of the domain compare.
        assert!(!entry_covers("1.2.0.0/16", "gw.discord.com"));
    }

    #[test]
    fn ip_entries_hold_a_single_or_a_subnet() {
        assert!(ip_entry_covers("203.0.113.0/24", "203.0.113.9"));
        assert!(ip_entry_covers("203.0.113.5", "203.0.113.5"));
        assert!(!ip_entry_covers("203.0.113.0/24", "203.0.114.9"));
        assert!(!ip_entry_covers("discord.com", "203.0.113.5"));
        assert!(!ip_entry_covers("::1", "::1"));
    }

    #[test]
    fn a_queue_line_yields_the_port_and_the_packets() {
        assert_eq!(parse_queue("  200  159031     0 2 65531"), Some((159031, 0)));
        assert_eq!(parse_queue("300 1 2"), None);
        assert_eq!(parse_queue("200 0 0"), Some((0, 0)));
    }

    #[test]
    fn the_bin_names_keep_their_file_case() {
        let text = r#"--blob=a:"%BIN%ACTIVE_GAME_UDP.bin" --new --blob=%BIN%/quic_initial_www_google_com.bin --blob=%BIN%missing.bin"#;
        assert_eq!(
            referenced_bins(text),
            ["ACTIVE_GAME_UDP.bin", "quic_initial_www_google_com.bin", "missing.bin"]
        );
    }

    #[test]
    fn a_query_frames_the_name_type_and_class() {
        let query = dns_query(0x1234u16, "discord.com");
        assert_eq!(&query[..12], &[0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&query[12..], b"\x07discord\x03com\x00\x00\x01\x00\x01");
        // A trailing dot changes nothing.
        assert_eq!(dns_query(1u16, "ya.ru."), dns_query(1u16, "ya.ru"));
    }

    #[test]
    fn donors_come_from_the_table_then_the_stem() {
        assert_eq!(donor_candidates("stun2.bin"), ["stun.bin"]);
        assert_eq!(
            donor_candidates("quic_initial_4pda_to.bin"),
            ["quic_initial_www_google_com.bin"]
        );
        assert_eq!(
            donor_candidates("tls_clienthello_sochi_park.bin"),
            ["tls_clienthello_max_ru.bin"]
        );
        // No table entry: the same name without its trailing number is tried.
        assert_eq!(donor_candidates("some2.bin"), ["some.bin"]);
        assert!(donor_candidates("unique.bin").is_empty());
    }
}
