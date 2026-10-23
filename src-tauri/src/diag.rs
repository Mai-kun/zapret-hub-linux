//! `doctor` and `probe`: the whole state of every subsystem in one answer, and a live check of
//! one target — what an agent reads in one go instead of hunting through the window.

use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

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

/// Everything at once; `issues` is what to fix and how, empty when it all looks healthy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct DoctorReport {
    pub engine: EngineDiag,
    pub lists_and_bins: ListsAndBins,
    pub service: ServiceDiag,
    pub nfqueue: NfQueueDiag,
    pub nftables: NftDiag,
    pub conflicts: Conflicts,
    pub proxies: ProxiesDiag,
    pub issues: Vec<String>,
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

    let opened = state.engine2();
    let service = service_diag(&settings, &mut issues);
    let (engine, opened) = engine_diag(opened, &mut issues);
    let lists_and_bins = lists_and_bins(&opened, &service, &mut issues);
    let nfqueue = nfqueue(&service, &mut issues);
    let nftables = nftables(&mut issues);
    let conflicts = conflicts(&service, &mut issues);
    let proxies = proxies(app, &settings, &mut issues);
    DoctorReport {
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

/// The `zapret2` service as the overview shows it, with its strategy and the game filter in force.
fn service_diag(settings: &Settings, issues: &mut Vec<String>) -> ServiceDiag {
    let (name, _) = service::active();
    let state = service::state(name);
    if state != SvcState::Running {
        issues.push(format!(
            "the {name} service is {state:?}: apply a strategy (`zapret-hub-cli apply <name>` \
             or `zapret-hub-cli apply-best`)"
        ));
    }
    ServiceDiag {
        name: name.to_owned(),
        state,
        strategy: service::strategy(),
        game_filter: settings.game_filter,
    }
}

/// The engine, its rights and its capabilities; each refusal becomes the remedy next to it.
fn engine_diag(
    engine: anyhow::Result<Option<Engine>>,
    issues: &mut Vec<String>,
) -> (EngineDiag, Option<Engine>) {
    let engine = match engine {
        Ok(Some(engine)) => engine,
        Ok(None) => {
            issues.push(
                "the zapret2 folder is not set: choose it in Zapret Hub → Settings".to_owned(),
            );
            return (empty_engine(None), None);
        }
        Err(err) => {
            issues.push(format!("{err:#}"));
            return (empty_engine(Some(format!("{err:#}"))), None);
        }
    };
    let exe = engine.exe();
    let path = exe.display().to_string();
    let version = match engine.version() {
        Ok(version) => Some(version.text),
        Err(err) => {
            issues.push(format!("{path}: {err:#}"));
            None
        }
    };
    if engine.is_nfqws() {
        let (executable, cap_net_admin, cap_net_raw) = rights(exe);
        if !executable {
            issues.push(format!("{path} cannot be executed: `sudo chmod +x {path}`"));
        } else if !(cap_net_admin && cap_net_raw) {
            issues.push(format!(
                "{path} misses capabilities (cap_net_admin {cap_net_admin}, cap_net_raw \
                 {cap_net_raw}): `sudo setcap 'cap_net_admin,cap_net_raw=eip' {path}`"
            ));
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
    issues: &mut Vec<String>,
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
            issues.push(format!(
                "{} is missing: the strategy would read nothing from it",
                lists.join(file).display()
            ));
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
            if used_by_active && bytes == 0 {
                issues.push(format!(
                    "{} of the bin folder is empty and the active strategy sends it as a fake \
                     or a blob: DPI would answer with an empty packet",
                    bin.join(&name).display()
                ));
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
            issues.push(format!(
                "the active strategy loads {} of the bin folder, which is missing",
                strategies::bin_dir(engine).join(used).display()
            ));
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
fn nfqueue(service: &ServiceDiag, issues: &mut Vec<String>) -> NfQueueDiag {
    let state = queue_text().as_deref().and_then(parse_queue);
    if service.state == SvcState::Running {
        match state {
            None => issues.push(format!(
                "queue {QNUM} is not in the kernel's queue list: the nft table did not apply it \
                 or the strategy named another --qnum"
            )),
            Some((0, _)) => issues.push(
                "the service runs but nobody holds its queue: nfqws2 did not bind it — see the \
                 journal (`zapret-hub-cli service logs`)"
                    .to_owned(),
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

/// The `inet zapret_hub` table as it is now: applied or not, and the two guards in place.
fn nftables(issues: &mut Vec<String>) -> NftDiag {
    #[cfg(unix)]
    {
        let text = table_text().unwrap_or_default();
        let lo_skip = text.contains(r#"oifname "lo""#);
        let fwmark = text.contains(FWMARK);
        let active = !text.trim().is_empty();
        if !active {
            issues.push(
                "the nft table inet zapret_hub is not applied: nfqws2 gets no packets — restart \
                 the service, its ExecStartPre applies the table"
                    .to_owned(),
            );
        } else if !lo_skip || !fwmark {
            issues.push(
                "the nft table misses the `oifname \"lo\" or the nfqws2-mark rule: apply the \
                 strategy again, the unit's table file holds both"
                    .to_owned(),
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
    let _ = issues;
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
fn conflicts(service: &ServiceDiag, issues: &mut Vec<String>) -> Conflicts {
    let own = std::process::id();
    let service_pid = service::status(&service.name).map_or(0, |(_, pid)| pid);
    let mut processes = Vec::new();
    for image in ["nfqws2", "nfqws", "winws2", "winws"] {
        for proc in zapret::procs::find(image) {
            if proc.pid == service_pid || proc.pid == own {
                continue; // the service's own engine, or this very app
            }
            issues.push(format!(
                "an outside {image} process runs, pid {}: it takes packets from the queue too — \
                 end it or stop its service",
                proc.pid
            ));
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
        issues.push(format!(
            "the foreign nftables table {table} filters traffic together with Zapret Hub: delete \
             or stop the tool that made it"
        ));
    }
    Conflicts { processes, tables }
}

/// The two proxies: does the SOCKS5 in the settings answer, and tg-ws take its port.
fn proxies(app: &AppHandle, settings: &Settings, issues: &mut Vec<String>) -> ProxiesDiag {
    let socks = match &settings.socks5 {
        Some(addr) => {
            let status = probe::socks::check(addr);
            if !status.ok {
                issues.push(format!(
                    "the SOCKS5 proxy {addr} does not answer: {} — check that it runs and the \
                     address holds, or clear it in Settings",
                    status.error.as_deref().unwrap_or("no greeting")
                ));
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
        issues.push(format!(
            "tg-ws-proxy runs but nothing listens on port {}: restart it (`zapret-hub-cli tg-ws on`)",
            tg.port
        ));
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
}
