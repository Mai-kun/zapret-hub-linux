//! The zapret systemd service: state through `systemctl`, changes as a unit file exactly like
//! `service.bat` makes them, and the quick check after an install (5.4).

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use probe::curl::{CheckKind, CheckStatus};

use crate::batparse::ParsedArgs;
use crate::folder::Folder;

pub const SERVICE: &str = "zapret";
/// zapret2's service and process (zapret2 spec 3.1, 6): this crate knows the second engine by
/// these two names only.
pub const SERVICE2: &str = "zapret2";
pub const WINWS2: &str = "winws2.exe";
const STRATEGY_VALUE: &str = "zapret-discord-youtube";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, specta::Type)]
pub enum SvcState {
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    Other,
}

fn cmd(program: &str, args: &[&str]) -> anyhow::Result<exec::Output> {
    Ok(exec::run(
        Command::new(program).args(args),
        Duration::from_secs(60),
        None,
    )?)
}

/// A change of the system's state (`systemctl` unit operations, `sysctl`): root only, so `sudo`
/// stands in when this process is not root (spec 4).
fn root_cmd(program: &str, args: &[&str]) -> anyhow::Result<exec::Output> {
    crate::root::run(program, args)
}

/// ActiveState and MainPID of unit `name`; `None` when systemd does not know it.
pub fn status(name: &str) -> Option<(SvcState, u32)> {
    let ask = cmd("systemctl", &["is-active", name]).ok()?;
    if ask.code == Some(4) {
        return None; // is-active exit 4: beyond systemd (not installed).
    }
    let shown = cmd(
        "systemctl",
        &["show", name, "--property=ActiveState,MainPID", "--value"],
    )
    .ok()?;
    let mut lines = shown.stdout.lines();
    let state = map_state(lines.next().unwrap_or("unknown"));
    let pid = lines.next().and_then(|line| line.parse().ok()).unwrap_or(0);
    Some((state, pid))
}

fn map_state(active: &str) -> SvcState {
    match active {
        "active" => SvcState::Running,
        "activating" => SvcState::StartPending,
        "deactivating" => SvcState::StopPending,
        "inactive" | "failed" | "maintenance" => SvcState::Stopped,
        _ => SvcState::Other,
    }
}

pub fn state(name: &str) -> SvcState {
    status(name).map_or(SvcState::NotInstalled, |(state, _)| state)
}

/// The installed engine's service and process (zapret2 spec 3.1): `zapret2` and `winws2.exe` while
/// the `zapret2` service exists, else Flowseal's. The app installs one engine at a time; when
/// `service.bat` puts `zapret` next to `zapret2`, the system checks name the conflict (spec 9).
pub fn active() -> (&'static str, &'static str) {
    if state(SERVICE2) == SvcState::NotInstalled {
        (SERVICE, "winws.exe")
    } else {
        (SERVICE2, WINWS2)
    }
}

/// The unit file of `name` as `systemctl cat` shows it, or `None` when it has no unit file.
fn unit_text(name: &str) -> Option<String> {
    cmd("systemctl", &["cat", name])
        .ok()?
        .check()
        .ok()
        .map(|out| out.stdout)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SvcConfig {
    pub image_path: String,
    pub auto_start: bool,
}

/// `ExecStart` from the unit file (5.1), what `systemctl cat` shows. `None` when the unit or its
/// ExecStart is missing.
pub fn config(name: &str) -> Option<SvcConfig> {
    let unit = unit_text(name)?;
    let mut exec_start = None;
    for line in unit.lines() {
        if let Some(rest) = line.strip_prefix("ExecStart=") {
            // Any `ExecStart=+/-service --args` modifier goes outside the command line.
            exec_start = Some(rest.trim_start_matches(['-', '+', '/']).trim().to_owned());
        }
    }
    Some(SvcConfig {
        image_path: exec_start?,
        auto_start: cmd("systemctl", &["is-enabled", name])
            .ok()?
            .success(),
    })
}

/// Name and description of every running service: what a bare `systemctl list-units` lists.
pub fn active_services() -> Vec<(String, String)> {
    let Ok(out) = cmd(
        "systemctl",
        &["list-units", "--type=service", "--state=running", "--no-legend"],
    ) else {
        return Vec::new();
    };
    out.stdout
        .lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next().unwrap_or_default().to_owned();
            let description: String = fields
                .skip(3)
                .collect::<Vec<&str>>()
                .join(" ");
            (name, description)
        })
        .collect()
}

/// `~/.local/share/zapret-hub/services.json`: service -> strategy name recorded next to it.
fn strategy_marker_path() -> PathBuf {
    std::env::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".local/share/zapret-hub/services.json")
}

fn markers() -> Option<HashMap<String, String>> {
    let text = std::fs::read_to_string(strategy_marker_path()).ok()?;
    serde_json::from_str(&text).ok()
}

/// The strategy name recorded next to service `name`: `service.bat` writes it for `zapret`, the app
/// writes `zapret2:<name>` for `zapret2` (zapret2 spec 6).
pub fn strategy_of(name: &str) -> Option<String> {
    markers()?.get(name).cloned()
}

/// The active engine's strategy: a Flowseal name or `zapret2:<name>`.
pub fn strategy() -> Option<String> {
    strategy_of(active().0)
}

pub fn set_strategy_of(service: &str, name: &str) -> anyhow::Result<()> {
    let path = strategy_marker_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let mut map = markers().unwrap_or_default();
    map.insert(service.to_owned(), name.to_owned());
    std::fs::write(&path, serde_json::to_string(&map)?)
        .with_context(|| format!("cannot write {}", path.display()))?;
    log::info!(target: "exec", "{}: {STRATEGY_VALUE} = {name}", path.display());
    Ok(())
}

fn wait_until(max: Duration, mut done: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < max {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    done()
}

/// The unit file path as `create` writes it and `request_delete` removes it.
fn unit_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/etc/systemd/system/{name}.service"))
}

/// `<name>.service` with `ExecStart = bin_path`, wanted by multi-user when `auto_start`, as
/// `service.bat` makes `zapret`; `zapret2` the same way (zapret2 spec 6). The file goes and the
/// systemd state changes with root rights.
pub fn create(name: &str, bin_path: &str, auto_start: bool) -> anyhow::Result<()> {
    let description = if name == SERVICE {
        "Zapret DPI bypass software"
    } else {
        "zapret2 DPI bypass software"
    };
    let wanted = if auto_start {
        "WantedBy=multi-user.target"
    } else {
        "# not started at boot"
    };
    let unit = format!(
        "[Unit]\nDescription={description}\nAfter=network.target\n\n[Service]\n{}ExecStart={bin_path}\n\n[Install]\n{wanted}\n",
        unit_hooks(name),
    );
    let path = unit_path(name);
    crate::root::write(&path, &unit)?;
    root_cmd("systemctl", &["daemon-reload"])?.check()?;
    if auto_start {
        let _ = root_cmd("systemctl", &["enable", name]);
    }
    Ok(())
}

/// `nfqws2`'s nftables queue comes up with its service and goes down with it (`nft::CONFIG`,
/// present only once its ports were written). An absent file or `nft` gives no hooks: without
/// them an engine that does not need them stays as it was.
fn unit_hooks(name: &str) -> String {
    let config = "/etc/zapret-hub/nfqws2.nft";
    if name != SERVICE2 || !std::path::Path::new(config).exists() {
        return String::new();
    }
    let which = which_nft();
    let Some(nft) = which.as_deref().filter(|shown| shown.starts_with('/')) else {
        return String::new();
    };
    format!("ExecStartPre={nft} -f {config}\nExecStopPost={nft} delete table inet zapret_hub\n")
}

/// The absolute path of `nft`, what systemd's unit lines need.
fn which_nft() -> Option<String> {
    let out = cmd("which", &["nft"]).ok()?;
    out.success()
        .then(|| out.stdout.trim().to_owned())
}

/// `:service_install` after the menu: timestamps on, the old service gone, the new one created
/// and started, the strategy name recorded. One engine at a time (zapret2 spec 6): zapret2 goes
/// too, so every path that installs a Flowseal strategy takes it down.
pub fn install(folder: &Folder, name: &str, parsed: &ParsedArgs) -> anyhow::Result<()> {
    let _ = enable_tcp_timestamps();
    stop_and_delete(SERVICE)?;
    stop_and_delete(SERVICE2)?;
    crate::procs::kill_all(WINWS2)?;
    create(SERVICE, &parsed.bin_path(&folder.winws()), true)?;
    root_cmd("systemctl", &["start", SERVICE])?.check()?;
    set_strategy_of(SERVICE, name)
}

/// `systemctl stop` + the unit file gone with errors ignored, as `service.bat` does where it
/// does not care.
pub fn request_delete(name: &str) {
    let _ = root_cmd("systemctl", &["stop", name]);
    let _ = root_cmd("systemctl", &["disable", name]);
    let path = unit_path(name);
    if path.exists() {
        crate::root::remove(&path);
        let _ = root_cmd("systemctl", &["daemon-reload"]);
    }
}

/// `request_delete`, then waits until `systemctl` forgets the service.
pub fn stop_and_delete(name: &str) -> anyhow::Result<()> {
    if state(name) == SvcState::NotInstalled {
        return Ok(());
    }
    request_delete(name);
    anyhow::ensure!(
        wait_until(Duration::from_secs(10), || state(name) == SvcState::NotInstalled),
        "service {name} is still there after its unit file was removed: close the systemd manager and try again"
    );
    Ok(())
}

/// `:service_remove`: zapret and zapret2, every winws and winws2. Only the services have to go.
/// The rest is best effort: a process may end by itself, and a program another holds stays; their
/// errors go to the journal as warnings. (A WinDivert driver has no unit here.)
pub fn remove() -> anyhow::Result<()> {
    stop_and_delete(SERVICE)?;
    stop_and_delete(SERVICE2)?;
    for image in ["winws.exe", WINWS2, "nfqws2"] {
        if let Err(err) = crate::procs::kill_all(image) {
            log::warn!(target: "exec", "{image} was not ended: {err:#}");
        }
    }
    Ok(())
}

pub fn start(name: &str) -> anyhow::Result<()> {
    if state(name) != SvcState::Running {
        root_cmd("systemctl", &["start", name])?.check()?;
    }
    Ok(())
}

pub fn stop(name: &str) -> anyhow::Result<()> {
    if matches!(
        state(name),
        SvcState::Running | SvcState::StartPending | SvcState::Other
    ) {
        root_cmd("systemctl", &["stop", name])?.check()?;
    }
    Ok(())
}

pub fn restart(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        state(name) != SvcState::NotInstalled,
        "service {name} is not installed"
    );
    stop(name)?;
    start(name)
}

/// After a list or ipset change: winws reads its files at start.
pub fn restart_if_running(name: &str) -> anyhow::Result<()> {
    if state(name) == SvcState::Running {
        restart(name)
    } else {
        Ok(())
    }
}

/// The arguments live in the service: after a game filter change the active strategy is
/// installed again. A service without a recorded strategy cannot be: that is an error, so the
/// change is undone instead of reported as done.
pub fn reinstall_active(folder: &Folder) -> anyhow::Result<()> {
    if state(SERVICE) == SvcState::NotInstalled {
        return Ok(());
    }
    let Some(name) = strategy_of(SERVICE) else {
        anyhow::bail!(
            "the zapret service has no strategy name recorded, so it cannot be installed again with the new game filter: apply a strategy first"
        );
    };
    let file = crate::strategies::find(folder, &name)?;
    install(
        folder,
        &file.name,
        &crate::batparse::parse_file(folder, &file.path)?,
    )
}

/// `/proc/sys/net/ipv4/tcp_timestamps`, the flag that Flowseal's install turns on. `None` when
/// the file is unreadable.
pub fn tcp_timestamps() -> Option<bool> {
    parse_timestamps(&std::fs::read_to_string("/proc/sys/net/ipv4/tcp_timestamps").ok()?)
}

pub fn parse_timestamps(text: &str) -> Option<bool> {
    match text.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

pub fn enable_tcp_timestamps() -> anyhow::Result<()> {
    root_cmd("sysctl", &["-w", "net.ipv4.tcp_timestamps=1"])?.check()?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, specta::Type)]
pub struct QuickItem {
    pub name: String,
    pub status: CheckStatus,
    pub time_ms: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, specta::Type)]
pub struct QuickCheck {
    pub ok: bool,
    pub service: SvcState,
    pub winws_running: bool,
    pub checks: Vec<QuickItem>,
}

/// 5.4: the active engine's process runs and the first two URL targets answer `HTTP:OK`.
/// The first two targets of the Flowseal folder's `targets.txt`, or of the built-in list without
/// one (zapret2 alone).
pub fn quick_check(folder: Option<&Folder>) -> QuickCheck {
    let (service, image) = active();
    let service = state(service);
    let winws_running = crate::procs::is_running(image);
    let checks: Vec<QuickItem> = folder
        .map_or_else(crate::targets::defaults, crate::targets::load)
        .into_iter()
        .filter_map(|target| Some((target.name, target.url?)))
        .take(2)
        .map(|(name, url)| {
            let result = probe::curl::check(&url, CheckKind::Http, None);
            QuickItem {
                name,
                status: result.status,
                time_ms: result.time_ms,
            }
        })
        .collect();
    let ok =
        winws_running && !checks.is_empty() && checks.iter().all(|c| c.status == CheckStatus::Ok);
    QuickCheck {
        ok,
        service,
        winws_running,
        checks,
    }
}

/// «Применить»: install `name` as the service, wait 2 s, run the quick check.
pub fn apply(folder: &Folder, name: &str) -> anyhow::Result<QuickCheck> {
    let file = crate::strategies::find(folder, name)?;
    let parsed = crate::batparse::parse_file(folder, &file.path)?;
    install(folder, &file.name, &parsed)?;
    std::thread::sleep(Duration::from_secs(2));
    Ok(quick_check(Some(folder)))
}
