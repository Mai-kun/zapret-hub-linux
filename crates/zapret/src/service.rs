//! The zapret2 systemd service: state through `systemctl`, changes as a unit file exactly like
//! `service.bat` makes them, and the quick check after an install (5.4).

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use probe::curl::{CheckKind, CheckStatus};

pub const SERVICE2: &str = "zapret2";
/// zapret2's engine process: the second engine is known by these two names only.
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

/// The installed engine's service and process (zapret2 spec 3.1): only zapret2 is left. On Linux
/// the engine runs as `nfqws2`, on Windows as `winws2.exe` under the service.
pub fn active() -> (&'static str, &'static str) {
    if cfg!(target_os = "linux") {
        (SERVICE2, "nfqws2")
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
        auto_start: cmd("systemctl", &["is-enabled", name]).ok()?.success(),
    })
}

/// Name and description of every running service: what a bare `systemctl list-units` lists.
pub fn active_services() -> Vec<(String, String)> {
    let Ok(out) = cmd(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
        ],
    ) else {
        return Vec::new();
    };
    out.stdout
        .lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next().unwrap_or_default().to_owned();
            let description: String = fields.skip(3).collect::<Vec<&str>>().join(" ");
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

/// The strategy name recorded next to service `name`: the app writes `zapret2:<name>` for
/// `zapret2` (zapret2 spec 6).
pub fn strategy_of(name: &str) -> Option<String> {
    markers()?.get(name).cloned()
}

/// The active engine's strategy: a `zapret2:<name>`.
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

/// `<name>.service` with `ExecStart = bin_path`, wanted by multi-user when `auto_start`.
/// The file goes and the systemd state changes with root rights.
pub fn create(name: &str, bin_path: &str, auto_start: bool) -> anyhow::Result<()> {
    let description = "zapret2 DPI bypass software";
    let wanted = if auto_start {
        "WantedBy=multi-user.target"
    } else {
        "# not started at boot"
    };
    let unit = format!(
        "[Unit]\nDescription={description}\nAfter=network.target\n\n[Service]\n{}{}ExecStart={bin_path}\n\n[Install]\n{wanted}\n",
        unit_hooks(name),
        run_as_user(name),
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
/// them an engine that does not need them stays as it was. The `+` is root for the hooks when
/// `run_as_user` keeps the engine itself unprivileged.
fn unit_hooks(name: &str) -> String {
    let config = "/etc/zapret-hub/nfqws2.nft";
    if name != SERVICE2 || !std::path::Path::new(config).exists() {
        return String::new();
    }
    let which = which_nft();
    let Some(nft) = which.as_deref().filter(|shown| shown.starts_with('/')) else {
        return String::new();
    };
    format!("ExecStartPre=+{nft} -f {config}\nExecStopPost=+{nft} delete table inet zapret_hub\n")
}

/// Linux: `nfqws2` started as root drops its rights to UID 0x7FFFFFFF, which cannot even enter
/// the user's home (`/home/<user>` is 700), so the strategy files fail on the first `--hostlist`.
/// The checks and tests run `nfqws2` as the user, and there it works and reads everything, so the
/// service does the same: `User=` of this process and the net capabilities the nfqueue asks for.
fn run_as_user(name: &str) -> String {
    if !cfg!(target_os = "linux") || name != SERVICE2 {
        return String::new();
    }
    let Some(uid) = uid_this_process() else {
        return String::new();
    };
    format!("User={uid}\nAmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\n")
}

/// The first `Uid:` field of `/proc/self/status` (the real uid): a numeric `User=` is systemd
/// enough. `None` off Linux.
fn uid_this_process() -> Option<String> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .map(str::to_owned)
}

/// The absolute path of `nft`, what systemd's unit lines need.
fn which_nft() -> Option<String> {
    let out = cmd("which", &["nft"]).ok()?;
    out.success().then(|| out.stdout.trim().to_owned())
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
        wait_until(Duration::from_secs(10), || state(name)
            == SvcState::NotInstalled),
        "service {name} is still there after its unit file was removed: close the systemd manager and try again"
    );
    Ok(())
}

/// `:service_remove`: the zapret2 service and every engine process. Only the service has to go.
/// The rest is best effort: a process may end by itself, and a program another holds stays; their
/// errors go to the journal as warnings.
pub fn remove() -> anyhow::Result<()> {
    stop_and_delete(SERVICE2)?;
    for image in [WINWS2, "nfqws2"] {
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
    if state(name) == SvcState::NotInstalled {
        if cfg!(target_os = "linux") || name == SERVICE2 {
            anyhow::bail!(
                "Служба {name} ещё не установлена: сначала примените стратегию кнопкой «Применить»"
            );
        }
        anyhow::bail!("service {name} is not installed");
    }
    stop(name)?;
    start(name)
}

/// After a hosts or settings change: the engine re-reads its files at start.
pub fn restart_if_running(name: &str) -> anyhow::Result<()> {
    if state(name) == SvcState::Running {
        restart(name)
    } else {
        Ok(())
    }
}

/// Last 100 lines of system logs from journalctl for the zapret2 service.
pub fn logs() -> String {
    const UNIT: &str = SERVICE2;
    let read = |root: bool| -> Option<String> {
        let out = if root {
            crate::root::run("journalctl", &["-u", UNIT, "-n", "100", "--no-pager"]).ok()?
        } else {
            exec::run(
                Command::new("journalctl").args(["-u", UNIT, "-n", "100", "--no-pager"]),
                Duration::from_secs(10),
                None,
            )
            .ok()?
        };
        if out.success() && !out.stdout.contains("-- No entries --") {
            let text = out.stdout.trim().to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
        None
    };
    read(true)
        .or_else(|| read(false))
        .unwrap_or_else(|| "-- No entries --".to_string())
}

/// `/proc/sys/net/ipv4/tcp_timestamps`, the flag the engine's install turns on. `None` when
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

/// 5.4: the active engine's process runs and the first two URL targets answer `HTTP:OK`, from
/// the built-in list.
pub fn quick_check() -> QuickCheck {
    let (service, image) = active();
    let service = state(service);
    let winws_running = crate::procs::is_running(image);
    let checks: Vec<QuickItem> = crate::targets::defaults()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_active_service_is_zapret2() {
        let (service, image) = active();
        assert_eq!(service, SERVICE2);
        let expected = if cfg!(target_os = "linux") {
            "nfqws2"
        } else {
            WINWS2
        };
        assert_eq!(image, expected);
    }

    #[test]
    fn reads_the_timestamps_value_as_the_kernel_keeps_it() {
        assert_eq!(parse_timestamps("1\n"), Some(true));
        assert_eq!(parse_timestamps("0\n"), Some(false));
        assert_eq!(parse_timestamps(" GARAGE "), None);
    }

    #[test]
    fn the_states_map_the_systemctl_words() {
        assert_eq!(map_state("active"), SvcState::Running);
        assert_eq!(map_state("activating"), SvcState::StartPending);
        assert_eq!(map_state("deactivating"), SvcState::StopPending);
        assert_eq!(map_state("inactive"), SvcState::Stopped);
        assert_eq!(map_state("failed"), SvcState::Stopped);
        assert_eq!(map_state("whatever"), SvcState::Other);
    }

    #[test]
    fn a_service_without_a_recorded_strategy_has_none() {
        assert_eq!(strategy_of("zapret-hub-no-such-service"), None);
    }
}
