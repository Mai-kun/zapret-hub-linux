//! What commands, the tray and background jobs share.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tauri::{AppHandle, Manager as _};
use tauri_specta::Event as _;
use zapret::service::{QuickCheck, active};

use crate::dto::{
    Candidates, Detected, FolderKind, Notice, NoticeLevel, NoticesChanged, Overview, StateChanged,
};
use crate::settings::Settings;
use crate::state::AppState;

pub fn state(app: &AppHandle) -> tauri::State<'_, AppState> {
    app.state::<AppState>()
}

/// Something to show even with the window closed: it waits in the queue (spec 10).
pub fn notice(app: &AppHandle, level: NoticeLevel, title: &str, text: String) {
    log::info!("notice: {title}: {text}");
    state(app).push_notice(Notice {
        level,
        title: title.to_owned(),
        text,
    });
    if let Err(err) = NoticesChanged.emit(app) {
        log::warn!("cannot announce a notice: {err}");
    }
}

/// zapret or the settings changed: the page reads them again, the tray redraws.
pub fn changed(app: &AppHandle) {
    if let Err(err) = StateChanged.emit(app) {
        log::warn!("cannot announce a change: {err}");
    }
    crate::tray::refresh(app);
}

/// A change that ends in a quick check: the check feeds the tray and the overview.
fn finish_with_check(
    app: &AppHandle,
    result: anyhow::Result<QuickCheck>,
) -> anyhow::Result<QuickCheck> {
    if let Ok(check) = &result {
        state(app).set_quick(check.clone());
    }
    changed(app);
    result
}

/// «Применить» (spec 6). Only `zapret2:` strategies run; the folder is opened first, so a broken
/// one changes nothing.
pub fn apply(app: &AppHandle, name: &str) -> anyhow::Result<QuickCheck> {
    let Some(name) = zapret2::strip_prefix(name) else {
        anyhow::bail!("{name} is a Flowseal strategy: zapret2 strategies only are applied");
    };
    let app_state = state(app);
    let engine = app_state.engine2_required()?;
    // The check runs first: a failure changes nothing, no snapshot, no restart (spec 6).
    let (strategy, tail) =
        app_state.change(|| zapret2::service::prepare(&engine, engine.root(), name))?;
    let check = app_state.change_safely("apply", || {
        zapret2::service::install_checked(&engine, &strategy, &tail)
    });
    finish_with_check(app, check)
}

/// «Применить лучшую»: the first of the newest standard run (spec 7.4).
pub fn apply_best(app: &AppHandle) -> anyhow::Result<QuickCheck> {
    let best = state(app)
        .best(1)
        .pop()
        .ok_or_else(|| anyhow::anyhow!("no test results yet: run the standard tests first"))?;
    apply(app, &best)
}

pub fn restart(app: &AppHandle) -> anyhow::Result<QuickCheck> {
    let result = state(app).change(|| {
        zapret::service::restart(active().0)?;
        // winws needs a moment before it intercepts anything (spec 5.4).
        std::thread::sleep(Duration::from_secs(2));
        Ok(zapret::service::quick_check())
    });
    finish_with_check(app, result)
}

/// Reads only, but in the queue: a restart or an apply that is half done would fail it for nothing,
/// and during a test run (`change` refuses it) it would check the strategy under test. A refusal
/// changes nothing, so it is not announced.
pub fn quick_check(app: &AppHandle) -> anyhow::Result<QuickCheck> {
    let check = state(app).change(|| Ok(zapret::service::quick_check()))?;
    finish_with_check(app, Ok(check))
}

/// One save at a time, from reading the settings in force to setting the new ones: otherwise the
/// file, the memory and the scheduled task could disagree. A save from the `pipe` never turns the
/// CLI on and never moves the zapret2 folder (`settings::to_save`, CLI spec 5, 7.2, zapret2 spec
/// 10).
pub fn save_settings(app: &AppHandle, settings: Settings, pipe: bool) -> anyhow::Result<()> {
    let state = state(app);
    let _saving = state.saving();
    let old = state.settings();
    let mut settings = crate::settings::to_save(&old, settings, pipe)?;
    settings.socks5 =
        crate::settings::validate_socks(settings.socks5.as_deref().unwrap_or_default())?;
    let engine_changed = settings.zapret2_dir != old.zapret2_dir;
    if engine_changed {
        anyhow::ensure!(
            !state.testing(),
            "a test run is going: wait for it or cancel it"
        );
    }
    if engine_changed && let Some(dir) = &settings.zapret2_dir {
        zapret2::Engine::open(dir)?;
    }
    if settings.autostart != old.autostart {
        if settings.autostart {
            crate::autostart::enable(&std::env::current_exe()?)?;
        } else {
            crate::autostart::disable()?;
        }
    }
    crate::settings::save(&state.paths.settings(), &settings)?;
    state.set_settings(settings);
    if engine_changed {
        state.migrate_strategies();
    }
    // The proxy or a folder, and with it the DLL, may have changed.
    crate::routing::sync(app);
    changed(app);
    Ok(())
}

/// `save_zapret2` (zapret2 spec 5.2). The active strategy's command line is baked into the
/// service: saving it installs it again, under a snapshot.
pub fn save_zapret2(
    app: &AppHandle,
    name: &str,
    text: &str,
    create: bool,
) -> anyhow::Result<Option<QuickCheck>> {
    let state = state(app);
    let engine = state.engine2_required()?;
    let data = engine.root().to_path_buf();
    let full = format!("{}{}", zapret2::PREFIX, name.trim());
    let active = zapret::service::strategy();
    if !create && active.is_some_and(|active| active.eq_ignore_ascii_case(&full)) {
        // The check runs first: a failure changes nothing (spec 6).
        let (claimed, tail) =
            state.change(|| zapret2::service::check_save(&engine, &data, name, text, false))?;
        let saved = zapret2::strategies::Strategy {
            name: claimed,
            text: text.to_owned(),
            builtin: false,
        };
        let result = state.change_safely("apply", || {
            zapret2::strategies::write(&data, &saved.name, text)?;
            zapret2::service::install(&engine, &saved, &tail)?;
            // winws2 needs a moment before it intercepts anything (spec 5.4).
            std::thread::sleep(Duration::from_secs(2));
            Ok(zapret::service::quick_check())
        });
        return finish_with_check(app, result).map(Some);
    }
    let result = state.change(|| zapret2::service::save(&engine, &data, name, text, create));
    changed(app);
    result.map(|_| None)
}

pub fn overview(app: &AppHandle) -> Overview {
    let state = state(app);
    let settings = state.settings();
    let (service, image) = active();
    Overview {
        service_name: service.to_owned(),
        service: zapret::service::state(service),
        windivert: zapret::service::state("WinDivert"),
        winws_running: zapret::procs::is_running(image),
        strategy: zapret::service::strategy(),
        zapret2: zapret2::info(settings.zapret2_dir.as_deref()),
        quick: state.quick(),
        last_run: state.last_run(),
        testing: state.testing(),
    }
}

/// Folders where zapret2 probably is, and SOCKS5 ports that answer now: NekoBox's own port when
/// it runs, then the default ports of known clients (spec 9.2).
pub fn candidates() -> Candidates {
    let mut ports: Vec<u16> = ["nekobox.exe", "nekoray.exe"]
        .iter()
        .flat_map(|image| zapret::procs::find(image))
        .filter_map(|proc| {
            proc.exe
                .as_deref()
                .and_then(Path::parent)
                .and_then(probe::socks::nekobox_port)
        })
        .collect();
    ports.extend(probe::socks::KNOWN_PORTS);
    Candidates {
        proxies: probe::socks::listening(&ports),
    }
}

/// What the wizard finds before the user picks anything: the zapret2 folder, searched where a
/// release is usually unpacked (spec 9.2).
pub fn detect_folders() -> Detected {
    Detected {
        zapret2: zapret2::find_zapret2(&nearby_dirs()).map(|path| path.display().to_string()),
    }
}

/// The cheap places a release is unpacked to, each with its direct subfolders: next to the app,
/// the home folders, then fixed roots. Stops listing when the 800 ms budget is spent.
/* shortcut: a near copy of the old zapret::folder::nearby_dirs, revive it when more callers appear */
fn nearby_dirs() -> Vec<PathBuf> {
    let deadline = std::time::Instant::now() + Duration::from_millis(800);
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(app) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    {
        if let Some(parent) = app.parent() {
            roots.push(parent.to_path_buf());
        }
        roots.push(app);
    }
    if let Some(home) = std::env::home_dir() {
        roots.extend(["Downloads", "Desktop", "Documents"].map(|name| home.join(name)));
        roots.push(home);
    }
    roots.extend(["/opt", "/usr/local/share"].map(PathBuf::from));
    let mut dirs: Vec<PathBuf> = Vec::new();
    for root in roots {
        if std::time::Instant::now() > deadline {
            break;
        }
        if !root.is_dir() || dirs.contains(&root) {
            continue;
        }
        dirs.push(root.clone());
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            if std::time::Instant::now() > deadline {
                break;
            }
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                dirs.push(entry.path());
            }
        }
    }
    dirs
}

/// Release pages and the issues `service.bat` links to: https only.
pub fn open_url(url: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        url.starts_with("https://"),
        "only https links are opened: {url}"
    );
    crate::shell::open(OsStr::new(url))
}

/// The folder of the user's zapret2 strategies, created when missing.
fn strategies_folder(home: &Path) -> anyhow::Result<PathBuf> {
    let dir = zapret2::strategies::dir(home);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Where a strategy's file is: a zapret2 strategy of the user's in the zapret2 folder's
/// `strategies`. Only names that are in the lists resolve, so the page cannot point anywhere else.
fn strategy_folder(home: Option<&Path>, name: &str) -> anyhow::Result<PathBuf> {
    let Some(name) = zapret2::strip_prefix(name) else {
        anyhow::bail!("{name} is a Flowseal strategy: only zapret2 strategies have files");
    };
    let home = home
        .ok_or_else(|| anyhow::anyhow!("the zapret2 folder is not set: choose it in Settings"))?;
    let strategy = zapret2::strategies::find(home, name)?;
    anyhow::ensure!(
        !strategy.builtin,
        "{} is built into Zapret Hub: it has no file",
        strategy.full_name()
    );
    Ok(zapret2::strategies::dir(home))
}

pub fn open_folder(app: &AppHandle, kind: FolderKind) -> anyhow::Result<()> {
    let state = state(app);
    let path = match kind {
        FolderKind::Zapret2 => strategies_folder(state.engine2_required()?.root())?,
        FolderKind::Logs => {
            let logs = state.paths.logs();
            std::fs::create_dir_all(&logs)?;
            logs
        }
        FolderKind::Strategy(name) => {
            let home = state.engine2()?.map(|engine| engine.root().to_path_buf());
            strategy_folder(home.as_deref(), &name)?
        }
    };
    crate::shell::open(path.as_os_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_strategy_opens_the_folder_of_its_file() {
        let data = tempfile::tempdir().unwrap();
        zapret2::strategies::write(data.path(), "mine", "--wf-tcp-out=443").unwrap();

        let open = |home: Option<&Path>, name: &str| {
            strategy_folder(home, name).map_err(|err| format!("{err:#}"))
        };
        assert_eq!(
            open(Some(data.path()), "zapret2:mine"),
            Ok(data.path().join("strategies"))
        );
        assert!(
            open(None, "zapret2:mine")
                .unwrap_err()
                .contains("zapret2 folder is not set")
        );
        assert!(
            open(Some(data.path()), "zapret2:general")
                .unwrap_err()
                .contains("no file")
        );
        assert!(open(Some(data.path()), "zapret2:other").is_err());
        assert!(
            open(Some(data.path()), r"..\..\Windows").is_err(),
            "a path is not a strategy name"
        );
        assert!(
            open(Some(data.path()), "general (ALT11)")
                .unwrap_err()
                .contains("Flowseal")
        );
    }

    #[test]
    fn the_strategies_folder_is_in_the_zapret2_folder_and_is_created() {
        let data = tempfile::tempdir().unwrap();
        let dir = strategies_folder(data.path()).unwrap();
        assert_eq!(dir, data.path().join("strategies"));
        assert!(dir.is_dir());
    }
}
