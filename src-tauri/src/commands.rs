//! IPC commands: argument plumbing only. The work is in `actions`, `jobs` and the crates.

use std::path::Path;

use probe::socks::ProxyStatus;
use router::flows::FlowRow;
use router::rules::{self, FieldError, Preset, Rule};
use router::{RouterStatus, RoutesView};
use tauri::{AppHandle, Manager as _, State};
use tauri_plugin_dialog::DialogExt as _;
use tauri_specta::Event as _;
use tester::catalog::{StrategyDetail, StrategyRow};
use tester::history::RunSummary;
use tester::model::TestRun;
use tester::run::Request;
use zapret::discord_cache::CacheReport;
use zapret::release::{Downloaded, Engine};
use zapret::service::QuickCheck;

use crate::actions::{self, state as app};
use crate::diag;
use crate::dto::{Candidates, Detected, DownloadProgress, FolderKind, LiveRun, Notice, Overview};
use crate::exclusions::ExclusionRule;
use crate::settings::Settings;
use crate::state::AppState;
use crate::{routing, texts, window};

type Answer<T> = Result<T, String>;

/// Every command touches processes, the disk or the network: it runs off the async runtime, and
/// its error reaches the page with the whole chain of causes.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> Answer<T> {
    match tauri::async_runtime::spawn_blocking(work).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => {
            log::warn!("command failed: {err:#}");
            Err(format!("{err:#}"))
        }
        Err(err) => Err(format!("the command did not finish: {err}")),
    }
}

fn data_tests(handle: &AppHandle) -> std::path::PathBuf {
    tester::history::dir(&app(handle).paths.data())
}

#[tauri::command]
#[specta::specta]
pub fn app_version() -> String {
    format!("{} ({})", env!("CARGO_PKG_VERSION"), env!("ZH_COMMIT"))
}

#[tauri::command]
#[specta::specta]
pub fn get_settings(state: State<'_, AppState>) -> Settings {
    let mut settings = state.settings();
    // The checkbox is honest: the user may have removed the entry in the system's settings, so
    // only the file on the disk makes it checked (the flag is not corrected the other way: an
    // entry made by hand stays the user's own business).
    if settings.autostart && let Ok(exe) = std::env::current_exe() {
        settings.autostart = crate::autostart::is_enabled(&exe);
    }
    settings
}

#[tauri::command]
#[specta::specta]
pub async fn save_settings(handle: AppHandle, settings: Settings) -> Answer<()> {
    blocking(move || actions::save_settings(&handle, settings, false)).await
}

/// `save_settings` for zapret-hub-cli (`cli.rs`), not a window command: it never turns the CLI on
/// and never moves the zapret2 folder (`settings::to_save`).
pub async fn save_settings_from_pipe(handle: AppHandle, settings: Settings) -> Answer<()> {
    blocking(move || actions::save_settings(&handle, settings, true)).await
}

#[tauri::command]
#[specta::specta]
pub async fn get_overview(handle: AppHandle) -> Answer<Overview> {
    blocking(move || Ok(actions::overview(&handle))).await
}

#[tauri::command]
#[specta::specta]
pub async fn check_proxy(addr: String) -> Answer<ProxyStatus> {
    blocking(move || Ok(probe::socks::check(&addr))).await
}

#[tauri::command]
#[specta::specta]
pub async fn wizard_candidates() -> Answer<Candidates> {
    blocking(|| Ok(actions::candidates())).await
}

#[tauri::command]
#[specta::specta]
pub async fn detect_folders() -> Answer<Detected> {
    blocking(|| Ok(actions::detect_folders())).await
}

#[tauri::command]
#[specta::specta]
pub async fn pick_folder(handle: AppHandle) -> Answer<Option<String>> {
    blocking(move || {
        let mut dialog = handle.dialog().file().set_title(texts::PICK_FOLDER);
        if let Some(window) = handle.get_webview_window(window::MAIN) {
            dialog = dialog.set_parent(&window);
        }
        let picked = dialog
            .blocking_pick_folder()
            .map(|path| path.into_path())
            .transpose()?;
        Ok(picked.map(|path| path.display().to_string()))
    })
    .await
}

#[tauri::command]
#[specta::specta]
pub async fn open_url(url: String) -> Answer<()> {
    blocking(move || actions::open_url(&url)).await
}

#[tauri::command]
#[specta::specta]
pub async fn open_folder(handle: AppHandle, kind: FolderKind) -> Answer<()> {
    blocking(move || actions::open_folder(&handle, kind)).await
}

#[tauri::command]
#[specta::specta]
pub async fn list_strategies(handle: AppHandle) -> Answer<Vec<StrategyRow>> {
    blocking(move || {
        let state = app(&handle);
        let active = zapret::service::strategy();
        tester::catalog::rows(
            state.engine2().ok().flatten().as_ref(),
            &state.paths.data(),
            active.as_deref(),
            state.settings().game_filter,
        )
    })
    .await
}

#[tauri::command]
#[specta::specta]
pub async fn get_strategy(handle: AppHandle, name: String) -> Answer<StrategyDetail> {
    blocking(move || {
        let state = app(&handle);
        let active = zapret::service::strategy();
        // A broken folder shows here as where the version is: the preview says what is missing.
        tester::catalog::detail(
            state.engine2().ok().flatten().as_ref(),
            &state.paths.data(),
            active.as_deref(),
            &name,
            state.settings().game_filter,
        )
    })
    .await
}

#[tauri::command]
#[specta::specta]
pub async fn apply_strategy(handle: AppHandle, name: String) -> Answer<QuickCheck> {
    blocking(move || actions::apply(&handle, &name)).await
}

#[tauri::command]
#[specta::specta]
pub async fn apply_best(handle: AppHandle) -> Answer<QuickCheck> {
    blocking(move || actions::apply_best(&handle)).await
}

#[tauri::command]
#[specta::specta]
pub async fn restart_zapret(handle: AppHandle) -> Answer<QuickCheck> {
    blocking(move || actions::restart(&handle)).await
}

#[tauri::command]
#[specta::specta]
pub async fn zapret2_info(handle: AppHandle) -> Answer<zapret2::Info> {
    blocking(move || {
        Ok(zapret2::info(
            app(&handle).settings().zapret2_dir.as_deref(),
        ))
    })
    .await
}

/// A zapret2 folder the first-run wizard was given, before it is saved: the same check as
/// `zapret2_info`. Window only: the pipe cannot choose the folder (zapret2 spec 10).
#[tauri::command]
#[specta::specta]
pub async fn check_zapret2_folder(path: String) -> Answer<zapret2::Info> {
    blocking(move || Ok(zapret2::info(Some(&path)))).await
}

/// The zapret2 editor's «Проверить»: the whole check of zapret2 spec 5.3, nothing saved.
#[tauri::command]
#[specta::specta]
pub async fn validate_zapret2(handle: AppHandle, text: String) -> Answer<()> {
    blocking(move || {
        let state = app(&handle);
        let engine = state.engine2_required()?;
        state.change(|| {
            let tail = zapret2::strategies::tail(&engine, &text, state.settings().game_filter)?;
            zapret2::service::validate(&engine, &tail)
        })
    })
    .await
}

/// `name` without the prefix: `mine` for `zapret2:mine`.
#[tauri::command]
#[specta::specta]
pub async fn save_zapret2(
    handle: AppHandle,
    name: String,
    text: String,
    create: bool,
) -> Answer<Option<QuickCheck>> {
    blocking(move || actions::save_zapret2(&handle, &name, &text, create)).await
}

/// `name` without the prefix: `mine` for `zapret2:mine`.
#[tauri::command]
#[specta::specta]
pub async fn delete_zapret2(handle: AppHandle, name: String) -> Answer<()> {
    blocking(move || {
        let state = app(&handle);
        let active = zapret::service::strategy();
        let deleted = state.engine2_required().and_then(|engine| {
            state.change(|| zapret2::strategies::delete(engine.root(), &name, active.as_deref()))
        });
        actions::changed(&handle);
        deleted
    })
    .await
}

/// The editor's circular builder reads the text it is given (zapret2 spec 5.4). Window only, as
/// are the two below: they shape a text the CLI writes itself.
#[tauri::command]
#[specta::specta]
pub fn zapret2_profiles(text: String) -> zapret2::circular::Analysis {
    zapret2::circular::analyze(&zapret2::strategies::args(&text))
}

/// `text` with the builder's circular profile written in; nothing saved.
#[tauri::command]
#[specta::specta]
pub fn zapret2_circular(
    text: String,
    target: zapret2::circular::CircularTarget,
    edit: zapret2::circular::CircularEdit,
) -> Answer<String> {
    zapret2::circular::apply(&text, &target, &edit).map_err(|err| format!("{err:#}"))
}

/// A new strategy's text made of 2-5 zapret2 strategies (full names), for its preview.
#[tauri::command]
#[specta::specta]
pub async fn zapret2_merge(
    handle: AppHandle,
    names: Vec<String>,
) -> Answer<zapret2::circular::Merged> {
    blocking(move || {
        let engine = app(&handle).engine2_required()?;
        let sources = names
            .iter()
            .map(|name| {
                let short = zapret2::strip_prefix(name).unwrap_or(name);
                let strategy = zapret2::strategies::find(engine.root(), short)?;
                Ok((strategy.name, strategy.text))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        zapret2::circular::merge(&sources)
    })
    .await
}

#[tauri::command]
#[specta::specta]
pub async fn start_tests(handle: AppHandle, request: Request) -> Answer<()> {
    blocking(move || crate::jobs::start_tests(&handle, request)).await
}

#[tauri::command]
#[specta::specta]
pub fn cancel_tests(state: State<'_, AppState>) {
    state.cancel_tests();
}

/// Window only, like the folders themselves: the pipe has no download (cli.md).
#[tauri::command]
#[specta::specta]
pub fn default_download_parent() -> String {
    zapret::release::default_parent().display().to_string()
}

/// The latest release of `engine` unpacked into a new folder under `parent`; the page follows
/// `DownloadProgress` and puts the folder into its field.
#[tauri::command]
#[specta::specta]
pub async fn download_engine(
    handle: AppHandle,
    engine: Engine,
    parent: String,
) -> Answer<Downloaded> {
    blocking(move || {
        let state = app(&handle);
        let socks5 = state.socks5();
        state.download(|cancel| {
            zapret::release::install(
                engine,
                Path::new(&parent),
                socks5.as_deref(),
                cancel,
                &|received, total| {
                    let clamp = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
                    let _ = DownloadProgress {
                        engine,
                        received: clamp(received),
                        total: clamp(total),
                    }
                    .emit(&handle);
                },
            )
        })
    })
    .await
}

#[tauri::command]
#[specta::specta]
pub fn cancel_download(state: State<'_, AppState>) {
    state.cancel_download();
}

#[tauri::command]
#[specta::specta]
pub fn test_live(state: State<'_, AppState>) -> Option<LiveRun> {
    state.live()
}

#[tauri::command]
#[specta::specta]
pub async fn list_runs(handle: AppHandle) -> Answer<Vec<RunSummary>> {
    blocking(move || tester::history::summaries(&data_tests(&handle))).await
}

#[tauri::command]
#[specta::specta]
pub async fn get_run(handle: AppHandle, id: String) -> Answer<TestRun> {
    blocking(move || tester::history::load(&data_tests(&handle), &id)).await
}

/// «Копировать»: the run as `test zapret.ps1` writes it.
#[tauri::command]
#[specta::specta]
pub async fn run_report(handle: AppHandle, id: String) -> Answer<String> {
    blocking(move || {
        Ok(tester::report::to_text(&tester::history::load(
            &data_tests(&handle),
            &id,
        )?))
    })
    .await
}

#[tauri::command]
#[specta::specta]
pub async fn clear_discord_cache() -> Answer<Vec<CacheReport>> {
    blocking(zapret::discord_cache::clear).await
}

#[tauri::command]
#[specta::specta]
pub async fn remove_service(handle: AppHandle) -> Answer<()> {
    blocking(move || {
        // It removes WinDivert too: the router's handles close first (router spec 11).
        let done = routing::paused(&handle, || {
            app(&handle).change_safely("remove_service", zapret::service::remove)
        });
        actions::changed(&handle);
        done
    })
    .await
}

#[tauri::command]
#[specta::specta]
pub async fn stop_service(handle: AppHandle) -> Answer<()> {
    blocking(move || {
        let done = routing::paused(&handle, || {
            let (name, _) = zapret::service::active();
            zapret::service::stop(name)?;
            // A stop by hand holds for boots too: the enablement is the user's switch,
            // and a start puts it back.
            let _ = zapret::service::disable(name);
            Ok(())
        });
        actions::changed(&handle);
        done
    })
    .await
}

#[tauri::command]
#[specta::specta]
pub async fn start_service(handle: AppHandle) -> Answer<()> {
    blocking(move || {
        let done = routing::paused(&handle, || {
            let (name, _) = zapret::service::active();
            zapret::service::start(name)
        });
        actions::changed(&handle);
        done
    })
    .await
}

#[tauri::command]
#[specta::specta]
pub async fn restart_service(handle: AppHandle) -> Answer<()> {
    blocking(move || {
        let done = routing::paused(&handle, || {
            let (name, _) = zapret::service::active();
            zapret::service::restart(name)
        });
        actions::changed(&handle);
        done
    })
    .await
}

#[tauri::command]
#[specta::specta]
pub async fn nft_rules() -> Answer<String> {
    blocking(|| Ok(zapret2::nft::rules())).await
}

#[tauri::command]
#[specta::specta]
pub async fn service_logs() -> Answer<String> {
    blocking(|| Ok(zapret::service::logs())).await
}

/// The exclusions card's contents: the named groups of `data/exclusions.toml`.
#[tauri::command]
#[specta::specta]
pub async fn get_exclusion_rules(handle: AppHandle) -> Answer<Vec<ExclusionRule>> {
    blocking(move || actions::read_exclusion_rules(&app(&handle))).await
}

/// The groups back onto `data/exclusions.toml`, the zapret2 lists and the settings' ports, then
/// the nftables queue rewritten and the service restarted into it.
#[tauri::command]
#[specta::specta]
pub async fn save_exclusion_rules(handle: AppHandle, rules: Vec<ExclusionRule>) -> Answer<()> {
    blocking(move || actions::save_exclusion_rules(&handle, rules)).await
}

#[tauri::command]
#[specta::specta]
pub async fn flush_dns() -> Answer<()> {
    blocking(zapret::hosts::flush_dns).await
}

/// `doctor`: every subsystem at once, with what to fix.
#[tauri::command]
#[specta::specta]
pub fn doctor(handle: AppHandle) -> Answer<diag::DoctorReport> {
    Ok(diag::doctor(&handle))
}

/// One remedy of `doctor`: the action runs, then the report is taken again so the page can drop
/// the issue it just fixed (and show what is left).
#[tauri::command]
#[specta::specta]
pub async fn fix_doctor_issue(
    handle: AppHandle,
    action: diag::FixAction,
) -> Answer<diag::DoctorReport> {
    blocking(move || {
        diag::fix(&handle, action)?;
        actions::changed(&handle);
        Ok(diag::doctor(&handle))
    })
    .await
}

/// Every fixable issue of a fresh `doctor`, one after another; what a fix could not cure comes
/// back in the report, the anchors fail loudly.
#[tauri::command]
#[specta::specta]
pub async fn fix_all_doctor_issues(handle: AppHandle) -> Answer<diag::DoctorReport> {
    blocking(move || {
        let report = diag::doctor(&handle);
        let mut actions = Vec::new();
        for fix in report.issues.iter().filter_map(|issue| issue.fix) {
            if !actions.contains(&fix) {
                actions.push(fix);
            }
        }
        for action in actions {
            if let Err(err) = diag::fix(&handle, action) {
                log::warn!("fix {action:?} failed: {err:#}");
            }
        }
        actions::changed(&handle);
        Ok(diag::doctor(&handle))
    })
    .await
}

/// `probe` of one domain or URL: DNS, the lists, the routing rule, HTTP/TLS and a ping.
#[tauri::command]
#[specta::specta]
pub fn probe(handle: AppHandle, target: String) -> Answer<diag::ProbeResult> {
    Ok(diag::probe(&handle, &target))
}

/// The TG WS Proxy card's contents: the binary on the disk, systemd and the journal in one go.
#[tauri::command]
#[specta::specta]
pub async fn tg_ws_status(handle: AppHandle) -> Answer<crate::dto::TgWsStatus> {
    blocking(move || Ok(crate::tgws::status(&handle))).await
}

/// The latest `tg-ws-proxy-rs` release unpacked into the data folder, then the service back the
/// way it was.
#[tauri::command]
#[specta::specta]
pub async fn install_tg_ws(handle: AppHandle) -> Answer<crate::dto::TgWsStatus> {
    blocking(move || crate::tgws::install(&handle)).await
}

#[tauri::command]
#[specta::specta]
pub async fn set_tg_ws_enabled(handle: AppHandle, enabled: bool) -> Answer<crate::dto::TgWsStatus> {
    blocking(move || crate::tgws::set_enabled(&handle, enabled)).await
}

#[tauri::command]
#[specta::specta]
pub async fn save_tg_ws_config(
    handle: AppHandle,
    port: u16,
    secret: String,
    args: String,
) -> Answer<crate::dto::TgWsStatus> {
    blocking(move || crate::tgws::save_config(&handle, port, secret, args)).await
}

#[tauri::command]
#[specta::specta]
pub async fn open_tg_proxy(handle: AppHandle) -> Answer<()> {
    blocking(move || crate::tgws::open(&actions::state(&handle).settings())).await
}

#[tauri::command]
#[specta::specta]
pub async fn quick_check(handle: AppHandle) -> Answer<QuickCheck> {
    blocking(move || actions::quick_check(&handle)).await
}

#[tauri::command]
#[specta::specta]
pub fn take_notices(state: State<'_, AppState>) -> Vec<Notice> {
    state.take_notices()
}

/// The only command that writes `router_enabled` (`routing::set_enabled`).
#[tauri::command]
#[specta::specta]
pub async fn set_router_enabled(handle: AppHandle, enabled: bool) -> Answer<RouterStatus> {
    blocking(move || routing::set_enabled(&handle, enabled)).await
}

#[tauri::command]
#[specta::specta]
pub fn router_status(state: State<'_, AppState>) -> RouterStatus {
    state.router.status()
}

/// Reading the rules may reopen the filter, up to a second: off the main thread.
#[tauri::command]
#[specta::specta]
pub async fn list_routes(handle: AppHandle) -> RoutesView {
    let router = app(&handle).router.clone();
    tauri::async_runtime::spawn_blocking(move || router.rules())
        .await
        .unwrap_or_else(|err| RoutesView {
            rules: Vec::new(),
            error: Some(format!("the command did not finish: {err}")),
            system_doh: false,
        })
}

#[tauri::command]
#[specta::specta]
pub async fn get_route(handle: AppHandle, name: String) -> Answer<Rule> {
    blocking(move || {
        let view = app(&handle).router.rules();
        let list: Vec<Rule> = view.rules.into_iter().map(|row| row.rule).collect();
        Ok(rules::find(&list, &name)?.clone())
    })
    .await
}

/// A rule changed in the window: the router edits `routes.toml` (it refuses a broken one).
fn edit_routes<T: Send + 'static>(
    handle: AppHandle,
    edit: impl FnOnce(&mut Vec<Rule>) -> anyhow::Result<T> + Send + 'static,
) -> impl Future<Output = Answer<T>> {
    blocking(move || {
        let done = app(&handle).router.edit(edit);
        actions::changed(&handle);
        done
    })
}

#[tauri::command]
#[specta::specta]
pub async fn save_route(handle: AppHandle, rule: Rule, create: bool) -> Answer<()> {
    edit_routes(handle, move |list| {
        if create {
            rules::add(list, rule)
        } else {
            rules::replace(list, rule)
        }
    })
    .await
}

#[tauri::command]
#[specta::specta]
pub async fn set_route_enabled(handle: AppHandle, name: String, enabled: bool) -> Answer<()> {
    edit_routes(handle, move |list| rules::set_enabled(list, &name, enabled)).await
}

#[tauri::command]
#[specta::specta]
pub async fn delete_route(handle: AppHandle, name: String) -> Answer<()> {
    edit_routes(handle, move |list| rules::remove(list, &name).map(|_| ())).await
}

#[tauri::command]
#[specta::specta]
pub async fn add_route_preset(handle: AppHandle, preset: Preset) -> Answer<Rule> {
    let rule = rules::preset(preset);
    edit_routes(handle, move |list| {
        rules::add(list, rule.clone())?;
        Ok(rule)
    })
    .await
}

#[tauri::command]
#[specta::specta]
pub fn route_flows(state: State<'_, AppState>, all: bool) -> Vec<FlowRow> {
    state.router.flows(all)
}

/// The editor's checks as it types: nothing saved.
#[tauri::command]
#[specta::specta]
pub fn validate_route(rule: Rule) -> Vec<FieldError> {
    rules::check(&rule)
}

/// `ips` and `domains` plus the entries of a list file (one subnet or domain per line).
#[tauri::command]
#[specta::specta]
pub fn import_route_lines(
    ips: Vec<String>,
    domains: Vec<String>,
    text: String,
) -> Answer<rules::Imported> {
    rules::import(&ips, &domains, &text).map_err(|err| err.to_string())
}
