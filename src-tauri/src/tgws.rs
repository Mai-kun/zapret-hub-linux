//! `tg-ws-proxy-rs` (valnesfjord/tg-ws-proxy-rs): the latest release unpacked into the user's
//! data folder, run through `systemd --user` — no root rights anywhere. Everything the commands
//! share lives here; `commands.rs` only plumbs.

use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use tauri::AppHandle;

use crate::actions::{self, changed};
use crate::dto::TgWsStatus;
use crate::settings::Settings;

/// The user's unit, written and driven here.
pub const UNIT: &str = "zapret-hub-tg-ws";
/// The Linux x86_64 musl asset: one static binary, no GUI.
const ASSET: &str = "tg-ws-proxy-x86_64-unknown-linux-musl.tar.gz";
const API_URL: &str = "https://api.github.com/repos/valnesfjord/tg-ws-proxy-rs/releases/latest";
const DOWNLOAD_PREFIX: &str = "https://github.com/valnesfjord/tg-ws-proxy-rs/releases/download/";
/// How the binary and any stray older `tg-ws-proxy` are named in the process table.
const IMAGE: &str = "tg-ws-proxy";

/// `~/.local/share/tg-ws-proxy` (or `$XDG_DATA_HOME/tg-ws-proxy`): where the release is unpacked.
pub fn dir() -> PathBuf {
    zapret::release::default_parent().join("tg-ws-proxy")
}

fn bin() -> PathBuf {
    dir().join(IMAGE)
}

/// The installed release's tag, from `version.txt` next to the binary.
fn version() -> Option<String> {
    std::fs::read_to_string(dir().join("version.txt"))
        .ok()
        .map(|text| text.trim().to_owned())
        .filter(|tag| !tag.is_empty())
}

fn config_home() -> anyhow::Result<PathBuf> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME");
    if let Some(dir) = xdg.filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::home_dir().context("cannot find the home folder")?;
    Ok(home.join(".config"))
}

/// `~/.config/systemd/user/zapret-hub-tg-ws.service`.
fn unit_path() -> anyhow::Result<PathBuf> {
    Ok(config_home()?
        .join("systemd/user")
        .join(format!("{UNIT}.service")))
}

/// 32 random hex characters the settings keep once generated, so the `tg://proxy` link survives
/// restarts. Generated only while `tg_ws_secret` is still empty; `true` when generated here.
pub fn ensure_secret(settings: &mut Settings) -> anyhow::Result<bool> {
    if !settings.tg_ws_secret.is_empty() {
        return Ok(false);
    }
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    settings.tg_ws_secret = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(true)
}

/// What Telegram Desktop adds the proxy from: `dd` + 32 hex characters — TCP only, IPv4, what a
/// local `--host 127.0.0.1` listener is.
pub fn tg_url(settings: &Settings) -> String {
    format!(
        "tg://proxy?server=127.0.0.1&port={}&secret=dd{}",
        settings.tg_ws_port, settings.tg_ws_secret
    )
}

/// The port, the 32 hex characters of the secret and the extra flags: what a unit file cannot
/// carry is refused here, before anything is saved or written. The flags go into `ExecStart`
/// verbatim, so a `%` (systemd specifier) or anything the quoting could take wrong is out.
fn validate(settings: &Settings) -> anyhow::Result<()> {
    anyhow::ensure!(
        settings.tg_ws_port != 0,
        "порт 0 не бывает: выберите 1–65535"
    );
    anyhow::ensure!(
        settings.tg_ws_secret.len() == 32
            && settings.tg_ws_secret.bytes().all(|b| b.is_ascii_hexdigit()),
        "секрет должен быть ровно 32 hex-символа"
    );
    for token in settings.tg_ws_args.split_whitespace() {
        anyhow::ensure!(
            token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._=/+,:-".contains(&b)),
            "доп. флаги содержат {token:?}: разрешены только латиница, цифры и . _ = / + , : -"
        );
    }
    Ok(())
}

/// The unit text with the settings in force; `validate` ran before it.
fn unit_text(bin: &Path, settings: &Settings) -> anyhow::Result<String> {
    anyhow::ensure!(
        !bin.display().to_string().contains('"'),
        "{}: путь содержит кавычку",
        bin.display()
    );
    Ok(format!(
        "[Unit]\n\
         Description=Zapret Hub: tg-ws-proxy (Telegram через WebSocket)\n\
         After=network.target\n\
         \n\
         [Service]\n\
         ExecStart=\"{}\" --host 127.0.0.1 --port {} --secret {} {}\n\
         Restart=on-failure\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        bin.display(),
        settings.tg_ws_port,
        settings.tg_ws_secret,
        settings.tg_ws_args,
    ))
}

/// `systemctl --user`. Nothing is checked: `is-active` answers 2 (error), 3 (inactive) and 4
/// (unknown) besides 0, so whoever reads the output decides.
fn systemctl_quiet(args: &[&str]) -> anyhow::Result<exec::Output> {
    let mut cmd = Command::new("systemctl");
    cmd.arg("--user").args(args);
    exec::run(&mut cmd, Duration::from_secs(30), None)
        .with_context(|| format!("systemctl --user {} не выполнился", args.join(" ")))
}

/// `systemctl --user` with an error when systemd refuses.
fn systemctl(args: &[&str]) -> anyhow::Result<()> {
    systemctl_quiet(args)?
        .check()
        .map(|_| ())
        .map_err(|err| err.context(format!("systemctl --user {}", args.join(" "))))
}

pub fn is_active() -> bool {
    systemctl_quiet(&["is-active", "--quiet", UNIT]).is_ok_and(|out| out.success())
}

/// The last 30 lines of the unit's journal, like `zapret::service::logs` but for `--user`.
fn logs() -> String {
    let mut cmd = Command::new("journalctl");
    cmd.args([
        "--user",
        "-u",
        UNIT,
        "-n",
        "30",
        "--no-pager",
        "--no-hostname",
    ]);
    match exec::run(&mut cmd, Duration::from_secs(10), None) {
        Ok(out) if out.success() && !out.stdout.trim().is_empty() => out.stdout.trim().to_owned(),
        _ => "-- No entries --".to_owned(),
    }
}

/// Everything a status card shows, read in one go: the disk, systemd and the journal.
pub fn status(app: &AppHandle) -> TgWsStatus {
    let settings = actions::state(app).settings();
    TgWsStatus {
        installed: bin().is_file(),
        version: version(),
        running: is_active(),
        port: settings.tg_ws_port,
        secret: settings.tg_ws_secret.clone(),
        args: settings.tg_ws_args.clone(),
        tg_url: tg_url(&settings),
        logs: logs(),
    }
}

/// The part of a save that only the service commands do: the file, the memory, the announcement.
/// The `saving` turn keeps it out of a whole settings save, like the ports save does.
fn save_settings(app: &AppHandle, with: impl FnOnce(&mut Settings)) -> anyhow::Result<()> {
    let state = actions::state(app);
    let _saving = state.saving();
    let mut settings = state.settings();
    with(&mut settings);
    crate::settings::save(&state.paths.settings(), &settings)?;
    state.set_settings(settings);
    changed(app);
    Ok(())
}

/// The unit file with the settings in force and systemd reloaded, nothing started. Needs the
/// binary: the caller decides whether that fails the command or is skipped.
fn write_unit(settings: &Settings) -> anyhow::Result<()> {
    validate(settings)?;
    let bin = bin();
    anyhow::ensure!(
        bin.is_file(),
        "{} отсутствует: сначала скачайте движок",
        bin.display()
    );
    let path = unit_path()?;
    let dir = path.parent().context("у юнита нет папки")?;
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    std::fs::write(&path, unit_text(&bin, settings)?)
        .with_context(|| format!("cannot write {}", path.display()))?;
    systemctl(&["daemon-reload"])
        .map_err(|err| err.context(format!("cannot reload {}", path.display())))
}

/// A stray `tg-ws-proxy` older than ours keeps the port busy: stop it, ours takes the port
/// through the unit. (A port busy with something else fails the start and the journal says so.
/// Only when ours is not already running: an `is-active` unit has a namesake process of its own.)
fn stop_strays() {
    if !is_active() && zapret::procs::is_running(IMAGE) {
        match zapret::procs::kill_all(IMAGE) {
            Ok(()) => log::info!("старый сторонний процесс {IMAGE} остановлен: наш берёт порт"),
            Err(err) => log::warn!("старый процесс {IMAGE} не остановлен: {err:#}"),
        }
    }
}

/// The unit and systemd's enablement, then the service while it was not running: the bottom of
/// `set_tg_ws_enabled` and, at the app's start, whatever else it was left off.
pub fn start(settings: &Settings) -> anyhow::Result<()> {
    write_unit(settings)?;
    stop_strays();
    systemctl(&["enable", "--now", UNIT])
}

/// `set_tg_ws_enabled`: the flag into the settings, the unit into systemd (or just a stop).
pub fn set_enabled(app: &AppHandle, enabled: bool) -> anyhow::Result<TgWsStatus> {
    if enabled {
        save_settings(app, |settings| {
            settings.tg_ws_enabled = true;
            if let Err(err) = ensure_secret(settings) {
                log::warn!("секрет не сгенерировался: {err:#}: заполните его вручную");
            }
        })?;
        start(&actions::state(app).settings())?;
    } else {
        // The unit may never have been created: a missed stop is not an error.
        let _ = systemctl(&["stop", UNIT]);
        save_settings(app, |settings| settings.tg_ws_enabled = false)?;
    }
    Ok(status(app))
}

/// `save_tg_ws_config`: the three fields into the settings, then the unit rewritten and the
/// service restarted when it was running.
pub fn save_config(
    app: &AppHandle,
    port: u16,
    secret: String,
    args: String,
) -> anyhow::Result<TgWsStatus> {
    let state = actions::state(app);
    // Refused before anything is saved: nothing changes on a bad save.
    validate(&Settings {
        tg_ws_port: port,
        tg_ws_secret: secret.clone(),
        tg_ws_args: args.clone(),
        ..state.settings()
    })?;
    save_settings(app, |settings| {
        settings.tg_ws_port = port;
        settings.tg_ws_secret = secret;
        settings.tg_ws_args = args;
    })?;
    let settings = state.settings();
    if bin().is_file() {
        write_unit(&settings)?;
        if is_active() {
            systemctl(&["restart", UNIT])?;
        }
    }
    Ok(status(app))
}

/// The staging folder, gone when the download is over either way.
const STAGING: &str = ".zapret-hub-download";

/// The tag and the asset URL of the latest release: the asset named exactly like the musl build,
/// its URL a download of the same repository. Nothing the answer carries becomes a command.
fn select(json: &str) -> anyhow::Result<(String, String)> {
    let value: serde_json::Value =
        serde_json::from_str(json).context("GitHub answered with something other than JSON")?;
    let tag = value["tag_name"]
        .as_str()
        .context("the GitHub answer has no tag_name")?;
    anyhow::ensure!(
        !tag.is_empty()
            && tag.len() <= 64
            && tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "unexpected release tag {tag:?}"
    );
    let url = value["assets"]
        .as_array()
        .and_then(|assets| {
            assets
                .iter()
                .find_map(|a| {
                    (a["name"].as_str() == Some(ASSET)).then(|| a["browser_download_url"].as_str())
                })
                .flatten()
        })
        .with_context(|| format!("release {tag} of tg-ws-proxy-rs has no {ASSET}"))?;
    anyhow::ensure!(
        url.starts_with(DOWNLOAD_PREFIX),
        "{ASSET} points outside tg-ws-proxy-rs: {url}"
    );
    Ok((tag.to_owned(), url.to_owned()))
}

/// The one `tg-ws-proxy` file inside the unpack, wherever the archive keeps it.
fn find_binary(root: &Path) -> anyhow::Result<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                stack.push(path);
            } else if entry.file_name() == IMAGE {
                return Ok(path);
            }
        }
    }
    anyhow::bail!("в архиве нет файла {IMAGE}: {ASSET} не тот архив")
}

/// The latest release unpacked over `dir`: the tar.gz downloaded, the binary moved out at
/// `0o755`, the tag into `version.txt`. On a failure the old files stay.
fn download_unpack(dir: &Path, socks5: Option<&str>, cancel: &AtomicBool) -> anyhow::Result<()> {
    let staging = dir.join(STAGING);
    let done = |result: &anyhow::Result<()>| {
        let _ = std::fs::remove_dir_all(&staging);
        if let Err(err) = result {
            log::warn!("tg-ws-proxy-rs не установился: {err:#}");
        }
    };
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let result = unpack(dir, &staging, socks5, cancel);
    done(&result);
    result
}

fn unpack(
    dir: &Path,
    staging: &Path,
    socks5: Option<&str>,
    cancel: &AtomicBool,
) -> anyhow::Result<()> {
    let (tag, url) = select(&probe::curl::fetch_text(API_URL, socks5)?)?;
    let raw = staging.join("x");
    std::fs::create_dir_all(&raw)?;
    let tgz = staging.join(ASSET);
    probe::curl::with_fallback(socks5, |proxy| {
        anyhow::ensure!(!cancel.load(Ordering::Relaxed), "canceled");
        let mut cmd = probe::curl::get(&url, proxy);
        cmd.args(["-m", "900", "-o"]).arg(&tgz);
        exec::run(&mut cmd, Duration::from_secs(910), Some(cancel))?.check()?;
        Ok(())
    })?;
    anyhow::ensure!(!cancel.load(Ordering::Relaxed), "canceled");
    let sha256 = std::fs::read(&tgz)
        .map(|bytes| zapret::sha256_hex(&bytes))
        .with_context(|| format!("cannot read {}", tgz.display()))?;
    log::info!("{ASSET} SHA-256 {sha256}");
    let mut cmd = Command::new("bsdtar");
    cmd.arg("-xf").arg(&tgz).arg("-C").arg(&raw);
    exec::run(&mut cmd, Duration::from_secs(300), Some(cancel))?.check()?;
    anyhow::ensure!(!cancel.load(Ordering::Relaxed), "canceled");
    let to = bin();
    std::fs::copy(find_binary(&raw)?, &to)
        .with_context(|| format!("cannot write {}", to.display()))?;
    std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("cannot chmod {}", to.display()))?;
    std::fs::write(dir.join("version.txt"), format!("{tag}\n"))
        .with_context(|| format!("cannot write {}", dir.join("version.txt").display()))?;
    log::info!("tg-ws-proxy-rs {tag} установлен: {}", to.display());
    Ok(())
}

/// `install_tg_ws`: the latest release unpacked over the folder, then the service back the way it
/// was. One download at a time with everything else of the app's, like a zapret2 download.
pub fn install(app: &AppHandle) -> anyhow::Result<TgWsStatus> {
    let state = actions::state(app);
    let socks5 = state.socks5();
    let settings = state.settings();
    let was_running = is_active();
    state.download(|cancel| download_unpack(&dir(), socks5.as_deref(), cancel))?;
    if was_running || settings.tg_ws_enabled {
        stop_strays();
        start(&settings)?;
    }
    Ok(status(app))
}

/// `open_tg_proxy`: the `tg://proxy` link to `xdg-open`, Telegram Desktop's own handler.
pub fn open(settings: &Settings) -> anyhow::Result<()> {
    crate::shell::open(std::ffi::OsStr::new(&tg_url(settings)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(tag: &str, assets: &[(&str, &str)]) -> String {
        let assets: Vec<_> = assets
            .iter()
            .map(|(name, url)| serde_json::json!({"name": name, "browser_download_url": url}))
            .collect();
        serde_json::json!({"tag_name": tag, "assets": assets}).to_string()
    }

    #[test]
    fn picks_the_musl_asset_of_the_same_repository() {
        const URL: &str = "https://github.com/valnesfjord/tg-ws-proxy-rs/releases/download/v1.2.3/tg-ws-proxy-x86_64-unknown-linux-musl.tar.gz";
        let (tag, url) = select(&json("v1.2.3", &[(ASSET, URL)])).unwrap();
        assert_eq!(tag, "v1.2.3");
        assert_eq!(url, URL);
        assert!(
            select(&json("v1.2.3", &[])).is_err(),
            "no asset is a failure"
        );
        let foreign = select(&json(
            "v1.2.3",
            &[(
                ASSET,
                "https://github.com/Flowseal/tg-ws-proxy/releases/download/1.9.3/tg-ws-proxy-x86_64-unknown-linux-musl.tar.gz",
            )],
        ));
        assert!(
            foreign.is_err(),
            "the URL is a release of another repository"
        );
        let odd = select(&json("../..", &[])).unwrap_err();
        assert!(odd.to_string().contains("unexpected release tag"), "{odd}");
        assert!(select("<html>").is_err(), "not JSON");
    }

    #[test]
    fn a_secret_is_32_hex_characters_once() {
        let mut settings = Settings::default();
        assert!(settings.tg_ws_secret.is_empty());
        ensure_secret(&mut settings).unwrap();
        assert_eq!(settings.tg_ws_secret.len(), 32);
        assert!(
            settings.tg_ws_secret.bytes().all(|b| b.is_ascii_hexdigit()),
            "{}",
            settings.tg_ws_secret
        );
        for _ in 0..9 {
            assert!(
                !ensure_secret(&mut settings).unwrap(),
                "generated only once"
            );
        }
    }

    #[test]
    fn the_url_has_the_dd_prefix() {
        let settings = Settings {
            tg_ws_port: 1443,
            tg_ws_secret: "ab".repeat(16),
            ..Settings::default()
        };
        assert_eq!(
            tg_url(&settings),
            format!(
                "tg://proxy?server=127.0.0.1&port=1443&secret=dd{}",
                "ab".repeat(16)
            )
        );
    }

    #[test]
    fn the_unit_is_the_service_the_spec_asks_for() {
        let settings = Settings {
            tg_ws_port: 1443,
            tg_ws_secret: "ab".repeat(16),
            tg_ws_args: "--fronting-domain example.com".into(),
            ..Settings::default()
        };
        let text = unit_text(
            Path::new("/home/user/.local/share/tg-ws-proxy/tg-ws-proxy"),
            &settings,
        )
        .unwrap();
        assert!(text.contains("ExecStart=\"/home/user/.local/share/tg-ws-proxy/tg-ws-proxy\" --host 127.0.0.1 --port 1443 --secret abababababababababababababababab --fronting-domain example.com\n"), "{text}");
        assert!(text.contains("Restart=on-failure"), "{text}");
        assert!(text.contains("WantedBy=default.target"), "{text}");
    }

    #[test]
    fn a_bad_port_secret_or_args_never_reach_the_unit() {
        let ok = Settings {
            ..Settings::default()
        };
        // Nothing filled: the validation refuses before the unit text is attempted.
        assert!(validate(&ok).is_err(), "an empty secret is refused");
        assert!(
            unit_text(Path::new("/bin/x"), &ok).is_ok(),
            "unit_text trusts its caller"
        );
        assert!(
            validate(&Settings {
                tg_ws_port: 0,
                tg_ws_secret: "ab".repeat(16),
                ..ok.clone()
            })
            .is_err()
        );
        // A short or non-hex secret goes out too.
        assert!(
            validate(&Settings {
                tg_ws_secret: "ab".repeat(15),
                ..ok.clone()
            })
            .is_err()
        );
        assert!(
            validate(&Settings {
                tg_ws_secret: "g".repeat(32),
                ..ok.clone()
            })
            .is_err()
        );
        assert!(
            validate(&Settings {
                tg_ws_port: 65535,
                tg_ws_secret: "AB".repeat(16),
                ..ok.clone()
            })
            .is_ok()
        );
        assert!(
            validate(&Settings {
                tg_ws_args: "--fronting-domain example.com".into(),
                tg_ws_secret: "ab".repeat(16),
                ..ok.clone()
            })
            .is_ok()
        );
        for bad in ["--x %p", "--x $(ls)", "--x `ls`", "--x a b\"]"] {
            let err = validate(&Settings {
                tg_ws_args: bad.to_string(),
                tg_ws_secret: "ab".repeat(16),
                ..ok.clone()
            })
            .unwrap_err()
            .to_string();
            assert!(err.contains("доп. флаги"), "{bad}: {err}");
        }
        assert!(
            unit_text(
                Path::new("/bin/\"quote\""),
                &Settings {
                    tg_ws_secret: "ab".repeat(16),
                    ..ok
                }
            )
            .is_err()
        );
    }
}
