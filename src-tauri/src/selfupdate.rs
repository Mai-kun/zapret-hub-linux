//! The portable install's self-update: what the updater plugin cannot do. On Linux the plugin
//! rewrites `current_exe` with the release AppImage, and a tar.gz install dies from that — the
//! hub would run from a read-only FUSE mount with its `data/` out of reach (the 0.7.2 regression).
//! Here the release `tar.gz` is downloaded instead, the new binaries take the old ones' place by
//! rename, and the app re-executes itself.

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::Context as _;
use serde::Serialize;
use specta::Type;
use tauri::AppHandle;
use tauri_specta::Event as _;

use crate::commands::Answer;

/// The repository whose releases carry both the plugin's `latest.json` and the portable archive.
const RELEASES: &str = "https://github.com/Mai-kun/zapret-hub-linux/releases/download";

/// The portable archive of a release, exactly what `release.yml` stages.
fn archive_url(version: &str) -> String {
    format!("{RELEASES}/v{version}/zapret-hub-linux-x86_64.tar.gz")
}

/// Whether this instance runs from an AppImage: only there the updater plugin does the right
/// thing, everywhere else the install is portable and its update goes through this module.
#[tauri::command]
#[specta::specta]
pub fn runs_as_appimage() -> bool {
    std::env::var_os("APPIMAGE").is_some()
}

/// The update's progress to the page: bytes received so far, the total when the server told it.
#[derive(Debug, Clone, Serialize, Type, tauri_specta::Event)]
pub struct UpdateProgress {
    pub received: u32,
    pub total: Option<u32>,
}

/// Downloads the `version` archive, replaces the running binaries with its own and restarts the
/// app into the new one. The rename keeps the old file on a failure, so a broken download never
/// takes the working install down.
#[tauri::command]
#[specta::specta]
pub async fn install_portable_update(handle: AppHandle, version: String) -> Answer<()> {
    crate::commands::blocking(move || install(&handle, &version)).await
}

fn install(handle: &AppHandle, version: &str) -> anyhow::Result<()> {
    let state = crate::actions::state(handle);
    let socks5 = state.socks5();

    let tag = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let temp = std::env::temp_dir().join(format!("zapret-hub-update-{tag}"));
    let _ = std::fs::remove_dir_all(&temp);
    let archive_dir = temp.join("archive");
    std::fs::create_dir_all(&archive_dir)?;
    let archive = archive_dir.join("zapret-hub-linux-x86_64.tar.gz");

    let url = archive_url(version);
    log::info!("portable update: downloading {url}");
    let mut cmd = probe::curl::get(&url, socks5.as_deref());
    cmd.args(["-m", "900", "-o"]).arg(&archive);
    std::thread::scope(|scope| {
        let run = scope.spawn(|| exec::run(&mut cmd, Duration::from_secs(910), None));
        while !run.is_finished() {
            progress(
                handle,
                std::fs::metadata(&archive).map_or(0, |m| m.len()),
                None,
            );
            std::thread::sleep(Duration::from_millis(300));
        }
        let out: exec::Output = run
            .join()
            .unwrap_or_else(|_| Err(std::io::Error::other("curl panicked")))?
            .check()?;
        anyhow::Ok(out)
    })?;
    let size = std::fs::metadata(&archive)?.len();
    progress(handle, size, Some(size));

    let unpacked = temp.join("unpacked");
    zapret::release::expand(&archive, &unpacked, &AtomicBool::new(false))
        .with_context(|| "cannot unpack the update archive")?;

    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent", exe.display()))?
        .to_path_buf();
    log::info!("portable update: replacing the binaries in {}", dir.display());

    // The hub binary cannot be written over while it runs: it goes to a staging name and one
    // rename puts it in place. The backup holds the old one until everything else succeeded.
    let backup = dir.join("zapret-hub.bak");
    std::fs::rename(&exe, &backup)?;
    let done = replace_run(&unpacked, &dir, &["zapret-hub", "zapret-hub-cli"])
        .and_then(|()| refresh_extras(&unpacked, &dir));
    if let Err(err) = done {
        let _ = std::fs::rename(&backup, &exe);
        let _ = std::fs::remove_dir_all(&temp);
        return Err(err);
    }
    let _ = std::fs::remove_file(&backup);
    let _ = std::fs::remove_dir_all(&temp);
    log::info!("portable update: {version} is in place, restarting");

    // The old binary is gone from its path already: this re-exec runs the new one.
    handle.restart()
}

/// Copies every `name` from `from` into `to` with the executable bit, through a staging name —
/// the running hub binary is among them. Every file is required.
fn replace_run(from: &Path, to: &Path, names: &[&str]) -> anyhow::Result<()> {
    for name in names {
        let source = from.join(name);
        anyhow::ensure!(
            source.is_file(),
            "{} is not in the update archive",
            source.display()
        );
        let staged = to.join(format!("{name}.new"));
        std::fs::copy(&source, &staged)
            .with_context(|| format!("cannot write {}", staged.display()))?;
        std::fs::set_permissions(
            &staged,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )?;
        std::fs::rename(&staged, to.join(name))
            .with_context(|| format!("cannot replace {}", to.join(name).display()))?;
    }
    Ok(())
}

/// The docs and icons of the release go over the install's copies, best effort: their loss
/// never breaks the app, and the tar.gz is the only place that refreshes them.
fn refresh_extras(from: &Path, to: &Path) -> anyhow::Result<()> {
    for name in ["README.md", "cli.md", "zapret-hub.desktop", "zapret-hub.png"] {
        let _ = std::fs::copy(from.join(name), to.join(name));
    }
    Ok(())
}

fn progress(handle: &AppHandle, received: u64, total: Option<u64>) {
    let clamp = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
    let _ = UpdateProgress {
        received: clamp(received),
        total: total.map(clamp),
    }
    .emit(handle);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_archive_url_follows_the_release_layout() {
        assert_eq!(
            archive_url("0.7.2"),
            format!(
                "{RELEASES}/v0.7.2/zapret-hub-linux-x86_64.tar.gz"
            )
        );
    }
}
