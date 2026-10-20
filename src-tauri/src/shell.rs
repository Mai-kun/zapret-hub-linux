//! Folders and links open the way the user's own shell opens them: through `xdg-open`, the
//! user's default handler.

use std::ffi::OsStr;
use std::process::Command;
use std::time::Duration;

pub fn open(target: &OsStr) -> anyhow::Result<()> {
    let mut cmd = Command::new("xdg-open");
    cmd.arg(target);
    // The returned code means nothing: the file manager takes over and lives on its own.
    exec::run(&mut cmd, Duration::from_secs(10), None)?;
    log::info!("opened {} through xdg-open", target.display());
    Ok(())
}
