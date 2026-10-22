//! The autostart desktop entry: at login it runs `zapret-hub --autostart` like this exe.

use std::path::Path;

fn entry_path() -> Option<std::path::PathBuf> {
    Some(
        std::env::home_dir()?
            .join(".config")
            .join("autostart")
            .join("zapret-hub.desktop"),
    )
}

fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// The `[Desktop Entry]` with `Exec` quoting a path as the spec allows.
pub fn task_entry(exe: &Path) -> String {
    let command = escape(&exe.display().to_string());
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={}\n\
         Comment=Zapret Hub at logon\n\
         Exec=\"{command}\" --autostart\n\
         Hidden=false\n\
         X-GNOME-Autostart-enabled=true\n",
        crate::texts::APP
    )
}

/// The exe an entry's `Exec=` starts.
pub fn command_of(entry: &str) -> Option<String> {
    let line = entry.lines().find_map(|l| l.strip_prefix("Exec="))?;
    let rest = line
        .trim()
        .strip_prefix('"')
        .filter(|rest| rest.contains('"'))?;
    Some(
        rest[..rest.find('"')?]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\"),
    )
}

/// The autostart as it is on the disk: the entry exists and `Exec=` runs this exe. The user may
/// have switched it off in the system's settings, so the file, not the saved flag, is the truth.
pub fn is_enabled(exe: &Path) -> bool {
    entry_path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .is_some_and(|text| command_of(&text).is_some_and(|command| Path::new(&command) == exe))
}

pub fn enable(exe: &Path) -> anyhow::Result<()> {
    let path =
        entry_path().ok_or_else(|| anyhow::anyhow!("no home folder for the autostart entry"))?;
    std::fs::create_dir_all(path.parent().expect("autostart has a parent"))?;
    std::fs::write(path, task_entry(exe))?;
    Ok(())
}

pub fn disable() -> anyhow::Result<()> {
    if let Some(path) = entry_path() {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

/// The exe moved since the entry was made, or the entry is gone: it is made again for `exe`.
pub fn refresh(exe: &Path) -> anyhow::Result<()> {
    if is_enabled(exe) {
        Ok(())
    } else {
        enable(exe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entry_runs_this_exe_at_logon() {
        let exe = Path::new("/opt/Tools & Apps/zapret-hub");
        let entry = task_entry(exe);
        assert!(
            entry.contains(r#"Exec="/opt/Tools & Apps/zapret-hub" --autostart"#),
            "{entry}"
        );
        assert_eq!(
            command_of(&entry).as_deref(),
            Some("/opt/Tools & Apps/zapret-hub"),
            "{entry}"
        );
        assert!(entry.contains("X-GNOME-Autostart-enabled=true"), "{entry}");
    }
}
