//! Steps that only root may do (`nft`, system `systemctl`, files under `/etc`): run as root when
//! this process is root, otherwise through `sudo -n`, and say in the error what is missing.

use anyhow::Context as _;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(90);

/// What a refused step names: the user can fix the rights themselves.
pub const HINT: &str =
    "not enough rights for this step: run Zapret Hub as root (sudo -E) or set up polkit/sudoers for it";

/// Has this process root rights?
pub fn is_root() -> bool {
    // SAFETY: `geteuid` is a plain syscall without invariants.
    (unsafe { libc::geteuid() }) == 0
}

/// The rights-asking program candidates: the first one present wins (`pkexec` only when `sudo` is
/// not there at all).
fn wrapper() -> Option<&'static str> {
    [("/usr/bin/sudo", Some("sudo")), ("/usr/bin/pkexec", Some("pkexec"))]
        .iter()
        .find(|(path, _)| std::fs::metadata(path).is_ok())
        .map(|(_, name)| name.expect("every wrapper carries a name"))
}

/// `prog` with `args` under root rights: directly as root, else through the rights wrapper.
pub fn command(prog: &str, args: &[&str]) -> anyhow::Result<Command> {
    let mut cmd = if is_root() {
        Command::new(prog)
    } else {
        let wrapper = wrapper().ok_or_else(|| anyhow::anyhow!("{HINT}"))?;
        let mut cmd = Command::new(wrapper);
        if wrapper == "sudo" {
            cmd.arg("-n");
        }
        cmd.arg(prog);
        cmd
    };
    cmd.args(args);
    Ok(cmd)
}

/// Runs `prog args` as root, and what came of it. A `sudo`-side refusal (no `-n` rights) reads
/// into the error with {HINT}, so the user knows to fix the rights.
pub fn run(prog: &str, args: &[&str]) -> anyhow::Result<exec::Output> {
    let shown = args.join(" ");
    let mut cmd = command(prog, args).with_context(|| format!("{prog} {shown}"))?;
    let out = exec::run(&mut cmd, WAIT, None)
        .with_context(|| format!("starting {prog} {shown}"))?;
    if !out.success() && !is_root() && sudo_refused(&out) {
        anyhow::bail!("{HINT}\n{}", out.describe());
    }
    Ok(out)
}

fn sudo_refused(out: &exec::Output) -> bool {
    let text = format!("{}{}", out.stdout, out.stderr);
    [
        "sudo: a password is required",
        "sudo: sorry",
        "polkit answer",
        "not authorized",
    ]
    .iter()
    .any(|phrase| text.contains(phrase))
}

/// Writes `contents` into a root-owned file: a plain write as root, a `sudo cp` otherwise.
pub fn write(path: &Path, contents: &str) -> anyhow::Result<()> {
    if is_root() {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create {}", parent.display()))?;
            }
        }
        std::fs::write(path, contents)
            .with_context(|| format!("cannot write {}", path.display()))?;
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let parent_str = parent.display().to_string();
            let out = run("mkdir", &["-p", &parent_str])?;
            check_out(out, &format!("cannot create directory {}", parent.display()))?;
        }
    }
    let temp = std::env::temp_dir().join(format!("zapret-hub-write-{}", std::process::id()));
    std::fs::write(&temp, contents).with_context(|| format!("cannot write {}", temp.display()))?;
    let copies = [temp.display().to_string(), path.display().to_string()];
    let copied = run("cp", &copies.iter().map(String::as_str).collect::<Vec<_>>());
    let _ = std::fs::remove_file(&temp);
    copied
        .and_then(|out| {
            check_out(out, &format!("cannot write {}", path.display()))
        })
}

/// Removes `path` as root, best effort: a missing file is fine.
pub fn remove(path: &Path) {
    if path.exists() {
        let _ = run("rm", &["-f", path.display().to_string().as_str()]);
    }
}

fn check_out(out: exec::Output, what: &str) -> anyhow::Result<()> {
    if out.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("{what}:\n{}", out.describe()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hint_says_what_to_do() {
        assert!(HINT.contains("sudo -E"));
        assert!(HINT.contains("polkit"));
    }
}
