//! Steps that only root may do (`nft`, system `systemctl`, files under `/etc`): run as root when
//! this process is root, otherwise through `sudo -n`, and say in the error what is missing.

use anyhow::Context as _;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(90);

/// What a refused step names: the user can fix the rights themselves.
pub const HINT: &str = "not enough rights for this step: run Zapret Hub as root (sudo -E) or set up polkit/sudoers for it";

/// Has this process root rights?
pub fn is_root() -> bool {
    // SAFETY: `geteuid` is a plain syscall without invariants.
    (unsafe { libc::geteuid() }) == 0
}

/// The rights-asking program candidates: the first one present wins (`pkexec` only when `sudo` is
/// not there at all).
fn wrapper() -> Option<&'static str> {
    [
        ("/usr/bin/sudo", Some("sudo")),
        ("/usr/bin/pkexec", Some("pkexec")),
    ]
    .iter()
    .find(|(path, _)| std::fs::metadata(path).is_ok())
    .map(|(_, name)| name.expect("every wrapper carries a name"))
}

/// The usual folders of a tool: `/sbin` and `/usr/sbin` hold `nft`, `modprobe` and `sysctl` on
/// Debian, Fedora and openSUSE, and a user session's `PATH` there does not cover them.
const PATH_DIRS: &[&str] = &["/usr/bin", "/usr/sbin", "/sbin", "/bin"];

/// The absolute path of a system tool: `which` on the `PATH` first, then the usual bin and sbin
/// folders (`which` finds the user's own `PATH` only). What systemd's unit lines and `sudo` need.
pub fn which(prog: &str) -> Option<String> {
    // A program with separators is a file to look up directly, no `which()` needed.
    if !prog.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    let mut cmd = Command::new("which");
    cmd.arg(prog);
    if let Ok(out) = exec::run(&mut cmd, Duration::from_secs(5), None)
        && out.success()
    {
        let path = out.stdout.trim().to_owned();
        if path.starts_with('/') {
            return Some(path);
        }
    }
    find_in(PATH_DIRS, prog)
}

/// The first existing `dir/prog` (the core of `which`, covered by a test).
fn find_in(dirs: &[&str], prog: &str) -> Option<String> {
    dirs.iter()
        .map(|dir| format!("{dir}/{prog}"))
        .find(|path| Path::new(path).is_file())
        .map(|path| path.to_owned())
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
    let out =
        exec::run(&mut cmd, WAIT, None).with_context(|| format!("starting {prog} {shown}"))?;
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
            check_out(
                out,
                &format!("cannot create directory {}", parent.display()),
            )?;
        }
    }
    let temp = std::env::temp_dir().join(format!("zapret-hub-write-{}", std::process::id()));
    std::fs::write(&temp, contents).with_context(|| format!("cannot write {}", temp.display()))?;
    let copies = [temp.display().to_string(), path.display().to_string()];
    let copied = run("cp", &copies.iter().map(String::as_str).collect::<Vec<_>>());
    let _ = std::fs::remove_file(&temp);
    copied.and_then(|out| check_out(out, &format!("cannot write {}", path.display())))
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

    #[test]
    fn a_tool_is_found_in_the_first_dir_that_has_it_and_nowhere_else() {
        let dir = tempfile::tempdir().unwrap();
        let bins = dir.path().join("bin");
        let sbins = dir.path().join("sbin");
        std::fs::create_dir(&bins).unwrap();
        std::fs::create_dir(&sbins).unwrap();
        std::fs::write(sbins.join("nft"), "").unwrap();
        std::fs::write(bins.join("curl"), "").unwrap();
        let names = [&bins, &sbins];
        let dirs: Vec<&str> = names.iter().map(|p| p.to_str().unwrap()).collect();
        assert_eq!(
            find_in(&dirs, "nft").unwrap(),
            sbins.join("nft").display().to_string(),
            "sbin counts even though a user PATH does not hold it"
        );
        assert_eq!(find_in(&dirs, "curl").unwrap(), bins.join("curl").display().to_string());
        assert_eq!(find_in(&dirs, "nothing"), None);
        // `which` refuses a program that is not a plain name.
        assert_eq!(which("bin/nft"), None);
    }
}
