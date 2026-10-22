//! Running processes: finding `winws.exe` and its arguments, stopping it, starting it again,
//! and the winws the tests run themselves.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Proc {
    pub pid: u32,
    pub exe: Option<PathBuf>,
    /// Arguments after the program name.
    pub args: Vec<String>,
}

/// The image name without its Windows `.exe`: how a program's own names keep matching.
fn same_image(name: &str, image: &str) -> bool {
    fn stem(s: &str) -> &str {
        let cut = s
            .len()
            .checked_sub(4)
            .filter(|i| s[*i..].eq_ignore_ascii_case(".exe"));
        match cut {
            Some(i) => &s[..i],
            None => s,
        }
    }
    stem(name).eq_ignore_ascii_case(stem(image))
}

/// Processes whose image name is `image` (case-insensitive, `.exe` ignored), with exe path and
/// arguments.
pub fn find(image: &str) -> Vec<Proc> {
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_exe(UpdateKind::Always)
            .with_cmd(UpdateKind::Always),
    );
    system
        .processes()
        .values()
        .filter(|p| same_image(&p.name().to_string_lossy(), image))
        .map(|p| Proc {
            pid: p.pid().as_u32(),
            exe: p.exe().map(Path::to_path_buf),
            args: p
                .cmd()
                .iter()
                .skip(1)
                .map(|a| a.to_string_lossy().into_owned())
                .collect(),
        })
        .collect()
}

pub fn is_running(image: &str) -> bool {
    !find(image).is_empty()
}

/// The queue `nfqws2 --qnum=` binds (`zapret2::nft::QNUM`; `zapret` does not depend on `zapret2`).
const NFQWS2_QUEUE: u32 = 200;
/// On Linux nothing on the pipes reports capture started (`nfqws2` writes nothing readable, and a
/// redirected stdout buffers): its readiness is the NFQUEUE being bound — the file that lists the
/// queues has ours with the child's pid as its portid.
const QUEUE_FILE: &str = "/proc/net/netfilter/nfnetlink_queue";
/// How long more to settle once the queue is open: the queue comes up after the Lua init, this is
/// only the last messages reaching the pipes while the process must stay alive.
const QUEUE_SETTLE: Duration = Duration::from_millis(150);

/// Ends every process named `image` (SIGKILL), waiting until the name is gone, so their file
/// handles (WinDivert's among them) are closed before what comes next starts.
pub fn kill_all(image: &str) -> anyhow::Result<()> {
    if !is_running(image) {
        return Ok(());
    }
    let started = Instant::now();
    loop {
        let mut system = System::new();
        system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing(),
        );
        for proc in system.processes().values() {
            if same_image(&proc.name().to_string_lossy(), image)
                && proc.pid().as_u32() != std::process::id()
            {
                proc.kill();
            }
        }
        if !is_running(image) {
            return Ok(());
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(10),
            "{image} is still running 10 s after the kill"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The queue file's text, as readable as this process can get it: a non-root user cannot — the
/// kernel makes it `0440 root:root` — so it is read through the same `sudo -n` as `nft`
/// (`zapret::root`). One short spawn per poll; an engine binds the queue within the first few.
fn queue_text() -> Option<String> {
    if let Ok(text) = std::fs::read_to_string(QUEUE_FILE) {
        return Some(text);
    }
    if super::root::is_root() {
        return None;
    }
    let out = super::root::run("cat", &[QUEUE_FILE]).ok()?;
    (out.success() && !out.stdout.is_empty()).then(|| out.stdout)
}

/// Starts a process from a snapshot again, without a window, not waiting for it. It gets no
/// standard handles: a long-lived winws must not hold a pipe of ours open.
pub fn spawn_detached(proc: &Proc) -> anyhow::Result<()> {
    let exe = proc
        .exe
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("pid {} had no executable path", proc.pid))?;
    let mut cmd = Command::new(exe);
    cmd.args(&proc.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(dir) = exe.parent() {
        cmd.current_dir(dir);
    }
    let child = cmd.spawn()?;
    log::info!(target: "exec", "started {} (pid {}) {}", exe.display(), child.id(), proc.args.join(" "));
    Ok(())
}

/// A `winws.exe` or `winws2.exe` the tests start directly, with the arguments the service would
/// get (7.3).
pub struct Winws {
    child: Child,
    output: Arc<Mutex<Vec<u8>>>,
    readers: Vec<JoinHandle<()>>,
    /// `winws.exe` or `winws2.exe`: the messages name it.
    image: String,
}

impl Winws {
    /// `"<exe>" <tail>` in `cwd`: Flowseal's `bin\winws.exe` from `bin`, zapret2's `winws2.exe`
    /// from its root. A tail with the Windows `cmd /c "..."` shape runs as `sh -c "..."`.
    pub fn start(exe: &Path, cwd: &Path, tail: &str) -> std::io::Result<Self> {
        let trimmed = tail.trim_start();
        let shell_c = trimmed.len() > 3
            && trimmed[..2].eq_ignore_ascii_case("/c")
            && trimmed[2..].starts_with(|c: char| c.is_whitespace());
        let mut command = if shell_c {
            // `cmd /c "..."`: cmd strips the outer quotes; without them sh handles the rest.
            let script = trimmed[2..].trim();
            let unquoted = script
                .strip_prefix('"')
                .filter(|rest| rest.ends_with('"'))
                .map(String::from)
                .map(|mut rest| {
                    rest.pop();
                    rest
                });
            let mut sh = Command::new("sh");
            sh.arg("-c").arg(unquoted.as_deref().unwrap_or(script));
            sh
        } else {
            let mut cmd = Command::new(exe);
            cmd.args(crate::spawn_tokens(tail));
            cmd
        };
        let mut child = command
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let output = Arc::new(Mutex::new(Vec::new()));
        let mut readers = Vec::new();
        let pipes: [Option<Box<dyn Read + Send>>; 2] = [
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ];
        for mut pipe in pipes.into_iter().flatten() {
            let output = Arc::clone(&output);
            readers.push(std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = pipe.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    output.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            }));
        }
        let image = if shell_c {
            "sh".to_owned()
        } else {
            exe.file_name().map_or_else(
                || exe.display().to_string(),
                |name| name.to_string_lossy().into_owned(),
            )
        };
        log::info!(target: "exec", "started {image} (pid {}) {}", child.id(), tail.trim_start());
        Ok(Self {
            child,
            output,
            readers,
            image,
        })
    }

    /// Waits until winws reports capture started (winws2: `windivert initialized. capture is
    /// started.`), Linux `nfqws2` binds its NFQUEUE, or `max` passes. One that exited is a launch
    /// error: `Err` carries its exit status and output. `Ok(true)` says the engine is fully ready —
    /// on Linux that is the queue, which it binds only after its Lua init.
    pub fn wait_ready(&mut self, max: Duration) -> Result<bool, String> {
        let started = Instant::now();
        loop {
            if let Some(error) = self.exited_error() {
                return Err(error);
            }
            if self.output_text().contains("capture is started") || started.elapsed() >= max {
                return Ok(self.queue_open(NFQWS2_QUEUE));
            }
            if self.queue_open(NFQWS2_QUEUE) {
                std::thread::sleep(QUEUE_SETTLE);
                // The one time the queue hints at the engine's state, it must still be there.
                if let Some(error) = self.exited_error() {
                    return Err(error);
                }
                return Ok(true);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// The whole output and the status of a winws that ended by itself, with both readers joined:
    /// the pipes close with the process, so the output is whole.
    fn exited_error(&mut self) -> Option<String> {
        let status = self.child.try_wait().ok().flatten()?;
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        Some(format!(
            "{} exited ({status}):\n{}",
            self.image,
            self.output_text()
        ))
    }

    /// Whether queue `qnum` is bound by an open socket in `QUEUE_FILE`: kernel order is column 1
    /// `queue_num`, column 2 `peer_portid` — nonzero while the owner lives — column 3 the queue
    /// total (0 around the start): `200 159031 0 2 65531 0 0 254 1`. Which live process it is,
    /// `try_wait` in the loop already says (ours is the only engine, `stop_engines` saw to it).
    fn queue_open(&self, qnum: u32) -> bool {
        let Some(text) = queue_text() else {
            return false;
        };
        let qnum = qnum.to_string();
        text.lines().any(|line| {
            let mut fields = line.split_whitespace();
            fields.next().is_some_and(|field| *field == qnum)
                && fields.next().is_some_and(|portid| portid != "0")
        })
    }

    pub fn output_text(&self) -> String {
        exec::decode(&self.output.lock().unwrap())
    }

    /// The exit status of a winws that ended by itself. One that exits while the checks run is a
    /// launch error too.
    pub fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    /// Kills winws and returns everything it printed.
    pub fn stop(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        let text = self.output_text();
        log::info!(target: "exec", "stopped {} (pid {})\n{text}", self.image, self.child.id());
        text
    }
}

/// Waits for the exit too: the next strategy must not start while this one's WinDivert handle is
/// open.
impl Drop for Winws {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
