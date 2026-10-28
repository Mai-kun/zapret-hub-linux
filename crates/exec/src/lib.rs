//! Every external program Zapret Hub starts goes through [`run`]: a hard
//! timeout, an optional cancel flag, and one journal entry with the whole output (spec 10).

mod time;

pub use time::LocalTime;

use std::io::Read;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use libc::SIGKILL;

/// What a finished, or killed, program left behind.
#[derive(Debug, Clone)]
pub struct Output {
    /// Program and arguments, as the journal shows them.
    pub command: String,
    /// `None` when the process was killed on timeout or cancel.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub canceled: bool,
    pub elapsed: Duration,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// `self` when the exit code is 0, otherwise an error that carries all of it.
    pub fn check(self) -> anyhow::Result<Self> {
        if self.success() {
            Ok(self)
        } else {
            Err(anyhow::anyhow!(self.describe()))
        }
    }

    /// Command, outcome and both streams, never shortened.
    pub fn describe(&self) -> String {
        let outcome = if self.canceled {
            "canceled".to_owned()
        } else if self.timed_out {
            format!("killed after {} ms (timeout)", self.elapsed.as_millis())
        } else {
            match self.code {
                Some(code) => format!("exit code {code}"),
                None => "no exit code".to_owned(),
            }
        };
        format!(
            "{} -> {outcome}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.command, self.stdout, self.stderr
        )
    }
}

/// A process that inherited the `zapret_bypass` cgroup at fork from an excluded agent leaves it
/// at once: the table's `socket cgroupv2` rule would send this program's whole traffic past
/// nfqws2. The move to the root cgroup succeeds for root or a delegated user; a plain user's
/// failed write is left to the app's own eviction, which runs through `sudo`.
fn leave_bypass_cgroup() {
    let Ok(self_cgroup) = std::fs::read_to_string("/proc/self/cgroup") else {
        return;
    };
    if !self_cgroup.contains("zapret_bypass") {
        return;
    }
    match std::fs::write("/sys/fs/cgroup/cgroup.procs", std::process::id().to_string()) {
        Ok(()) => log::info!(target: "exec", "this process left the zapret_bypass cgroup"),
        Err(err) => log::debug!(target: "exec", "cannot leave zapret_bypass: {err}"),
    }
}

/// Runs `cmd` to the end, or kills it and everything it started after `timeout` or once `cancel`
/// turns true. When `run` returns it has ended every process the program started, so long-lived
/// processes must not be started through it.
pub fn run(
    cmd: &mut Command,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
) -> std::io::Result<Output> {
    leave_bypass_cgroup();
    let command = command_line(cmd);
    let started = Instant::now();
    // Its own process group, so a `killpid(-pid)` ends the forks and grandchildren too.
    let spawned = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(err) => {
            log::error!(target: "exec", "{command} -> failed to start: {err}");
            return Err(err);
        }
    };
    let group_pid = -(child.id() as i32);
    let killpid = |signal: libc::c_int| {
        // SAFETY: the group stays alive while `child` is not reaped, and -pid is just a number.
        let _ = unsafe { libc::kill(group_pid, signal) };
    };
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let (mut timed_out, mut canceled) = (false, false);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        canceled = cancel.is_some_and(|flag| flag.load(Ordering::Relaxed));
        timed_out = started.elapsed() >= timeout;
        if canceled || timed_out {
            killpid(SIGKILL);
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // Whatever the program started and left running keeps the pipes open, and `join` below waiting.
    killpid(SIGKILL);
    let _ = child.wait();
    let output = Output {
        command,
        code: status.and_then(|status| status.code()),
        stdout: decode(&stdout.join().unwrap_or_default()),
        stderr: decode(&stderr.join().unwrap_or_default()),
        timed_out,
        canceled,
        elapsed: started.elapsed(),
    };
    log::info!(target: "exec", "{}", output.describe());
    Ok(output)
}

fn command_line(cmd: &Command) -> String {
    let mut line = cmd.get_program().to_string_lossy().into_owned();
    for arg in cmd.get_args() {
        line.push(' ');
        line.push_str(&arg.to_string_lossy());
    }
    line
}

fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut bytes);
        }
        bytes
    })
}

/// Console programs write UTF-8, UTF-16 (some system tools when redirected) or their legacy
/// single-byte code page; this reads the first two and falls back to lossy UTF-8.
pub fn decode(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16le(rest);
    }
    let odd_zeros = bytes.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
    if bytes.len() >= 4 && bytes.len().is_multiple_of(2) && odd_zeros * 4 > bytes.len() {
        return utf16le(bytes);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16_lossy(&units)
}
