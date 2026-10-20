//! The local socket between `zapret-hub-cli` and the app (CLI spec 4, 5): local only, one request
//! line and one answer line per connection, a thread per client.

use std::fs::{File, Permissions};
use std::io::{self, BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::io::AsRawFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use libc::{EACCES, EAGAIN, ECONNREFUSED, LOCK_EX, LOCK_NB};

use crate::MAX_REQUEST;

/// One per machine, like the zapret service (spec 12, decision 12).
pub const NAME: &str = "/tmp/zapret-hub-cli.sock";

/// SYSTEM and Administrators may do anything, `user` may read and write, nobody else may open it;
/// Medium integrity with no-write-up and no-read-up keeps sandboxed (Low) programs out (spec 5).
pub fn sddl(user: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{user})S:(ML;;NWNR;;;ME)")
}

/// `S-1-5-21-…` of the user this process runs as: keeps the shape the Windows SID had, from the
/// effective uid, so an elevated app still names the user who started it.
pub fn current_user_sid() -> io::Result<String> {
    let uid = unsafe { libc::geteuid() };
    Ok(format!("S-1-5-21-{uid}"))
}

/// The app's end: an exclusive lock on `{name}.lock` keeps a second server out, and the socket
/// file with mode 0600 keeps other users away (spec 5).
pub struct Server {
    _lock: File,
    listener: UnixListener,
}

impl Server {
    /// Fails with os error 5 (EACCES) when another program holds `name` (spec 5).
    pub fn bind(name: &str) -> io::Result<Self> {
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(format!("{name}.lock"))?;
        // SAFETY: a valid fd, the file stays open as long as the `Server` lives.
        if unsafe { libc::flock(lock.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
            let err = io::Error::last_os_error();
            let code = if err.kind() == io::ErrorKind::WouldBlock {
                EACCES
            } else {
                err.raw_os_error().unwrap_or(EACCES)
            };
            return Err(io::Error::from_raw_os_error(code));
        }
        // A crashed server leaves a dead socket file behind.
        let _ = std::fs::remove_file(name);
        let listener = UnixListener::bind(name)?;
        std::fs::set_permissions(name, Permissions::from_mode(0o600))?;
        Ok(Self {
            _lock: lock,
            listener,
        })
    }

    /// Answers clients until `accept` fails, and returns that error. `handler` gets the request
    /// line without its `\n` and returns the answer line. Each client has its own thread: one that
    /// never sends its line holds only that thread (spec 11).
    pub fn serve(self, handler: impl Fn(&[u8]) -> String + Send + Sync + 'static) -> io::Error {
        let handler = Arc::new(handler);
        let listener = self.listener;
        loop {
            let (client, _) = match listener.accept() {
                Ok(client) => client,
                Err(err) => return err,
            };
            let handler = Arc::clone(&handler);
            // No thread to be had: the closure is dropped and closes this client's socket; the
            // next client may get one.
            let _ = std::thread::Builder::new().spawn(move || {
                // An error here means the client went away: nobody to tell.
                let _ = answer(client, &*handler);
            });
        }
    }
}

/// Reads one line, keeping at most `MAX_REQUEST + 1` bytes of it, writes the handler's answer and
/// waits until the client has read it. A line the client never finished reaches no handler.
fn answer(pipe: UnixStream, handler: &impl Fn(&[u8]) -> String) -> io::Result<()> {
    let mut reader = BufReader::new(&pipe);
    let mut line = Vec::new();
    (&mut reader)
        .take(MAX_REQUEST as u64 + 1)
        .read_until(b'\n', &mut line)?;
    if line.last() == Some(&b'\n') {
        line.pop();
    } else if line.len() > MAX_REQUEST {
        // The client writes the rest before it reads: drain it, or both ends wait forever.
        reader.skip_until(b'\n')?;
    } else {
        // The client closed before its `\n`: nobody would read the answer, so nothing runs.
        return Ok(());
    }
    let mut response = handler(&line);
    response.push('\n');
    (&pipe).write_all(response.as_bytes())?;
    (&pipe).flush()
}

/// The CLI's end: sends `line` and returns the answer line. While the backlog is full the socket
/// refuses or would block; that is retried for up to `busy`. An answer without its `\n` is
/// UnexpectedEof.
pub fn request(name: &str, line: &[u8], busy: Duration) -> io::Result<Vec<u8>> {
    let since = Instant::now();
    let pipe = loop {
        match UnixStream::connect(name) {
            Ok(pipe) => break pipe,
            Err(err)
                if matches!(
                    err.raw_os_error(),
                    Some(code) if code == EAGAIN || code == ECONNREFUSED
                ) && since.elapsed() < busy =>
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            opened => break opened?,
        }
    };
    let mut message = line.to_vec();
    message.push(b'\n');
    (&pipe).write_all(&message)?;
    let mut answer = Vec::new();
    BufReader::new(&pipe).read_until(b'\n', &mut answer)?;
    if answer.pop() != Some(b'\n') {
        // The handler failed, or whatever holds the name is not the app.
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the app closed the connection without an answer",
        ));
    }
    Ok(answer)
}
