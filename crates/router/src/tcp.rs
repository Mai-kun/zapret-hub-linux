//! Byte relaying of a proxied connection and the RST-style close.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::io::AsRawFd as _;
use std::time::Duration;

/// Copies `from` into `to` until EOF, then half-closes `to`. Checks `stop` every second while
/// reading; the caller's `stop` should also turn true once the session ended. A write to a peer
/// that does not read blocks: the caller unblocks it with `shutdown(Both)` on both sockets.
pub fn pipe(
    from: &TcpStream,
    to: &TcpStream,
    stop: &dyn Fn() -> bool,
    count: &mut dyn FnMut(u64),
) -> std::io::Result<()> {
    from.set_read_timeout(Some(Duration::from_secs(1)))?;
    let (mut from, mut to) = (from, to);
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) => return to.shutdown(Shutdown::Write),
            Ok(n) => {
                to.write_all(&buf[..n])?;
                count(n as u64);
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if stop() {
                    return Ok(());
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Closes `stream` with a zero linger, so the peer gets an RST.
pub fn reset(stream: TcpStream) {
    // `{l_onoff: 1, l_linger: 0}`: a close sends RST instead of the lingering FIN handshake.
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `stream` owns a live socket for the call; the pointer covers exactly the bytes of
    // `linger`. A failure only leaves the normal close.
    unsafe {
        let _ = libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const linger).cast(),
            size_of::<libc::linger>() as u32,
        );
    }
    drop(stream);
}
