//! The TCP side of a running session: the local acceptor, the real destinations recovered with
//! `SO_ORIGINAL_DST`, and the relaying of every accepted connection to its way (the SOCKS5 proxy
//! or, for what the rules leave alone, a direct connection of the hub itself).

use std::io;
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream};
use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::flows::{self, DirectReason, FlowKey, Via};
use crate::nft;
use crate::owner::{self, PID_WAIT};
use crate::rules::Protocol;
use crate::socks::{self, OPEN_TIMEOUT, SocksError};
use crate::tcp;
use crate::{Live, ProxyState};

/// How long a direct way out waits for the server.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// A silently gone client is dropped by TCP keepalives after about 3 minutes.
const KEEPALIVE_SECS: libc::c_int = 120;

impl Live {
    pub(crate) fn domain_of(&self, dst: SocketAddrV4, now: Instant) -> Option<String> {
        self.names
            .lock()
            .unwrap()
            .name_of(*dst.ip(), now)
            .map(str::to_owned)
    }

    /// `rule` is empty for a connection caught by the table that matches no rule now.
    fn open_row(&self, key: FlowKey, rule: &str, exe: Option<&str>, via: Via, now: Instant) {
        let domain = self.domain_of(key.dst, now);
        let mut stats = self.stats.lock().unwrap();
        stats.open(key, rule, via, now);
        if let Some(d) = domain {
            stats.set_domain(key, d);
        }
        if let Some(exe) = exe {
            stats.set_program(key, exe.to_owned());
        }
    }

    /// A connection left alone: its row opens and closes at once.
    fn direct_row(
        &self,
        key: FlowKey,
        rule: &str,
        exe: Option<&str>,
        reason: DirectReason,
        now: Instant,
    ) {
        self.open_row(key, rule, exe, Via::Direct { reason }, now);
        self.stats.lock().unwrap().close(key, now);
    }

    /// The real destination of a redirected connection, the one the client meant to reach
    /// before the nftables `redirect` rewrote it.
    fn original_dst(client: &TcpStream) -> io::Result<SocketAddrV4> {
        let mut addr = libc::sockaddr_in {
            sin_family: 0,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SAFETY: `client` owns a live socket for the call; `addr`/`len` are valid out-pointers
        // of the exact type getsockopt fills.
        let rc = unsafe {
            libc::getsockopt(
                client.as_raw_fd(),
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                (&mut addr as *mut libc::sockaddr_in).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        Ok(SocketAddrV4::new(ip, u16::from_be(addr.sin_port)))
    }

    /// A direct TCP connection that carries the nftables mark, so the router's own table lets
    /// it pass. `false` in the second item says the mark was refused (no `CAP_NET_ADMIN`).
    fn connect_marked(orig: SocketAddrV4, timeout: Duration) -> io::Result<(TcpStream, bool)> {
        // SAFETY: a plain socket() call; the fd is wrapped (and so owned) before any early return.
        let fd = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, owned socket fd; the wrapper takes it over exactly once.
        let sock = unsafe { TcpStream::from_raw_fd(fd) };
        let marked = nft::mark(&sock);
        let sin = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: orig.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(*orig.ip()).to_be(),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: `sin` outlives the call; `fd` is a live socket.
        let rc = unsafe {
            libc::connect(
                fd,
                (&sin as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(err);
            }
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: `pfd` is a valid one-entry poll array for the call.
            let waited = unsafe { libc::poll(&mut pfd, 1, timeout.as_millis() as libc::c_int) };
            if waited <= 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the direct connection timed out",
                ));
            }
            let mut soerr: libc::c_int = 0;
            let mut len = size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: `soerr`/`len` are valid out-pointers of the exact type getsockopt fills.
            unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut soerr as *mut libc::c_int).cast(),
                    &mut len,
                )
            };
            if soerr != 0 {
                return Err(io::Error::from_raw_os_error(soerr));
            }
        }
        sock.set_nonblocking(false)?;
        Ok((sock, marked))
    }

    /// Keepalives drop a client that vanished without a FIN or an RST.
    fn keepalive(stream: &TcpStream) {
        let on: libc::c_int = 1;
        // SAFETY: `stream` owns a live socket for each call; the pointers cover the ints.
        unsafe {
            if libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                (&raw const on).cast(),
                size_of::<libc::c_int>() as u32,
            ) != 0
            {
                return;
            }
            for (opt, value) in [
                (libc::TCP_KEEPIDLE, KEEPALIVE_SECS),
                (libc::TCP_KEEPINTVL, 10),
                (libc::TCP_KEEPCNT, 6),
            ] {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    opt,
                    (&raw const value).cast(),
                    size_of::<libc::c_int>() as u32,
                );
            }
        }
    }

    /// One redirected connection: decide its way from the table, the process behind the client
    /// port and the proxy state, then relay it there.
    pub(crate) fn handle_conn(self: &Arc<Self>, client: TcpStream) {
        let Ok(SocketAddr::V4(peer)) = client.peer_addr() else {
            return tcp::reset(client);
        };
        let Ok(orig) = Self::original_dst(&client) else {
            return tcp::reset(client);
        };
        let port = peer.port();
        let key = FlowKey {
            protocol: Protocol::Tcp,
            local_port: port,
            dst: orig,
        };
        let table = self.table.read().unwrap().clone();
        let pid = self.tcp_owners.pid(port, PID_WAIT, |p| {
            owner::table_pid(Protocol::Tcp, p)
        });
        let exe = pid.and_then(|p| self.images.get(p));
        let exe = exe.as_deref();
        let rule = table
            .matches_flow(Protocol::Tcp, orig, exe)
            .map(str::to_owned);
        let state = self.proxy_state.lock().unwrap().clone();
        let proxy_pid = *self.proxy_pid.lock().unwrap();
        let blocked = flows::decide(&state, pid, std::process::id(), proxy_pid);
        let rule = rule.as_deref().unwrap_or("");
        let mark_ok = self.mark_ok.load(Ordering::Relaxed);
        if let Some(reason) = blocked {
            if matches!(reason, DirectReason::Loop) && !mark_ok {
                // A direct way out would come back to the acceptor: refuse instead of looping.
                return tcp::reset(client);
            }
            return self.direct_flow(key, rule, exe, client, reason);
        }
        if !rule.is_empty() {
            return self.proxy_flow(key, rule, exe, client);
        }
        if mark_ok {
            return self.direct_flow(key, rule, exe, client, DirectReason::NoRule);
        }
        // Nothing says this connection must go direct, and a direct way out is not protected
        // from coming back: the proxy takes it.
        self.proxy_flow(key, rule, exe, client);
    }

    fn direct_flow(
        self: &Arc<Self>,
        key: FlowKey,
        rule: &str,
        exe: Option<&str>,
        client: TcpStream,
        reason: DirectReason,
    ) {
        match Self::connect_marked(key.dst, CONNECT_TIMEOUT) {
            Ok((up, marked)) => {
                if !marked {
                    self.mark_ok.store(false, Ordering::Relaxed);
                }
                self.open_row(key, rule, exe, Via::Direct { reason }, Instant::now());
                let _ = self.pipe_both(key, &client, &up);
                self.end_conn(key);
                self.stats.lock().unwrap().close(key, Instant::now());
            }
            Err(e) => {
                self.direct_row(
                    key,
                    rule,
                    exe,
                    DirectReason::Failed { error: e.to_string() },
                    Instant::now(),
                );
                tcp::reset(client);
            }
        }
    }

    fn proxy_flow(
        self: &Arc<Self>,
        key: FlowKey,
        rule: &str,
        exe: Option<&str>,
        client: TcpStream,
    ) {
        let domain = self.domain_of(key.dst, Instant::now());
        match socks::connect(self.proxy, key.dst, domain.as_deref(), OPEN_TIMEOUT) {
            Ok(up) => {
                self.open_row(key, rule, exe, Via::Proxy, Instant::now());
                let _ = self.pipe_both(key, &client, &up);
                self.end_conn(key);
                self.stats.lock().unwrap().close(key, Instant::now());
            }
            Err(e) => {
                let now = Instant::now();
                // Ruling P6: a refused CONNECT is a failure, not "no UDP".
                let reason = match e {
                    SocksError::Refused(_) => DirectReason::Failed {
                        error: e.to_string(),
                    },
                    _ => DirectReason::from(&e),
                };
                self.direct_row(key, rule, exe, reason, now);
                if matches!(e, SocksError::AuthRequired) {
                    self.set_proxy(ProxyState::AuthRequired);
                }
                tcp::reset(client);
            }
        }
    }

    /// Client to the way out on a new thread, the way out to the client here. An error, a stop
    /// or the session ending shuts both sockets down, which also ends the other direction; after
    /// an EOF the other direction goes on (a half-close).
    fn pipe_both(
        self: &Arc<Self>,
        key: FlowKey,
        client: &TcpStream,
        up: &TcpStream,
    ) -> io::Result<()> {
        Self::keepalive(client);
        Self::keepalive(up);
        self.conns
            .lock()
            .unwrap()
            .insert(key, (client.try_clone()?, up.try_clone()?));
        if self.is_stopped() {
            return Ok(()); // `shut` may have run before the insert
        }
        let (from, to, l, s2) = (client.try_clone()?, up.try_clone()?, self.clone(), self.clone());
        let upload = std::thread::spawn(move || {
            let stop = move || s2.is_stopped();
            let r = tcp::pipe(&from, &to, &stop, &mut |n| {
                l.stats.lock().unwrap().add(key, n, 0, Instant::now());
            });
            if r.is_err() || stop() {
                l.end_conn(key);
            }
        });
        let r = tcp::pipe(up, client, &|| self.is_stopped(), &mut |n| {
            self.stats.lock().unwrap().add(key, 0, n, Instant::now());
        });
        if r.is_err() || self.is_stopped() {
            self.end_conn(key);
        }
        let _ = upload.join();
        Ok(())
    }

    /// Shuts down both sockets of a relayed connection, which unblocks its pipes.
    fn end_conn(&self, key: FlowKey) {
        if let Some((a, b)) = self.conns.lock().unwrap().remove(&key) {
            let _ = a.shutdown(Shutdown::Both);
            let _ = b.shutdown(Shutdown::Both);
            // Its owner lookup must not answer for the next connection on the port.
            let busy = self
                .conns
                .lock()
                .unwrap()
                .keys()
                .any(|k| k.local_port == key.local_port);
            if !busy {
                self.tcp_owners.forget(key.local_port);
            }
        }
    }
}
