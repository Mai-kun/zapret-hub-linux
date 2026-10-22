//! ICMP echo, like `System.Net.NetworkInformation.Ping.Send(host, 1000)` in `test zapret.ps1`.

use std::net::{SocketAddr, ToSocketAddrs};
use std::process::Command;
use std::time::Duration;

/// Round-trip time in ms; `None` on timeout, error, or a name that does not resolve.
pub fn ping(host: &str, timeout_ms: u32) -> Option<u32> {
    let ip = (host, 0)
        .to_socket_addrs()
        .ok()?
        .find_map(|addr| match addr {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        })?;
    // The system utility does the ICMP work; `-W` only takes whole seconds.
    let timeout_s = (timeout_ms / 1000).max(1).to_string();
    let mut cmd = Command::new("ping");
    cmd.args(["-c", "1", "-W", &timeout_s, "-n", &ip.to_string()]);
    let out = exec::run(
        &mut cmd,
        Duration::from_secs(u64::from(timeout_ms / 1000) + 5),
        None,
    )
    .ok()?;
    if !out.success() {
        return None;
    }
    parse_rtt(&out.stdout)
}

/// `time=4.5 ms` from `ping`'s own line, rounded to whole ms.
pub fn parse_rtt(stdout: &str) -> Option<u32> {
    let line = stdout.lines().find(|line| line.contains("time="))?;
    let time = line.split("time=").nth(1)?;
    let ms = time.split(" ms").next()?;
    ms.trim().parse::<f64>().ok().map(|ms| ms.round() as u32)
}
