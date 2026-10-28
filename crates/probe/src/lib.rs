//! Network checks: `curl.exe` with the arguments `test zapret.ps1` uses, ICMP ping, SOCKS5, and
//! the real-traffic probes: Discord voice UDP, the Discord gateway WebSocket, a YouTube chunk.

pub mod curl;
pub mod discord_voice;
pub mod ping;
pub mod socks;
