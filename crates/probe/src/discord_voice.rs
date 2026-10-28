//! The real-traffic probes: Discord voice UDP (IP discovery), the Discord gateway WebSocket and
//! a YouTube video chunk — the protocols a passing HTTP check says nothing about.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs as _, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// The Discord IP-discovery packet is exactly 70 bytes: type, length, SSRC, then zeros.
pub const DISCOVERY_PACKET_LEN: usize = 70;
/// The well-known voice relays of Discord, in the order they are tried: one resolves, that one
/// is the target (`*.discord.media` is the voice SRV domain of the voice gateway).
const VOICE_HOSTS: [&str; 4] = [
    "rotterdam.discord.media",
    "frankfurt.discord.media",
    "tokyo.discord.media",
    "singapore.discord.media",
];
/// Voice relays answer IP discovery on the ports of the 50000–65535 range the client was given;
/// the two the web client sees most are probed first.
const DISCOVERY_PORTS: [u16; 2] = [50001, 50000];
/// The Discord gateway the web client opens first, before any voice.
const GATEWAY_HOST: &str = "gateway.discord.gg";
const GATEWAY_PATH: &str = "/?v=9&encoding=json";
/// The WebSocket frame opcodes a JSON gateway session may open with: text for `encoding=json`.
const WS_OPCODE_TEXT: u8 = 0x01;
const WS_OPCODE_BINARY: u8 = 0x02;
/// Discord's gateway op code of the `Hello` message, inside the frame's JSON payload.
const WS_GATEWAY_HELLO: u64 = 10;
/// The range request of the chunk check: exactly 128 KiB of a video.
pub const CHUNK_BYTES: u32 = 131_072;
/// The window where ТСПУ freezes the video: the first 16–20 KiB pass, then silence.
pub const STALL_MIN_BYTES: u32 = 16 * 1024;
pub const STALL_MAX_BYTES: u32 = 20 * 1024;
/// A video the check asks the player API about: public, old, and never taken down.
pub const SAMPLE_VIDEO_ID: &str = "dQw4w9WgXcQ";

// --- Discord voice UDP ----------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub enum VoiceStatus {
    /// The relay echoed the discovery packet back with the outside address.
    Ok,
    /// No reply came: the packets are dropped (ТСПУ, a firewall) or the relay is down.
    Timeout,
    /// The relay refused the datagram: a UDP port the relay does not listen on.
    Refused,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct VoiceCheckResult {
    pub status: VoiceStatus,
    /// The voice relay the packet went to.
    pub endpoint: String,
    pub port: u16,
    pub time_ms: Option<u32>,
    /// The outside address the relay saw, when it answered.
    pub external_ip: Option<String>,
    pub external_port: Option<u16>,
    pub detail: String,
}

/// A pseudo-random SSRC without a `rand` dependency: the nanoseconds of the clock mixed with the
/// process id. The relay only echoes it back, nothing depends on its quality.
fn ssrc() -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.subsec_nanos() ^ (t.as_secs() as u32))
        .unwrap_or(0x5353_5243); // "SSRC"
    nanos ^ std::process::id()
}

/// The standard 70-byte Discord IP-discovery request: `0x00 0x01` (Request), `0x00 0x46` (70),
/// the SSRC, then 62 zero bytes.
pub fn discovery_packet(ssrc: u32) -> [u8; DISCOVERY_PACKET_LEN] {
    let mut packet = [0u8; DISCOVERY_PACKET_LEN];
    packet[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Request
    packet[2..4].copy_from_slice(&(DISCOVERY_PACKET_LEN as u16).to_be_bytes()); // 70
    packet[4..8].copy_from_slice(&ssrc.to_be_bytes());
    packet
}

/// `(ip, port)` of a discovery reply, or `None` when the bytes are not one. The reply is
/// `0x00 0x02` (Response), 70 again, the SSRC echo, then the address: the current servers send it
/// as a null-terminated ASCII string, the older ones as raw IPv4 bytes — both are handled.
pub fn parse_discovery_reply(reply: &[u8]) -> Option<(String, u16)> {
    if reply.len() != DISCOVERY_PACKET_LEN || reply[0] != 0x00 || reply[1] != 0x02 {
        return None;
    }
    let address = &reply[8..68];
    let ip = if address[..4].iter().all(|b| b.is_ascii_digit() || *b == b'.') {
        let end = address
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(address.len());
        String::from_utf8_lossy(&address[..end]).into_owned()
    } else {
        format!("{}.{}.{}.{}", address[0], address[1], address[2], address[3])
    };
    let port = u16::from_be_bytes([reply[68], reply[69]]);
    let parsed = ip.parse::<std::net::Ipv4Addr>().is_ok();
    parsed.then_some((ip, port))
}

/// One IP-discovery request of `endpoint:port`: the packet goes out, the reply tells what the
/// relay sees as this machine's outside address. `Timeout` is the picture ТСПУ leaves.
pub fn check_discord_udp(endpoint: &str, port: u16, timeout: Duration) -> VoiceCheckResult {
    let started = Instant::now();
    let mut result = udp_attempt(endpoint, port, timeout);
    result.time_ms = Some(elapsed_ms(started));
    result
}

fn udp_attempt(endpoint: &str, port: u16, timeout: Duration) -> VoiceCheckResult {
    let miss = |status: VoiceStatus, detail: String| VoiceCheckResult {
        status,
        endpoint: endpoint.to_owned(),
        port,
        time_ms: None,
        external_ip: None,
        external_port: None,
        detail,
    };
    let Ok(mut addrs) = (endpoint, port).to_socket_addrs() else {
        return miss(VoiceStatus::Error, format!("{endpoint} does not resolve"));
    };
    let Some(target) = addrs.find(|addr| addr.is_ipv4()) else {
        return miss(VoiceStatus::Error, format!("{endpoint} has no IPv4 address"));
    };
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return miss(VoiceStatus::Error, "cannot bind a UDP socket".to_owned());
    };
    let _ = socket.set_read_timeout(Some(timeout));
    let _ = socket.set_write_timeout(Some(timeout));
    if let Err(err) = socket.connect(target) {
        return miss(VoiceStatus::Error, format!("{target}: {err}"));
    }
    if let Err(err) = socket.send(&discovery_packet(ssrc())) {
        return miss(VoiceStatus::Error, format!("the packet did not go out: {err}"));
    }
    let mut reply = [0u8; DISCOVERY_PACKET_LEN];
    match socket.recv(&mut reply) {
        Ok(len) => match parse_discovery_reply(&reply[..len]) {
            Some((ip, port)) => VoiceCheckResult {
                status: VoiceStatus::Ok,
                endpoint: endpoint.to_owned(),
                port,
                time_ms: None,
                external_ip: Some(ip),
                external_port: Some(port),
                detail: "the voice relay answered with the outside address".to_owned(),
            },
            None => miss(
                VoiceStatus::Error,
                format!("the answer of {len} bytes is not an IP-discovery reply"),
            ),
        },
        Err(err) => match err.kind() {
            ErrorKind::WouldBlock | ErrorKind::TimedOut => miss(
                VoiceStatus::Timeout,
                "no reply: the discovery packet or its answer is dropped (ТСПУ or a firewall)"
                    .to_owned(),
            ),
            ErrorKind::ConnectionRefused => miss(
                VoiceStatus::Refused,
                "the relay refused the datagram: nobody listens on this port".to_owned(),
            ),
            _ => miss(VoiceStatus::Error, err.to_string()),
        },
    }
}

/// The well-known voice relays and their two usual ports, one after another: the first `Ok`
/// stops the walk; when nothing answers, the last `Timeout` is the answer. The relay hostnames
/// are handed out per voice session, so when none of the well-known ones resolves the result is
/// `Error` with that explanation — not a verdict about the provider.
pub fn check_discord_udp_any(timeout: Duration) -> VoiceCheckResult {
    let mut last = None;
    for host in VOICE_HOSTS {
        for port in DISCOVERY_PORTS {
            let result = check_discord_udp(host, port, timeout);
            if result.status == VoiceStatus::Ok {
                return result;
            }
            if result.status != VoiceStatus::Error {
                last = Some(result); // a refused or silent relay is worth keeping, a dead DNS is not
            }
        }
    }
    last.unwrap_or_else(|| VoiceCheckResult {
        status: VoiceStatus::Error,
        endpoint: VOICE_HOSTS[0].to_owned(),
        port: DISCOVERY_PORTS[0],
        time_ms: None,
        external_ip: None,
        external_port: None,
        detail: "no known voice relay resolves: Discord hands out the *.discord.media endpoint \
                 per voice session, so run the check again while a Discord voice channel is open"
            .to_owned(),
    })
}

// --- Discord gateway WebSocket --------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub enum WsStatus {
    /// The gateway switched protocols and sent its `Hello`.
    Ok,
    /// The connection died mid-handshake with a reset: what ТСПУ does to a WebSocket it dislikes.
    Reset,
    /// Nothing came within the deadline.
    Timeout,
    /// The TLS handshake failed.
    Tls,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct WsCheckResult {
    pub status: WsStatus,
    pub url: String,
    pub time_ms: Option<u32>,
    /// `heartbeat_interval` of the `Hello` frame, in ms — the proof a real gateway answered.
    pub heartbeat_interval_ms: Option<u32>,
    pub detail: String,
}

/// `wss://gateway.discord.gg/?v=9&encoding=json` over TLS: the upgrade, then the `Hello`
/// (gateway op 10) with `heartbeat_interval`, all within `timeout`. A reset on the way is
/// recorded as `Reset`.
pub fn check_discord_websocket(timeout: Duration) -> WsCheckResult {
    let started = Instant::now();
    let url = format!("wss://{GATEWAY_HOST}{GATEWAY_PATH}");
    match ws_attempt(timeout) {
        Ok(interval) => WsCheckResult {
            status: WsStatus::Ok,
            url,
            time_ms: Some(elapsed_ms(started)),
            heartbeat_interval_ms: interval,
            detail: format!(
                "the gateway sent Hello{}",
                interval
                    .map(|ms| format!(" (heartbeat every {ms} ms)"))
                    .unwrap_or_default()
            ),
        },
        Err((status, detail)) => WsCheckResult {
            status,
            url,
            time_ms: Some(elapsed_ms(started)),
            heartbeat_interval_ms: None,
            detail,
        },
    }
}

fn ws_attempt(timeout: Duration) -> Result<Option<u32>, (WsStatus, String)> {
    let addr = (GATEWAY_HOST, 443)
        .to_socket_addrs()
        .map_err(|err| (WsStatus::Error, format!("{GATEWAY_HOST} does not resolve: {err}")))?
        .find(|addr| addr.is_ipv4())
        .ok_or((
            WsStatus::Error,
            format!("{GATEWAY_HOST} has no IPv4 address"),
        ))?;
    let stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|err| (ws_io_status(&err), err.to_string()))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = GATEWAY_HOST
        .try_into()
        .map_err(|err| (WsStatus::Tls, format!("the server name does not parse: {err}")))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|err| (WsStatus::Tls, format!("TLS handshake: {err}")))?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    // The handshake runs on the first write; from here every error is an I/O one.
    let request = format!(
        "GET {GATEWAY_PATH} HTTP/1.1\r\n\
         Host: {GATEWAY_HOST}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n",
        ws_key()
    );
    tls.write_all(request.as_bytes())
        .map_err(|err| (ws_io_status(&err), err.to_string()))?;
    // The 101 answer's headers, up to the empty line.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let read = tls.read(&mut byte).map_err(|err| (ws_io_status(&err), err.to_string()))?;
        if read == 0 {
            return Err((
                WsStatus::Reset,
                "the connection closed in the middle of the upgrade".to_owned(),
            ));
        }
        head.push(byte[0]);
        if head.len() > 16 * 1024 {
            return Err((WsStatus::Error, "the gateway's headers are too long".to_owned()));
        }
    }
    let head = String::from_utf8_lossy(&head);
    let code = head.split_whitespace().nth(1).unwrap_or("");
    if code != "101" {
        return Err((
            WsStatus::Error,
            format!("the gateway answered {code} instead of switching protocols"),
        ));
    }
    // The first server frame carries the `Hello`: a text (or binary) WebSocket frame whose JSON
    // payload holds Discord's op code 10 and the `heartbeat_interval`.
    let (opcode, payload) = ws_frame(&mut tls)?;
    if opcode != WS_OPCODE_TEXT && opcode != WS_OPCODE_BINARY {
        return Err((
            WsStatus::Error,
            format!("the gateway opened with frame opcode {opcode} instead of a Hello message"),
        ));
    }
    let text = String::from_utf8_lossy(&payload);
    let op = json_number(&text, "op");
    if op != Some(WS_GATEWAY_HELLO) {
        return Err((
            WsStatus::Error,
            format!(
                "the gateway opened with op {:?} instead of Hello ({WS_GATEWAY_HELLO})",
                op.map(|op| op.to_string()).unwrap_or_else(|| "?".to_owned())
            ),
        ));
    }
    Ok(json_number(&text, "heartbeat_interval").map(|interval| interval as u32))
}

/// The first integer after `"key":` of a JSON text, or `None`.
fn json_number(text: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let rest = text.split(&needle).nth(1)?;
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

/// One server frame of `(opcode, payload)`: the 2-byte header, an optional extended length,
/// no masking (servers never mask). Errors keep the reset/timeout classification.
fn ws_frame(tls: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>) -> Result<(u8, Vec<u8>), (WsStatus, String)> {
    let mut header = [0u8; 2];
    tls.read_exact(&mut header).map_err(|err| (ws_io_status(&err), err.to_string()))?;
    let opcode = header[0] & 0x0F;
    let len7 = usize::from(header[1] & 0x7F);
    let len = match len7 {
        126 => {
            let mut ext = [0u8; 2];
            tls.read_exact(&mut ext).map_err(|err| (ws_io_status(&err), err.to_string()))?;
            u16::from_be_bytes(ext) as usize
        }
        127 => {
            let mut ext = [0u8; 8];
            tls.read_exact(&mut ext).map_err(|err| (ws_io_status(&err), err.to_string()))?;
            u64::from_be_bytes(ext) as usize
        }
        len => len,
    };
    let mut payload = vec![0u8; len];
    tls.read_exact(&mut payload).map_err(|err| (ws_io_status(&err), err.to_string()))?;
    Ok((opcode, payload))
}

fn ws_io_status(err: &std::io::Error) -> WsStatus {
    match err.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => WsStatus::Timeout,
        ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe
        | ErrorKind::UnexpectedEof => WsStatus::Reset,
        _ => WsStatus::Error,
    }
}

/// `Sec-WebSocket-Key`: base64 of 16 timestamp-derived bytes (the server only needs a well-formed
/// key, the session is never continued).
fn ws_key() -> String {
    let mut bytes = [0u8; 16];
    for (i, chunk) in bytes.chunks_mut(4).enumerate() {
        chunk.copy_from_slice(&ssrc().wrapping_add(i as u32).to_le_bytes());
    }
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(24);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        out.push(ALPHABET[(b[0] >> 2) as usize] as char);
        out.push(ALPHABET[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b[1] & 0x0F) << 2) | (b[2] >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { ALPHABET[(b[2] & 0x3F) as usize] as char } else { '=' });
    }
    out
}

fn elapsed_ms(started: Instant) -> u32 {
    started.elapsed().as_millis().min(u32::MAX as u128) as u32
}

// --- YouTube video chunk --------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub enum YoutubeStreamStatus {
    /// 128 KiB of the video came through.
    Ok,
    /// The transfer froze inside the 16–20 KiB window and died on the timeout — the ТСПУ stall.
    DpiStall,
    /// Nothing was delivered at all.
    Timeout,
    /// The video server refused the range (a code of 4xx/5xx).
    Blocked,
    /// The player API gave no URL to download from.
    UrlUnavailable,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct YoutubeStreamResult {
    pub status: YoutubeStreamStatus,
    /// The `%{http_code}` of the chunk request (`000` when nothing answered).
    pub http_code: String,
    pub downloaded_bytes: u32,
    /// The download speed of the chunk, KB/s; `None` when nothing was delivered or no time printed.
    pub speed_kbps: Option<u32>,
    pub time_ms: Option<u32>,
    /// The video host the chunk came from, when one was reached.
    pub host: Option<String>,
    pub detail: String,
}

/// A real video chunk: the player API names a `*.googlevideo.com` URL when it can, then curl
/// fetches exactly `CHUNK_BYTES` of it with `--range 0-131071`. A transfer that dies inside the
/// 16–20 KiB window is the ТСПУ stall the verdicts name. The player API answers plain curl
/// rarely (a proof-of-origin token is asked these days), so the fallback chunk comes from
/// Google's own CDN host — the transfer and the stall behaviour stay real, only the host is
/// not a voice of googlevideo.
pub const FALLBACK_CHUNK_URL: &str =
    "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb";

pub fn check_youtube_stream(cancel: Option<&AtomicBool>, video_id: &str, timeout: Duration) -> YoutubeStreamResult {
    let started = Instant::now();
    let (url, host, note) = match stream_url(video_id, cancel) {
        Some((url, host)) => (url, host, String::new()),
        None => (
            FALLBACK_CHUNK_URL.to_owned(),
            "dl.google.com".to_owned(),
            "the player API gave no googlevideo URL (a proof-of-origin token is asked these \
             days), so the chunk came from the fallback CDN host. "
                .to_owned(),
        ),
    };
    let mut cmd = std::process::Command::new("curl");
    cmd.args([
        "-s",
        "--show-error",
        "--range",
        &format!("0-{}", CHUNK_BYTES - 1),
        "--connect-timeout",
        "5",
        "-m",
        &timeout.as_secs().max(1).to_string(),
        "-o",
        "/dev/null",
        "-w",
        "%{http_code} %{size_download} %{time_total} %{speed_download}",
    ])
    .arg(&url);
    let (exit, text) = match exec::run(&mut cmd, timeout + Duration::from_secs(5), cancel) {
        Ok(out) => (out.code, format!("{}{}", out.stdout, out.stderr)),
        Err(err) => (None, err.to_string()),
    };
    let (http_code, downloaded, speed_kbps) = parse_w4(&text);
    let status = classify_stream(exit, downloaded, &http_code);
    let detail = format!(
        "{note}{}",
        match status {
            YoutubeStreamStatus::Ok => {
                format!("{downloaded} of {CHUNK_BYTES} bytes came through from {host}")
            }
            YoutubeStreamStatus::DpiStall => format!(
                "the transfer froze at {downloaded} bytes (inside the 16–20 KiB window) and \
                 died on the timeout: the classic ТСПУ video stall"
            ),
            YoutubeStreamStatus::Timeout => {
                "the chunk did not start: nothing was delivered within the deadline".to_owned()
            }
            YoutubeStreamStatus::Blocked => {
                format!("the video server refused the range ({http_code})")
            }
            YoutubeStreamStatus::Error => format!("curl failed: {text}"),
            YoutubeStreamStatus::UrlUnavailable => String::new(),
        }
    );
    YoutubeStreamResult {
        status,
        http_code,
        downloaded_bytes: downloaded,
        speed_kbps,
        time_ms: Some(elapsed_ms(started)),
        host: Some(host),
        detail,
    }
}

/// The verdict of the chunk transfer: pure, so the tests hold it without a network. A partial
/// transfer that died is the ТСПУ stall inside the 16–20 KiB window; outside it, and with
/// nothing delivered at all, an ordinary timeout.
pub fn classify_stream(exit: Option<i32>, downloaded: u32, http_code: &str) -> YoutubeStreamStatus {
    let refused = http_code
        .split_once('-')
        .and_then(|(major, _)| major.parse::<u32>().ok())
        .or_else(|| http_code.parse().ok())
        .is_some_and(|code| (400..600).contains(&code));
    if exit == Some(0) && downloaded > 0 {
        YoutubeStreamStatus::Ok
    } else if downloaded == 0 && refused {
        YoutubeStreamStatus::Blocked
    } else if downloaded == 0 {
        YoutubeStreamStatus::Timeout
    } else if (STALL_MIN_BYTES..=STALL_MAX_BYTES).contains(&downloaded) {
        YoutubeStreamStatus::DpiStall
    } else {
        YoutubeStreamStatus::Timeout
    }
}

/// `"206 131072 0.512000 256000.000"` → (`"206"`, `131072`, `250`): the `-w` fields of the chunk
/// request; `None` when curl printed no numbers.
fn parse_w4(text: &str) -> (String, u32, Option<u32>) {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let [code, downloaded, _time, speed] = parts[..] else {
        return ("000".to_owned(), 0, None);
    };
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return ("000".to_owned(), 0, None);
    }
    let kbps = speed
        .parse::<f64>()
        .ok()
        .map(|s| (s / 1024.0).round() as u32);
    (
        code.to_owned(),
        downloaded.parse().unwrap_or(0),
        kbps.filter(|k| *k > 0),
    )
}

/// `(url, host)` of a playable format from the YouTube player API: the ANDROID client first
/// (its URLs need no deciphering), the WEB one after. `None` when neither answers with a URL.
fn stream_url(video_id: &str, cancel: Option<&AtomicBool>) -> Option<(String, String)> {
    const CLIENTS: [&str; 2] = ["ANDROID", "WEB"];
    for client in CLIENTS {
        let body = match client {
            "ANDROID" => json_body(
                video_id,
                r#"{"clientName":"ANDROID","clientVersion":"19.09.37","androidSdkVersion":30,"hl":"en"}"#,
            ),
            _ => json_body(
                video_id,
                r#"{"clientName":"WEB","clientVersion":"2.20240726.00.00","hl":"en"}"#,
            ),
        };
        let mut cmd = std::process::Command::new("curl");
        cmd.args([
            "-s",
            "-m",
            "10",
            "--connect-timeout",
            "5",
            "-H",
            "Content-Type: application/json",
            "--data",
            &body,
        ])
        .arg("https://www.youtube.com/youtubei/v1/player");
        let answer = exec::run(&mut cmd, Duration::from_secs(15), cancel)
            .ok()
            .and_then(|out| serde_json::from_str::<serde_json::Value>(&out.stdout).ok())
            .and_then(|value| {
                let url = value["streamingData"]["formats"]
                    .as_array()?
                    .iter()
                    .filter_map(|format| format["url"].as_str())
                    .find(|url| url.contains("googlevideo.com"))?
                    .to_owned();
                let host = url
                    .split(['/', '?'])
                    .find(|part| part.contains("googlevideo.com"))
                    .unwrap_or("googlevideo.com")
                    .to_owned();
                Some((url, host))
            });
        if let Some((url, host)) = answer {
            return Some((url, host));
        }
        // This client gave nothing: the next one may still answer.
    }
    None
}

fn json_body(video_id: &str, client: &str) -> String {
    format!(
        r#"{{"videoId":"{video_id}","context":{{"client":{client}}},"contentCheckOk":true,"racyCheckOk":true}}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_discovery_packet_is_70_bytes_with_the_type_length_and_ssrc() {
        let packet = discovery_packet(0x01020304);
        assert_eq!(packet.len(), 70);
        assert_eq!(&packet[0..4], &[0x00, 0x01, 0x00, 0x46]);
        assert_eq!(&packet[4..8], &[0x01, 0x02, 0x03, 0x04]);
        assert!(packet[8..].iter().all(|b| *b == 0));
    }

    #[test]
    fn a_reply_with_an_ascii_address_parses() {
        let mut reply = [0u8; 70];
        reply[0] = 0x00;
        reply[1] = 0x02;
        reply[8..19].copy_from_slice(b"203.0.113.9");
        reply[68..70].copy_from_slice(&50001u16.to_be_bytes());
        assert_eq!(
            parse_discovery_reply(&reply),
            Some(("203.0.113.9".to_owned(), 50001))
        );
    }

    #[test]
    fn a_reply_with_raw_address_bytes_parses() {
        let mut reply = [0u8; 70];
        reply[0] = 0x00;
        reply[1] = 0x02;
        reply[8..12].copy_from_slice(&[198, 51, 100, 7]);
        reply[68..70].copy_from_slice(&[0xC3, 0x51]); // port 50001, big-endian
        assert_eq!(
            parse_discovery_reply(&reply),
            Some(("198.51.100.7".to_owned(), 0xC351))
        );
    }

    #[test]
    fn a_wrong_type_or_length_is_not_a_reply() {
        let mut reply = [0u8; 70];
        reply[1] = 0x01; // Request, not Response
        assert_eq!(parse_discovery_reply(&reply), None);
        assert_eq!(parse_discovery_reply(&reply[..69]), None);
        let mut short = [0u8; 69];
        short[1] = 0x02;
        assert_eq!(parse_discovery_reply(&short), None);
    }

    #[test]
    fn the_stall_verdict_fires_only_inside_the_window() {
        // A full chunk on success, whatever the code says.
        assert_eq!(
            classify_stream(Some(0), CHUNK_BYTES, "206"),
            YoutubeStreamStatus::Ok
        );
        // 16–20 KiB and a failure: the ТСПУ stall.
        for bytes in [STALL_MIN_BYTES, 18 * 1024, STALL_MAX_BYTES] {
            assert_eq!(
                classify_stream(None, bytes, "206"),
                YoutubeStreamStatus::DpiStall,
                "{bytes} bytes"
            );
        }
        // Outside the window the same failure is an ordinary timeout.
        assert_eq!(
            classify_stream(None, 15 * 1024, "206"),
            YoutubeStreamStatus::Timeout
        );
        assert_eq!(
            classify_stream(None, 21 * 1024, "206"),
            YoutubeStreamStatus::Timeout
        );
        // Nothing at all: refused by code, otherwise timed out.
        assert_eq!(
            classify_stream(Some(0), 0, "403"),
            YoutubeStreamStatus::Blocked
        );
        assert_eq!(
            classify_stream(None, 0, "000"),
            YoutubeStreamStatus::Timeout
        );
    }

    #[test]
    fn the_chunk_metrics_come_from_the_four_w_fields() {
        assert_eq!(
            parse_w4("206 131072 0.512000 256000.000"),
            ("206".to_owned(), 131_072, Some(250))
        );
        assert_eq!(parse_w4("000 0 0 0"), ("000".to_owned(), 0, None));
        assert_eq!(parse_w4("curl: (28) Operation timed out"), ("000".to_owned(), 0, None));
    }

    #[test]
    fn the_player_api_body_names_the_video_and_the_client() {
        let body = json_body("abc123", r#"{"clientName":"WEB","clientVersion":"2.0"}"#);
        assert!(body.contains(r#""videoId":"abc123""#));
        assert!(body.contains(r#""clientName":"WEB""#));
    }

    #[test]
    fn the_websocket_key_is_well_formed_base64() {
        let key = ws_key();
        assert_eq!(key.len(), 24);
        assert_eq!(&key[22..], "==");
        assert!(key[..22].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/'));
        // The keys differ while the clock moves.
        assert_ne!(ws_key(), ws_key());
    }

    #[test]
    fn a_hello_payload_names_the_gateway_op_and_the_heartbeat() {
        let hello = r#"{"t":null,"s":null,"op":10,"d":{"heartbeat_interval":41250,"_trace":["le-e5"]}}"#;
        assert_eq!(json_number(hello, "op"), Some(10));
        assert_eq!(json_number(hello, "heartbeat_interval"), Some(41250));
        assert_eq!(json_number(hello, "absent"), None);
        assert_eq!(json_number(r#"{"op":"x"}"#, "op"), None);
    }
}
