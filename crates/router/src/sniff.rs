//! DNS answers sniffed off the wire with an `AF_PACKET` raw socket (no WinDivert): every
//! interface's IPv4 traffic, minus loopback, where the system stub resolver usually sits.

use std::net::UdpSocket;
use std::os::unix::io::FromRawFd;

/// Ethernet: IPv4.
const ETH_P_IP: u16 = 0x0800;
/// 802.1Q VLAN tagging: one extra header may wrap the IPv4 one.
const ETH_P_VLAN: u16 = 0x8100;

/// A live raw packet socket; dropping it closes the capture.
pub struct Capture {
    socket: UdpSocket,
}

// SAFETY: the fd is owned by `socket` alone, like any `UdpSocket`.
unsafe impl Send for Capture {}

impl Capture {
    /// Opens the capture; `None` when the rights or the address family are missing.
    pub fn open() -> Option<Capture> {
        // SAFETY: a plain socket() call of fixed constants; the fd is wrapped or closed below.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (ETH_P_IP as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return None;
        }
        // SAFETY: `fd` is a fresh, owned socket fd; the wrapper takes it over exactly once.
        let socket = unsafe { UdpSocket::from_raw_fd(fd) };
        socket.set_nonblocking(false).ok()?;
        Some(Capture { socket })
    }

    /// Reads one frame and, when it is an IPv4/UDP DNS answer, returns its payload.
    pub fn dns_answer<'a>(&self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        let n = self.socket.recv(buf).ok()?;
        ip_udp_dns(&buf[..n])
    }
}

/// Splits `frame` into an IPv4/UDP payload with source port 53 (an answer from a resolver).
pub fn ip_udp_dns(frame: &[u8]) -> Option<&[u8]> {
    // The link layer is Ethernet here (AF_PACKET with ETH_P_IP binds to that); a VLAN tag
    // shifts the IPv4 header by 4 bytes.
    let mut at = 14;
    let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    if ethertype == ETH_P_VLAN {
        at += 4;
    } else if ethertype != ETH_P_IP {
        return None;
    }
    let packet = frame.get(at..)?;
    let udp = crate::packet::parse_udp(packet)?;
    (udp.src.port() == 53).then_some(udp.payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    /// An Ethernet frame with an IPv4/UDP packet inside.
    fn frame(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![
            0x45, 0, 0, 0, 0, 1, 0x40, 0, 128, 17, 0, 0, 192, 168, 1, 5, 0, 0, 0, 0,
        ];
        p[16..20].copy_from_slice(&dst.ip().octets());
        p.extend_from_slice(&src.port().to_be_bytes());
        p.extend_from_slice(&dst.port().to_be_bytes());
        p.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        let mut frame = vec![0u8; 6];
        frame.extend_from_slice(&[0xa0, 0x88, 0xb4, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&ETH_P_IP.to_be_bytes());
        frame.extend_from_slice(&p);
        frame
    }

    #[test]
    fn a_dns_answer_frame_yields_its_payload() {
        let src: SocketAddrV4 = "192.168.1.1:53".parse().unwrap();
        let dst: SocketAddrV4 = "192.168.1.5:40000".parse().unwrap();
        let f = frame(src, dst, b"answer");
        assert_eq!(ip_udp_dns(&f), Some(&b"answer"[..]));
    }

    #[test]
    fn queries_and_other_udp_do_not_parse() {
        let src: SocketAddrV4 = "192.168.1.5:40000".parse().unwrap();
        let dst: SocketAddrV4 = "192.168.1.1:53".parse().unwrap();
        let f = frame(src, dst, b"query");
        assert_eq!(ip_udp_dns(&f), None, "port 53 must be the source");

        let arp_only = vec![0xff; 60];
        assert_eq!(ip_udp_dns(&arp_only), None);
        assert_eq!(ip_udp_dns(&[]), None);
    }

    #[test]
    fn a_vlan_tagged_answer_parses() {
        let src: SocketAddrV4 = "192.168.1.1:53".parse().unwrap();
        let dst: SocketAddrV4 = "192.168.1.5:40000".parse().unwrap();
        let f = frame(src, dst, b"answer");
        // Insert an 802.1Q header after the two MAC addresses.
        let mut tagged = f[..12].to_vec();
        tagged.extend_from_slice(&ETH_P_VLAN.to_be_bytes());
        tagged.extend_from_slice(&[0x00, 0x64, 0x08, 0x00]);
        tagged.extend_from_slice(&f[14..]);
        assert_eq!(ip_udp_dns(&tagged), Some(&b"answer"[..]));
    }

    #[test]
    fn opening_the_capture_never_panics() {
        // The result depends on the rights of this process; a miss is fine.
        let _ = Capture::open();
    }
}
