//! IPv4/UDP packet parsing (the DNS sniffer reads answers out of raw frames).

use std::net::{Ipv4Addr, SocketAddrV4};

pub struct Udp<'a> {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub payload: &'a [u8],
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// Unfragmented IPv4/UDP only; lengths must agree with the buffer.
pub fn parse_udp(packet: &[u8]) -> Option<Udp<'_>> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0F) * 4;
    let total = usize::from(be16(packet, 2));
    if ihl < 20 || total > packet.len() || total < ihl + 8 || be16(packet, 6) & 0x3FFF != 0 {
        return None;
    }
    let udp_len = usize::from(be16(packet, ihl + 4));
    if udp_len < 8 || ihl + udp_len > total {
        return None;
    }
    let addr = |at: usize, port_at: usize| {
        SocketAddrV4::new(
            Ipv4Addr::new(packet[at], packet[at + 1], packet[at + 2], packet[at + 3]),
            be16(packet, port_at),
        )
    };
    Some(Udp {
        src: addr(12, ihl),
        dst: addr(16, ihl + 2),
        payload: &packet[ihl + 8..ihl + udp_len],
    })
}
