use router::packet::parse_udp;

/// 1.2.3.4:50001 -> 192.168.1.5:61000, payload `hi`.
fn packet() -> Vec<u8> {
    let mut p = vec![
        0x45, 0, 0, 30, 0, 7, 0x40, 0, 64, 17, 0, 0, 1, 2, 3, 4, 192, 168, 1, 5,
    ];
    p.extend_from_slice(&[0xC3, 0x51, 0xEE, 0x48, 0, 10, 0, 0]);
    p.extend_from_slice(b"hi");
    p
}

#[test]
fn a_udp_packet_parses_back_to_its_addresses_and_payload() {
    let p = packet();
    let udp = parse_udp(&p).unwrap();
    assert_eq!(
        (udp.src.to_string(), udp.dst.to_string(), udp.payload),
        (
            "1.2.3.4:50001".into(),
            "192.168.1.5:61000".into(),
            &b"hi"[..]
        )
    );
}

#[test]
fn tcp_fragments_and_short_packets_do_not_parse() {
    let p = packet();
    let mut tcp = p.clone();
    tcp[9] = 6;
    let mut fragment = p.clone();
    fragment[6] = 0x20; // MF
    assert!(parse_udp(&tcp).is_none() && parse_udp(&fragment).is_none());
    assert!(parse_udp(&p[..27]).is_none() && parse_udp(&[0x60; 40]).is_none());
    let mut lying = p.clone();
    lying[3] = 100; // total length past the buffer
    assert!(parse_udp(&lying).is_none());
    let mut cut = p.clone();
    cut[25] = 0xFF; // udp length past the ip total
    assert!(parse_udp(&cut).is_none());
}
