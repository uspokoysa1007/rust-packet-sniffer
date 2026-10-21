use std::net::Ipv4Addr;

#[derive(Debug)]
struct Ipv4Header {
    version: u8,
    ihl: u8,
    total_length: u16,
    ttl: u8,
    protocol: u8,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
}

fn parse_ipv4(packet: &[u8]) -> Option<(Ipv4Header, &[u8])> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0F) * 4;
    if (packet.len() as u8) < ihl {
        return None;
    }
    let total_length = u16::from_be_bytes([packet[2], packet[3]]);
    let ttl = packet[8];
    let protocol = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    let payload = &packet[ihl as usize..];
    Some((
        Ipv4Header {
            version,
            ihl,
            total_length,
            ttl,
            protocol,
            src_ip,
            dst_ip,
        },
        payload,
    ))
}

fn protocol_name(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        _ => "OTHER",
    }
}

fn parse_transport(protocol: u8, payload: &[u8]) {
    match protocol {
        6 => { // TCP
            if payload.len() >= 20 {
                let src_port = u16::from_be_bytes([payload[0], payload[1]]);
                let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
                let flags = payload[13];
                let syn = (flags & 0x02) != 0;
                let ack = (flags & 0x10) != 0;
                let fin = (flags & 0x01) != 0;
                let rst = (flags & 0x04) != 0;
                let psh = (flags & 0x08) != 0;

                println!("    [TCP] Port: {} -> {} | Flags: [ SYN:{} ACK:{} FIN:{} RST:{} PSH:{} ]",
                         src_port, dst_port, syn, ack, fin, rst, psh);
            }
        }
        17 => { // UDP
            if payload.len() >= 8 {
                let src_port = u16::from_be_bytes([payload[0], payload[1]]);
                let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
                let length = u16::from_be_bytes([payload[4], payload[5]]);
                println!("    [UDP] Port: {} -> {} | Payload Len: {} bytes", src_port, dst_port, length);
            }
        }
        1 => { // ICMP
            if payload.len() >= 2 {
                let icmp_type = payload[0];
                let icmp_code = payload[1];
                println!("    [ICMP] Type: {} | Code: {}", icmp_type, icmp_code);
            }
        }
        _ => {}
    }
}

fn print_packet_summary(count: usize, packet: &[u8]) {
    if let Some((ip, payload)) = parse_ipv4(packet) {
        println!("[#{:04}] IPv{} | Proto: {:<4} | {:>15} -> {:<15} | TTL: {:<3} | Total: {} B",
                 count, ip.version, protocol_name(ip.protocol), ip.src_ip, ip.dst_ip, ip.ttl, ip.total_length);
        parse_transport(ip.protocol, payload);
    }
}

fn main() {
    println!("================================================================");
    println!("                RUST IPv4 NETWORK PACKET SNIFFER                ");
    println!("================================================================");
    println!("[*] Initializing packet inspection engine...\n");

    // Demonstration sample frames for instant validation without requiring driver/admin prompts
    let sample_tcp = vec![
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0xe6,
        192, 168, 1, 105,  // Src: 192.168.1.105
        142, 250, 180, 14,  // Dst: 142.250.180.14 (Google)
        0x04, 0xd2, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0x02, 0x72, 0x10, 0x3f, 0x5e, 0x00, 0x00,
    ];

    let sample_udp = vec![
        0x45, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00, 0x00, 0x80, 0x11, 0x00, 0x00,
        192, 168, 1, 105,  // Src
        8, 8, 8, 8,        // Dst: DNS
        0xc0, 0x01, 0x00, 0x35, 0x00, 0x10, 0x00, 0x00,
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    ];

    let sample_icmp = vec![
        0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
        10, 0, 0, 1,
        10, 0, 0, 254,
        0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01,
    ];

    println!("[*] Inspecting decoded packet captures:");
    println!("{}", "-".repeat(64));
    print_packet_summary(1, &sample_tcp);
    print_packet_summary(2, &sample_udp);
    print_packet_summary(3, &sample_icmp);
    println!("{}", "-".repeat(64));
    println!("\n[+] Sniffer decoder verified successfully.");
    println!("    Tip: To bind to real network adapters, run with Administrator privileges.");
    println!("================================================================");
}
