use pcap::Capture;
use pcap::Device;
use std::usize;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Error: Command unknown or missing. Please provide a valid command.");
        eprintln!("Usage: rustygrab <command> [<args>]");
        eprintln!("Use 'rustygrab help' for more information.");
        return;
    }

    match args[1].as_str() {
        "read" => match args.get(2) {
            Some(file_path) => read_file(file_path),
            None => {
                eprintln!("Error: Missing file path for 'read' command.");
                eprintln!("Usage: rustygrab read <file_path>");
            }
        },
        "live" => match args.get(2) {
            Some(inter_index) => {
                live_capture(inter_index);
            }
            None => list_devices(),
        },
        "help" => help(),
        "version" => version(),
        _ => println!("Unknown command: {}", args[1]),
    }
}

fn version() {
    println!("rustygrab version 0.1.0");
}

fn help() {
    println!("Usage: rustygrab <command> [<args>]");
    println!("Commands:");
    println!("  read <file_path>   Read packets from a file");
    println!("  live               Capture packets live (not implemented yet)");
    println!("  help               Show this help message");
    println!("  version            Show version information");
}

fn list_devices() {
    match Device::list() {
        Ok(devices) => {
            if devices.is_empty() {
                eprintln!("No network devices found for live capture.");
            } else {
                println!("Available network devices:");
                for (i, device) in devices.iter().enumerate() {
                    println!(
                        "#{} - {} - {}",
                        i,
                        device.name,
                        device.desc.clone().unwrap_or("No description".to_string())
                    );
                }
            }
        }
        Err(e) => eprintln!("Error listing network devices: {}", e),
    }
}

fn live_capture(interface: &str) {
    let mut count = 0;
    let index = match interface.parse::<usize>() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("Invalid index provided");
            return;
        }
    };

    let devices = match Device::list() {
        Ok(devices) => devices,
        Err(e) => {
            eprintln!("Error getting network devices: {}", e);
            return;
        }
    };

    let device = match devices.get(index) {
        Some(device) => device,
        None => {
            eprint!("No network interface for index {}", index);
            return;
        }
    };

    let inactive = match Capture::from_device(device.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error getting capture: {}", e);
            return;
        }
    };

    let mut cap = match inactive.promisc(true).timeout(1000).open() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error getting active capture: {}", e);
            return;
        }
    };

    loop {
        match cap.next_packet() {
            Ok(packet) => { 
                let p = Packet::parse(count, packet.data.len() as u32 , packet.data);
                println!("{}",p.summary());
                count += 1;
             }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => { eprintln!("capture error: {}", e); break; }
        }
    }
}

fn read_file(path: &str) {
    let path = std::path::Path::new(path);
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("rustygrab: cannot read '{}': {}", path.display(), e);
            return;
        }
    };

    if data.len() < 24 {
        eprintln!(
            "rustygrab: Invalid file: {} is too small to be a valid file",
            path.display()
        );
        return;
    }

    let magic_le = u32::from_le_bytes(data[0..4].try_into().expect("Failed to read magic number"));

    let endian = match magic_le {
        0xa1b2c3d4 => Endian::Little,
        0xd4c3b2a1 => Endian::Big,
        _ => {
            eprintln!("rustygrab: Not a valid magic number: {:08x}", magic_le);
            return;
        }
    };

    let mut pos = 24;
    let mut count = 0;
    while pos + 16 <= data.len() {
        let data_length;
        let header: [u8; 16] = data[pos..pos + 16]
            .try_into()
            .expect("Failed to read header");
        data_length = endian.read_u32(&header[8..12]);
        if pos + 16 + data_length as usize > data.len() {
            eprintln!(
                "rustygrab: Invalid packet length: {} exceeds file size",
                data_length
            );
            break;
        }
        let packet_data: &[u8] = &data[pos + 16..(pos + 16 + data_length as usize)];
        let packet = Packet::parse(count, data_length, packet_data);
        println!("{}", packet.summary());
        pos += 16 + data_length as usize;
        count += 1;
    }
}

enum Endian {
    Little,
    Big,
}

impl Endian {
    fn read_u32(&self, bytes: &[u8]) -> u32 {
        match self {
            Endian::Little => u32::from_le_bytes(bytes.try_into().expect("Failed to read u32")),
            Endian::Big => u32::from_be_bytes(bytes.try_into().expect("Failed to read u32")),
        }
    }
}

struct Packet {
    count: u32,
    data_length: u32,
    ethernet: Ethernet,
}

impl Packet {
    fn parse(count: u32, data_lenght: u32, bytes: &[u8]) -> Packet {
        Packet {
            count: count,
            data_length: data_lenght,
            ethernet: Ethernet::parse(bytes),
        }
    }

    fn format_mac(mac: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }

    fn summary(&self) -> String {
        match self.ethernet.payload {
            EtherPayload::Ipv4(ref ipv4) => {
                let source_ip = std::net::Ipv4Addr::from(ipv4.src_ip);
                let destination_ip = std::net::Ipv4Addr::from(ipv4.dest_ip);
                let source_port = match ipv4.transport {
                    Transport::Tcp(ref tcp) => tcp.src_port,
                    Transport::Udp(ref udp) => udp.src_port,
                    _ => 0,
                };
                let destination_port = match ipv4.transport {
                    Transport::Tcp(ref tcp) => tcp.dest_port,
                    Transport::Udp(ref udp) => udp.dest_port,
                    _ => 0,
                };
                let protocol = match ipv4.transport {
                    Transport::Tcp(_) => "TCP",
                    Transport::Udp(_) => "UDP",
                    _ => "Other",
                };
                let data_length = self.data_length;
                let flags = match ipv4.transport {
                    Transport::Tcp(ref tcp) => TcpSegment::format_flags(tcp.flags),
                    _ => String::from(""),
                };

                return format!(
                    "#{} {}:{} -> {}:{} {} {} {}",
                    self.count,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                    protocol,
                    flags,
                    data_length
                );
            }
            _ => {
                let source_mac = Self::format_mac(&self.ethernet.src_mac);
                let destination_mac = Self::format_mac(&self.ethernet.dest_mac);
                let ethertype = self.ethernet.ethertype;
                let data_length = self.data_length;

                return format!(
                    "#{} {} -> {} Ethertype: 0x{:04x} {}",
                    self.count, source_mac, destination_mac, ethertype, data_length
                );
            }
        }
    }
}

struct Ethernet {
    dest_mac: [u8; 6],
    src_mac: [u8; 6],
    ethertype: u16,
    payload: EtherPayload,
}

impl Ethernet {
    fn parse(bytes: &[u8]) -> Ethernet {
        let ethertype =
            u16::from_be_bytes(bytes[12..14].try_into().expect("Failed to read ethertype"));
        Ethernet {
            dest_mac: bytes[0..6]
                .try_into()
                .expect("Failed to read destination MAC"),
            src_mac: bytes[6..12].try_into().expect("Failed to read source MAC"),
            ethertype: ethertype,
            payload: EtherPayload::parse(ethertype, &bytes[14..bytes.len()]),
        }
    }
}

enum EtherPayload {
    Ipv4(Ipv4Packet),
    Other(Other),
}

impl EtherPayload {
    fn parse(ethertype: u16, bytes: &[u8]) -> EtherPayload {
        match ethertype {
            0x0800 => EtherPayload::Ipv4(Ipv4Packet::parse(bytes)),
            _ => EtherPayload::Other(Other::parse(bytes)),
        }
    }
}

struct Ipv4Packet {
    version: u8,
    ihl: u8,
    protocol: u8,
    src_ip: u32,
    dest_ip: u32,
    transport: Transport,
}

impl Ipv4Packet {
    fn parse(bytes: &[u8]) -> Ipv4Packet {
        let version = bytes[0] >> 4;
        let ihl = bytes[0] & 0x0F;
        let protocol = bytes[9];
        let src_ip =
            u32::from_be_bytes(bytes[12..16].try_into().expect("Failed to read source IP"));
        let dest_ip = u32::from_be_bytes(
            bytes[16..20]
                .try_into()
                .expect("Failed to read destination IP"),
        );
        let transport_header_start = (ihl * 4) as usize;
        let transport = Transport::parse(protocol, &bytes[transport_header_start..bytes.len()]);
        Ipv4Packet {
            version,
            ihl,
            protocol,
            src_ip,
            dest_ip,
            transport,
        }
    }
}

enum Transport {
    Tcp(TcpSegment),
    Udp(UdpDatagram),
    Other(Other),
}

impl Transport {
    fn parse(protocol: u8, bytes: &[u8]) -> Transport {
        match protocol {
            6 => Transport::Tcp(TcpSegment::parse(bytes)),
            17 => Transport::Udp(UdpDatagram::parse(bytes)),
            _ => Transport::Other(Other::parse(bytes)),
        }
    }
}

struct TcpSegment {
    src_port: u16,
    dest_port: u16,
    flags: u8,
}

impl TcpSegment {
    fn parse(bytes: &[u8]) -> TcpSegment {
        let src_port =
            u16::from_be_bytes(bytes[0..2].try_into().expect("Failed to read source port"));
        let dest_port = u16::from_be_bytes(
            bytes[2..4]
                .try_into()
                .expect("Failed to read destination port"),
        );
        let flags = bytes[13];
        TcpSegment {
            src_port,
            dest_port,
            flags,
        }
    }

    fn format_flags(flags: u8) -> String {
        let mut flag = Vec::new();
        if flags & 0x01 != 0 {
            flag.push("FIN");
        } // FIN
        if flags & 0x02 != 0 {
            flag.push("SYN");
        } // SYN
        if flags & 0x04 != 0 {
            flag.push("RST");
        } // RST
        if flags & 0x08 != 0 {
            flag.push("PSH");
        } // PSH
        if flags & 0x10 != 0 {
            flag.push("ACK");
        } // ACK
        if flags & 0x20 != 0 {
            flag.push("URG");
        } // URG
        if flags & 0x40 != 0 {
            flag.push("ECE");
        } // ECE
        if flags & 0x80 != 0 {
            flag.push("CWR");
        } // CWR
        return format!("{:?}", flag);
    }
}

struct UdpDatagram {
    src_port: u16,
    dest_port: u16,
    length: u16,
}

impl UdpDatagram {
    fn parse(bytes: &[u8]) -> UdpDatagram {
        let src_port =
            u16::from_be_bytes(bytes[0..2].try_into().expect("Failed to read source port"));
        let dest_port = u16::from_be_bytes(
            bytes[2..4]
                .try_into()
                .expect("Failed to read destination port"),
        );
        let length = u16::from_be_bytes(bytes[4..6].try_into().expect("Failed to read length"));
        UdpDatagram {
            src_port,
            dest_port,
            length,
        }
    }
}

struct Other {
    other: Vec<u8>,
}

impl Other {
    fn parse(bytes: &[u8]) -> Other {
        Other {
            other: bytes.to_vec(),
        }
    }
}
