use crate::protocols::{transport};

pub struct Ipv4Packet {
    version: u8,
    ihl: u8,
    protocol: u8,
    pub src_ip: u32,
    pub dest_ip: u32,
    pub transport: transport::Transport,
}

impl Ipv4Packet {
    pub fn parse(bytes: &[u8]) -> Ipv4Packet {
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
        let transport = transport::Transport::parse(protocol, &bytes[transport_header_start..bytes.len()]);
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