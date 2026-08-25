use crate::protocols::transport;

pub struct Ipv6Packet {
    pub version: u8,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_address: [u8; 16],
    pub dst_address: [u8; 16],
    pub transport: transport::Transport,
}

impl Ipv6Packet {
    pub fn parse(bytes: &[u8]) -> Ipv6Packet {
        let version = bytes[0] >> 4;
        let payload_length = u16::from_be_bytes(
            bytes[4..6]
                .try_into()
                .expect("Failed to read payload length"),
        );
        let next_header = bytes[6];
        let hop_limit = bytes[7];
        let src_address = bytes[8..24]
            .try_into()
            .expect("Failed to read source address");
        let dst_address = bytes[24..40]
            .try_into()
            .expect("Failed to read destination address");
        let transport = transport::Transport::parse(next_header, &bytes[40..]);
        Ipv6Packet {
            version,
            payload_length,
            next_header,
            hop_limit,
            src_address,
            dst_address,
            transport
        }
    }
}
