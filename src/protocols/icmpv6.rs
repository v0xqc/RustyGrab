pub struct Icmpv6Packet {
    pub icmp_type: u8,
    pub code: u8,
    pub body: Icmpv6Body
}

pub enum Icmpv6Body {
    Echo { identifier: u16, sequence: u16},
    Neighbor { target: [u8; 16] },
    Other
}

impl Icmpv6Packet {
    pub fn parse(bytes: &[u8]) -> Icmpv6Packet {
        let icmp_type = bytes[0];
        let code = bytes[1];
        let body: Icmpv6Body = match icmp_type {
            128 | 129 => {Icmpv6Body::Echo { identifier: (u16::from_be_bytes(bytes[4..6].try_into().expect("Failed to read identifier"))), sequence: (u16::from_be_bytes(bytes[6..8].try_into().expect("Failed to read sequence"))) }}
            135 | 136 => {Icmpv6Body::Neighbor { target: (bytes[8..24].try_into().expect("Failed to read target")) }}
            _ => Icmpv6Body::Other
        };
        Icmpv6Packet { 
            icmp_type,
            code,
            body
            }
    }
}