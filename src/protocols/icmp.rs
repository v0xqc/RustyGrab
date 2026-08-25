pub struct IcmpPacket {
    pub icmp_type: u8,
    pub code: u8,
    pub body: IcmpBody

}

pub enum IcmpBody {
    Echo { identifier: u16, sequence: u16},
    Other
}

impl IcmpPacket {
    pub fn parse(bytes: &[u8]) -> IcmpPacket {
        let icmp_type = bytes[0];
        let code = bytes[1];
        let body: IcmpBody = match icmp_type {
            0 | 8 => {IcmpBody::Echo { identifier: (u16::from_be_bytes(bytes[4..6].try_into().expect("Failed to read identifier"))), sequence: (u16::from_be_bytes(bytes[6..8].try_into().expect("Failed to read sequence"))) }}
            _ => IcmpBody::Other
        };
        IcmpPacket { 
            icmp_type,
            code,
            body
            }
    }
}