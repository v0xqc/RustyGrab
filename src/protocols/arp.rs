pub struct ArpPacket {
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: u32,
    pub target_mac: [u8; 6],
    pub target_ip: u32,
}

impl ArpPacket {
    pub fn parse(bytes: &[u8]) -> ArpPacket {
        let opcode = u16::from_be_bytes(bytes[6..8].try_into().expect("Failed to read opcode."));
        let sender_mac = bytes[8..14].try_into().expect("Failed to read sender MAC.");
        let sender_ip =
            u32::from_be_bytes(bytes[14..18].try_into().expect("Failed to read sender IP"));
        let target_mac = bytes[18..24]
            .try_into()
            .expect("Failed to read target MAC.");
        let target_ip =
            u32::from_be_bytes(bytes[24..28].try_into().expect("Failed to read target IP."));
        ArpPacket {
            opcode,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }
    }
}
