pub struct UdpDatagram {
    pub src_port: u16,
    pub dest_port: u16,
    length: u16,
}

impl UdpDatagram {
    pub fn parse(bytes: &[u8]) -> UdpDatagram {
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