pub struct TcpSegment {
    pub src_port: u16,
    pub dest_port: u16,
    pub flags: u8,
}

impl TcpSegment {
    pub fn parse(bytes: &[u8]) -> TcpSegment {
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

    pub fn format_flags(flags: u8) -> String {
        let mut flag = Vec::new();
        if flags & 0x01 != 0 {
            flag.push("FIN");
        }
        if flags & 0x02 != 0 {
            flag.push("SYN");
        }
        if flags & 0x04 != 0 {
            flag.push("RST");
        }
        if flags & 0x08 != 0 {
            flag.push("PSH");
        }
        if flags & 0x10 != 0 {
            flag.push("ACK");
        }
        if flags & 0x20 != 0 {
            flag.push("URG");
        }
        if flags & 0x40 != 0 {
            flag.push("ECE");
        }
        if flags & 0x80 != 0 {
            flag.push("CWR");
        }
        return format!("[{}]", flag.join(", "));
    }
}
