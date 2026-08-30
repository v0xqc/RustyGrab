use crate::model::packet;

/// Everything a successful read produced: the decoded packets, plus any
/// non-fatal warning encountered along the way (e.g. a truncated record).
pub struct ReadResult {
    pub packets: Vec<packet::Packet>,
    pub warning: Option<String>,
}

pub fn read_file(path: &str) -> Result<ReadResult, String> {
    let path = std::path::Path::new(path);
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return Err(format!("cannot read '{}': {}", path.display(), e)),
    };

    if data.len() < 24 {
        return Err(format!(
            "invalid file: {} is too small to be a valid file",
            path.display()
        ));
    }

    let magic_le = u32::from_le_bytes(data[0..4].try_into().expect("Failed to read magic number"));

    let endian = match magic_le {
        0xa1b2c3d4 => Endian::Little,
        0xd4c3b2a1 => Endian::Big,
        _ => return Err(format!("not a valid magic number: {:08x}", magic_le)),
    };

    let mut packets = Vec::new();
    let mut warning = None;
    let mut pos = 24;
    let mut count = 0;

    while pos + 16 <= data.len() {
        let header: [u8; 16] = data[pos..pos + 16]
            .try_into()
            .expect("Failed to read header");
        let data_length = endian.read_u32(&header[8..12]);
        if pos + 16 + data_length as usize > data.len() {
            warning = Some(format!(
                "invalid packet length: {} exceeds file size",
                data_length
            ));
            break;
        }
        let packet_data: &[u8] = &data[pos + 16..(pos + 16 + data_length as usize)];
        packets.push(packet::Packet::parse(count, data_length, packet_data));
        pos += 16 + data_length as usize;
        count += 1;
    }

    Ok(ReadResult { packets, warning })
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
