pub struct Other {
    other: Vec<u8>,
}

impl Other {
    pub fn parse(bytes: &[u8]) -> Other {
        Other {
            other: bytes.to_vec(),
        }
    }
}