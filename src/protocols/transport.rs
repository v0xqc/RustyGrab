use crate::protocols::{tcp,udp};
use crate::model::other;
pub enum Transport {
    Tcp(tcp::TcpSegment),
    Udp(udp::UdpDatagram),
    Other(other::Other),
}

impl Transport {
    pub fn parse(protocol: u8, bytes: &[u8]) -> Transport {
        match protocol {
            6 => Transport::Tcp(tcp::TcpSegment::parse(bytes)),
            17 => Transport::Udp(udp::UdpDatagram::parse(bytes)),
            _ => Transport::Other(other::Other::parse(bytes)),
        }
    }
}