use crate::protocols::{tcp,udp,icmp,icmpv6};
use crate::model::other;
pub enum Transport {
    Tcp(tcp::TcpSegment),
    Udp(udp::UdpDatagram),
    Icmp(icmp::IcmpPacket),
    Icmpv6(icmpv6::Icmpv6Packet),
    Other(other::Other),
}

impl Transport {
    pub fn parse(protocol: u8, bytes: &[u8]) -> Transport {
        match protocol {
            1 => Transport::Icmp(icmp::IcmpPacket::parse(bytes)),
            6 => Transport::Tcp(tcp::TcpSegment::parse(bytes)),
            17 => Transport::Udp(udp::UdpDatagram::parse(bytes)),
            58 => Transport::Icmpv6(icmpv6::Icmpv6Packet::parse(bytes)),
            _ => Transport::Other(other::Other::parse(bytes)),
        }
    }
}