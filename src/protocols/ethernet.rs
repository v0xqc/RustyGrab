use crate::model::other;
use crate::protocols::{ipv4,arp,ipv6};

pub struct Ethernet {
    pub dest_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub payload: EtherPayload,
}

impl Ethernet {
    pub fn parse(bytes: &[u8]) -> Ethernet {
        let ethertype =
            u16::from_be_bytes(bytes[12..14].try_into().expect("Failed to read ethertype"));
        Ethernet {
            dest_mac: bytes[0..6]
                .try_into()
                .expect("Failed to read destination MAC"),
            src_mac: bytes[6..12].try_into().expect("Failed to read source MAC"),
            ethertype: ethertype,
            payload: EtherPayload::parse(ethertype, &bytes[14..bytes.len()]),
        }
    }
}

pub enum EtherPayload {
    Ipv4(ipv4::Ipv4Packet),
    Arp(arp::ArpPacket),
    Ipv6(ipv6::Ipv6Packet),
    Other(other::Other),
}

impl EtherPayload {
    pub fn parse(ethertype: u16, bytes: &[u8]) -> EtherPayload {
        match ethertype {
            0x0800 => EtherPayload::Ipv4(ipv4::Ipv4Packet::parse(bytes)),
            0x0806 => EtherPayload::Arp(arp::ArpPacket::parse(bytes)),
            0x86DD => EtherPayload::Ipv6(ipv6::Ipv6Packet::parse(bytes)),
            _ => EtherPayload::Other(other::Other::parse(bytes)),
        }
    }
}