use crate::protocols::arp;
use crate::protocols::ethernet;
use crate::protocols::ethernet::EtherPayload;
use crate::protocols::ethernet::EtherPayload::Arp;
use crate::protocols::transport;
use crate::protocols::tcp;


pub struct Packet {
    count: u32,
    data_length: u32,
    ethernet: ethernet::Ethernet,
}

impl Packet {
    pub fn parse(count: u32, data_lenght: u32, bytes: &[u8]) -> Packet {
        Packet {
            count: count,
            data_length: data_lenght,
            ethernet: ethernet::Ethernet::parse(bytes),
        }
    }

    fn format_mac(mac: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }

    pub fn summary(&self) -> String {
        match self.ethernet.payload {
            ethernet::EtherPayload::Ipv4(ref ipv4) => {
                let source_ip = std::net::Ipv4Addr::from(ipv4.src_ip);
                let destination_ip = std::net::Ipv4Addr::from(ipv4.dest_ip);
                let source_port = match ipv4.transport {
                    transport::Transport::Tcp(ref tcp) => tcp.src_port,
                    transport::Transport::Udp(ref udp) => udp.src_port,
                    _ => 0,
                };
                let destination_port = match ipv4.transport {
                    transport::Transport::Tcp(ref tcp) => tcp.dest_port,
                    transport::Transport::Udp(ref udp) => udp.dest_port,
                    _ => 0,
                };
                let protocol = match ipv4.transport {
                    transport::Transport::Tcp(_) => "TCP",
                    transport::Transport::Udp(_) => "UDP",
                    _ => "Other",
                };
                let data_length = self.data_length;
                let flags = match ipv4.transport {
                    transport::Transport::Tcp(ref tcp) => tcp::TcpSegment::format_flags(tcp.flags),
                    _ => String::from(""),
                };

                return format!(
                    "#{} {}:{} -> {}:{} {} {} {}",
                    self.count,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                    protocol,
                    flags,
                    data_length
                );
            }

            ethernet::EtherPayload::Arp(ref arp) => {
                let target_ip = std::net::Ipv4Addr::from(arp.target_ip);
                let sender_ip = std::net::Ipv4Addr::from(arp.sender_ip);
                match arp.opcode {
                    1 => {return format!("#{} Who has {}? Tell {}",self.count, target_ip,sender_ip);},
                    2 => {return format!("#{} {} is at {}",self.count, sender_ip, Self::format_mac(&arp.sender_mac) );},
                    _ => return format!("#{} Unknown opcode {}",self.count, arp.opcode)
                }
            }
            _ => {
                let source_mac = Self::format_mac(&self.ethernet.src_mac);
                let destination_mac = Self::format_mac(&self.ethernet.dest_mac);
                let ethertype = self.ethernet.ethertype;
                let data_length = self.data_length;

                return format!(
                    "#{} {} -> {} Ethertype: 0x{:04x} {}",
                    self.count, source_mac, destination_mac, ethertype, data_length
                );
            }
        }
    }
}