use pcap::{Capture, Device};
use crate::model::packet;

pub fn live_capture(interface: &str) {
    let mut count = 0;
    let index = match interface.parse::<usize>() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("Invalid index provided");
            return;
        }
    };

    let devices = match Device::list() {
        Ok(devices) => devices,
        Err(e) => {
            eprintln!("Error getting network devices: {}", e);
            return;
        }
    };

    let device = match devices.get(index) {
        Some(device) => device,
        None => {
            eprint!("No network interface for index {}", index);
            return;
        }
    };

    let inactive = match Capture::from_device(device.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error getting capture: {}", e);
            return;
        }
    };

    let mut cap = match inactive.promisc(true).timeout(1000).open() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error getting active capture: {}", e);
            return;
        }
    };

    loop {
        match cap.next_packet() {
            Ok(packet) => { 
                let p = packet::Packet::parse(count, packet.data.len() as u32 , packet.data);
                println!("{}",p.summary());
                count += 1;
             }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => { eprintln!("capture error: {}", e); break; }
        }
    }
}

pub fn list_devices() {
    match Device::list() {
        Ok(devices) => {
            if devices.is_empty() {
                eprintln!("No network devices found for live capture.");
            } else {
                println!("Available network devices:");
                for (i, device) in devices.iter().enumerate() {
                    println!(
                        "#{} - {} - {}",
                        i,
                        device.name,
                        device.desc.clone().unwrap_or("No description".to_string())
                    );
                }
            }
        }
        Err(e) => eprintln!("Error listing network devices: {}", e),
    }
}
