use crate::model::packet;
use pcap::{Capture, Device};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;

/// A message from the capture thread to the UI.
pub enum CaptureMsg {
    Line(String),
    Error(String),
    Ended,
}

/// Runs a capture until `stop` is set or the capture fails, sending each
/// decoded packet's summary over `tx`. Always finishes with `Ended`.
pub fn capture_loop(index: usize, tx: Sender<CaptureMsg>, stop: Arc<AtomicBool>) {
    if let Err(e) = run_capture(index, &tx, &stop) {
        let _ = tx.send(CaptureMsg::Error(e));
    }
    let _ = tx.send(CaptureMsg::Ended);
}

fn run_capture(index: usize, tx: &Sender<CaptureMsg>, stop: &AtomicBool) -> Result<(), String> {
    let devices = Device::list().map_err(|e| format!("error getting network devices: {}", e))?;
    let device = devices
        .get(index)
        .ok_or_else(|| format!("no network interface for index {}", index))?;

    let inactive = Capture::from_device(device.clone())
        .map_err(|e| format!("error getting capture: {}", e))?;
    let mut cap = inactive
        .promisc(true)
        .timeout(200)
        .open()
        .map_err(|e| format!("error opening capture (run as Administrator?): {}", e))?;

    let mut count = 0;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        match cap.next_packet() {
            Ok(p) => {
                let packet = packet::Packet::parse(count, p.data.len() as u32, p.data);
                if tx.send(CaptureMsg::Line(packet.summary())).is_err() {
                    return Ok(());
                }
                count += 1;
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(format!("capture error: {}", e)),
        }
    }
}

pub fn list_devices() -> Result<Vec<String>, String> {
    let devices = Device::list().map_err(|e| format!("error listing network devices: {}", e))?;
    if devices.is_empty() {
        return Err("no network devices found for live capture".to_string());
    }
    Ok(devices
        .iter()
        .enumerate()
        .map(|(i, d)| {
            format!(
                "#{} - {} - {}",
                i,
                d.name,
                d.desc.as_deref().unwrap_or("no description")
            )
        })
        .collect())
}
