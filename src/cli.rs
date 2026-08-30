use crate::source::{live, pcap_file};
use std::io::{self, Write};
use crate::ui::tui;

pub fn cli_app() {
    if let Err(e) = tui::tui() {
        let _ = crossterm::terminal::disable_raw_mode();
        eprintln!("rustygrab: terminal error: {}", e);
    }
}

fn version() {
    println!("rustygrab version {}", env!("CARGO_PKG_VERSION"));
}

fn help() {
    println!("Usage: rustygrab <command> [<args>]");
    println!("Commands:");
    println!("  read <file_path>   Read packets from a file");
    println!("  live               List available interfaces");
    println!("  live <index>       Capture packets on the selected interface");
    println!("  help               Show this help message");
    println!("  version            Show version information");
}
