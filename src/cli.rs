use crate::source::{pcap_file, live};

pub fn start_cli(args: Vec<String>) {
    if args.len() < 2 {
        eprintln!("Error: Command unknown or missing. Please provide a valid command.");
        eprintln!("Usage: rustygrab <command> [<args>]");
        eprintln!("Use 'rustygrab help' for more information.");
        return;
    }

    match args[1].as_str() {
        "read" => match args.get(2) {
            Some(file_path) => pcap_file::read_file(file_path),
            None => {
                eprintln!("Error: Missing file path for 'read' command.");
                eprintln!("Usage: rustygrab read <file_path>");
            }
        },
        "live" => match args.get(2) {
            Some(inter_index) => {
                live::live_capture(inter_index);
            }
            None => live::list_devices(),
        },
        "help" => help(),
        "version" => version(),
        _ => println!("Unknown command: {}", args[1]),
    }

}

fn version() {
    println!("rustygrab version 0.1.1");
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
