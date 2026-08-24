mod cli;
mod source;
mod protocols;
mod model;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    cli::start_cli(args);
}
