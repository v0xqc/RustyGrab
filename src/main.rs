mod cli;
mod source;
mod protocols;
mod model;
mod ui;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    cli::cli_app();
   // cli::start_cli(args);
}
