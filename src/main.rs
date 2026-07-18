use clap::Parser;

mod cli;
mod config;
mod output;

fn main() {

    println!("{}", output::motd::motd());

    let args = cli::App::parse();
    
    
}

