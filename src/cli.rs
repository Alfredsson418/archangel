use clap::Parser;

use crate::params::Params;

#[derive(Parser)]
#[command(name = "archangel", about = "Archangel backend")]
pub struct App {
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,
}

impl App {
    pub fn into_params(self) -> Params {
        Params {
            verbose: self.verbose,
        }
    }
}
