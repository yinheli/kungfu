// #![feature(hash_drain_filter)]

use clap::Parser;
use log::info;
use std::process;
use tokio::join;
mod cli;
mod config;
mod dns;
mod gateway;
mod logger;

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();

    // init logger
    logger::init(&cli);

    if !cli.test {
        info!("kungfu version: v{}", env!("CARGO_PKG_VERSION"));
        info!("Across the Great Wall, We can reach every corner in the world.");
    }

    let setting = match config::load(&cli) {
        Ok(s) => s,
        Err(e) => {
            log::error!("load config file failed, {:?}", e);
            process::exit(1);
        }
    };

    if cli.test {
        info!("config files passed");
        process::exit(0);
    }

    join!(gateway::serve(setting.clone()), dns::serve(setting.clone()));
}
