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

fn main() {
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

    let cpu = num_cpus::get();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("kungfu")
        .worker_threads(cpu)
        .max_blocking_threads(cpu * 10)
        .thread_stack_size(1024 * 256)
        .build()
        .unwrap();

    rt.block_on(async { join!(gateway::serve(setting.clone()), dns::serve(setting.clone())) });
}
