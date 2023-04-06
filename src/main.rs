#![feature(test)]

#[macro_use]
extern crate lazy_static;

use clap::Parser;
use log::info;
use std::process;
use tokio::join;

mod cli;
mod config;
mod dns;
mod gateway;
mod logger;
mod metrics;

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
            log::error!("load config file failed, {e:?}");
            process::exit(1);
        }
    };

    if cli.test {
        info!("config files passed");
        process::exit(0);
    }

    let cpu = num_cpus::get();

    // setup rayon thread pool
    rayon::ThreadPoolBuilder::new()
        .num_threads(2.max(cpu))
        .thread_name(|_| "kungfu-rayon".to_string())
        .build_global()
        .unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("kungfu-worker")
        .worker_threads(cpu)
        .thread_stack_size(1024 * 256)
        .build()
        .unwrap();

    let metrics_addr = setting.metrics.clone();

    rt.block_on(async move {
        join!(
            gateway::serve(setting.clone()),
            dns::serve(setting.clone()),
            metrics::serve(metrics_addr),
        )
    });
}
