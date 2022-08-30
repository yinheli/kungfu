use crate::cli;
use chrono::Local;
use std::io::Write;

pub(crate) fn init(cli: &cli::Cli) {
    let mut level = log::LevelFilter::Info;

    if cli.verbose {
        level = log::LevelFilter::Debug;
    }

    env_logger::Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{:<5}] {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                record.level(),
                record.args()
            )
        })
        // .filter_level(level)
        .filter_module("kungfu", level)
        .init();
}
