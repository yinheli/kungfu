use crate::cli;
use std::io::Write;

pub(crate) fn init(cli: &cli::Cli) {
    let mut level = log::LevelFilter::Info;

    if cli.verbose {
        level = log::LevelFilter::Debug;
    }

    env_logger::Builder::new()
        .format(|buf, record| writeln!(buf, "[{:<5}] {}", record.level(), record.args()))
        .filter_module("kungfu", level)
        .init();
}
