use clap::Parser;

#[derive(Parser, Debug)]
#[clap(version, about)]
pub struct Cli {
    /// Config file
    #[clap(short, long, value_hint=clap::ValueHint::FilePath, default_value = "config/config.yml")]
    pub config: String,

    /// Test config
    #[clap(short, long)]
    pub test: bool,

    /// Disable watch rules update
    #[clap(long)]
    pub disable_watch: bool,

    /// Verbose log
    #[clap(long)]
    pub verbose: bool,
}
