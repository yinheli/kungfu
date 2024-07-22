use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Cli {
    /// Config file
    #[arg(short, long, value_hint=clap::ValueHint::FilePath, default_value = "config/config.yaml")]
    pub config: String,

    /// Test config
    #[arg(short, long)]
    pub test: bool,

    /// Disable watch rules update
    #[arg(long)]
    pub disable_watch: bool,

    /// Verbose log
    #[arg(long)]
    pub verbose: bool,
}
