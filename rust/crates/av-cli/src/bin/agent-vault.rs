//! `agent-vault` (also installed as `av`). Ports `bin/agent-vault.js`: refuse
//! root, parse, run, exit with the command's status.

use clap::Parser;

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if let Some(exit) = av_cli::refuse_root(&argv) {
        std::process::exit(exit.code());
    }
    let cli = match av_cli::Cli::try_parse_from(&argv) {
        Ok(cli) => cli,
        Err(err) => std::process::exit(av_cli::clap_failure(err, &argv).code()),
    };
    std::process::exit(av_cli::run(cli));
}
