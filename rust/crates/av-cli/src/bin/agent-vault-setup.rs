//! `agent-vault-setup`, the privileged installer. Ports
//! `bin/agent-vault-setup.js`.

use clap::Parser;

fn main() {
    let cli = match av_cli::SetupCli::try_parse() {
        Ok(cli) => cli,
        Err(err) => std::process::exit(av_cli::setup::setup_clap_failure(err).code()),
    };
    std::process::exit(av_cli::run_setup(cli).code());
}
