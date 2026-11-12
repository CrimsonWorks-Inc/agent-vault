//! `agent-vault-setup`, the privileged installer. Ports
//! `bin/agent-vault-setup.js`.
//!
//! The verb is the first argument that does not start with `-`, matching the
//! JS installer. Clap's [`av_cli::SetupCli`] remains for callers that already
//! parsed a command tree.

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(av_cli::setup::run_setup_argv(&argv).code());
}
