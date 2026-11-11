//! `agent-vault-setup`: the privileged installer (run by absolute path under
//! sudo). Ports `bin/agent-vault-setup.js`.
//!
//! # JS parsing quirks clap does not reproduce on its own
//!
//! - The JS verb is the **first argument that does not start with `-`**
//!   (`args.find((a) => !a.startsWith('-'))`), so `--user alice install`
//!   picks `alice` as the verb and prints the help. Clap reads the flag's
//!   value properly and runs `install`.
//! - An unknown verb, or none, prints the help and exits 0. Clap refuses an
//!   unknown subcommand; the runner should map that to the help (exit 0),
//!   and no subcommand is [`SetupCommand`]`::Help` by default.
//! - The JS reads every flag whichever verb runs (`flag(name)` /
//!   `value(name)` scan the whole argv). Here `--dry-run` is global and the
//!   rest belong to the verb that uses them, so `uninstall --port 1` is a
//!   clap error where the JS ignored it.
//! - `value(name)` takes the next argument whatever it is, even one starting
//!   with `-` (`--user --dry-run` sets the user to `--dry-run`), and reads
//!   only the first occurrence; `--name=value` is not understood (the flag
//!   is simply absent). Clap accepts `--user=alice`.

use clap::{Args, Parser, Subcommand};

use av_core::errors::Exit;

/// The `agent-vault-setup` command line. Ports the `args`, `verb`, `flag`
/// and `value` parsing at the top of `bin/agent-vault-setup.js`.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "agent-vault-setup",
    about = "agent-vault-setup  the privileged installer",
    disable_help_subcommand = true,
    disable_version_flag = true
)]
pub struct SetupCli {
    /// Print every change it would make and touch nothing. Ports
    /// `DRY = flag('dry-run')` in `bin/agent-vault-setup.js`.
    #[arg(long = "dry-run", global = true)]
    pub dry_run: bool,

    /// The verb; none prints the help. Ports the `switch (verb)` in
    /// `bin/agent-vault-setup.js`.
    #[command(subcommand)]
    pub command: Option<SetupCommand>,
}

/// The installer's verbs. Ports the `switch (verb)` cases in
/// `bin/agent-vault-setup.js`.
#[derive(Debug, Clone, Subcommand)]
pub enum SetupCommand {
    /// Create the service user and the root-owned tree, install and start
    /// the service. Ports `install()` in `bin/agent-vault-setup.js`.
    Install(InstallArgs),
    /// Stop and remove the service; keep the vault unless `--purge`. Ports
    /// `uninstall()` in `bin/agent-vault-setup.js`.
    Uninstall(UninstallArgs),
    /// What is installed. Ports `status()` in `bin/agent-vault-setup.js`.
    Status,
    /// Print the help. Ports `help()` (the `default` case) in
    /// `bin/agent-vault-setup.js`.
    Help,
}

/// `install [--user <name>] [--port 7411] [--use-node <path>] [--from
/// <checkout>]`. Ports the `value('user')`, `value('port')`,
/// `value('use-node')` and `value('from')` reads in `install()` in
/// `bin/agent-vault-setup.js`. `--from` is not in the JS help text.
#[derive(Debug, Clone, Default, Args)]
pub struct InstallArgs {
    /// The account to enrol (default `SUDO_USER`).
    #[arg(long)]
    pub user: Option<String>,
    /// Gateway port, written to the unit as `AV_PORT` (default 7411).
    #[arg(long)]
    pub port: Option<String>,
    /// A root-owned Node binary to use. The Rust install ships no Node; the
    /// flag is kept so old invocations parse, and the CLI worker decides
    /// whether it is refused or ignored.
    #[arg(long = "use-node")]
    pub use_node: Option<String>,
    /// The checkout to install from (default: relative to this binary).
    #[arg(long)]
    pub from: Option<String>,
}

/// `uninstall [--purge]`. Ports the `flag('purge')` read in `uninstall()` in
/// `bin/agent-vault-setup.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct UninstallArgs {
    /// Delete the vault instead of keeping it aside.
    #[arg(long)]
    pub purge: bool,
}

/// Run the installer; returns the exit code (`die()` is `Exit::Failure`).
/// Ports the `try { switch (verb) ... } catch (e) { die(e.message) }` body
/// of `bin/agent-vault-setup.js`.
pub fn run_setup(cli: SetupCli) -> Exit {
    todo!()
}

/// Render a clap parse error as the installer would: an unknown or missing
/// verb prints the help and exits 0; anything else is `die()`. Ports the
/// `default: help()` case of `bin/agent-vault-setup.js`.
pub fn setup_clap_failure(err: clap::Error) -> Exit {
    todo!()
}
