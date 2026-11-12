//! The `agent-vault` and `agent-vault-setup` command-line apps. Ports
//! `src/cli/*`, `bin/agent-vault.js` and `bin/agent-vault-setup.js`.
//!
//! The CLI is untrusted by design: it holds no key material, and every
//! command is a thin client of the daemon's control socket. Commands, flags,
//! exit codes (`EXIT`, here [`av_core::errors::Exit`]), the `--json`
//! envelopes (`{ok, data}` / `{ok:false, error:{message, next, code,
//! hint}}`) and human wording are frozen (PLAN.md, "Frozen external
//! contract" item 4).
//!
//! The root of this crate ports the non-command parts of `src/cli/index.js`
//! (the runner, the control-socket client, the install paths,
//! `sessionRetry`, `COMMAND_NAMES`); [`cli`] is the command tree;
//! [`commands`] the handlers that live in `index.js`.
#![forbid(unsafe_code)]
// Scaffold: bodies are `todo!()` until the next wave fills them in. Remove
// this allow when the last `todo!()` in the crate is gone.
#![allow(unused_variables)]

pub mod cli;
pub mod commands;
pub mod control_commands;
pub mod files;
pub mod mcp_install;
pub mod policy_input;
pub mod prompt;
pub mod setup;
pub mod watch;
pub mod wizards;

use std::path::PathBuf;

use serde_json::Value;

use av_core::errors::Exit;

pub use cli::Cli;
pub use setup::{run_setup, SetupCli};

/// The system install root: `/var/db/agent-vault` on macOS,
/// `/usr/libexec/agent-vault` elsewhere. Ports `SYSTEM_ROOT`
/// (module-private) in `src/cli/index.js`.
#[cfg(target_os = "macos")]
pub const SYSTEM_ROOT: &str = "/var/db/agent-vault";
/// The system install root: `/var/db/agent-vault` on macOS,
/// `/usr/libexec/agent-vault` elsewhere. Ports `SYSTEM_ROOT`
/// (module-private) in `src/cli/index.js`.
#[cfg(not(target_os = "macos"))]
pub const SYSTEM_ROOT: &str = "/usr/libexec/agent-vault";

/// The system vault dir. Ports `SYSTEM_VAULT` (module-private) in
/// `src/cli/index.js`.
#[cfg(target_os = "macos")]
pub const SYSTEM_VAULT: &str = "/var/db/agent-vault/vault";
/// The system vault dir. Ports `SYSTEM_VAULT` (module-private) in
/// `src/cli/index.js`.
#[cfg(not(target_os = "macos"))]
pub const SYSTEM_VAULT: &str = "/var/lib/agent-vault";

/// The system run dir (holds `control.sock`). Ports `SYSTEM_RUN`
/// (module-private) in `src/cli/index.js`.
#[cfg(target_os = "macos")]
pub const SYSTEM_RUN: &str = "/var/db/agent-vault/run";
/// The system run dir (holds `control.sock`). Ports `SYSTEM_RUN`
/// (module-private) in `src/cli/index.js`.
#[cfg(not(target_os = "macos"))]
pub const SYSTEM_RUN: &str = "/run/agent-vault";

/// Whether the privileged installer has run (`<SYSTEM_ROOT>/state.json`
/// exists). Ports `SYSTEM_INSTALLED` in `src/cli/index.js`.
pub fn system_installed() -> bool {
    todo!()
}

/// Whether `AGENT_VAULT_DIR` is set. Ports `VAULT_OVERRIDDEN` in
/// `src/cli/index.js`.
pub fn vault_overridden() -> bool {
    todo!()
}

/// True only when the system install is the vault actually in use. Ports
/// `USING_SYSTEM` in `src/cli/index.js`.
pub fn using_system() -> bool {
    todo!()
}

/// `AGENT_VAULT_DIR`, else the system vault, else `~/.agent-vault`. Ports
/// `VAULT_DIR` in `src/cli/index.js`.
pub fn vault_dir() -> PathBuf {
    todo!()
}

/// The control socket path for the vault in use. Ports `SOCKET`
/// (module-private) in `src/cli/index.js`.
pub fn socket_path() -> PathBuf {
    todo!()
}

/// Every command as a human types it. Ports `COMMAND_NAMES` in
/// `src/cli/index.js` (`Object.keys(COMMANDS)` in definition order, with the
/// `controlCommands` keys merged after), plus `migrate`, new in the port.
pub const COMMAND_NAMES: [&str; 68] = [
    "setup",
    "daemon",
    "upgrade",
    "quickstart",
    "status",
    "cred add",
    "cred list",
    "cred rm",
    "session create",
    "session list",
    "session revoke",
    "ph next",
    "ph check",
    "ph pattern",
    "env",
    "exec",
    "approvals",
    "approve",
    "deny",
    "audit tail",
    "listen add",
    "tls setup",
    "tls status",
    "listen list",
    "listen rm",
    "mcp install",
    "mcp url",
    "mcp",
    "ui",
    "docs",
    "passphrase set",
    "passphrase remove",
    "lock",
    "unlock",
    "profiles",
    "doctor",
    "watch",
    "cred rotate",
    "cred expiry",
    "cred scrub",
    "cred pin",
    "cred test",
    "cred quarantine",
    "cred release",
    "panic",
    "tripwire show",
    "tripwire on",
    "tripwire off",
    "tripwire set",
    "notify set",
    "notify show",
    "notify off",
    "notify test",
    "template save",
    "template list",
    "template show",
    "template rm",
    "session narrow",
    "session show",
    "report",
    "backup export",
    "backup inspect",
    "backup restore",
    "audit export",
    "audit witness",
    "audit verify",
    "preflight",
    "migrate",
];

/// A command failure, carrying what the failure envelope needs. Ports the
/// `Error` objects the JS throws with `{ exit, next, problem, skew }`
/// properties (`control`, `usage`, …) in `src/cli/index.js`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct CliError {
    /// What went wrong.
    pub message: String,
    /// The process exit code.
    pub exit: Exit,
    /// The command to run next, if any.
    pub next: Option<String>,
    /// The daemon's problem document, if this came from the control API.
    pub problem: Option<Box<Value>>,
    /// Daemon older than this CLI (`EXIT.VERSION_SKEW`).
    pub skew: bool,
}

/// The runner's state for one invocation: output mode, socket, and the
/// control client. Ports the module-level `JSON_OUT`, `SOCKET`, `C`, `out`,
/// `fail`, `control`, `controlWithPresence`, `readSecret` and `ask` in
/// `src/cli/index.js` (and the `ctx` object passed to `controlCommands`).
#[derive(Debug, Clone)]
pub struct Context {
    /// `--json`. Ports `JSON_OUT`.
    pub json: bool,
    /// The control socket. Ports `SOCKET`.
    pub socket: PathBuf,
    /// Color output (stdout is a TTY and `NO_COLOR` unset). Ports `C`.
    pub color: bool,
}

impl Context {
    /// Print human text, or `{ok:true,data}` under `--json`. Ports
    /// `out(human, data)` in `src/cli/index.js`.
    pub fn out(&self, human: Option<&str>, data: &Value) {
        todo!()
    }

    /// Print the failure envelope (`{ok:false,error:{message,...extra}}`, or
    /// `error <message>` and `next: <next>` on stderr) and return the exit
    /// code. Ports `fail(message, code, extra)` in `src/cli/index.js`.
    pub fn fail(&self, err: &CliError) -> Exit {
        todo!()
    }

    /// One control-socket call; a 4xx/5xx becomes a [`CliError`] with the
    /// code's own exit, a "no control route" 404 becomes
    /// `EXIT.VERSION_SKEW`, and a missing socket `EXIT.DAEMON_UNREACHABLE`.
    /// Ports `control(method, path, body)` in `src/cli/index.js`.
    pub async fn control(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, CliError> {
        todo!()
    }

    /// [`Context::control`], and on `AV_PRESENCE_REQUIRED` ask for the
    /// passphrase (fresh, or a presence window) and retry once. Ports
    /// `controlWithPresence(method, path, body)` in `src/cli/index.js`.
    pub async fn control_with_presence(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, CliError> {
        todo!()
    }

    /// Read a secret with echo off on a TTY, or one line from a pipe. Never
    /// from argv. Ports `readSecret(prompt)` (and `readPipedLine`) in
    /// `src/cli/index.js`.
    pub fn read_secret(&self, prompt: &str) -> Result<av_core::secret::SecretString, CliError> {
        todo!()
    }

    /// Ask a plain question on the terminal. Ports `ask(prompt)` in
    /// `src/cli/index.js`.
    pub fn ask(&self, prompt: &str) -> Result<String, CliError> {
        todo!()
    }

    /// The gateway port recorded in the client state. Ports
    /// `gatewayPortOf(st)` in `src/cli/index.js`.
    pub fn gateway_port_of(&self, state: &Value) -> u16 {
        todo!()
    }
}

/// Refuse to run as root (uid 0 without `AGENT_VAULT_ALLOW_ROOT`), printing
/// the "Do not run agent-vault under sudo" text with the command to run
/// instead; returns `Some(Exit::Usage)` when refused. Runs before argument
/// parsing. Ports the R3 check at the top of `main(argv)` in
/// `src/cli/index.js`.
pub fn refuse_root(argv: &[String]) -> Option<Exit> {
    todo!()
}

/// Render a clap parse error as the JS would (see the quirks in [`cli`]):
/// the failure envelope with `EXIT.USAGE`, or the help text when the error
/// is a help request. Ports the `unknown command` and usage-error paths of
/// `main(argv)` in `src/cli/index.js`.
pub fn clap_failure(err: clap::Error, argv: &[String]) -> Exit {
    todo!()
}

/// What a handler returns: the process exit status on success (normally
/// `Exit::Ok.code()`; some handlers set another, as the JS sets
/// `process.exitCode`, and `exec` passes through the child's status, 127,
/// 126 or 128 + signal), or the failure for the envelope.
pub type Outcome = Result<i32, CliError>;

/// Run one parsed command: help, the secret-flag refusal, dispatch, and
/// the failure envelope for any error (`problem.next.cli[0]`, `code`,
/// `hint`). Returns the process exit status: an [`Exit`] code, except that
/// `exec` passes its child's status through. Ports the body of `main(argv)`
/// after `parseArgs` in `src/cli/index.js`, and `bin/agent-vault.js`.
pub fn run(cli: Cli) -> i32 {
    todo!()
}

/// Print the top-level help (`{ok:true,data:{help}}` under `--json`). Ports
/// `printHelp()` in `src/cli/index.js`.
pub fn print_help(ctx: &Context) {
    todo!()
}

/// How the reader is invoking this CLI, so printed commands can be pasted
/// (`agent-vault`, `av`, or the full path). Ports `cliInvocation()` in
/// `src/cli/index.js`.
pub fn cli_invocation() -> String {
    todo!()
}

/// A resend of the MCP calls a bridge sent before a session existed. Ports
/// the `{ line, merge }` result of `sessionRetry` in `src/cli/index.js`.
#[derive(Debug, Clone)]
pub struct SessionRetry {
    /// The JSON-RPC line (or batch) to send again.
    pub line: String,
    /// The original answers, for [`SessionRetry::merge`].
    pub answers: Value,
}

impl SessionRetry {
    /// Put the new answers in place of the refusals and keep every other
    /// answer as it came. Ports `merge(again)` in `sessionRetry` in
    /// `src/cli/index.js`.
    pub fn merge(&self, again: &str) -> String {
        todo!()
    }
}

/// The tool error the daemon gives for a call that needs a live session.
/// Ports `NEEDS_SESSION` (module-private) in `src/cli/index.js`.
pub const NEEDS_SESSION: &str = "this tool needs a live session";

/// Which calls in a bridged MCP line were refused for want of a session, so
/// the bridge can resend just those once one exists; `None` when there is
/// nothing to resend. Ports `sessionRetry(line, text)` in
/// `src/cli/index.js`.
pub fn session_retry(line: &str, text: &str) -> Option<SessionRetry> {
    todo!()
}

#[cfg(test)]
mod tests;
