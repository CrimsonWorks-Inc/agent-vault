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

pub mod argv;
pub mod cli;
pub mod commands;
pub mod control_commands;
pub mod files;
pub(crate) mod http_client;
pub mod mcp_install;
pub mod policy_input;
pub mod prompt;
pub mod setup;
pub mod watch;
pub mod wizards;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Map, Value};

use av_core::errors::{ErrorCode, Exit};
use av_core::secret::{ExposeSecret, SecretString};
use av_store::client_state::{self, RememberedSession};

pub use argv::{prepare, was_bare, Prepared};
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
    Path::new(SYSTEM_ROOT).join("state.json").is_file()
}

/// Whether `AGENT_VAULT_DIR` is set. Ports `VAULT_OVERRIDDEN` in
/// `src/cli/index.js`.
pub fn vault_overridden() -> bool {
    std::env::var_os("AGENT_VAULT_DIR").is_some_and(|v| !v.is_empty())
}

/// True only when the system install is the vault actually in use. Ports
/// `USING_SYSTEM` in `src/cli/index.js`.
pub fn using_system() -> bool {
    system_installed() && !vault_overridden()
}

/// `AGENT_VAULT_DIR`, else the system vault, else `~/.agent-vault`. Ports
/// `VAULT_DIR` in `src/cli/index.js`.
pub fn vault_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("AGENT_VAULT_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(dir);
    }
    if system_installed() {
        return PathBuf::from(SYSTEM_VAULT);
    }
    home_dir().join(".agent-vault")
}

/// The control socket path for the vault in use. Ports `SOCKET`
/// (module-private) in `src/cli/index.js`.
pub fn socket_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("AGENT_VAULT_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(dir).join("control.sock");
    }
    if system_installed() {
        PathBuf::from(SYSTEM_RUN).join("control.sock")
    } else {
        vault_dir().join("control.sock")
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// `<state dir>/cli-state.json`.
pub fn client_state_path() -> PathBuf {
    client_state::state_path(&client_state::state_dir())
}

/// Record a session the daemon just created. Ports `rememberSession(s)` at
/// the call sites in `src/cli/index.js`, falling back to the first grant
/// when the top-level placeholder lives only there.
pub fn remember_created(session: &Value) -> Result<(), CliError> {
    let grant0 = session
        .get("grants")
        .and_then(|g| g.as_array())
        .and_then(|a| a.first());
    let text = |k: &str| {
        session
            .get(k)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| {
                grant0
                    .and_then(|g| g.get(k))
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            })
    };
    let remembered = RememberedSession {
        session_id: text("session_id"),
        token: text("token"),
        placeholder: text("placeholder"),
        base_url: text("base_url"),
    };
    client_state::remember_session(&remembered, &client_state_path()).map_err(|e| CliError {
        message: e.to_string(),
        exit: Exit::Failure,
        next: None,
        problem: None,
        skew: false,
    })
}

pub(crate) fn load_client_state() -> Value {
    serde_json::to_value(client_state::load_state(&client_state_path())).unwrap_or(Value::Null)
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
    /// A fresh context for this process: socket, color, `--json`.
    pub fn new(json: bool) -> Self {
        Self {
            json,
            socket: socket_path(),
            color: stdout_is_tty() && std::env::var_os("NO_COLOR").is_none(),
        }
    }

    /// ANSI wrap when color is on. `code` is the SGR parameter (`31`, `2`).
    pub fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    /// Print human text, or `{ok:true,data}` under `--json`. Ports
    /// `out(human, data)` in `src/cli/index.js`.
    pub fn out(&self, human: Option<&str>, data: &Value) {
        if self.json {
            let envelope = json!({ "ok": true, "data": data });
            println!(
                "{}",
                serde_json::to_string_pretty(&envelope).unwrap_or_else(|_| "{}".into())
            );
        } else if let Some(human) = human.filter(|s| !s.is_empty()) {
            println!("{human}");
        }
    }

    /// Print the failure envelope and return the exit code. Ports
    /// `fail(message, code, extra)` in `src/cli/index.js`. The message is
    /// `problem.detail` unless this is version skew. `next` is
    /// `problem.next.cli[0]`, or a string `next`, or the error's own.
    pub fn fail(&self, err: &CliError) -> Exit {
        let message = if err.skew {
            err.message.clone()
        } else if let Some(detail) = err
            .problem
            .as_ref()
            .and_then(|p| p.get("detail"))
            .and_then(|d| d.as_str())
        {
            detail.to_string()
        } else {
            err.message.clone()
        };
        let next = problem_next(err.problem.as_deref()).or_else(|| err.next.clone());
        let code = err.problem.as_ref().and_then(|p| p.get("code")).cloned();
        let hint = err.problem.as_ref().and_then(|p| p.get("hint")).cloned();
        if self.json {
            let mut error = Map::new();
            error.insert("message".into(), Value::from(message));
            if let Some(next) = next {
                error.insert("next".into(), Value::from(next));
            }
            if let Some(code) = code {
                error.insert("code".into(), code);
            }
            if let Some(hint) = hint {
                error.insert("hint".into(), hint);
            }
            let envelope = json!({ "ok": false, "error": error });
            println!(
                "{}",
                serde_json::to_string_pretty(&envelope).unwrap_or_else(|_| "{}".into())
            );
        } else {
            eprintln!("{} {message}", self.paint("31", "error"));
            if let Some(next) = next {
                eprintln!("{} {next}", self.paint("2", "next:"));
            }
        }
        err.exit
    }

    /// One control-socket call. Ports `control(method, path, body)`.
    pub async fn control(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, CliError> {
        if !self.socket.exists() {
            return Err(CliError {
                message: "the daemon is not running".into(),
                exit: Exit::DaemonUnreachable,
                next: Some("agent-vault daemon".into()),
                problem: None,
                skew: false,
            });
        }
        let bytes = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|e| CliError {
                message: e.to_string(),
                exit: Exit::Failure,
                next: None,
                problem: None,
                skew: false,
            })?;
        let response = http_client::request_unix(&self.socket, method, path, bytes.as_deref(), &[])
            .map_err(|e| CliError {
                message: e.to_string(),
                exit: Exit::DaemonUnreachable,
                next: Some("agent-vault daemon".into()),
                problem: None,
                skew: false,
            })?;
        let text = response.text();
        let parsed: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
        if response.status == 404
            && parsed
                .get("detail")
                .and_then(|d| d.as_str())
                .is_some_and(|d| d.contains("no control route"))
        {
            return Err(CliError {
                message: "the running daemon is older than this command".into(),
                exit: Exit::VersionSkew,
                skew: true,
                next: Some(if using_system() {
                    "agent-vault setup   (reinstalls from this checkout and restarts the service)"
                        .into()
                } else {
                    "restart the daemon you started with: agent-vault daemon".into()
                }),
                problem: Some(Box::new(parsed)),
            });
        }
        if response.status >= 400 {
            let message = parsed
                .get("detail")
                .and_then(|d| d.as_str())
                .or_else(|| parsed.get("message").and_then(|d| d.as_str()))
                .unwrap_or(text.as_str())
                .to_string();
            let exit = parsed
                .get("code")
                .and_then(|c| c.as_str())
                .and_then(ErrorCode::parse)
                .map(|c| c.spec().exit)
                .unwrap_or(Exit::Failure);
            return Err(CliError {
                message,
                exit,
                next: None,
                problem: Some(Box::new(parsed)),
                skew: false,
            });
        }
        Ok(parsed)
    }

    /// [`Context::control`], and on `AV_PRESENCE_REQUIRED` ask and retry once.
    /// Ports `controlWithPresence`.
    pub async fn control_with_presence(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, CliError> {
        let err = match self.control(method, path, body).await {
            Ok(v) => return Ok(v),
            Err(e) => e,
        };
        let code = err
            .problem
            .as_ref()
            .and_then(|p| p.get("code"))
            .and_then(|c| c.as_str());
        if code != Some("AV_PRESENCE_REQUIRED") {
            return Err(err);
        }
        let state = self.control("GET", "/v1/lockstate", None).await.ok();
        if state
            .as_ref()
            .and_then(|s| s.get("locked"))
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Err(CliError {
                message: "the vault is locked".into(),
                exit: Exit::Locked,
                next: Some("agent-vault unlock".into()),
                problem: None,
                skew: false,
            });
        }
        let rule = err
            .problem
            .as_ref()
            .and_then(|p| p.get("rule"))
            .and_then(|r| r.as_str());
        if rule == Some("factor_required") {
            let detail = err
                .problem
                .as_ref()
                .and_then(|p| p.get("detail"))
                .and_then(|d| d.as_str());
            return Err(factor_required(detail));
        }
        let factors: Vec<String> = err
            .problem
            .as_ref()
            .and_then(|p| p.get("factors"))
            .and_then(|f| f.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .filter(|v: &Vec<String>| !v.is_empty())
            .unwrap_or_else(|| vec!["passphrase".into()]);
        if !factors.iter().any(|f| f == "passphrase") {
            return Err(CliError {
                message: format!("this change needs your {}", factors.join(" or ")),
                exit: Exit::Presence,
                next: Some("agent-vault ui   (confirm it there with your authenticator)".into()),
                problem: None,
                skew: false,
            });
        }
        if !stdin_is_tty() {
            return Err(presence_without_a_terminal(&factors));
        }
        if rule == Some("fresh_presence") {
            let passphrase = self.read_secret("passphrase (for this change only): ")?;
            let mut retry = body.cloned().unwrap_or_else(|| json!({}));
            if let Value::Object(map) = &mut retry {
                let mut presence = Map::new();
                presence.insert(
                    "passphrase".into(),
                    Value::from(passphrase.expose_secret().to_string()),
                );
                map.insert("presence".into(), Value::Object(presence));
            }
            return self.control(method, path, Some(&retry)).await;
        }
        eprintln!("{}", self.paint("2", "This change needs a human."));
        let passphrase = self.read_secret("passphrase: ")?;
        let window = json!({ "passphrase": passphrase.expose_secret() });
        self.control("POST", "/v1/presence/window", Some(&window))
            .await?;
        self.control(method, path, body).await
    }

    /// Read a secret with echo off on a TTY, or one trimmed line from a pipe.
    pub fn read_secret(&self, prompt: &str) -> Result<SecretString, CliError> {
        if !stdin_is_tty() {
            return Ok(SecretString::from(read_piped_line().trim().to_string()));
        }
        match rpassword::prompt_password(prompt) {
            Ok(value) => Ok(SecretString::from(value)),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Err(prompt::cancelled()),
            Err(e) => Err(CliError {
                message: e.to_string(),
                exit: Exit::Failure,
                next: None,
                problem: None,
                skew: false,
            }),
        }
    }

    /// Ask a plain question. A pipe yields one line, untrimmed past the newline.
    pub fn ask(&self, prompt: &str) -> Result<String, CliError> {
        if stdin_is_tty() {
            print!("{prompt}");
            let _ = std::io::stdout().flush();
        }
        Ok(read_piped_line())
    }

    /// The gateway port recorded in the client state. A non-numeric or
    /// out-of-range `gateway_port` is ignored (the state loader already
    /// drops those; a raw value is checked again). Ports `gatewayPortOf`.
    pub fn gateway_port_of(&self, state: &Value) -> u16 {
        if let Some(port) = state.get("gateway_port").and_then(json_port) {
            return port;
        }
        if let Some(url) = state.get("base_url").and_then(|v| v.as_str()) {
            if let Some(rest) = url.strip_prefix("http://127.0.0.1:") {
                if let Some(digits) = rest.split('/').next() {
                    if let Ok(port) = digits.parse::<u16>() {
                        if port >= 1 {
                            return port;
                        }
                    }
                }
            }
        }
        7411
    }
}

fn json_port(value: &Value) -> Option<u16> {
    match value {
        Value::Number(n) => {
            let u = n.as_u64()?;
            u16::try_from(u).ok().filter(|p| (1..=65535).contains(p))
        }
        _ => None,
    }
}

/// A gated change on a vault with no human factor. Exit 5, and the next
/// step is to enroll one. Ports the `factor_required` arm of
/// `controlWithPresence` in `src/cli/index.js`.
pub(crate) fn factor_required(detail: Option<&str>) -> CliError {
    CliError {
        message: detail
            .unwrap_or("this change needs a human factor, and none is enrolled")
            .to_string(),
        exit: Exit::Presence,
        next: Some("agent-vault passphrase set".into()),
        problem: None,
        skew: false,
    }
}

/// A presence gate with no terminal does not open a window. An authenticator
/// factor names `agent-vault ui`; a passphrase-only factor does not.
pub(crate) fn presence_without_a_terminal(factors: &[String]) -> CliError {
    let mut err = CliError {
        message: "this change needs your passphrase, and there is no terminal to ask on".into(),
        exit: Exit::Presence,
        next: None,
        problem: None,
        skew: false,
    };
    if factors.iter().any(|f| f == "authenticator") {
        err.next = Some("agent-vault ui   (confirm it there with your authenticator)".into());
    }
    err
}

fn problem_next(problem: Option<&Value>) -> Option<String> {
    let next = problem?.get("next")?;
    if let Some(s) = next.as_str() {
        return Some(s.to_string());
    }
    next.get("cli")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn stdout_is_tty() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}

fn stdin_is_tty() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdin())
}

fn read_piped_line() -> String {
    static STDIN: Mutex<Option<BufReader<std::io::Stdin>>> = Mutex::new(None);
    let mut guard = STDIN.lock().unwrap_or_else(|e| e.into_inner());
    let reader = guard.get_or_insert_with(|| BufReader::new(std::io::stdin()));
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) | Err(_) => String::new(),
        Ok(_) => {
            if line.ends_with('\n') {
                line.pop();
                if line.ends_with('\r') {
                    line.pop();
                }
            }
            line
        }
    }
}

/// Print a [`CliError`] with color and `--json` taken from the environment
/// and argv. Used before a [`Context`] exists (prepare, clap).
pub fn emit(err: &CliError, json: bool) -> Exit {
    Context::new(json).fail(err)
}

/// Refuse to run as root (uid 0 without `AGENT_VAULT_ALLOW_ROOT`), printing
/// the "Do not run agent-vault under sudo" text with the command to run
/// instead; returns `Some(Exit::Usage)` when refused. Runs before argument
/// parsing. Ports the R3 check at the top of `main(argv)` in
/// `src/cli/index.js`.
/// Whether this process may continue. An empty `AGENT_VAULT_ALLOW_ROOT` is
/// unset, matching `!!process.env.AGENT_VAULT_ALLOW_ROOT` in
/// `src/cli/index.js`. A missing uid (`id` failed) is treated as root so the
/// check fails closed.
pub(crate) fn root_is_allowed(allow_root: Option<&str>, uid: Option<u32>) -> bool {
    if allow_root.is_some_and(|value| !value.is_empty()) {
        return true;
    }
    match uid {
        Some(0) | None => false,
        Some(_) => true,
    }
}

fn own_uid() -> Option<u32> {
    std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
}

pub fn refuse_root(argv: &[String]) -> Option<Exit> {
    let allow = std::env::var("AGENT_VAULT_ALLOW_ROOT").ok();
    if root_is_allowed(allow.as_deref(), own_uid()) {
        return None;
    }
    let asked = argv.iter().skip(1).cloned().collect::<Vec<_>>().join(" ");
    let invoked = std::env::var("SUDO_COMMAND")
        .ok()
        .and_then(|s| {
            s.rsplit('/')
                .next()
                .and_then(|tail| tail.split_whitespace().next().map(str::to_string))
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "agent-vault".into());
    eprintln!("Do not run agent-vault under sudo.");
    eprintln!();
    if asked.is_empty() {
        eprintln!("  run this instead:  {invoked}");
    } else {
        eprintln!("  run this instead:  {invoked} {asked}");
    }
    eprintln!();
    eprintln!("  Running the whole CLI as root would put every code path in this package,");
    eprintln!("  and whichever interpreter is first on root PATH, inside a root process.");
    eprintln!("  \"agent-vault setup\" already handles the privileged step for you: it runs");
    eprintln!("  as you and hands root one small installer by absolute path.");
    Some(Exit::Usage)
}

/// Render a clap parse error as the JS would (see the quirks in [`cli`]):
/// the failure envelope with `EXIT.USAGE`, or the help text when the error
/// is a help request. Ports the `unknown command` and usage-error paths of
/// `main(argv)` in `src/cli/index.js`.
pub fn clap_failure(err: clap::Error, argv: &[String]) -> Exit {
    use clap::error::ErrorKind;
    let json = argv.iter().any(|a| a == "--json");
    if matches!(
        err.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        let ctx = Context::new(json);
        print_help(&ctx);
        return Exit::Ok;
    }
    let raw = err.to_string();
    let message = if let Some(flag) = raw
        .split('\'')
        .nth(1)
        .filter(|_| raw.contains("value is required") || raw.contains("requires a value"))
    {
        let name = flag.trim_start_matches('-');
        format!("--{name} needs a value")
    } else if raw.contains("unrecognized subcommand") || raw.contains("unexpected argument") {
        let name = argv
            .iter()
            .skip(1)
            .find(|a| !a.starts_with('-'))
            .map(String::as_str)
            .unwrap_or("command");
        format!("unknown command \"{name}\"")
    } else {
        let line = raw.lines().next().unwrap_or("usage error").trim();
        line.trim_start_matches("error:").trim().to_string()
    };
    emit(
        &CliError {
            message,
            exit: Exit::Usage,
            next: Some("agent-vault help".into()),
            problem: None,
            skew: false,
        },
        json,
    )
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
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let rt = match rt {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error {e}");
            return Exit::Failure.code();
        }
    };
    rt.block_on(run_async(cli))
}

async fn run_async(cli: Cli) -> i32 {
    let ctx = Context::new(cli.json);
    if cli.help {
        if let Some(cli::Command::Cred {
            command: cli::CredCommand::Scrub(_),
        }) = &cli.command
        {
            let help = control_commands::SCRUB_HELP;
            ctx.out(Some(help), &json!({ "help": help }));
            return Exit::Ok.code();
        }
    }
    if cli.help || cli.command.is_none() {
        print_help(&ctx);
        return Exit::Ok.code();
    }
    if cli.secret_traps.any() {
        return ctx
            .fail(&policy_input::usage(
                "secrets are read from the terminal or stdin, never command-line flags",
            ))
            .code();
    }
    let outcome = dispatch(&ctx, cli.command.unwrap()).await;
    match outcome {
        Ok(code) => code,
        Err(err) if err.message == "cancelled" && err.exit == Exit::Ok => {
            println!("\n{}", ctx.paint("2", "cancelled; nothing was changed"));
            Exit::Ok.code()
        }
        Err(err) => ctx.fail(&err).code(),
    }
}

async fn dispatch(ctx: &Context, command: cli::Command) -> Outcome {
    use cli::Command;
    match command {
        Command::Setup(a) => commands::setup(ctx, &a).await,
        Command::Upgrade(a) => commands::upgrade(ctx, &a).await,
        Command::Daemon(a) => commands::daemon(ctx, &a).await,
        Command::Status => commands::status(ctx).await,
        Command::Doctor => commands::doctor(ctx).await,
        Command::Profiles => commands::profiles(ctx).await,
        Command::Quickstart => commands::quickstart(ctx).await,
        Command::Cred { command } => match command {
            cli::CredCommand::Add(a) => commands::cred_add(ctx, &a).await,
            cli::CredCommand::List => commands::cred_list(ctx).await,
            cli::CredCommand::Rm(a) => commands::cred_rm(ctx, &a).await,
            cli::CredCommand::Rotate(a) => control_commands::cred_rotate(ctx, &a).await,
            cli::CredCommand::Test(a) => control_commands::cred_test(ctx, &a).await,
            cli::CredCommand::Expiry(a) => control_commands::cred_expiry(ctx, &a).await,
            cli::CredCommand::Scrub(a) => control_commands::cred_scrub(ctx, &a).await,
            cli::CredCommand::Pin(a) => control_commands::cred_pin(ctx, &a).await,
            cli::CredCommand::Quarantine(a) => control_commands::cred_quarantine(ctx, &a).await,
            cli::CredCommand::Release(a) => control_commands::cred_release(ctx, &a).await,
        },
        Command::Session { command } => match command {
            cli::SessionCommand::Create(a) => commands::session_create(ctx, &a).await,
            cli::SessionCommand::List => commands::session_list(ctx).await,
            cli::SessionCommand::Revoke(a) => commands::session_revoke(ctx, &a).await,
            cli::SessionCommand::Narrow(a) => control_commands::session_narrow(ctx, &a).await,
            cli::SessionCommand::Show(a) => control_commands::session_show(ctx, &a).await,
        },
        Command::Template { command } => match command {
            cli::TemplateCommand::Save(a) => control_commands::template_save(ctx, &a).await,
            cli::TemplateCommand::List => control_commands::template_list(ctx).await,
            cli::TemplateCommand::Show(a) => control_commands::template_show(ctx, &a).await,
            cli::TemplateCommand::Rm(a) => control_commands::template_rm(ctx, &a).await,
        },
        Command::Ph { command } => match command {
            cli::PhCommand::Next(a) => commands::ph_next(ctx, &a).await,
            cli::PhCommand::Check(a) => commands::ph_check(ctx, &a).await,
            cli::PhCommand::Pattern => commands::ph_pattern(ctx).await,
        },
        Command::Env(a) => commands::env(ctx, &a).await,
        Command::Exec(a) => commands::exec(ctx, &a).await,
        Command::Preflight(a) => control_commands::preflight(ctx, &a).await,
        Command::Approvals(a) => commands::approvals(ctx, &a).await,
        Command::Approve(a) => commands::approve(ctx, &a).await,
        Command::Deny(a) => commands::deny(ctx, &a).await,
        Command::Watch(a) => commands::watch(ctx, &a).await,
        Command::Notify { command } => match command {
            cli::NotifyCommand::Set(a) => control_commands::notify_set(ctx, &a).await,
            cli::NotifyCommand::Show => control_commands::notify_show(ctx).await,
            cli::NotifyCommand::Off => control_commands::notify_off(ctx).await,
            cli::NotifyCommand::Test => control_commands::notify_test(ctx).await,
        },
        Command::Panic(a) => control_commands::panic(ctx, &a).await,
        Command::Tripwire { command } => match command {
            cli::TripwireCommand::Show => control_commands::tripwire_show(ctx).await,
            cli::TripwireCommand::On => control_commands::tripwire_on(ctx).await,
            cli::TripwireCommand::Off => control_commands::tripwire_off(ctx).await,
            cli::TripwireCommand::Set(a) => control_commands::tripwire_set(ctx, &a).await,
        },
        Command::Lock => commands::lock(ctx).await,
        Command::Unlock => commands::unlock(ctx).await,
        Command::Passphrase { command } => match command {
            cli::PassphraseCommand::Set => commands::passphrase_set(ctx).await,
            cli::PassphraseCommand::Remove => commands::passphrase_remove(ctx).await,
        },
        Command::Audit { command } => match command {
            cli::AuditCommand::Tail(a) => commands::audit_tail(ctx, &a).await,
            cli::AuditCommand::Verify(a) => control_commands::audit_verify(ctx, &a).await,
            cli::AuditCommand::Export(a) => control_commands::audit_export(ctx, &a).await,
            cli::AuditCommand::Witness(a) => control_commands::audit_witness(ctx, &a).await,
        },
        Command::Report(a) => control_commands::report(ctx, &a).await,
        Command::Backup { command } => match command {
            cli::BackupCommand::Export(a) => control_commands::backup_export(ctx, &a).await,
            cli::BackupCommand::Inspect(a) => control_commands::backup_inspect(ctx, &a).await,
            cli::BackupCommand::Restore(a) => control_commands::backup_restore(ctx, &a).await,
        },
        Command::Listen { command } => match command {
            cli::ListenCommand::Add(a) => commands::listen_add(ctx, &a).await,
            cli::ListenCommand::List => commands::listen_list(ctx).await,
            cli::ListenCommand::Rm(a) => commands::listen_rm(ctx, &a).await,
        },
        Command::Tls { command } => match command {
            cli::TlsCommand::Setup(a) => commands::tls_setup(ctx, &a).await,
            cli::TlsCommand::Status => commands::tls_status(ctx).await,
        },
        Command::Ui(a) => commands::ui(ctx, &a, "").await,
        Command::Mcp(a) => match a.command {
            Some(cli::McpCommand::Url) => commands::mcp_url(ctx).await,
            Some(cli::McpCommand::Install(a)) => commands::mcp_install(ctx, &a).await,
            None => commands::mcp(ctx).await,
        },
        Command::Docs(a) => commands::docs(ctx, &a).await,
        Command::Migrate(a) => commands::migrate(ctx, &a).await,
        Command::Help { .. } => {
            print_help(ctx);
            Ok(0)
        }
    }
}

/// Print the top-level help (`{ok:true,data:{help}}` under `--json`). Ports
/// `printHelp()` in `src/cli/index.js`.
pub fn print_help(ctx: &Context) {
    let b = |s: &str| ctx.paint("1", s);
    let d = |s: &str| ctx.paint("2", s);
    let help = format!(
        "{title} - a local credential proxy for agents

{setup}
  setup [--dev] [--print-only]         install properly (--dev skips the uid boundary)
  upgrade                              reinstall the daemon from this checkout
  migrate [--dry-run] [--from D] [--to D]  move a JavaScript vault (vault.json) into vault.db
  daemon [--port N]                    run the daemon (gateway + control socket)
  status | doctor | profiles           what is running, and what is configured

{guided}                               {guided_note}
  quickstart                           credential, session, and what to give the agent
  cred add                             walks you through storing a credential
  session create                       walks you through scoping a session

{credentials}                          {cred_note}
  cred add <slug> --kind <kind> [--host H] [--expires YYYY-MM-DD]
  cred list | cred rm <slug>
  cred rotate <slug> [--field F] [--revoke] [--retire-hours N]
                                       replace the value; sessions keep working
  cred test [<slug> | --all]           run the connector's read-only probe
  cred expiry <slug> <YYYY-MM-DD|none> record when the token expires
  cred scrub <slug> [--add PATTERN [--sample TEXT] | --rm ID]
                                       extra token shapes to redact from responses
  cred pin <slug> --host H [--add sha256/...] [--rm sha256/... | --clear] [--live]
                                       refuse any TLS key you did not pin
  cred quarantine <slug> [--reason T]  stop all use at once; cred release <slug> undoes it

{sessions}
  session create --cred <slug>[,<slug>...] [--methods GET,POST] [--paths \"/repos/**\"]
                 [--budget N] [--uses N] [--approval each|on-write|first-use|auto]
                 [--ttl HOURS | --infinite] [--label TEXT] [--grants-file F]
                 [--template NAME] [--rate 60/min] [--concurrency N] [--quota 1000/day]
                 [--route GET:/repos/**]... [--payload-file F] [--graphql query]
                 [--redirects N] [--spend-tokens N] [--spend-usd X] [--grant-ttl MIN]
                                       --approval auto or first-use with writes,
                                       and --infinite, ask for your passphrase
                                       every time
  session list | session revoke [<sid>]
  session narrow [<sid>] [--cred S] [any limit above] [--ttl MIN]
                                       tighten a live session; it can never widen
  session show [<sid>] [--markdown]    what it may do, and what it did
  template save <name> --cred <slug> [session flags] | template list
  template show <name> | template rm <name>
  ph next <cred> [--uses N]            issue a placeholder
  ph check <placeholder> | ph pattern  validate one, or print the scanner regex
  env [--out F [--force]] [--map NAME=<slug>[:base_url]]... [--map-file F] [--profile-vars]
                                       placeholders for your tools; the file is 0600 and
                                       never replaced unless you say so
  exec [--map NAME=<slug>]... -- <command>
                                       run a command with a scrubbed environment
  preflight --cred S --method M --path P [--body-file F]
                                       would this request pass? nothing is sent

{approvals}
  approvals [--show <id>] | approve <id> | deny <id>
  watch [--no-notify] [--open]         tell you the moment something is waiting
  notify set | notify show | notify off | notify test
                                       an optional webhook for the same signal
  panic [--lock] [--reason T]          revoke every session, deny everything waiting
  tripwire show | tripwire on | tripwire off | tripwire set --rule ID ...
  lock | unlock                        stop and resume every proxied request
  passphrase set | passphrase remove   make the lock cryptographic (or undo it)
  audit tail [--limit N] | audit verify [--witness F]
  audit export [--since-seq N] [--out F] [--follow] | audit witness [--out F]
  report [--since 7d] [--markdown]     access review across every session
  backup export --out F | backup inspect F | backup restore F [--on-conflict skip|rename|fail]
  listen add <id> --address <iface:port> [--surfaces gateway,mcp]
                 [--tls managed | --tls-cert F --tls-key F]
  listen list | listen rm <id>
  tls setup [--port 7443]              certificate for the loopback MCP listener
  tls status                           fingerprint and expiry

{ui}
  ui [--port N] [--no-open] [--idle 30] open the web UI (single-use link, no secrets rendered)

{mcp}
  mcp                                  stdio transport (for an MCP client)
  mcp url                              the Streamable HTTP endpoint and header
  mcp install --agent <claude-code|cursor|gemini|codex> [--scope project|user]
                                       merge the server into that tool's config
                                       (--print shows the block instead)
              [--transport http --tls] a custom connector; the URL must be https

{docs}
  docs [section]                       open the docs, written against this install
                                       how | start | connect | models | locking
                                       | safety | refused | commands

{json_note}",
        title = b("agent-vault"),
        setup = b("setup"),
        guided = b("guided"),
        guided_note = d("(run these with no arguments)"),
        credentials = b("credentials"),
        cred_note = d("(the value is read from the terminal, never argv)"),
        sessions = b("sessions and placeholders"),
        approvals = b("approvals, audit, listeners"),
        ui = b("ui"),
        mcp = b("mcp"),
        docs = b("docs"),
        json_note = d("--json on any command prints a machine-readable envelope."),
    );
    ctx.out(Some(&help), &json!({ "help": help }));
}

/// How the reader is invoking this CLI, so printed commands can be pasted
/// (`agent-vault`, `av`, or the full path). Ports `cliInvocation()` in
/// `src/cli/index.js`.
pub fn cli_invocation() -> String {
    let argv0 = std::env::args().next().unwrap_or_default();
    let base = argv0.rsplit('/').next().unwrap_or("");
    if base == "agent-vault" || base == "av" {
        return base.to_string();
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for name in ["agent-vault", "av"] {
                if dir.join(name).is_file() {
                    return name.to_string();
                }
            }
        }
    }
    if argv0.is_empty() {
        "agent-vault".into()
    } else {
        argv0
    }
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
        // A single message is resent whole; the new answer replaces it.
        if !self.answers.is_array() {
            return again.to_string();
        }
        let Ok(fresh) = serde_json::from_str::<Value>(again) else {
            return serde_json::to_string(&self.answers).unwrap_or_else(|_| again.to_string());
        };
        let Value::Array(fresh) = fresh else {
            return serde_json::to_string(&self.answers).unwrap_or_else(|_| again.to_string());
        };
        let Value::Array(answers) = &self.answers else {
            return again.to_string();
        };
        let mut out = Vec::new();
        for answer in answers {
            let replaced = if refused(answer) {
                fresh
                    .iter()
                    .find(|a| json_id(a) == json_id(answer) && json_id(a).is_some())
            } else {
                None
            };
            out.push(replaced.cloned().unwrap_or_else(|| answer.clone()));
        }
        serde_json::to_string(&Value::Array(out)).unwrap_or_else(|_| self.answers.to_string())
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
    let request: Value = serde_json::from_str(line).ok()?;
    let answers: Value = serde_json::from_str(text).ok()?;
    if !request.is_array() {
        if !answers.is_array() && refused(&answers) {
            return Some(SessionRetry {
                line: line.to_string(),
                answers: answers.clone(),
            });
        }
        return None;
    }
    let (Value::Array(requests), Value::Array(answer_list)) = (&request, &answers) else {
        return None;
    };
    let redo: Vec<Value> = requests
        .iter()
        .filter(|m| {
            let Some(id) = json_id(m) else {
                return false;
            };
            answer_list
                .iter()
                .any(|a| refused(a) && json_id(a).as_ref() == Some(&id))
        })
        .cloned()
        .collect();
    if redo.is_empty() {
        return None;
    }
    Some(SessionRetry {
        line: serde_json::to_string(&Value::Array(redo)).ok()?,
        answers,
    })
}

fn json_id(value: &Value) -> Option<String> {
    let id = value.get("id")?;
    if id.is_null() {
        return None;
    }
    Some(id.to_string())
}

fn refused(answer: &Value) -> bool {
    if answer
        .get("result")
        .and_then(|r| r.get("isError"))
        .and_then(|v| v.as_bool())
        != Some(true)
    {
        return false;
    }
    let Some(text) = answer
        .pointer("/result/content/0/text")
        .and_then(|v| v.as_str())
    else {
        return false;
    };
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .as_deref()
        == Some(NEEDS_SESSION)
}

#[cfg(test)]
mod review_probes;
#[cfg(test)]
mod tests;
