//! The command handlers defined in `src/cli/index.js` (`COMMANDS`), one
//! function per key. The handlers merged in from `controlCommands` are in
//! [`crate::control_commands`]. Each returns an [`Outcome`].

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Map, Value};

use av_core::errors::Exit;
use av_core::placeholder::{self, diagnose, parse_at};
use av_core::policy::APPROVAL_ORDER;
use av_core::profiles::{get_profile, list_profiles};
use av_core::secret::ExposeSecret;
use av_store::client_state::{self, ClientState};
use av_store::migrate::{self, MigrateError, MigrateOptions, MigrateReport};
use av_store::model::FactorClass;
use av_store::pending::{self, PendingKind};
use av_store::vault::{CreateOptions, Vault};

use crate::cli::{
    ApprovalsArgs, ApproveArgs, AuditTailArgs, CredAddArgs, DaemonArgs, DenyArgs, DocsArgs,
    EnvArgs, ExecArgs, ListenAddArgs, ListenIdArg, McpInstallArgs, MigrateArgs, PhCheckArgs,
    PhNextArgs, SessionSpecArgs, SetupArgs, SidArg, SlugArg, TlsSetupArgs, UiArgs, UpgradeArgs,
    WatchArgs,
};
use crate::control_commands::{approval_preview_lines, clean_text};
use crate::files::{self, FileError};
use crate::mcp_install::{self, EntrySpec, InstallSpec};
use crate::policy_input::{
    self, boolean_flag, json_number, optional_number, session_input, text_flag, NumberLimits,
};
use crate::{
    cli_invocation, client_state_path, load_client_state, remember_created, socket_path,
    using_system, vault_dir, was_bare, CliError, Context, Outcome, SYSTEM_ROOT, SYSTEM_VAULT,
};

fn err(message: impl Into<String>, exit: Exit) -> CliError {
    CliError {
        message: message.into(),
        exit,
        next: None,
        problem: None,
        skew: false,
    }
}

fn err_next(message: impl Into<String>, exit: Exit, next: impl Into<String>) -> CliError {
    let mut e = err(message, exit);
    e.next = Some(next.into());
    e
}

fn state() -> ClientState {
    client_state::load_state(&client_state_path())
}

fn state_value() -> Value {
    load_client_state()
}

pub(crate) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn encode_component(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'~'
            | b'*'
            | b'\''
            | b'('
            | b')' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn checkout_root() -> Result<PathBuf, CliError> {
    let mut starts = vec![std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            starts.push(dir.to_path_buf());
        }
    }
    resolve_checkout_root(&starts)
}

/// Walk `starts` upward for a directory that has `package.json`, `src` and
/// `bin`. The installed tree has those too. It is `<SYSTEM_ROOT>/app`,
/// canonicalized, so `/var` and `/private/var` are the same directory. A
/// checkout whose own directory is named `app` is not that tree. Landing
/// on the installed app is skipped so a later start can still be a checkout.
/// The error is only when every start lands there.
pub(crate) fn resolve_checkout_root(starts: &[PathBuf]) -> Result<PathBuf, CliError> {
    let mut saw_installed = false;
    for start in starts {
        let mut dir = start.as_path();
        loop {
            if dir.join("package.json").is_file()
                && dir.join("src").is_dir()
                && dir.join("bin").is_dir()
            {
                if is_installed_app(dir) {
                    saw_installed = true;
                    break;
                }
                return Ok(dir.to_path_buf());
            }
            let Some(parent) = dir.parent() else { break };
            if parent == dir {
                break;
            }
            dir = parent;
        }
    }
    if saw_installed {
        return Err(err_next(
            "run agent-vault upgrade from your checkout.",
            Exit::Usage,
            "This directory is the installed app, not a checkout.",
        ));
    }
    Ok(std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// True when `dir` is the installed app, `<SYSTEM_ROOT>/app`. The comparison
/// is canonical, so the `/var` and `/private/var` spellings match. A checkout
/// that happens to be named `app` does not.
pub(crate) fn is_installed_app(dir: &Path) -> bool {
    crate::setup::canonical_prefix(dir)
        == crate::setup::canonical_prefix(&PathBuf::from(SYSTEM_ROOT).join("app"))
}

fn setup_bin() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("agent-vault-setup");
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("agent-vault-setup")
}

fn vault_present(dir: &Path) -> bool {
    dir.join("vault.json").exists() || dir.join("vault.db").exists()
}

/// Why a session spec needs fresh presence. Ports `elevationOf` in
/// `src/daemon/session-requests.js`. Duplicated here because the daemon
/// crate's copy still panics.
pub fn elevation_of(spec: &Value) -> Vec<&'static str> {
    let mut out = Vec::new();
    let Value::Object(spec) = spec else {
        return vec!["approval_auto_writes"];
    };
    if spec.get("infinite") == Some(&Value::Bool(true)) {
        out.push("infinite");
    }
    if spec.get("grants").is_some() && !spec.get("grants").is_some_and(|g| g.is_array()) {
        out.push("approval_auto_writes");
        return out;
    }
    let grants: Vec<&Value> = match spec.get("grants") {
        Some(Value::Array(g)) => g.iter().collect(),
        // A missing list is replaced below with the spec itself. A non-array
        // already returned. This arm only exists so the types agree.
        _ => Vec::new(),
    };
    // The single-spec case is the object itself, not a null stand-in.
    let owned;
    let grants: Vec<&Value> = if spec.get("grants").is_none() {
        owned = Value::Object(spec.clone());
        vec![&owned]
    } else {
        grants
    };
    let bad = grants
        .iter()
        .any(|g| !readable_grant(g) || (unasked(g) && permits_write(g)));
    if bad {
        out.push("approval_auto_writes");
    }
    out
}

fn readable_grant(g: &Value) -> bool {
    let Value::Object(g) = g else {
        return false;
    };
    let names = |v: &Value| {
        v.as_array()
            .is_some_and(|a| a.iter().all(|m| m.is_string()))
    };
    if let Some(methods) = g.get("methods") {
        if !methods.is_null() && !names(methods) {
            return false;
        }
    }
    if let Some(routes) = g.get("routes") {
        if !routes.is_null() {
            let ok = routes
                .as_array()
                .is_some_and(|rs| rs.iter().all(|r| r.get("methods").is_some_and(names)));
            if !ok {
                return false;
            }
        }
    }
    true
}

fn unasked(g: &Value) -> bool {
    matches!(
        g.get("approval").and_then(|v| v.as_str()),
        Some("auto" | "first-use")
    )
}

fn permits_write(g: &Value) -> bool {
    let mut named: Vec<String> = match g.get("methods") {
        None | Some(Value::Null) => vec!["GET".into(), "HEAD".into()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    if let Some(Value::Array(routes)) = g.get("routes") {
        for route in routes {
            if let Some(Value::Array(methods)) = route.get("methods") {
                for method in methods {
                    if let Some(s) = method.as_str() {
                        named.push(s.to_string());
                    }
                }
            }
        }
    }
    named
        .iter()
        .any(|m| !matches!(m.to_ascii_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS"))
}

pub(crate) fn looks_like_credential(name: &str, value: &str) -> bool {
    const CONFIG: &[&str] = &[
        "AGENT_VAULT_DIR",
        "AGENT_VAULT_PORT",
        "AGENT_VAULT_ALLOW_ROOT",
    ];
    if CONFIG.contains(&name) {
        return false;
    }
    let upper = name.to_ascii_uppercase();
    const WORDS: &[&str] = &[
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "APIKEY",
        "API_KEY",
        "ACCESSKEY",
        "ACCESS_KEY",
        "PRIVATEKEY",
        "PRIVATE_KEY",
        "SECRETKEY",
        "SECRET_KEY",
        "CLIENTSECRET",
        "CLIENT_SECRET",
        "CREDENTIAL",
        "CREDENTIALS",
    ];
    for word in WORDS {
        let mut from = 0;
        while let Some(at) = upper[from..].find(word) {
            let at = from + at;
            let before = at == 0 || upper.as_bytes()[at - 1] == b'_';
            let after_at = at + word.len();
            let after = after_at == upper.len() || upper.as_bytes()[after_at] == b'_';
            if before && after {
                return true;
            }
            from = at + 1;
            if from >= upper.len() {
                break;
            }
        }
    }
    if upper == "KEY" || upper.ends_with("_KEY") || upper == "DSN" || upper.ends_with("_DSN") {
        return true;
    }
    url_has_password(value)
}

/// `urlHasPassword` in `src/cli/index.js`: the password pattern anywhere in
/// the value, then WHATWG `URL.password` when the value starts with a scheme.
fn url_has_password(value: &str) -> bool {
    if url_password_anywhere(value) {
        return true;
    }
    let Ok(scheme) = av_core::jsre::compile(r"(?i)^[a-z][a-z0-9+.-]*://") else {
        return false;
    };
    if !scheme.is_match(value) {
        return false;
    }
    // `new URL` percent-encodes a space in the password (`p w` -> `p%20w`).
    // Parse the raw value, then the same value with spaces encoded, which is
    // what that constructor does when the raw form is rejected.
    parsed_url_has_password(value)
        || (value.contains(' ') && parsed_url_has_password(&value.replace(' ', "%20")))
}

fn parsed_url_has_password(value: &str) -> bool {
    url::Url::parse(value)
        .is_ok_and(|url| url.password().is_some_and(|password| !password.is_empty()))
}

fn url_password_anywhere(value: &str) -> bool {
    let Ok(pattern) = av_core::jsre::compile(r"://[^/\s:@]*:[^/\s@]+@") else {
        return false;
    };
    pattern.is_match(value)
}

/// Parent environment entries that may reach a child. Non-UTF-8 names and
/// values are dropped: `std::env::vars` panics on them, and the JS child
/// never sees a byte string it cannot decode.
pub(crate) fn kept_parent_env() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(name, value)| {
            let (name, value) = utf8_pair(&name, &value)?;
            parent_env_kept(&name, &value).then_some((name, value))
        })
        .collect()
}

/// UTF-8 environment entries, for writers that keep every variable. A
/// non-UTF-8 name or value is dropped.
pub(crate) fn utf8_env_map() -> std::collections::BTreeMap<String, String> {
    std::env::vars_os()
        .filter_map(|(name, value)| utf8_pair(&name, &value))
        .collect()
}

pub(crate) fn utf8_pair(
    name: &std::ffi::OsStr,
    value: &std::ffi::OsStr,
) -> Option<(String, String)> {
    Some((name.to_str()?.to_string(), value.to_str()?.to_string()))
}

/// Whether a parent environment variable may reach the `exec` child.
/// Generated vault variables are dropped (the child gets the ones this
/// command just computed) and anything that looks like a credential is
/// dropped. Ports the filter in `COMMANDS.exec` in `src/cli/index.js`.
pub(crate) fn parent_env_kept(name: &str, value: &str) -> bool {
    const GENERATED: &[&str] = &[
        "AGENT_VAULT",
        "AGENT_VAULT_URL",
        "AGENT_VAULT_SESSION",
        "AGENT_VAULT_PLACEHOLDER",
        "AGENT_VAULT_HINT",
    ];
    !(GENERATED.contains(&name) || looks_like_credential(name, value))
}

fn show_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "none".into(),
        other => other.to_string(),
    }
}

fn file_conflict(path: &str, error: FileError) -> CliError {
    match error {
        FileError::Exists(_) => err(
            format!("{path} exists; pass --force to replace it"),
            Exit::Conflict,
        ),
        FileError::NotRegular(message) | FileError::Symlink(message) => {
            err(message, Exit::Conflict)
        }
        FileError::NotPlaceholder => err(
            "refusing to write a value that is not a placeholder",
            Exit::Internal,
        ),
        FileError::Io(e) => err(e.to_string(), Exit::Failure),
    }
}

/// Ports `COMMANDS.setup`.
pub async fn setup(ctx: &Context, args: &SetupArgs) -> Outcome {
    let dev = boolean_flag(args.dev.then_some(""), "dev")?;
    let print_only = boolean_flag(args.print_only.then_some(""), "print-only")?;
    let port = optional_number(
        args.port.as_deref(),
        "port",
        NumberLimits {
            min: 1.0,
            max: 65535.0,
            integer: true,
        },
    )?;
    if using_system() && !dev {
        ctx.out(
            Some(&format!(
                "{} system install present {}",
                ctx.paint("32", "ok"),
                ctx.paint("2", &format!("vault at {SYSTEM_VAULT}"))
            )),
            &json!({ "mode": "system", "vault": SYSTEM_VAULT, "up_to_date": false }),
        );
        if !ctx.json {
            println!(
                "  {}",
                ctx.paint("33", "The installed daemon is not this code.")
            );
            println!(
                "  Updating reinstalls the daemon from this checkout and restarts the service."
            );
            println!("  {}", ctx.paint("36", "agent-vault upgrade"));
        }
        return Ok(0);
    }
    if !dev {
        let installer = setup_bin();
        let checkout = checkout_root()?;
        let mut cmd = format!(
            "sudo {} install --from {}",
            installer.display(),
            checkout.display()
        );
        if let Some(port) = port {
            cmd.push_str(&format!(" --port {port}"));
        }
        if ctx.json {
            ctx.out(
                None,
                &json!({ "mode": "system", "command": cmd, "installer": installer, "installed": false }),
            );
            return Ok(0);
        }
        if print_only {
            println!("{cmd}");
            return Ok(0);
        }
        println!(
            "{}",
            ctx.paint("1", "agent-vault needs one privileged step.")
        );
        println!();
        println!("  It creates a system user and gives it sole ownership of the vault, so");
        println!("  an agent running as you cannot read your credentials at all.");
        println!();
        println!("  root will run exactly one program:");
        println!("    {}", ctx.paint("36", &installer.display().to_string()));
        println!();
        println!("  {}", ctx.paint("2", "Plan:"));
        let plan = Command::new(&installer)
            .args(["install", "--dry-run"])
            .output();
        if let Ok(plan) = plan {
            let text = String::from_utf8_lossy(&plan.stdout);
            for line in text.lines().skip(2) {
                if !line.trim().is_empty() {
                    println!("  {}", ctx.paint("2", line));
                }
            }
        }
        // This process never elevates itself. A terminal used to be asked
        // "Run it now? [y/N]" and a yes was ignored. There is no question:
        // the command is printed, and a non-terminal says so the way the
        // JS client does.
        println!();
        if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            println!("  Run it yourself:");
        } else {
            println!("  No terminal here, so run it yourself:");
        }
        println!("    {}", ctx.paint("36", &cmd));
        return Ok(0);
    }
    let dir = vault_dir();
    if vault_present(&dir) {
        ctx.out(
            Some(&format!(
                "{} dev vault already at {}",
                ctx.paint("32", "ok"),
                dir.display()
            )),
            &json!({ "dir": dir, "existed": true }),
        );
        return Ok(0);
    }
    std::fs::create_dir_all(&dir).map_err(|e| err(e.to_string(), Exit::Failure))?;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    let passphrase = if boolean_flag(args.passphrase.then_some(""), "passphrase")? {
        Some(ctx.read_secret("passphrase: ")?)
    } else {
        None
    };
    let factor = if passphrase.is_some() {
        FactorClass::Passphrase
    } else {
        FactorClass::None
    };
    Vault::create(&dir, CreateOptions { factor, passphrase })
        .map_err(|e| err(e.to_string(), Exit::Failure))?;
    println!(
        "{} {} {}",
        ctx.paint("32", "created"),
        dir.display(),
        ctx.paint("2", "(mode 0700)")
    );
    println!();
    println!(
        "{}",
        ctx.paint(
            "33",
            "  Dev mode: the daemon will run as you, so the vault is protected by file"
        )
    );
    println!(
        "{}",
        ctx.paint(
            "33",
            "  mode alone. Anything running as your account can read it, including an"
        )
    );
    println!(
        "{}",
        ctx.paint(
            "33",
            "  agent. Do not put a credential here you would mind losing."
        )
    );
    println!();
    println!(
        "next: {} in one terminal, then {}",
        ctx.paint("36", "agent-vault daemon"),
        ctx.paint("36", "agent-vault cred add <slug> --kind github")
    );
    Ok(0)
}

/// Ports `COMMANDS.daemon`. The Rust daemon owns the process; this hands off.
pub async fn daemon(ctx: &Context, args: &DaemonArgs) -> Outcome {
    if using_system() {
        return Err(err_next(
            "the daemon is managed by the system service and is already running as its own user",
            Exit::Usage,
            "agent-vault status",
        ));
    }
    let port = optional_number(
        args.port.as_deref(),
        "port",
        NumberLimits {
            min: 0.0,
            max: 65535.0,
            integer: true,
        },
    )?;
    let requested = boolean_flag(args.passphrase.then_some(""), "passphrase")?;
    let secret = if requested {
        Some(ctx.read_secret("passphrase: ")?)
    } else {
        None
    };
    let passphrase = passphrase_for_daemon(requested, secret);
    // The daemon binary reads AV_VAULT_DIR and AV_RUN_DIR. Dev mode is
    // AGENT_VAULT_DIR: the vault and the control socket live in that one
    // directory. `--port` is AV_PORT (0 is ephemeral).
    let vault = vault_dir();
    let socket = socket_path();
    let run = socket
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| vault.clone());
    std::env::set_var("AV_VAULT_DIR", &vault);
    std::env::set_var("AV_RUN_DIR", &run);
    if let Some(port) = port {
        std::env::set_var("AV_PORT", (port as u16).to_string());
    }
    // `run_from_env` builds its own runtime. This command is already inside
    // the CLI runtime, so the daemon runs on a blocking thread.
    let code =
        tokio::task::spawn_blocking(move || av_daemon::run_from_env_unlocking(passphrase).code())
            .await
            .unwrap_or(Exit::Failure.code());
    Ok(code)
}

/// The passphrase `daemon --passphrase` hands to `startInRecordedState`.
/// Without the flag the secret is dropped, even if one was read.
pub(crate) fn passphrase_for_daemon(
    requested: bool,
    secret: Option<av_core::secret::SecretString>,
) -> Option<av_core::secret::SecretString> {
    if requested {
        secret
    } else {
        None
    }
}

/// Ports `COMMANDS.upgrade`.
pub async fn upgrade(ctx: &Context, args: &UpgradeArgs) -> Outcome {
    if !using_system() {
        return Err(err_next(
            "there is no system install to upgrade",
            Exit::Usage,
            "agent-vault setup   (installs it), or just restart: agent-vault daemon",
        ));
    }
    let checkout_installer = setup_bin();
    let checkout = checkout_root()?;
    let root_owned = PathBuf::from(SYSTEM_ROOT).join("app/bin/agent-vault-setup");
    let (cmd, installer, using_root) =
        format_upgrade_command(&root_owned, &checkout_installer, &checkout)?;
    if boolean_flag(args.print_only.then_some(""), "print-only")? || ctx.json {
        ctx.out(Some(&cmd), &json!({ "command": cmd }));
        return Ok(0);
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        println!(
            "Run this to update the installed daemon:\n  {}",
            ctx.paint("36", &cmd)
        );
        return Ok(0);
    }
    println!(
        "{} {}",
        ctx.paint("2", "root will run:"),
        ctx.paint("36", &installer.display().to_string())
    );
    println!(
        "{} {}",
        ctx.paint("2", "installing from:"),
        checkout.display()
    );
    if !using_root {
        println!(
            "{}",
            ctx.paint(
                "2",
                "  (the installed copy is too old to upgrade itself, so this uses the"
            )
        );
        println!(
            "{}",
            ctx.paint(
                "2",
                "   installer from your checkout; later upgrades use the root-owned one)"
            )
        );
    }
    println!();
    println!("  Run it yourself:");
    println!("    {}", ctx.paint("36", &cmd));
    Ok(0)
}

/// Whether an installed installer understands `--from`. The JS file is probed
/// for `value('from')`; a Rust binary is probed for the `--from` flag text.
pub(crate) fn installer_supports_from(bytes: &[u8]) -> bool {
    let marker_js: &[u8] = b"value('from')";
    let marker_rs: &[u8] = b"--from";
    contains_bytes(bytes, marker_js) || contains_bytes(bytes, marker_rs)
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// True when `path` is `<something>/app/bin/<file>`. The root-owned installer
/// has this shape. It is safe to run when `--from` names a checkout outside
/// `app`, because the installed bytes come from that checkout's release dir.
pub(crate) fn installer_runs_inside_app(path: &Path) -> bool {
    let Some(bin_dir) = path.parent() else {
        return false;
    };
    let Some(app) = bin_dir.parent() else {
        return false;
    };
    bin_dir.file_name().is_some_and(|name| name == "bin")
        && app.file_name().is_some_and(|name| name == "app")
}

/// Prefer the root-owned installer when it understands `--from`. An agent
/// cannot edit that binary. The checkout's release installer is only the
/// bootstrap, for an installed copy that is missing or too old to take
/// `--from`, and only when that file exists. A debug binary next to the CLI
/// is not that installer, and a release path that is not on disk is not
/// named either: both say to build the release first.
pub(crate) fn choose_upgrade_installer(
    root_owned: &Path,
    _checkout_installer: &Path,
    checkout_root: &Path,
) -> Result<(PathBuf, bool), CliError> {
    if let Ok(bytes) = std::fs::read(root_owned) {
        if installer_supports_from(&bytes) {
            return Ok((root_owned.to_path_buf(), true));
        }
    }
    let release = checkout_root.join("rust/target/release/agent-vault-setup");
    if release.is_file() && !installer_runs_inside_app(&release) {
        return Ok((release, false));
    }
    // `_checkout_installer` is the binary beside the CLI. It may be a debug
    // build, or this same missing release path. Neither is printable.
    Err(err_next(
        "the release installer is not built.",
        Exit::Usage,
        "cargo build --release first",
    ))
}

/// The line `upgrade --print-only` prints, the installer it names, and
/// whether that installer is the root-owned copy.
pub(crate) fn format_upgrade_command(
    root_owned: &Path,
    checkout_installer: &Path,
    checkout_root: &Path,
) -> Result<(String, PathBuf, bool), CliError> {
    let (installer, using_root) =
        choose_upgrade_installer(root_owned, checkout_installer, checkout_root)?;
    let cmd = format!(
        "sudo {} install --from {}",
        installer.display(),
        checkout_root.display()
    );
    Ok((cmd, installer, using_root))
}

/// Ports `COMMANDS.quickstart`.
pub async fn quickstart(ctx: &Context) -> Outcome {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(err_next(
            "quickstart needs a terminal",
            Exit::Usage,
            "agent-vault cred add <slug> --kind <kind>, then agent-vault session create --cred <slug>",
        ));
    }
    crate::wizards::quickstart(ctx).await
}

/// Ports `COMMANDS.status`.
pub async fn status(ctx: &Context) -> Outcome {
    let s = ctx.control("GET", "/v1/status", None).await?;
    if ctx.json {
        ctx.out(None, &s);
        return Ok(0);
    }
    let locked = s.get("locked").and_then(|v| v.as_bool()).unwrap_or(false);
    let version = s
        .get("daemon_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    println!(
        "{} {version}  {}",
        ctx.paint("1", "agent-vault"),
        if locked {
            ctx.paint("31", "locked")
        } else {
            ctx.paint("32", "unlocked")
        }
    );
    let port = s
        .get("gateway_port")
        .map(show_value)
        .unwrap_or_else(|| "?".into());
    println!("  gateway        http://127.0.0.1:{port}");
    println!(
        "  credentials    {}",
        s.get("credentials")
            .map(show_value)
            .unwrap_or_else(|| "0".into())
    );
    if s.get("credentials_expiring")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        > 0
    {
        println!(
            "  expiring       {}",
            s.get("credentials_expiring")
                .map(show_value)
                .unwrap_or_default()
        );
    }
    println!(
        "  sessions       {} active",
        s.get("sessions_active")
            .map(show_value)
            .unwrap_or_else(|| "0".into())
    );
    println!(
        "  grants         {} active",
        s.get("grants_active")
            .map(show_value)
            .unwrap_or_else(|| "0".into())
    );
    println!(
        "  placeholders   {} live",
        s.get("placeholders_live")
            .map(show_value)
            .unwrap_or_else(|| "0".into())
    );
    let audit = s
        .get("audit_records")
        .map(show_value)
        .unwrap_or_else(|| ctx.paint("2", "unavailable while locked"));
    println!("  audit records  {audit}");
    if let Ok(ls) = ctx.control("GET", "/v1/lockstate", None).await {
        let pass = ls
            .get("has_passphrase")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let touch = ls
            .get("has_touchid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if let Some(lines) = no_factor_status_lines(pass, touch) {
            println!();
            println!("  {}", ctx.paint("33", lines[0]));
            println!("{}", ctx.paint("2", lines[1]));
            println!("{}", ctx.paint("2", lines[2]));
            println!("  {}", ctx.paint("36", "agent-vault passphrase set"));
        }
    }
    Ok(0)
}

/// Ports `COMMANDS['cred:add']`.
pub async fn cred_add(ctx: &Context, args: &CredAddArgs) -> Outcome {
    let slug = args.slug.clone();
    if slug.is_none() && !ctx.json {
        if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            return Err(err_next(
                "cred add needs a name when there is no terminal",
                Exit::Usage,
                "agent-vault cred add <slug> --kind github   (value on stdin)",
            ));
        }
        return crate::wizards::credential_wizard(ctx, None).await;
    }
    let Some(slug) = slug else {
        return Err(err(
            "usage: agent-vault cred add <slug> --kind <kind> [--host <host>]",
            Exit::Usage,
        ));
    };
    let expires_at = if args.expires.is_some() {
        policy_input::expiry_input(args.expires.as_deref())?
    } else {
        None
    };
    let value = ctx.read_secret(&format!("value for {slug} (not echoed): "))?;
    if value.expose_secret().is_empty() {
        return Err(err("no value given", Exit::Usage));
    }
    let mut body = Map::new();
    body.insert("slug".into(), Value::from(slug));
    body.insert(
        "kind".into(),
        Value::from(args.kind.clone().unwrap_or_else(|| "http".into())),
    );
    if let Some(host) = &args.host {
        body.insert("host".into(), Value::from(host.clone()));
    }
    if let Some(scheme) = &args.scheme {
        body.insert("scheme".into(), Value::from(scheme.clone()));
    }
    body.insert(
        "value".into(),
        Value::from(value.expose_secret().to_string()),
    );
    if let Some(expires) = expires_at {
        body.insert("expires_at".into(), Value::from(expires));
    }
    let cred = ctx
        .control_with_presence("POST", "/v1/credentials", Some(&Value::Object(body)))
        .await?;
    let fp = cred
        .pointer("/fields/0/fp8")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let kind = cred.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let slug = cred.get("slug").and_then(|v| v.as_str()).unwrap_or("");
    let sites = cred
        .pointer("/fields/0/sites")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let human = format!(
        "{} {slug} {}\n  placeholder goes at: {sites}",
        ctx.paint("32", "added"),
        ctx.paint("2", &format!("({kind}, fingerprint {fp})"))
    );
    ctx.out(Some(&human), &cred);
    if let Some(warnings) = cred.get("warnings").and_then(|v| v.as_array()) {
        for warning in warnings {
            if let Some(text) = warning.as_str() {
                eprintln!("{} {text}", ctx.paint("33", "note"));
            }
        }
    }
    Ok(0)
}

/// Ports `COMMANDS['cred:list']`.
pub async fn cred_list(ctx: &Context) -> Outcome {
    let creds = ctx.control("GET", "/v1/credentials", None).await?;
    if ctx.json {
        ctx.out(None, &creds);
        return Ok(0);
    }
    let Some(list) = creds.as_array() else {
        return Ok(0);
    };
    if list.is_empty() {
        println!("{}", ctx.paint("2", "no credentials yet"));
        return Ok(0);
    }
    for c in list {
        let slug = c.get("slug").and_then(|v| v.as_str()).unwrap_or("");
        let kind = c.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let host = c
            .pointer("/connector/host")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        println!(
            "{} {} {}",
            ctx.paint("1", slug),
            ctx.paint("2", kind),
            ctx.paint("2", host)
        );
        match c.get("expiry_warning").and_then(|v| v.as_str()) {
            Some("expired") => println!("  {}", ctx.paint("31", "expired")),
            Some("soon") => println!("  {}", ctx.paint("33", "expires soon")),
            _ => {}
        }
        if let Some(health) = c.pointer("/health/status").and_then(|v| v.as_str()) {
            println!("  health: {}", clean_text(health));
        }
        if c.get("quarantine").is_some_and(|v| !v.is_null()) {
            println!("  {}", ctx.paint("33", "quarantined"));
        }
        if let Some(Value::Object(pins)) = c.get("pins") {
            for (host, n) in pins {
                println!("  pinned: {} ({})", clean_text(host), show_value(n));
            }
        }
        if let Some(fields) = c.get("fields").and_then(|v| v.as_array()) {
            for f in fields {
                let name = f.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let fp = f.get("fp8").and_then(|v| v.as_str()).unwrap_or("");
                let sites = f
                    .get("sites")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                println!("  {name} {}", ctx.paint("2", &cred_field_label(fp, &sites)));
            }
        }
    }
    Ok(0)
}

/// Ports `COMMANDS['cred:rm']`.
pub async fn cred_rm(ctx: &Context, args: &SlugArg) -> Outcome {
    let slug = text_flag(args.slug.as_deref(), "credential")?;
    ctx.control_with_presence(
        "DELETE",
        &format!("/v1/credentials?slug={}", encode_component(slug)),
        None,
    )
    .await?;
    ctx.out(
        Some(&format!("{} {slug}", ctx.paint("32", "removed"))),
        &json!({ "removed": slug }),
    );
    Ok(0)
}

/// Status text when neither factor is enrolled. `None` once one is.
pub(crate) fn no_factor_status_lines(pass: bool, touch: bool) -> Option<[&'static str; 3]> {
    if pass || touch {
        return None;
    }
    Some([
        "no human factor is enrolled",
        "  Anything running as you can use every credential here, and can set a",
        "  passphrase of its own — after which the vault is no longer yours.",
    ])
}

/// Doctor's human-factor row: not enrolled until a passphrase or authenticator exists.
pub(crate) fn doctor_factor_note(pass: bool, touch: bool) -> (bool, String) {
    if pass || touch {
        let mut parts = Vec::new();
        if pass {
            parts.push("passphrase");
        }
        if touch {
            parts.push("authenticator");
        }
        (true, parts.join(" + "))
    } else {
        (
            false,
            "none: anything running as you can use every credential, and can claim the vault by setting its own passphrase. Run: agent-vault passphrase set".into(),
        )
    }
}

/// Doctor always asks whether the audit chain is intact, and only a boolean `ok` counts.
pub(crate) fn doctor_audit_check(chain: &Value) -> (&'static str, bool) {
    (
        "audit chain intact",
        chain.get("ok").and_then(|v| v.as_bool()) == Some(true),
    )
}

/// The human `cred list` field line: fingerprint and injection site, never the value.
pub(crate) fn cred_field_label(fp: &str, sites: &str) -> String {
    format!("fp:{fp} -> {sites}")
}

/// The stdio command `mcp install` writes. Project scope with a shim on `PATH`
/// stays portable; an installed user scope names the system binary.
pub(crate) fn mcp_launch(
    portable: bool,
    shim: Option<&str>,
    use_system: bool,
    system_bin: &str,
    current_exe: &str,
) -> (String, Vec<String>) {
    let args = vec!["mcp".into()];
    if portable {
        (shim.unwrap_or("agent-vault").to_string(), args)
    } else if use_system {
        (system_bin.to_string(), args)
    } else {
        (current_exe.to_string(), args)
    }
}

/// Copy the reviewed template's hash onto the session body. Ports
/// `body.template_hash = template.hash` in `src/cli/index.js`.
pub(crate) fn bind_template_hash(body: &mut Map<String, Value>, template: &Value) {
    if let Some(hash) = template.get("hash").cloned() {
        body.insert("template_hash".into(), hash);
    }
}

/// The line `approve` prints: what was granted, not the agent's ask.
/// Ports the `describeGranted` branch of `COMMANDS.approve`.
pub(crate) fn approval_human(answered: &Value) -> String {
    let granted = answered.get("granted").cloned().unwrap_or(Value::Null);
    if granted.is_object() {
        pending::describe_granted(&granted)
    } else {
        answered
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }
}

/// Ports `COMMANDS['session:create']`.
pub async fn session_create(ctx: &Context, args: &SessionSpecArgs) -> Outcome {
    let no_spec = args.cred.is_none() && args.grants_file.is_none() && args.template.is_none();
    if no_spec && !ctx.json && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return crate::wizards::session_wizard(ctx, None).await;
    }
    if no_spec {
        return Err(err(
            "usage: agent-vault session create --cred <slug>[,<slug>...] [--methods GET,POST] [--paths \"/repos/**\"] [--approval MODE] [--ttl HOURS | --infinite]",
            Exit::Usage,
        ));
    }
    let mut body = match session_input(args)? {
        Value::Object(m) => m,
        other => return Err(err(format!("session spec was {other}"), Exit::Usage)),
    };
    let mut template = None;
    if let Some(name) = body
        .get("template")
        .and_then(|v| v.as_str())
        .map(str::to_string)
    {
        let got = ctx
            .control(
                "GET",
                &format!("/v1/templates?name={}", encode_component(&name)),
                None,
            )
            .await?;
        bind_template_hash(&mut body, &got);
        if !ctx.json {
            let summary = got
                .get("summary")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    format!(
                        "template {} v{}",
                        got.get("name").and_then(|v| v.as_str()).unwrap_or(&name),
                        got.get("version")
                            .map(show_value)
                            .unwrap_or_else(|| "?".into())
                    )
                });
            println!("{}", clean_text(&summary));
        }
        template = Some(got);
    } else if !body.contains_key("label") {
        body.insert("label".into(), Value::from("cli session"));
    }
    let body_value = Value::Object(body.clone());
    let s = ctx
        .control_with_presence("POST", "/v1/sessions", Some(&body_value))
        .await?;
    let _ = remember_created(&s);
    if ctx.json {
        ctx.out(None, &s);
        return Ok(0);
    }
    let sid = s.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
    if s.get("infinite").and_then(|v| v.as_bool()) == Some(true) {
        println!(
            "{} {sid} {}",
            ctx.paint("32", "session"),
            ctx.paint("33", "never expires")
        );
        println!(
            "  {}",
            ctx.paint(
                "2",
                &format!("revoke it with: agent-vault session revoke {sid}")
            )
        );
    } else {
        let exp = s.get("expires_at").and_then(|v| v.as_str()).unwrap_or("");
        println!(
            "{} {sid} {}",
            ctx.paint("32", "session"),
            ctx.paint("2", &format!("expires {exp}"))
        );
    }
    let specs = template
        .as_ref()
        .and_then(|t| t.get("spec"))
        .map(|spec| {
            spec.get("grants")
                .and_then(|g| g.as_array())
                .cloned()
                .unwrap_or_else(|| vec![spec.clone()])
        })
        .or_else(|| body.get("grants").and_then(|g| g.as_array()).cloned())
        .unwrap_or_else(|| vec![Value::Object(body.clone())]);
    let grants = s
        .get("grants")
        .and_then(|g| g.as_array())
        .cloned()
        .unwrap_or_else(|| vec![s.clone()]);
    for g in &grants {
        if let Some(url) = g.get("base_url").and_then(|v| v.as_str()) {
            println!("  base url     {url}");
        }
        if let Some(ph) = g.get("placeholder").and_then(|v| v.as_str()) {
            println!("  placeholder  {ph}");
        }
        if let Some(usage) = g.get("usage").and_then(|v| v.as_array()) {
            let joined = usage
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" | ");
            println!("  put it at    {joined}");
        }
        if let Some(exp) = g.get("expires_at").and_then(|v| v.as_str()) {
            println!("  expires      {exp}");
        }
        let cred = g.get("cred").and_then(|v| v.as_str());
        let spec = specs
            .iter()
            .find(|x| x.get("cred").and_then(|v| v.as_str()) == cred)
            .unwrap_or(&specs[0]);
        let reasons = elevation_of(spec);
        if reasons.contains(&"approval_auto_writes") {
            if spec.get("approval").and_then(|v| v.as_str()) == Some("first-use") {
                println!(
                    "  {}   first-use: after the first request, writes go through without asking you",
                    ctx.paint("33", "approval")
                );
            } else {
                println!(
                    "  {}   auto: writes go through without asking you",
                    ctx.paint("33", "approval")
                );
            }
        }
        if let Some(lint) = g.get("lint").and_then(|v| v.as_array()) {
            for problem in lint {
                let level = problem.get("level").and_then(|v| v.as_str()).unwrap_or("");
                let message = problem
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let tag = if level == "error" {
                    ctx.paint("31", "lint")
                } else {
                    ctx.paint("33", "lint")
                };
                println!("  {tag} {message}");
            }
        }
    }
    let site = s
        .get("usage")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let base = s.get("base_url").and_then(|v| v.as_str()).unwrap_or("");
    let probe = s.get("probe_path").and_then(|v| v.as_str()).unwrap_or("/");
    let token = s.get("token").and_then(|v| v.as_str()).unwrap_or("");
    println!();
    println!("{}", ctx.paint("2", "  try:"));
    for line in try_command_lines(base, probe, token, site) {
        println!("{}", ctx.paint("2", &line));
    }
    Ok(0)
}

/// The `try:` curl. The session token is `AV-Session`. A header injection
/// site is one more `-H`, so `Authorization` appears once.
pub(crate) fn try_command_lines(base: &str, probe: &str, token: &str, site: &str) -> Vec<String> {
    let mut lines = vec![
        format!("    curl \"{base}{probe}\" \\"),
        format!("      -H \"AV-Session: {token}\" \\"),
    ];
    if header_site(site) {
        lines.push(format!("      -H \"{site}\""));
    } else {
        lines.push(format!("      # then put the placeholder at: {site}"));
    }
    lines
}

fn header_site(site: &str) -> bool {
    let Some((name, rest)) = site.split_once(':') else {
        return false;
    };
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && rest.starts_with([' ', '\t'])
}

/// Ports `COMMANDS['session:list']`.
pub async fn session_list(ctx: &Context) -> Outcome {
    let sessions = ctx.control("GET", "/v1/sessions", None).await?;
    if ctx.json {
        ctx.out(None, &sessions);
        return Ok(0);
    }
    let Some(list) = sessions.as_array() else {
        return Ok(0);
    };
    for s in list {
        let state_name = s.get("state").and_then(|v| v.as_str()).unwrap_or("");
        let state = if state_name == "active" {
            ctx.paint("32", state_name)
        } else {
            ctx.paint("2", state_name)
        };
        let modes: Vec<&str> = s
            .get("creds")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .map(|c| c.get("approval").and_then(|v| v.as_str()).unwrap_or("auto"))
                    .collect()
            })
            .unwrap_or_default();
        let rank = |m: &str| {
            APPROVAL_ORDER
                .iter()
                .position(|x| *x == m)
                .unwrap_or(APPROVAL_ORDER.len())
        };
        let mode = modes
            .iter()
            .copied()
            .reduce(|a, b| if rank(b) > rank(a) { b } else { a })
            .unwrap_or("-");
        let mut badges = String::new();
        if s.get("elevated")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty())
        {
            badges.push_str(&ctx.paint("33", "elevated"));
            badges.push(' ');
        }
        if s.get("infinite").and_then(|v| v.as_bool()) == Some(true) {
            badges.push_str(&ctx.paint("33", "infinite"));
            badges.push(' ');
        }
        let expiry = if s.get("infinite").and_then(|v| v.as_bool()) == Some(true) {
            "never".into()
        } else {
            s.get("expires_at")
                .map(show_value)
                .unwrap_or_else(|| "-".into())
        };
        let id = s.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let label = clean_text(s.get("label").and_then(|v| v.as_str()).unwrap_or(""));
        let grants = s
            .get("grants")
            .map(show_value)
            .unwrap_or_else(|| "0".into());
        println!(
            "{id}  {state}  {label} {badges}{}",
            ctx.paint(
                "2",
                &format!("grants:{grants} approval:{mode} expires:{expiry}")
            )
        );
    }
    Ok(0)
}

/// Ports `COMMANDS['session:revoke']`.
pub async fn session_revoke(ctx: &Context, args: &SidArg) -> Outcome {
    let sid = args
        .sid
        .clone()
        .or_else(|| state().session_id)
        .unwrap_or_default();
    ctx.control(
        "DELETE",
        &format!("/v1/sessions?sid={}", encode_component(&sid)),
        None,
    )
    .await?;
    ctx.out(
        Some(&ctx.paint("32", "revoked")),
        &json!({ "revoked": true }),
    );
    Ok(0)
}

/// Ports `COMMANDS['ph:next']`.
pub async fn ph_next(ctx: &Context, args: &PhNextArgs) -> Outcome {
    let cred = text_flag(args.cred.as_deref(), "cred")
        .map_err(|_| err("usage: agent-vault ph next <cred>", Exit::Usage))?;
    let uses = optional_number(
        args.uses.as_deref(),
        "uses",
        NumberLimits {
            min: 1.0,
            ..NumberLimits::default()
        },
    )?;
    let mut body = Map::new();
    body.insert("cred".into(), Value::from(cred));
    let sid = args
        .session
        .clone()
        .or_else(|| state().session_id)
        .unwrap_or_default();
    body.insert("sid".into(), Value::from(sid));
    if let Some(uses) = uses {
        body.insert("uses".into(), json_number(uses));
    }
    let r = ctx
        .control_with_presence("POST", "/v1/placeholders", Some(&Value::Object(body)))
        .await?;
    if let Some(ph) = r.get("placeholder").and_then(|v| v.as_str()) {
        let patch = ClientState {
            placeholder: Some(ph.to_string()),
            ..ClientState::default()
        };
        let _ = client_state::save_state(&patch, &client_state_path());
    }
    if ctx.json {
        ctx.out(None, &r);
        return Ok(0);
    }
    if let Some(ph) = r.get("placeholder").and_then(|v| v.as_str()) {
        println!("{ph}");
    }
    let usage = r
        .get("usage")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .unwrap_or_default();
    eprintln!("{}", ctx.paint("2", &format!("put it at: {usage}")));
    Ok(0)
}

/// Ports `COMMANDS['ph:check']`.
pub async fn ph_check(ctx: &Context, args: &PhCheckArgs) -> Outcome {
    let text = match &args.placeholder {
        Some(s) => s.trim().to_string(),
        None => ctx.read_secret("")?.expose_secret().trim().to_string(),
    };
    let parsed = parse_at(&text, 0);
    if parsed.as_ref().is_none_or(|p| p.text != text) {
        return Err(err(
            format!("not a valid placeholder: {}", diagnose(&text)),
            Exit::Placeholder,
        ));
    }
    let parsed = parsed.expect("checked");
    ctx.out(
        Some(&format!(
            "{} session {}, credential {}, field {}",
            ctx.paint("32", "well formed"),
            parsed.sid,
            parsed.slug,
            parsed.field
        )),
        &json!({
            "text": parsed.text,
            "sid": parsed.sid,
            "slug": parsed.slug,
            "field": parsed.field,
        }),
    );
    Ok(0)
}

/// Ports `COMMANDS['ph:pattern']`.
pub async fn ph_pattern(ctx: &Context) -> Outcome {
    ctx.out(
        Some(placeholder::SCANNER_PATTERN),
        &json!({ "pattern": placeholder::SCANNER_PATTERN }),
    );
    Ok(0)
}

/// Ports `COMMANDS.env`.
pub async fn env(ctx: &Context, args: &EnvArgs) -> Outcome {
    let force = boolean_flag(args.force.then_some(""), "force")?;
    if force && args.out.is_none() {
        return Err(err("--force needs --out", Exit::Usage));
    }
    if !wants_mapping(args) && args.out.is_none() {
        return legacy_env(ctx);
    }
    let format = args.format.as_deref().unwrap_or("dotenv");
    if format != "dotenv" && format != "shell" {
        return Err(err("--format is dotenv or shell", Exit::Usage));
    }
    if args.out.as_deref().is_some_and(|s| s.is_empty()) {
        return Err(err("--out needs a file name", Exit::Usage));
    }
    let mappings = parse_mappings(args)?;
    // Canonicalize fails when the file does not exist. Resolve against cwd instead.
    let target = args.out.as_ref().map(|p| {
        let path = PathBuf::from(p);
        if path.is_absolute() {
            path
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
        }
    });
    let mut force = force;
    if let Some(target) = &target {
        match inspect_target(target) {
            "foreign" => {
                return Err(err(
                    format!(
                        "{} is not a regular file you own",
                        args.out.as_deref().unwrap_or("")
                    ),
                    Exit::Conflict,
                ));
            }
            "file" if !force => {
                if std::io::IsTerminal::is_terminal(&std::io::stdin()) && !ctx.json {
                    let answer = ctx.ask(&format!(
                        "{} exists. Replace it? [y/N] ",
                        args.out.as_deref().unwrap_or("")
                    ))?;
                    let yes = answer.trim().eq_ignore_ascii_case("y")
                        || answer.trim().eq_ignore_ascii_case("yes");
                    if yes {
                        force = true;
                    } else {
                        return Err(err(
                            format!(
                                "{} exists; pass --force to replace it",
                                args.out.as_deref().unwrap_or("")
                            ),
                            Exit::Conflict,
                        ));
                    }
                } else {
                    return Err(err(
                        format!(
                            "{} exists; pass --force to replace it",
                            args.out.as_deref().unwrap_or("")
                        ),
                        Exit::Conflict,
                    ));
                }
            }
            _ => {}
        }
    }
    let resolved = resolve_mappings(
        ctx,
        args.session.as_deref(),
        args.uses.as_deref(),
        args.profile_vars,
        mappings,
        "env",
    )
    .await?;
    let prefix = if format == "shell" { "export " } else { "" };
    let mut lines = vec![
        "# agent-vault env file: these are placeholders, not secrets.".to_string(),
        format!(
            "# session {}, written {} by agent-vault env",
            resolved.sid,
            chrono_now()
        ),
    ];
    for entry in &resolved.entries {
        lines.push(format!("{prefix}{}={}", entry.name, entry.value));
    }
    let text = format!("{}\n", lines.join("\n"));
    let described: Vec<Value> = resolved
        .entries
        .iter()
        .map(|e| {
            let mut row = Map::new();
            row.insert("name".into(), Value::from(e.name.clone()));
            row.insert("kind".into(), Value::from(e.kind.clone()));
            row.insert("cred".into(), Value::from(e.cred.clone()));
            if let Some(field) = &e.field {
                row.insert("field".into(), Value::from(field.clone()));
            }
            Value::Object(row)
        })
        .collect();
    let Some(target) = target else {
        if ctx.json {
            let mut entries = Vec::new();
            for e in &resolved.entries {
                let mut row = Map::new();
                row.insert("name".into(), Value::from(e.name.clone()));
                row.insert("kind".into(), Value::from(e.kind.clone()));
                row.insert("cred".into(), Value::from(e.cred.clone()));
                if let Some(field) = &e.field {
                    row.insert("field".into(), Value::from(field.clone()));
                }
                row.insert("value".into(), Value::from(e.value.clone()));
                entries.push(Value::Object(row));
            }
            ctx.out(
                None,
                &json!({
                    "path": null, "session_id": resolved.sid, "format": format,
                    "mode": null, "replaced": false, "entries": entries,
                }),
            );
        } else {
            print!("{text}");
        }
        return Ok(0);
    };
    let replaced = files::write_file_exclusive(&target, &text, force, 0o600)
        .map_err(|e| file_conflict(args.out.as_deref().unwrap_or(""), e))?;
    if replaced {
        eprintln!("replaced {}", args.out.as_deref().unwrap_or(""));
    }
    if git_would_commit(&target) {
        eprintln!(
            "{} {} is inside a git repository and is not ignored",
            ctx.paint("33", "note"),
            args.out.as_deref().unwrap_or("")
        );
    }
    ctx.out(
        Some(&format!(
            "{} {} {}",
            ctx.paint("32", "wrote"),
            args.out.as_deref().unwrap_or(""),
            ctx.paint(
                "2",
                &format!("({} entries, mode 0600)", resolved.entries.len())
            )
        )),
        &json!({
            "path": target, "session_id": resolved.sid, "format": format,
            "mode": "0600", "replaced": replaced, "entries": described,
        }),
    );
    Ok(0)
}

/// Shell lines for a recorded session. A missing placeholder unsets any
/// earlier one, and every value is single-quoted. Ports `legacyEnv` in
/// `src/cli/index.js`.
pub(crate) fn legacy_env_lines(token: &str, port: u16, placeholder: Option<&str>) -> Vec<String> {
    let mut lines = vec![
        format!("export AGENT_VAULT={}", shell_quote("1")),
        format!(
            "export AGENT_VAULT_URL={}",
            shell_quote(&format!("http://127.0.0.1:{port}"))
        ),
        format!("export AGENT_VAULT_SESSION={}", shell_quote(token)),
    ];
    if let Some(ph) = placeholder {
        lines.push(format!(
            "export AGENT_VAULT_PLACEHOLDER={}",
            shell_quote(ph)
        ));
    }
    lines.push(format!(
        "export AGENT_VAULT_HINT={}",
        shell_quote(
            "Credentials are placeholders. Put one only where the usage says. On AV_PH_EXHAUSTED run: agent-vault ph next <cred>"
        )
    ));
    if placeholder.is_none() {
        lines.push("unset AGENT_VAULT_PLACEHOLDER".into());
    }
    lines
}

fn legacy_env(ctx: &Context) -> Outcome {
    let st = state();
    let Some(token) = st.token else {
        return Err(err_next(
            "no session yet",
            Exit::Session,
            "agent-vault session create --cred <slug>",
        ));
    };
    let port = ctx.gateway_port_of(&state_value());
    let lines = legacy_env_lines(&token, port, st.placeholder.as_deref());
    ctx.out(Some(&lines.join("\n")), &json!({ "env": lines }));
    Ok(0)
}

fn wants_mapping(args: &EnvArgs) -> bool {
    !args.map.is_empty() || args.map_file.is_some() || args.profile_vars
}

struct Mapping {
    name: String,
    kind: String,
    cred: Option<String>,
    field: Option<String>,
}

struct Resolved {
    sid: String,
    port: u16,
    entries: Vec<EnvEntryOut>,
}

struct EnvEntryOut {
    name: String,
    kind: String,
    cred: Option<String>,
    field: Option<String>,
    value: String,
}

fn parse_mappings_from(map: &[String], map_file: Option<&str>) -> Result<Vec<Mapping>, CliError> {
    let mut out = Vec::new();
    let mut names = Vec::new();
    let mut add = |raw: &str, where_: &str| -> Result<(), CliError> {
        let eq = raw.find('=');
        let name = eq.map(|i| &raw[..i]).unwrap_or("");
        if !env_name_ok(name) {
            return Err(err(
                format!("{where_}: not a NAME=SPEC mapping"),
                Exit::Usage,
            ));
        }
        let spec = eq.map(|i| &raw[i + 1..]).unwrap_or("");
        let Some(parsed) = parse_spec(spec) else {
            return Err(err(
                format!("{where_} ({name}): expected <slug>, <slug>.<field>, <slug>:base_url or :gateway"),
                Exit::Usage,
            ));
        };
        if names.iter().any(|n| n == name) {
            return Err(err(format!("{name} is mapped twice"), Exit::Usage));
        }
        names.push(name.to_string());
        out.push(Mapping {
            name: name.to_string(),
            ..parsed
        });
        Ok(())
    };
    for raw in map {
        add(raw, "--map")?;
    }
    if let Some(path) = map_file {
        if path.is_empty() {
            return Err(err("--map-file needs a file name", Exit::Usage));
        }
        let text = std::fs::read_to_string(path).map_err(|e| {
            err(
                format!("cannot read --map-file: {}", io_code(&e)),
                Exit::Usage,
            )
        })?;
        for (i, line) in text.lines().enumerate() {
            let trimmed = line.trim().trim_start_matches("export ").trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            add(trimmed, &format!("--map-file line {}", i + 1))?;
        }
    }
    if out.len() > 64 {
        return Err(err("at most 64 names can be mapped", Exit::Usage));
    }
    Ok(out)
}

fn parse_mappings(args: &EnvArgs) -> Result<Vec<Mapping>, CliError> {
    parse_mappings_from(&args.map, args.map_file.as_deref())
}

fn env_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn parse_spec(spec: &str) -> Option<Mapping> {
    if spec == ":gateway" {
        return Some(Mapping {
            name: String::new(),
            kind: "url".into(),
            cred: None,
            field: None,
        });
    }
    if let Some(slug) = spec.strip_suffix(":base_url") {
        if !slug.contains([':', '.']) && placeholder::is_valid_slug(slug) {
            return Some(Mapping {
                name: String::new(),
                kind: "url".into(),
                cred: Some(slug.to_string()),
                field: None,
            });
        }
        return None;
    }
    let mut parts = spec.split('.');
    let slug = parts.next().unwrap_or("");
    let field = parts.next();
    if parts.next().is_some() || !placeholder::is_valid_slug(slug) {
        return None;
    }
    if let Some(field) = field {
        if !placeholder::is_valid_field(field) {
            return None;
        }
    }
    Some(Mapping {
        name: String::new(),
        kind: "placeholder".into(),
        cred: Some(slug.to_string()),
        field: field.map(str::to_string),
    })
}

fn io_code(err: &std::io::Error) -> String {
    match err.raw_os_error() {
        Some(2) => "ENOENT".into(),
        Some(13) => "EACCES".into(),
        Some(17) => "EEXIST".into(),
        Some(20) => "ENOTDIR".into(),
        Some(21) => "EISDIR".into(),
        Some(62) => "ELOOP".into(),
        Some(6) => "ENXIO".into(),
        Some(1) => "EPERM".into(),
        Some(22) => "EINVAL".into(),
        Some(5) => "EIO".into(),
        _ => err.to_string(),
    }
}

async fn resolve_mappings(
    ctx: &Context,
    session_flag: Option<&str>,
    uses_flag: Option<&str>,
    profile_vars: bool,
    mut mappings: Vec<Mapping>,
    purpose: &str,
) -> Result<Resolved, CliError> {
    if session_flag.is_some_and(|s| s.is_empty()) {
        return Err(err("--session needs a session id", Exit::Usage));
    }
    let sid = session_flag
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| state().session_id);
    let Some(sid) = sid else {
        return Err(err_next(
            "no session yet",
            Exit::Session,
            "agent-vault session create --cred <slug>",
        ));
    };
    let uses = if let Some(text) = uses_flag {
        if text.is_empty()
            || text.parse::<u64>().ok().filter(|n| *n >= 1).is_none()
            || text.chars().any(|c| !c.is_ascii_digit())
        {
            return Err(err("--uses must be a whole number, 1 or more", Exit::Usage));
        }
        Some(text.parse::<u64>().unwrap_or(0))
    } else {
        None
    };
    let sessions = ctx.control("GET", "/v1/sessions", None).await?;
    let session = sessions
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|s| s.get("id").and_then(|v| v.as_str()) == Some(sid.as_str()))
        })
        .cloned()
        .ok_or_else(|| {
            err_next(
                format!("no session {sid}"),
                Exit::NotFound,
                "agent-vault session list",
            )
        })?;
    let slugs: Vec<String> = session
        .get("creds")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|c| c.get("slug").and_then(|v| v.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if profile_vars {
        let _ = boolean_flag(Some(""), "profile-vars")?;
        let creds = ctx.control("GET", "/v1/credentials", None).await?;
        let mut taken: Vec<String> = mappings.iter().map(|m| m.name.clone()).collect();
        for slug in &slugs {
            let kind = creds.as_array().and_then(|a| {
                a.iter().find_map(|c| {
                    (c.get("slug").and_then(|v| v.as_str()) == Some(slug.as_str()))
                        .then(|| c.get("kind").and_then(|v| v.as_str()).unwrap_or("http"))
                        .map(str::to_string)
                })
            });
            let Some(env) = kind
                .as_deref()
                .and_then(|k| get_profile(k).ok())
                .and_then(|p| p.env)
            else {
                continue;
            };
            for (name, kind_name, cred) in [
                (env.key, "placeholder", slug.clone()),
                (env.base, "url", slug.clone()),
            ] {
                if taken.iter().any(|n| n == name) {
                    continue;
                }
                taken.push(name.to_string());
                mappings.push(Mapping {
                    name: name.to_string(),
                    kind: kind_name.into(),
                    cred: Some(cred),
                    field: None,
                });
            }
        }
        if mappings.len() > 64 {
            return Err(err("at most 64 names can be mapped", Exit::Usage));
        }
    }
    if mappings.is_empty() {
        return Err(err(
            "nothing to map: pass --map NAME=<slug>, --map-file F or --profile-vars",
            Exit::Usage,
        ));
    }
    for m in &mappings {
        if let Some(cred) = &m.cred {
            if !slugs.iter().any(|s| s == cred) {
                return Err(err_next(
                    format!("{cred} is not in session {sid}"),
                    Exit::NotFound,
                    "agent-vault session list",
                ));
            }
        }
    }
    let status = ctx.control("GET", "/v1/status", None).await?;
    let port = status
        .get("gateway_port")
        .and_then(|v| v.as_u64())
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(7411);
    let mut wanted: Vec<(String, Value)> = Vec::new();
    for m in &mappings {
        if m.kind == "placeholder" {
            let key = format!(
                "{}\u{0}{}",
                m.cred.as_deref().unwrap_or(""),
                m.field.as_deref().unwrap_or("")
            );
            if wanted.iter().any(|(k, _)| k == &key) {
                continue;
            }
            let mut item = Map::new();
            item.insert(
                "cred".into(),
                Value::from(m.cred.clone().unwrap_or_default()),
            );
            if let Some(field) = &m.field {
                item.insert("field".into(), Value::from(field.clone()));
            }
            if let Some(uses) = uses {
                item.insert("uses".into(), json!(uses));
            }
            wanted.push((key, Value::Object(item)));
        }
    }
    let mut issued: Vec<(String, Value)> = Vec::new();
    if !wanted.is_empty() {
        let items: Vec<Value> = wanted.iter().map(|(_, v)| v.clone()).collect();
        let batch = ctx
            .control_with_presence(
                "POST",
                "/v1/placeholders/batch",
                Some(&json!({ "sid": sid, "items": items, "purpose": purpose })),
            )
            .await?;
        let rows = batch
            .get("items")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for (i, (key, _)) in wanted.iter().enumerate() {
            if let Some(row) = rows.get(i) {
                issued.push((key.clone(), row.clone()));
            }
        }
    }
    let mut entries = Vec::new();
    for m in &mappings {
        if m.kind == "url" {
            let value = match &m.cred {
                Some(cred) => format!("http://127.0.0.1:{port}/p/{cred}"),
                None => format!("http://127.0.0.1:{port}"),
            };
            entries.push(files::EnvEntry {
                name: m.name.clone(),
                value,
                cred: m.cred.clone().unwrap_or_default(),
            });
            continue;
        }
        let key = format!(
            "{}\u{0}{}",
            m.cred.as_deref().unwrap_or(""),
            m.field.as_deref().unwrap_or("")
        );
        let got = issued.iter().find(|(k, _)| k == &key).map(|(_, v)| v);
        let value = got
            .and_then(|g| g.get("placeholder"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let field = got
            .and_then(|g| g.get("field"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| m.field.clone());
        entries.push(files::EnvEntry {
            name: m.name.clone(),
            value: value.clone(),
            cred: m.cred.clone().unwrap_or_default(),
        });
        let _ = field;
    }
    let check: Vec<files::EnvEntry> = entries
        .iter()
        .map(|e| files::EnvEntry {
            name: e.name.clone(),
            value: e.value.clone(),
            cred: e.cred.clone(),
        })
        .collect();
    files::assert_placeholder_only(&check, &sid, port, &slugs).map_err(|e| match e {
        FileError::NotPlaceholder => err(
            "refusing to write a value that is not a placeholder",
            Exit::Internal,
        ),
        other => err(other.to_string(), Exit::Internal),
    })?;
    let mut rich = Vec::new();
    for m in &mappings {
        if m.kind == "url" {
            let value = match &m.cred {
                Some(cred) => format!("http://127.0.0.1:{port}/p/{cred}"),
                None => format!("http://127.0.0.1:{port}"),
            };
            rich.push(EnvEntryOut {
                name: m.name.clone(),
                kind: "url".into(),
                cred: m.cred.clone(),
                field: None,
                value,
            });
        } else {
            let key = format!(
                "{}\u{0}{}",
                m.cred.as_deref().unwrap_or(""),
                m.field.as_deref().unwrap_or("")
            );
            let got = issued.iter().find(|(k, _)| k == &key).map(|(_, v)| v);
            rich.push(EnvEntryOut {
                name: m.name.clone(),
                kind: "placeholder".into(),
                cred: m.cred.clone(),
                field: got
                    .and_then(|g| g.get("field"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .or_else(|| m.field.clone()),
                value: got
                    .and_then(|g| g.get("placeholder"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }
    Ok(Resolved {
        sid,
        port,
        entries: rich,
    })
}

fn inspect_target(path: &Path) -> &'static str {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            use std::os::unix::fs::MetadataExt;
            if meta.file_type().is_file() && meta.uid() == files::euid() {
                "file"
            } else {
                "foreign"
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "none",
        Err(_) => "foreign",
    }
}

fn git_would_commit(path: &Path) -> bool {
    let dir = path.parent().unwrap_or(Path::new("."));
    Command::new("git")
        .args(["check-ignore", "-q", "--"])
        .arg(path)
        .current_dir(dir)
        .status()
        .map(|s| s.code() == Some(1))
        .unwrap_or(false)
}

fn chrono_now() -> String {
    // ISO-8601 without the time crate: seconds since epoch via SystemTime.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix(secs)
}

fn format_unix(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.000Z")
}

/// Ports `COMMANDS.exec`.
pub async fn exec(ctx: &Context, args: &ExecArgs) -> Outcome {
    let mapping = !args.map.is_empty() || args.map_file.is_some() || args.profile_vars;
    let st = state();
    if !mapping && st.token.is_none() {
        return Err(err_next(
            "no session yet",
            Exit::Session,
            "agent-vault session create --cred <slug>",
        ));
    }
    if args.command.is_empty() {
        return Err(err(
            "usage: agent-vault exec [--map NAME=<slug>]... -- <command>",
            Exit::Usage,
        ));
    }
    let mapped = if mapping {
        let mappings = parse_mappings_from(&args.map, args.map_file.as_deref())?;
        Some(
            resolve_mappings(
                ctx,
                args.session.as_deref(),
                args.uses.as_deref(),
                args.profile_vars,
                mappings,
                "exec",
            )
            .await?,
        )
    } else {
        None
    };
    let mut env: Vec<(String, String)> = kept_parent_env();
    let same = mapped
        .as_ref()
        .is_none_or(|m| st.session_id.as_deref() == Some(m.sid.as_str()));
    let port = mapped
        .as_ref()
        .map(|m| m.port)
        .unwrap_or_else(|| ctx.gateway_port_of(&state_value()));
    env.push(("AGENT_VAULT".into(), "1".into()));
    env.push(("AGENT_VAULT_URL".into(), format!("http://127.0.0.1:{port}")));
    if same {
        if let Some(token) = &st.token {
            env.push(("AGENT_VAULT_SESSION".into(), token.clone()));
        }
        if let Some(ph) = &st.placeholder {
            env.push(("AGENT_VAULT_PLACEHOLDER".into(), ph.clone()));
        }
    }
    if let Some(mapped) = &mapped {
        for entry in &mapped.entries {
            env.push((entry.name.clone(), entry.value.clone()));
        }
    }
    let mut child = Command::new(&args.command[0]);
    child.args(&args.command[1..]).env_clear().envs(env);
    match child.status() {
        Ok(status) => Ok(child_status_code(status)),
        Err(e) => {
            let code = spawn_error_code(e.kind());
            let failure = err(
                if code == 127 {
                    format!("command not found: {}", args.command[0])
                } else {
                    format!("could not run {}: {e}", args.command[0])
                },
                Exit::Failure,
            );
            ctx.fail(&failure);
            Ok(code)
        }
    }
}

/// A child's exit code. A signal is `128 + signal`, never success.
pub(crate) fn child_status_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        code
    } else if let Some(sig) = status.signal() {
        128 + sig
    } else {
        1
    }
}

/// `127` when the binary is missing, `126` for any other spawn failure.
pub(crate) fn spawn_error_code(kind: std::io::ErrorKind) -> i32 {
    if kind == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    }
}

/// Ports `COMMANDS.approvals`.
pub async fn approvals(ctx: &Context, args: &ApprovalsArgs) -> Outcome {
    let pending = load_pending(ctx).await?;
    if let Some(show) = &args.show {
        if !pending.iter().any(|p| p.id == *show) {
            return Err(err("nothing waiting with that id", Exit::NotFound));
        }
    }
    if ctx.json {
        ctx.out(None, &serde_json::to_value(&pending).unwrap_or(Value::Null));
        return Ok(0);
    }
    if pending.is_empty() {
        println!("{}", ctx.paint("2", "nothing waiting"));
        return Ok(0);
    }
    for item in pending
        .iter()
        .filter(|p| args.show.as_ref().is_none_or(|id| p.id == *id))
    {
        let label = if item.kind == PendingKind::Session {
            "session requested"
        } else {
            "pending"
        };
        println!("{} {}", ctx.paint("33", label), item.id);
        println!(
            "  {}",
            ctx.paint("1", &clean_text(&show_value(&item.headline)))
        );
        if let Some(claim) = &item.claim {
            println!(
                "  {}",
                ctx.paint(
                    "2",
                    &format!("claimed by the agent (unverified): {}", clean_text(claim))
                )
            );
        }
        if let Some(caution) = &item.caution {
            println!("  {}", ctx.paint("2", &clean_text(caution)));
        }
        if let Some(preview) = &item.preview {
            for line in approval_preview_lines(preview, args.show.is_some()) {
                println!("{line}");
            }
        }
        let narrow = if item.narrowable.is_empty() {
            String::new()
        } else {
            format!(
                " {}",
                item.narrowable
                    .iter()
                    .map(|f| format!("[--{f} ...]"))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        };
        let owner = if item.owner_settable.is_empty() {
            ""
        } else {
            " [--approval MODE] [--infinite]"
        };
        println!(
            "  {}",
            ctx.paint(
                "2",
                &format!("agent-vault approve {}{narrow}{owner}", item.id)
            )
        );
        println!(
            "  {}",
            ctx.paint("2", &format!("agent-vault deny {}", item.id))
        );
    }
    Ok(0)
}

async fn load_pending(ctx: &Context) -> Result<Vec<av_store::pending::PendingItem>, CliError> {
    let mut rows = Vec::new();
    for source in pending::SOURCES {
        let value = ctx.control("GET", source.path, None).await?;
        let list = if let Some(items) = value.as_array() {
            items.clone()
        } else {
            value
                .get("items")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
        };
        rows.push((source.kind, list));
    }
    Ok(pending::collect_pending(rows))
}

/// Ports `COMMANDS.approve` / `decide(args, true)`.
pub async fn approve(ctx: &Context, args: &ApproveArgs) -> Outcome {
    let r = decide(ctx, args.id.as_deref(), true, Some(args)).await?;
    let summary = approval_human(&r);
    ctx.out(
        Some(&format!(
            "{} {}",
            ctx.paint("32", "approved"),
            clean_text(&summary)
        )),
        &r,
    );
    if r.get("collected").is_some() && !ctx.json {
        let sid = r
            .pointer("/collected/session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        println!(
            "{}",
            ctx.paint(
                "2",
                &format!("  session {sid} is now the one your agents use")
            )
        );
        println!(
            "{}",
            ctx.paint("2", "  a running MCP bridge picks it up on its next call")
        );
    }
    Ok(0)
}

/// Ports `COMMANDS.deny`.
pub async fn deny(ctx: &Context, args: &DenyArgs) -> Outcome {
    let r = decide(ctx, args.id.as_deref(), false, None).await?;
    let summary = r.get("summary").and_then(|v| v.as_str()).unwrap_or("");
    ctx.out(
        Some(&format!(
            "{} {}",
            ctx.paint("31", "denied"),
            clean_text(summary)
        )),
        &r,
    );
    Ok(0)
}

pub(crate) async fn decide(
    ctx: &Context,
    id: Option<&str>,
    granted: bool,
    approve: Option<&ApproveArgs>,
) -> Result<Value, CliError> {
    let Some(id) = id.filter(|s| !s.is_empty()) else {
        return Err(err_next(
            "name the id to answer",
            Exit::Usage,
            "agent-vault approvals",
        ));
    };
    let overrides = if granted {
        let args = approve.ok_or_else(|| err("name the id to answer", Exit::Usage))?;
        Some(policy_input::approval_overrides(args)?)
    } else {
        None
    };
    let pending = load_pending(ctx).await?;
    let Some(item) = pending.into_iter().find(|p| p.id == id) else {
        return Err(err_next(
            format!("nothing waiting with id {id}"),
            Exit::NotFound,
            "agent-vault approvals",
        ));
    };
    let mut settable = item.narrowable.clone();
    settable.extend(item.owner_settable.iter().cloned());
    if let Some(Value::Object(map)) = &overrides {
        for field in map.keys() {
            if !settable.iter().any(|s| s == field) {
                let next = if settable.is_empty() {
                    "agent-vault approvals   (this decision is yes or no)".to_string()
                } else {
                    format!(
                        "agent-vault approvals   (you can set: {})",
                        settable.join(", ")
                    )
                };
                return Err(err_next(
                    format!("--{field} does not apply to a {}", kind_name(item.kind)),
                    Exit::Usage,
                    next,
                ));
            }
        }
        if let Some(mode) = map.get("approval").and_then(|v| v.as_str()) {
            if !["each", "on-write", "first-use", "auto"].contains(&mode) {
                return Err(err(
                    "--approval is one of: each, on-write, first-use, auto",
                    Exit::Usage,
                ));
            }
        }
    }
    if granted {
        if let Some(args) = approve {
            if args.infinite {
                // boolean true is fine. A value was refused in prepare.
            }
        }
    }
    let map = overrides.as_ref().and_then(|v| v.as_object());
    let call = pending::decision(&item, granted, map.filter(|m| !m.is_empty()));
    let answered = ctx
        .control_with_presence("POST", &call.path, Some(&call.body))
        .await?;
    if !granted {
        return Ok(answered);
    }
    let collected = pending::collect_approved(&item, &answered, |session| {
        let _ = remember_created(session);
    });
    let mut rest = match answered {
        Value::Object(m) => m,
        other => return Ok(other),
    };
    rest.remove("session");
    if let Some(collected) = collected {
        rest.insert("collected".into(), collected);
    }
    Ok(Value::Object(rest))
}

fn kind_name(kind: PendingKind) -> &'static str {
    match kind {
        PendingKind::Request => "request",
        PendingKind::Session => "session",
    }
}

/// Ports `COMMANDS['audit:tail']`.
pub async fn audit_tail(ctx: &Context, args: &AuditTailArgs) -> Outcome {
    let limit = optional_number(
        args.limit.as_deref(),
        "limit",
        NumberLimits {
            min: 1.0,
            ..NumberLimits::default()
        },
    )?
    .unwrap_or(20.0);
    let rows = ctx
        .control("GET", &format!("/v1/audit?limit={limit}"), None)
        .await?;
    if ctx.json {
        ctx.out(None, &rows);
        return Ok(0);
    }
    let Some(list) = rows.as_array() else {
        return Ok(0);
    };
    for r in list {
        let decision = r.get("decision").and_then(|v| v.as_str()).unwrap_or("");
        let decision = match decision {
            "deny" => ctx.paint("31", "deny"),
            "allow" => ctx.paint("32", "allow"),
            _ => ctx.paint("2", "-"),
        };
        let detail = r
            .get("reason_code")
            .or_else(|| r.get("credential_slug"))
            .or_else(|| r.get("cred"))
            .or_else(|| r.get("detail"))
            .map(show_value)
            .unwrap_or_default();
        let ts = r.get("ts").and_then(|v| v.as_str()).unwrap_or("");
        let clock = if ts.len() >= 19 { &ts[11..19] } else { ts };
        let seq = r.get("seq").map(show_value).unwrap_or_default();
        let kind = r.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        println!(
            "{} {seq:>4} {decision} {} {}",
            ctx.paint("2", clock),
            ctx.paint("1", kind),
            ctx.paint("2", &clean_text(&detail))
        );
    }
    Ok(0)
}

/// Ports `COMMANDS['listen:add']`.
pub async fn listen_add(ctx: &Context, args: &ListenAddArgs) -> Outcome {
    let id = args.id.clone().unwrap_or_default();
    let address = args.address.clone().unwrap_or_default();
    if id.is_empty() || address.is_empty() {
        return Err(err(
            "usage: agent-vault listen add <id> --address <iface:port|ip:port>",
            Exit::Usage,
        ));
    }
    let surfaces: Vec<String> = args
        .surfaces
        .as_deref()
        .unwrap_or("gateway,mcp")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let split = |v: &Option<String>| {
        v.as_deref()
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let mut entry = Map::new();
    entry.insert("id".into(), Value::from(id));
    entry.insert("address".into(), Value::from(address));
    entry.insert("surfaces".into(), json!(surfaces));
    entry.insert("advertise".into(), json!(split(&args.advertise)));
    entry.insert("client_auth".into(), Value::from("bearer"));
    entry.insert("allow_cidr".into(), json!(split(&args.allow_cidr)));
    if args
        .tls
        .as_ref()
        .and_then(|v| v.as_ref())
        .is_some_and(|s| s == "managed")
        || matches!(args.tls, Some(None))
    {
        entry.insert("tls".into(), json!({ "managed": true }));
    } else if args.tls_cert.is_some() || args.tls_key.is_some() {
        let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) else {
            return Err(err("--tls-cert and --tls-key go together", Exit::Usage));
        };
        let abs = |p: &str| {
            let path = PathBuf::from(p);
            if path.is_absolute() {
                path
            } else {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(path)
            }
        };
        entry.insert("tls".into(), json!({ "cert": abs(cert), "key": abs(key) }));
    }
    let r = ctx
        .control_with_presence("POST", "/v1/listeners", Some(&Value::Object(entry)))
        .await?;
    let surfaces = r
        .get("surfaces")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    ctx.out(
        Some(&format!(
            "{} {} {} {}",
            ctx.paint("32", "listener"),
            r.get("id").and_then(|v| v.as_str()).unwrap_or(""),
            r.get("address").and_then(|v| v.as_str()).unwrap_or(""),
            ctx.paint("2", &format!("surfaces: {surfaces}"))
        )),
        &r,
    );
    if !ctx.json {
        println!(
            "{}",
            ctx.paint(
                "2",
                "  it binds when the daemon next starts; listen rm stops it at once"
            )
        );
    }
    Ok(0)
}

/// Ports `COMMANDS['tls:setup']`.
pub async fn tls_setup(ctx: &Context, args: &TlsSetupArgs) -> Outcome {
    let port = optional_number(
        args.port.as_deref(),
        "port",
        NumberLimits {
            min: 1.0,
            max: 65535.0,
            integer: true,
        },
    )?
    .unwrap_or(7443.0) as u16;
    let force = boolean_flag(args.force.then_some(""), "force")?;
    let info = ctx
        .control_with_presence("POST", "/v1/tls/ensure", Some(&json!({ "force": force })))
        .await?;
    let dir = client_state::state_dir();
    std::fs::create_dir_all(&dir).ok();
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    let ca = dir.join("agent-vault-ca.pem");
    let cert = info
        .get("certificate")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    files::write_file_exclusive(&ca, cert, true, 0o644)
        .map_err(|e| err(e.to_string(), Exit::Failure))?;
    if ctx.json {
        let mut data = info.clone();
        if let Value::Object(map) = &mut data {
            map.insert("ca_path".into(), Value::from(ca.display().to_string()));
            map.insert("port".into(), json!(port));
        }
        ctx.out(None, &data);
        return Ok(0);
    }
    let created = info
        .get("created")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!(
        "{}",
        ctx.paint(
            "32",
            if created {
                "certificate generated"
            } else {
                "certificate present"
            }
        )
    );
    let fp = info
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let shown = if fp.len() > 47 { &fp[..47] } else { fp };
    println!("  {} {shown}...", ctx.paint("2", "fingerprint"));
    if let Some(exp) = info.get("not_after").and_then(|v| v.as_str()) {
        let day = if exp.len() >= 10 { &exp[..10] } else { exp };
        println!("  {}     {day}", ctx.paint("2", "expires"));
    }
    println!(
        "  {} {}",
        ctx.paint("2", "trust anchor"),
        ctx.paint("36", &ca.display().to_string())
    );
    println!();
    println!("  The private key stays inside the vault and never leaves that uid.");
    println!("  The file above is the public certificate, which is also its own CA,");
    println!("  so pointing a client at it is what makes the listener trusted.");
    println!();
    println!("  {} Bind the TLS listener:", ctx.paint("1", "1."));
    println!(
        "     {}",
        ctx.paint(
            "36",
            &format!(
                "agent-vault listen add mcp-tls --address 127.0.0.1:{port} --surfaces mcp --tls managed"
            )
        )
    );
    println!();
    println!(
        "  {} Make the client trust it. Node does not read the keychain by",
        ctx.paint("1", "2.")
    );
    println!("     default, so this variable is the reliable way:");
    println!(
        "     {}",
        ctx.paint(
            "36",
            &format!("export NODE_EXTRA_CA_CERTS=\"{}\"", ca.display())
        )
    );
    println!();
    println!("  {} Add the connector:", ctx.paint("1", "3."));
    println!(
        "     {}",
        ctx.paint(
            "36",
            "agent-vault mcp install --agent claude-code --transport http --tls"
        )
    );
    Ok(0)
}

/// Ports `COMMANDS['tls:status']`.
pub async fn tls_status(ctx: &Context) -> Outcome {
    let info = ctx.control("GET", "/v1/tls", None).await?;
    if ctx.json {
        ctx.out(None, &info);
        return Ok(0);
    }
    if info.get("configured").and_then(|v| v.as_bool()) != Some(true) {
        println!(
            "{}  {}",
            ctx.paint("2", "no certificate yet"),
            ctx.paint("2", "agent-vault tls setup")
        );
        return Ok(0);
    }
    let exp = info
        .get("not_after")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let day = if exp.len() >= 10 { &exp[..10] } else { exp };
    println!("{} expires {day}", ctx.paint("32", "certificate"));
    println!(
        "  {}",
        ctx.paint(
            "2",
            info.get("fingerprint")
                .and_then(|v| v.as_str())
                .unwrap_or("")
        )
    );
    Ok(0)
}

/// Ports `COMMANDS['listen:list']`.
pub async fn listen_list(ctx: &Context) -> Outcome {
    let rows = ctx.control("GET", "/v1/listeners", None).await?;
    if ctx.json {
        ctx.out(None, &rows);
        return Ok(0);
    }
    println!(
        "{}  unix + 127.0.0.1  {}",
        ctx.paint("1", "local"),
        ctx.paint(
            "2",
            "gateway,mcp,connect  (always present, cannot be removed)"
        )
    );
    if let Some(list) = rows.as_array() {
        for l in list {
            let surfaces = l
                .get("surfaces")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            println!(
                "{}  {}  {}",
                ctx.paint("1", l.get("id").and_then(|v| v.as_str()).unwrap_or("")),
                l.get("address").and_then(|v| v.as_str()).unwrap_or(""),
                ctx.paint("2", &surfaces)
            );
        }
    }
    Ok(0)
}

/// Ports `COMMANDS['listen:rm']`.
pub async fn listen_rm(ctx: &Context, args: &ListenIdArg) -> Outcome {
    let id = text_flag(args.id.as_deref(), "id")?;
    ctx.control(
        "DELETE",
        &format!("/v1/listeners?id={}", encode_component(id)),
        None,
    )
    .await?;
    ctx.out(
        Some(&format!("{} {id}", ctx.paint("32", "removed"))),
        &json!({ "removed": id }),
    );
    Ok(0)
}

/// Ports `COMMANDS['mcp:install']`.
pub async fn mcp_install(ctx: &Context, args: &McpInstallArgs) -> Outcome {
    let agent = args
        .agent
        .clone()
        .or_else(|| args.agent_positional.clone())
        .unwrap_or_default();
    let Some(spec) = mcp_install::agent(&agent) else {
        let keys = mcp_install::AGENTS
            .iter()
            .map(|a| a.key)
            .collect::<Vec<_>>()
            .join("|");
        return Err(err_next(
            "--agent is required",
            Exit::Usage,
            format!("agent-vault mcp install --agent {keys}"),
        ));
    };
    let scope = args
        .scope
        .clone()
        .or_else(|| spec.default_scope.map(str::to_string))
        .unwrap_or_else(|| "project".into());
    let has_scope = match scope.as_str() {
        "project" => spec.project_path.is_some(),
        "user" => spec.user_path.is_some(),
        _ => false,
    };
    if !has_scope {
        let known = ["project", "user"]
            .into_iter()
            .filter(|s| {
                (*s == "project" && spec.project_path.is_some())
                    || (*s == "user" && spec.user_path.is_some())
            })
            .collect::<Vec<_>>()
            .join("|");
        return Err(err_next(
            format!("{} has no {scope} scope", spec.label),
            Exit::Usage,
            format!("agent-vault mcp install --agent {agent} --scope {known}"),
        ));
    }
    let transport = args.transport.clone().unwrap_or_else(|| "stdio".into());
    let name = args.name.clone().unwrap_or_else(|| "agent-vault".into());
    let tls = boolean_flag(args.tls.then_some(""), "tls")?;
    let _ = boolean_flag(args.print.then_some(""), "print")?;
    if was_bare("port") {
        return Err(err(
            "--port must be a number between 1 and 65535, not true",
            Exit::Usage,
        ));
    }
    let port = match &args.port {
        None => 7443u16,
        Some(text) => {
            let n = text.parse::<i64>().ok();
            if n.is_none_or(|n| !(1..=65535).contains(&n))
                || text.parse::<f64>().ok().is_some_and(|f| f.fract() != 0.0) && n.is_none()
            {
                let shown = serde_json::to_string(text).unwrap_or_else(|_| text.clone());
                return Err(err(
                    format!("--port must be a number between 1 and 65535, not {shown}"),
                    Exit::Usage,
                ));
            }
            n.unwrap_or(0) as u16
        }
    };
    let shim = ["agent-vault", "av"].into_iter().find(|name| {
        std::env::var_os("PATH").is_some_and(|path| {
            std::env::split_paths(&path)
                .any(|dir| !dir.as_os_str().is_empty() && dir.join(name).is_file())
        })
    });
    let portable = shim.is_some() && scope == "project";
    let system_bin = Path::new(SYSTEM_ROOT)
        .join("app")
        .join("bin")
        .join("agent-vault");
    let use_system = !portable && using_system() && system_bin.is_file();
    let current_exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "agent-vault".into());
    let (command, cmd_args) = mcp_launch(
        portable,
        shim,
        use_system,
        &system_bin.display().to_string(),
        &current_exe,
    );
    let url = if tls {
        format!("https://localhost:{port}/mcp")
    } else {
        format!(
            "http://127.0.0.1:{}/mcp",
            ctx.gateway_port_of(&state_value())
        )
    };
    let entry = mcp_install::server_entry(&EntrySpec {
        transport: transport.clone(),
        command: Some(command),
        args: cmd_args,
        url: Some(url),
        token_env: None,
        format: spec.format.to_string(),
    });
    let env = utf8_env_map();
    let result = mcp_install::install(&InstallSpec {
        agent: agent.clone(),
        scope: scope.clone(),
        name,
        entry,
        print: args.print,
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        home: home(),
        env,
    })
    .map_err(|e| err(e, Exit::Usage))?;
    if ctx.json {
        ctx.out(
            None,
            &json!({
                "agent": agent, "scope": scope, "transport": transport,
                "path": result.path, "block": result.block, "wrote": result.wrote,
                "unchanged": result.unchanged, "backup": result.backup,
            }),
        );
        return Ok(0);
    }
    if args.print {
        println!(
            "{}",
            ctx.paint("2", &format!("# {}", result.path.display()))
        );
        println!("{}", result.block);
        return Ok(0);
    }
    println!(
        "{} {} {}",
        ctx.paint(
            "32",
            if result.unchanged {
                "already configured"
            } else {
                "configured"
            }
        ),
        ctx.paint("1", spec.label),
        ctx.paint("2", &format!("({scope} scope)"))
    );
    println!("  {}", ctx.paint("36", &result.path.display().to_string()));
    if let Some(backup) = &result.backup {
        println!(
            "{}",
            ctx.paint(
                "2",
                &format!("  previous file kept at {}", backup.display())
            )
        );
    }
    let note = if scope == "project" {
        spec.project_note
    } else {
        spec.user_note
    };
    if let Some(note) = note {
        println!("{}", ctx.paint("2", &format!("  {note}")));
    }
    println!();
    if transport == "stdio" {
        println!(
            "{}",
            ctx.paint(
                "2",
                "  The stdio bridge finds your session from the CLI, so no token is"
            )
        );
        println!(
            "{}",
            ctx.paint(
                "2",
                "  written into that file. Create a session first if you have not:"
            )
        );
        println!(
            "    {}",
            ctx.paint("36", "agent-vault session create --cred <slug>")
        );
    } else {
        println!(
            "{}",
            ctx.paint(
                "2",
                "  HTTP transport reads the token from $AGENT_VAULT_SESSION at launch."
            )
        );
        println!("    {}", ctx.paint("36", "eval \"$(agent-vault env)\""));
        if tls {
            let ca = client_state::state_dir().join("agent-vault-ca.pem");
            println!();
            println!(
                "{}",
                ctx.paint(
                    "2",
                    "  The certificate is self-signed, so the client will refuse it until"
                )
            );
            println!(
                "{}",
                ctx.paint(
                    "2",
                    "  it is told to trust it. Node does not read the keychain by default:"
                )
            );
            println!(
                "    {}",
                ctx.paint(
                    "36",
                    &format!("export NODE_EXTRA_CA_CERTS=\"{}\"", ca.display())
                )
            );
        } else {
            println!();
            println!(
                "{}",
                ctx.paint(
                    "33",
                    "  Note: a custom connector URL must be https. Plain http is refused"
                )
            );
            println!(
                "{}",
                ctx.paint("33", "  even on loopback. Run: agent-vault tls setup")
            );
        }
    }
    println!();
    println!(
        "{}",
        ctx.paint(
            "2",
            &format!("  Restart {} so it picks up the new server.", spec.label)
        )
    );
    Ok(0)
}

/// `true` when `origin` is not in the daemon's trusted UI origin list.
pub(crate) fn origin_is_untrusted(origins: &[Value], origin: &str) -> bool {
    !origins.iter().any(|o| o.as_str() == Some(origin))
}

/// The warning `agent-vault ui` prints for a page the daemon will not trust.
pub(crate) fn untrusted_origin_warning(origin: &str) -> String {
    format!(
        "  {origin} is not a trusted UI origin, so the daemon will refuse fingerprints from this page."
    )
}

/// The Streamable HTTP endpoint on the session's gateway port.
pub(crate) fn mcp_endpoint(port: u16) -> String {
    format!("http://127.0.0.1:{port}/mcp")
}

/// Ports `COMMANDS['mcp:url']`.
pub async fn mcp_url(ctx: &Context) -> Outcome {
    let st = state();
    let url = mcp_endpoint(ctx.gateway_port_of(&state_value()));
    let stored = st.token.clone();
    let token = stored.clone().unwrap_or_else(|| "<session token>".into());
    if ctx.json {
        let header_token = stored.unwrap_or_default();
        ctx.out(
            None,
            &json!({ "url": url, "header": format!("Authorization: Bearer {header_token}") }),
        );
        return Ok(0);
    }
    println!("{url}");
    eprintln!(
        "{}",
        ctx.paint("2", &format!("header: Authorization: Bearer {token}"))
    );
    Ok(0)
}

/// Ports `COMMANDS.mcp`, the stdio bridge.
pub async fn mcp(ctx: &Context) -> Outcome {
    let token = std::env::var("AGENT_VAULT_SESSION")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| state().token);
    let Some(_) = token else {
        eprintln!("agent-vault mcp: no session. Run: agent-vault session create --cred <slug>");
        return Ok(Exit::Session.code());
    };
    let status = ctx.control("GET", "/v1/status", None).await?;
    let port = status
        .get("gateway_port")
        .and_then(|v| v.as_u64())
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(7411);
    let mut mcp_session: Option<String> = None;
    let stdin = std::io::stdin();
    for line in stdin.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        match bridge_one(port, &line, &mut mcp_session) {
            Ok(text) => {
                if !text.is_empty() {
                    println!("{text}");
                }
            }
            Err(e) => {
                let id = serde_json::from_str::<Value>(&line)
                    .ok()
                    .and_then(|v| v.get("id").cloned())
                    .unwrap_or(Value::Null);
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32603, "message": format!("agent-vault daemon unreachable: {e}") },
                    }))
                    .unwrap_or_default()
                );
            }
        }
    }
    Ok(0)
}

fn current_token() -> Option<String> {
    std::env::var("AGENT_VAULT_SESSION")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| state().token)
}

fn bridge_one(port: u16, line: &str, mcp_session: &mut Option<String>) -> Result<String, String> {
    let send = |tok: &str,
                body: &str,
                sid: &Option<String>|
     -> Result<crate::http_client::HttpResponse, String> {
        let mut headers = vec![
            ("accept", "application/json, text/event-stream"),
            ("authorization", ""),
        ];
        let auth = format!("Bearer {tok}");
        headers[1].1 = &auth;
        let mut extra: Vec<(&str, &str)> = vec![
            ("accept", "application/json, text/event-stream"),
            ("authorization", auth.as_str()),
        ];
        if let Some(sid) = sid {
            extra.push(("mcp-session-id", sid.as_str()));
        }
        let _ = headers;
        crate::http_client::request_tcp(port, "POST", "/mcp", Some(body.as_bytes()), &extra)
            .map_err(|e| e.to_string())
    };
    let token = current_token().ok_or_else(|| "no session".to_string())?;
    let mut res = send(&token, line, mcp_session)?;
    let invalid = launch_token_dead(res.status, res.header("av-session-invalid").is_some());
    let mut answer: Option<String> = None;
    if invalid {
        let fresh = state().token;
        if fresh.as_ref().is_some_and(|f| f != &token) {
            std::env::remove_var("AGENT_VAULT_SESSION");
            let fresh = fresh.unwrap_or_default();
            if res.status == 401 {
                *mcp_session = None;
                res = send(&fresh, line, mcp_session)?;
            } else {
                answer = Some(res.text());
                if let Some(redo) = crate::session_retry(line, answer.as_deref().unwrap_or("")) {
                    *mcp_session = None;
                    res = send(&fresh, &redo.line, mcp_session)?;
                    answer = Some(redo.merge(&res.text()));
                }
            }
        }
    }
    if res.status == 404 && mcp_session.is_some() {
        let body = answer.clone().unwrap_or_else(|| res.text());
        if body.contains("AV_MCP_SESSION_UNKNOWN") {
            *mcp_session = None;
            let tok = current_token().unwrap_or_default();
            res = send(&tok, line, mcp_session)?;
            answer = None;
        }
    }
    if let Some(sid) = res.header("mcp-session-id") {
        *mcp_session = Some(sid.to_string());
    }
    let text = answer.unwrap_or_else(|| res.text());
    if text.is_empty() {
        return Ok(String::new());
    }
    Ok(as_rpc(&text, line, res.status))
}

/// A 401, or the daemon's `av-session-invalid` header, means the launch
/// token is dead and the bridge must pick up the newly recorded session.
pub(crate) fn launch_token_dead(status: u16, session_invalid_header: bool) -> bool {
    status == 401 || session_invalid_header
}

/// Stdout of the stdio bridge is MCP JSON-RPC, never the daemon's raw body.
pub(crate) fn as_rpc(text: &str, request_line: &str, http_status: u16) -> String {
    let is_message = |m: &Value| m.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0");
    if let Ok(payload) = serde_json::from_str::<Value>(text) {
        let ok = match &payload {
            Value::Array(a) => !a.is_empty() && a.iter().all(is_message),
            other => is_message(other),
        };
        if ok {
            return text.to_string();
        }
        let id = serde_json::from_str::<Value>(request_line)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(Value::Null);
        let detail = payload
            .get("detail")
            .or_else(|| payload.get("message"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| text.chars().take(200).collect());
        let hint = payload
            .get("hint")
            .and_then(|v| v.as_str())
            .map(|h| format!(" {h}"))
            .unwrap_or_default();
        let code = payload.get("code").and_then(|v| v.as_str()).unwrap_or("");
        eprintln!(
            "agent-vault mcp: the daemon answered {http_status} {}: {detail}{hint}",
            if code.is_empty() {
                "with a non-protocol body"
            } else {
                code
            }
        );
        let label = if code.is_empty() {
            format!("HTTP {http_status}")
        } else {
            code.to_string()
        };
        let mut data = Map::new();
        // JSON.stringify drops a missing field (`undefined`) and keeps an
        // explicit null. Insert only keys the daemon sent.
        if let Some(hint) = payload.get("hint") {
            data.insert("hint".into(), hint.clone());
        }
        if let Some(next) = payload.get("next") {
            data.insert("next".into(), next.clone());
        }
        data.insert("http_status".into(), json!(http_status));
        return serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32603,
                "message": format!("{label}: {detail}"),
                "data": data,
            },
        }))
        .unwrap_or_default();
    }
    let id = serde_json::from_str::<Value>(request_line)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(Value::Null);
    eprintln!(
        "agent-vault mcp: the daemon answered {http_status} with a non-protocol body: {}",
        text.chars().take(200).collect::<String>()
    );
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32603,
            "message": format!("HTTP {http_status}: {}", text.chars().take(200).collect::<String>()),
            "data": { "http_status": http_status },
        },
    }))
    .unwrap_or_default()
}

/// Ports `COMMANDS.ui`. The UI server lives in av-daemon; a down daemon fails
/// on `GET /v1/status` before that server is constructed.
pub async fn ui(ctx: &Context, args: &UiArgs, hash: &str) -> Outcome {
    ctx.control("GET", "/v1/status", None).await?;
    let trusted = ctx.control("GET", "/v1/ui", None).await.ok();
    let port = optional_number(
        args.port.as_deref(),
        "port",
        NumberLimits {
            min: 0.0,
            max: 65535.0,
            integer: true,
        },
    )?;
    let idle = optional_number(
        args.idle.as_deref(),
        "idle",
        NumberLimits {
            min: 1.0,
            max: NumberLimits::default().max,
            integer: false,
        },
    )?;
    let port = port.map(|n| n as u16).unwrap_or_else(|| {
        trusted
            .as_ref()
            .and_then(|t| t.get("port"))
            .and_then(|v| v.as_u64())
            .and_then(|n| u16::try_from(n).ok())
            .unwrap_or(0)
    });
    let server = match av_daemon::ui::server::serve(
        &socket_path(),
        av_daemon::ui::server::UiServerOptions {
            port,
            idle_ms: Some(((idle.unwrap_or(30.0)) * 60_000.0) as u64),
            cli: Some(cli_invocation()),
            state_path: Some(client_state_path()),
            dist_dir: None,
        },
    )
    .await
    {
        Ok(server) => server,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            return Err(err_next(
                format!("port {port} is in use; is another agent-vault ui running?"),
                Exit::Failure,
                "agent-vault ui --port <free port> --allow-origin",
            ));
        }
        Err(e) => return Err(err(e.to_string(), Exit::Failure)),
    };
    if let Some(trusted) = &trusted {
        let origins = trusted
            .get("origins")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let origin = server.origin();
        if origin_is_untrusted(&origins, &origin) {
            if args.allow_origin {
                ctx.control_with_presence(
                    "POST",
                    "/v1/ui/origins",
                    Some(&json!({ "origin": origin })),
                )
                .await?;
                if !ctx.json {
                    println!(
                        "{}",
                        ctx.paint(
                            "2",
                            &format!("  trusted {origin} for Touch ID confirmations")
                        )
                    );
                }
            } else if !ctx.json {
                println!("{}", ctx.paint("33", &untrusted_origin_warning(&origin)));
                println!(
                    "{}",
                    ctx.paint(
                        "2",
                        "  Run without --port, or add --allow-origin to trust it (asks for your passphrase)."
                    )
                );
            }
        }
    }
    let url = format!("{}{hash}", server.url());
    if ctx.json {
        ctx.out(None, &json!({ "url": url, "port": server.bound_port() }));
    } else {
        println!(
            "{} {}",
            ctx.paint("32", "agent-vault ui"),
            ctx.paint("2", &format!("on 127.0.0.1:{}", server.bound_port()))
        );
        println!();
        println!("  {}", ctx.paint("36", &url));
        println!();
        println!(
            "{}",
            ctx.paint(
                "2",
                "  The link works once. If your browser says the session was already"
            )
        );
        println!(
            "{}",
            ctx.paint(
                "2",
                "  claimed, something else opened it first: check agent-vault audit tail."
            )
        );
        println!(
            "{}",
            ctx.paint(
                "2",
                "  No credential value is ever sent to the page. Ctrl-C to stop."
            )
        );
        if !args.no_open {
            let opener = if cfg!(target_os = "macos") {
                "open"
            } else {
                "xdg-open"
            };
            let _ = Command::new(opener).arg(&url).spawn();
        }
    }
    // Stdout is block-buffered when piped. The URL has to leave the process
    // while the server is still up, or a client that waits for the JSON
    // fetches a port nothing is listening on.
    let _ = std::io::Write::flush(&mut std::io::stdout());
    tokio::select! {
        _ = server.stopped() => {}
        _ = tokio::signal::ctrl_c() => {
            server.stop().await;
        }
    }
    Ok(0)
}

/// Ports `COMMANDS.docs`.
pub async fn docs(ctx: &Context, args: &DocsArgs) -> Outcome {
    const SECTIONS: &[&str] = &[
        "how", "start", "connect", "models", "locking", "safety", "refused", "commands",
    ];
    if let Some(asked) = &args.section {
        if !SECTIONS.contains(&asked.as_str()) {
            return Err(err_next(
                format!("no docs section named {asked}"),
                Exit::Usage,
                format!("agent-vault docs [{}]", SECTIONS.join("|")),
            ));
        }
    }
    let hash = format!("#docs/{}", args.section.as_deref().unwrap_or("how"));
    ui(ctx, &args.ui, &hash).await
}

/// Ports `COMMANDS['passphrase:set']`.
pub async fn passphrase_set(ctx: &Context) -> Outcome {
    let state = ctx.control("GET", "/v1/lockstate", None).await?;
    if state.get("locked").and_then(|v| v.as_bool()) == Some(true) {
        return Err(err_next(
            "unlock the vault first",
            Exit::Locked,
            "agent-vault unlock",
        ));
    }
    let current = if state.get("has_passphrase").and_then(|v| v.as_bool()) == Some(true) {
        Some(ctx.read_secret("current passphrase: ")?)
    } else {
        None
    };
    let next1 = ctx.read_secret("new passphrase (min 8 chars): ")?;
    if next1.expose_secret().chars().count() < 8 {
        return Err(err(
            "a passphrase must be at least 8 characters",
            Exit::Usage,
        ));
    }
    let next2 = ctx.read_secret("confirm new passphrase: ")?;
    if next1.expose_secret() != next2.expose_secret() {
        return Err(err("the two passphrases do not match", Exit::Usage));
    }
    let mut body = Map::new();
    body.insert("action".into(), Value::from("set"));
    body.insert(
        "passphrase".into(),
        Value::from(next1.expose_secret().to_string()),
    );
    if let Some(current) = &current {
        body.insert(
            "current".into(),
            Value::from(current.expose_secret().to_string()),
        );
    }
    ctx.control("POST", "/v1/passphrase", Some(&Value::Object(body)))
        .await?;
    println!("{}", ctx.paint("32", "passphrase set"));
    println!(
        "{}",
        ctx.paint(
            "2",
            "  The lock is now cryptographic: locking zeroizes the key, and unlocking"
        )
    );
    println!(
        "{}",
        ctx.paint(
            "2",
            "  needs this passphrase. An agent that reaches the socket cannot undo it."
        )
    );
    Ok(0)
}

/// Ports `COMMANDS['passphrase:remove']`.
pub async fn passphrase_remove(ctx: &Context) -> Outcome {
    let state = ctx.control("GET", "/v1/lockstate", None).await?;
    if state.get("locked").and_then(|v| v.as_bool()) == Some(true) {
        return Err(err_next(
            "unlock the vault first",
            Exit::Locked,
            "agent-vault unlock",
        ));
    }
    if state.get("has_passphrase").and_then(|v| v.as_bool()) != Some(true) {
        ctx.out(
            Some(&format!("{} no passphrase is set", ctx.paint("32", "ok"))),
            &json!({ "removed": false }),
        );
        return Ok(0);
    }
    let current = ctx.read_secret("current passphrase: ")?;
    ctx.control(
        "POST",
        "/v1/passphrase",
        Some(&json!({ "action": "remove", "current": current.expose_secret() })),
    )
    .await?;
    println!(
        "{} {}",
        ctx.paint("33", "passphrase removed"),
        ctx.paint(
            "2",
            "unlocking needs no secret now; your authenticator still confirms changes"
        )
    );
    Ok(0)
}

/// Ports `COMMANDS.lock`.
pub async fn lock(ctx: &Context) -> Outcome {
    ctx.control("POST", "/v1/lock", Some(&json!({}))).await?;
    ctx.out(
        Some(&format!(
            "{} keys zeroized; the gateway answers 423 until you unlock",
            ctx.paint("32", "locked")
        )),
        &json!({ "locked": true }),
    );
    Ok(0)
}

/// Ports `COMMANDS.unlock`.
pub async fn unlock(ctx: &Context) -> Outcome {
    let mut locked_state = json!({ "locked": true, "needs_secret": false });
    match ctx.control("GET", "/v1/lockstate", None).await {
        Ok(state) => locked_state = state,
        Err(e) if e.skew => {}
        Err(e) => return Err(e),
    }
    if locked_state.get("locked").and_then(|v| v.as_bool()) == Some(false) {
        ctx.out(
            Some(&format!("{} already unlocked", ctx.paint("32", "ok"))),
            &json!({ "locked": false }),
        );
        return Ok(0);
    }
    let passphrase = if locked_state.get("needs_secret").and_then(|v| v.as_bool()) == Some(true) {
        Some(ctx.read_secret("passphrase: ")?)
    } else {
        None
    };
    let body = json!({ "passphrase": passphrase.as_ref().map(|p| p.expose_secret()) });
    ctx.control("POST", "/v1/unlock", Some(&body)).await?;
    if ctx.json {
        ctx.out(None, &json!({ "locked": false }));
        return Ok(0);
    }
    println!("{}", ctx.paint("32", "unlocked"));
    if locked_state.get("needs_secret").and_then(|v| v.as_bool()) != Some(true) {
        println!(
            "{}",
            ctx.paint(
                "2",
                "  This vault has no passphrase, so unlocking needed no secret: the"
            )
        );
        println!(
            "{}",
            ctx.paint(
                "2",
                "  lock is a policy gate, not a cryptographic one. Anything that can"
            )
        );
        println!(
            "{}",
            ctx.paint("2", "  reach the control socket can undo it.")
        );
        println!(
            "  {} {}",
            ctx.paint("2", "Make the lock cryptographic:"),
            ctx.paint("36", "agent-vault passphrase set")
        );
    }
    Ok(0)
}

/// Ports `COMMANDS.profiles`.
pub async fn profiles(ctx: &Context) -> Outcome {
    let creds = ctx
        .control("GET", "/v1/credentials", None)
        .await
        .unwrap_or_else(|_| json!([]));
    let rows = list_profiles();
    if ctx.json {
        let mut out = Vec::new();
        for p in &rows {
            let pins = pins_for(&creds, &p.kind);
            out.push(json!({
                "kind": p.kind, "hosts": p.hosts, "fields": p.fields,
                "l4": p.l4, "implemented": p.implemented, "pins": pins,
            }));
        }
        ctx.out(None, &Value::Array(out));
        return Ok(0);
    }
    for p in &rows {
        let hosts = if p.hosts.is_empty() {
            "any host you name".to_string()
        } else {
            p.hosts.join(", ")
        };
        let note = if p.implemented {
            String::new()
        } else {
            format!("  {}", ctx.paint("33", "not implemented yet"))
        };
        println!(
            "{} {}{note}",
            ctx.paint("1", &format!("{:<14}", p.kind)),
            ctx.paint("2", &hosts)
        );
        for pin in pins_for(&creds, &p.kind) {
            println!(
                "  pinned: {} ({}) · {}",
                clean_text(pin.get("host").and_then(|v| v.as_str()).unwrap_or("")),
                pin.get("count").map(show_value).unwrap_or_default(),
                clean_text(pin.get("cred").and_then(|v| v.as_str()).unwrap_or(""))
            );
        }
    }
    Ok(0)
}

fn pins_for(creds: &Value, kind: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let Some(list) = creds.as_array() else {
        return out;
    };
    for c in list
        .iter()
        .filter(|c| c.get("kind").and_then(|v| v.as_str()) == Some(kind))
    {
        if let Some(Value::Object(pins)) = c.get("pins") {
            for (host, count) in pins {
                out.push(json!({
                    "cred": c.get("slug").and_then(|v| v.as_str()).unwrap_or(""),
                    "host": host,
                    "count": count,
                }));
            }
        }
    }
    out
}

/// Ports `COMMANDS.doctor`.
pub async fn doctor(ctx: &Context) -> Outcome {
    use std::os::unix::fs::MetadataExt;
    let mut checks: Vec<(String, bool, String)> = Vec::new();
    checks.push((
        "install mode".into(),
        true,
        if using_system() {
            "system (separate service user)".into()
        } else if system_installed_note() {
            "dev (runs as you), overriding the system install".into()
        } else {
            "dev (runs as you)".into()
        },
    ));
    let dir = vault_dir();
    if using_system() {
        let readable = std::fs::metadata(dir.join("vault.json")).is_ok()
            || std::fs::metadata(dir.join("vault.db")).is_ok();
        checks.push((
            "vault unreadable by your account".into(),
            !readable,
            if !readable {
                format!("EACCES on {} - correct", dir.display())
            } else {
                format!(
                    "readable at {} - the boundary is NOT in effect",
                    dir.display()
                )
            },
        ));
    } else {
        let exists = vault_present(&dir);
        checks.push(("vault present".into(), exists, dir.display().to_string()));
        if exists {
            if let Ok(meta) = std::fs::metadata(&dir) {
                let mode = meta.mode() & 0o777;
                checks.push((
                    "vault directory mode 0700".into(),
                    mode == 0o700,
                    format!("0{mode:o}"),
                ));
            }
        }
        checks.push((
            "separate uid boundary".into(),
            false,
            format!(
                "dev mode: anything running as you can read {}. Install it properly: agent-vault setup",
                dir.display()
            ),
        ));
    }
    let socket = socket_path();
    checks.push((
        "daemon reachable".into(),
        socket.exists(),
        socket.display().to_string(),
    ));
    if let Ok(chain) = ctx.control("GET", "/v1/audit/verify", None).await {
        let (audit_name, ok) = doctor_audit_check(&chain);
        let note = if ok {
            format!(
                "{} records",
                chain
                    .get("count")
                    .map(show_value)
                    .unwrap_or_else(|| "0".into())
            )
        } else {
            chain
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        checks.push((audit_name.into(), ok, note));
        if let Some(before) = chain.get("unanchored_before").filter(|v| !v.is_null()) {
            checks.push((
                "audit log anchored throughout".into(),
                false,
                format!(
                    "anchored from record {}; nothing proves how many records came before it",
                    show_value(before)
                ),
            ));
        }
    }
    if let Ok(lock) = ctx.control("GET", "/v1/lockstate", None).await {
        let pass = lock.get("has_passphrase").and_then(|v| v.as_bool()) == Some(true);
        let touch = lock.get("has_touchid").and_then(|v| v.as_bool()) == Some(true);
        let (enrolled, note) = doctor_factor_note(pass, touch);
        checks.push(("human factor enrolled".into(), enrolled, note));
    }
    let credentials = ctx
        .control("GET", "/v1/credentials", None)
        .await
        .unwrap_or_else(|_| json!([]));
    let expiring: Vec<&Value> = credentials
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|c| c.get("expiry_warning").is_some_and(|v| !v.is_null()))
                .collect()
        })
        .unwrap_or_default();
    if expiring.is_empty() {
        checks.push((
            "credential expiry".into(),
            true,
            "no credentials expiring".into(),
        ));
    }
    for c in expiring {
        checks.push((
            "credential expiry".into(),
            false,
            format!(
                "{}: {}",
                c.get("slug").and_then(|v| v.as_str()).unwrap_or(""),
                c.get("expiry_warning").map(show_value).unwrap_or_default()
            ),
        ));
    }
    if ctx.json {
        let data: Vec<Value> = checks
            .iter()
            .map(|(name, ok, note)| json!({ "name": name, "ok": ok, "note": note }))
            .collect();
        ctx.out(None, &Value::Array(data));
        return Ok(0);
    }
    for (name, ok, note) in &checks {
        let mark = if *ok {
            ctx.paint("32", "ok  ")
        } else {
            ctx.paint("33", "warn")
        };
        println!("{mark} {:<26} {}", name, ctx.paint("2", note));
    }
    Ok(0)
}

fn system_installed_note() -> bool {
    crate::system_installed()
}

/// Ports `COMMANDS.watch`.
pub async fn watch(ctx: &Context, args: &WatchArgs) -> Outcome {
    let no_notify = boolean_flag(args.no_notify.then_some(""), "no-notify")?;
    let open = boolean_flag(args.open.then_some(""), "open")?;
    let quiet = boolean_flag(args.quiet.then_some(""), "quiet")?;
    crate::watch::watch_approvals(crate::watch::WatchOptions {
        socket_path: socket_path(),
        json: ctx.json,
        notify: !no_notify,
        open,
        quiet,
    })
    .await?;
    Ok(0)
}

/// Ports `agent-vault migrate` (PLAN.md). The passphrase is prompted, never
/// an argument. A completed migration exits 0.
pub async fn migrate(ctx: &Context, args: &MigrateArgs) -> Outcome {
    let from = args
        .from
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(vault_dir);
    let to = args
        .to
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| from.clone());
    let opts = MigrateOptions {
        from: from.clone(),
        to: to.clone(),
        dry_run: args.dry_run,
    };
    let db = to.join("vault.db");
    // Only a finished migration (opens, schema_version, vault.migrated in
    // the audit chain) is "already migrated". Any other vault.db is an
    // error that names the file. Nothing is written on this path.
    if db.exists() && !migrate::is_completed_migration(&db) {
        return Err(err(
            format!(
                "{} is not a completed migration. It must open, have schema_version, and an audit record of kind vault.migrated. Remove that file, or pass --to an empty directory. Nothing was written.",
                db.display()
            ),
            Exit::Failure,
        ));
    }
    if db.exists() {
        let legacy_files = migrate::read_legacy(&from)
            .map(|legacy| legacy.files)
            .unwrap_or_default();
        let report = MigrateReport {
            already_migrated: true,
            dry_run: args.dry_run,
            counts: std::collections::BTreeMap::new(),
            audit_first_seq: None,
            audit_last_seq: None,
            audit_head: None,
            dropped: Vec::new(),
            written: None,
            legacy_files,
        };
        return finish_migrate(ctx, &report);
    }
    // The CLI's own socket (AGENT_VAULT_DIR, or the system socket when the
    // install's state.json exists) is one of the places the JS looks, in
    // addition to the library's candidates. Name the socket that answered:
    // it is not always `--from`.
    let sock = socket_path();
    if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
        return Err(daemon_running_at(&sock));
    }
    if let Err(error) = migrate::preflight(&opts) {
        let message = error.to_string();
        return match error {
            MigrateError::AlreadyMigrated(path) => Err(err(
                format!(
                    "{}/vault.db is not a completed migration. Remove that file, or pass --to an empty directory. Nothing was written.",
                    path.display()
                ),
                Exit::Failure,
            )),
            MigrateError::DaemonRunning { next, .. } => Err(err_next(message, Exit::Failure, next)),
            other => Err(err(other.to_string(), Exit::Failure)),
        };
    }
    let legacy = migrate::read_legacy(&from).map_err(|e| err(e.to_string(), Exit::Failure))?;
    let passphrase = if migrate::needs_passphrase(&legacy) {
        Some(ctx.read_secret("passphrase: ")?)
    } else {
        None
    };
    let report = migrate::migrate(&opts, legacy, passphrase.as_ref()).map_err(|e| {
        let message = e.to_string();
        match e {
            MigrateError::DaemonRunning { next, .. } => err_next(message, Exit::Failure, next),
            other => err(other.to_string(), Exit::Failure),
        }
    })?;
    finish_migrate(ctx, &report)
}

fn daemon_running_at(sock: &Path) -> CliError {
    err_next(
        format!(
            "the agent-vault daemon is running at {}",
            sock.display()
        ),
        Exit::Failure,
        "stop the daemon first (installed: sudo launchctl bootout system/com.agentvault.daemon; dev: stop the `agent-vault daemon` process), then run agent-vault migrate again",
    )
}

fn finish_migrate(ctx: &Context, report: &MigrateReport) -> Outcome {
    if ctx.json {
        ctx.out(None, &serde_json::to_value(report).unwrap_or(Value::Null));
        return Ok(0);
    }
    let mut lines = Vec::new();
    if report.already_migrated {
        let path = report
            .written
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "vault.db".into());
        lines.push(format!(
            "{} vault.db already exists at {path}",
            ctx.paint("32", "ok")
        ));
        lines.push("nothing to do".into());
        println!("{}", lines.join("\n"));
        return Ok(0);
    }
    if report.dry_run {
        lines.push("dry run: nothing was written".into());
    }
    for (name, count) in &report.counts {
        lines.push(format!("  {name}: {count}"));
    }
    if let (Some(first), Some(last)) = (report.audit_first_seq, report.audit_last_seq) {
        let head = report.audit_head.as_deref().unwrap_or("");
        lines.push(format!("audit {first}..={last} head {head}"));
    }
    for dropped in &report.dropped {
        lines.push(format!("dropped {}: {}", dropped.what, dropped.why));
        lines.push(format!("  re-enroll: {}", dropped.next));
    }
    if !report.dry_run {
        lines.push("left vault.json in place. Once you are satisfied, remove it:".into());
        for file in &report.legacy_files {
            lines.push(format!("  rm {}", file.display()));
        }
    }
    println!("{}", lines.join("\n"));
    Ok(0)
}
