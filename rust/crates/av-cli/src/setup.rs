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
    let mut argv = Vec::new();
    if cli.dry_run {
        argv.push("--dry-run".into());
    }
    match cli.command {
        Some(SetupCommand::Install(args)) => {
            argv.push("install".into());
            push_opt(&mut argv, "--user", args.user);
            push_opt(&mut argv, "--port", args.port);
            push_opt(&mut argv, "--use-node", args.use_node);
            push_opt(&mut argv, "--from", args.from);
        }
        Some(SetupCommand::Uninstall(args)) => {
            argv.push("uninstall".into());
            if args.purge {
                argv.push("--purge".into());
            }
        }
        Some(SetupCommand::Status) => argv.push("status".into()),
        Some(SetupCommand::Help) | None => argv.push("help".into()),
    }
    run_setup_argv(&argv)
}

fn push_opt(argv: &mut Vec<String>, flag: &str, value: Option<String>) {
    if let Some(value) = value {
        argv.push(flag.into());
        argv.push(value);
    }
}

/// Render a clap parse error as the installer would: an unknown or missing
/// verb prints the help and exits 0; anything else is `die()`. Ports the
/// `default: help()` case of `bin/agent-vault-setup.js`.
pub fn setup_clap_failure(err: clap::Error) -> Exit {
    use clap::error::ErrorKind::{DisplayHelp, DisplayVersion, InvalidSubcommand};
    match err.kind() {
        DisplayHelp | DisplayVersion | InvalidSubcommand => {
            help();
            Exit::Ok
        }
        _ => {
            emit_die(&Die {
                message: err.to_string(),
                hint: None,
            });
            Exit::Failure
        }
    }
}

/// JS-style argv: the verb is the first argument that does not start with `-`.
pub fn run_setup_argv(argv: &[String]) -> Exit {
    match dispatch(argv) {
        Ok(()) => Exit::Ok,
        Err(die) => {
            emit_die(&die);
            Exit::Failure
        }
    }
}

fn dispatch(argv: &[String]) -> Result<(), Die> {
    let setup = Ctx {
        args: argv.to_vec(),
        dry: flag(argv, "dry-run"),
        verb: verb_of(argv),
    };
    match setup.verb.as_str() {
        "install" => install(&setup),
        "uninstall" => uninstall(&setup),
        "status" => status(&setup),
        _ => {
            help();
            Ok(())
        }
    }
}

#[derive(Debug)]
pub(crate) struct Die {
    pub(crate) message: String,
    hint: Option<String>,
}

impl Die {
    fn new(message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            hint: Some(hint.into()),
        }
    }

    fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            hint: None,
        }
    }
}

impl From<std::io::Error> for Die {
    fn from(error: std::io::Error) -> Self {
        Self::msg(error.to_string())
    }
}

fn emit_die(die: &Die) {
    eprintln!("\ncannot continue  {}", die.message);
    if let Some(hint) = &die.hint {
        eprintln!("  {hint}");
    }
}

struct Ctx {
    args: Vec<String>,
    dry: bool,
    verb: String,
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == &format!("--{name}"))
}

fn value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let key = format!("--{name}");
    let index = args.iter().position(|a| a == &key)?;
    args.get(index + 1).map(String::as_str)
}

fn verb_of(args: &[String]) -> String {
    args.iter()
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| "help".into())
}

fn tty() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}

fn paint(code: &str, text: &str) -> String {
    if tty() {
        format!("\u{1b}[{code}m{text}\u{1b}[0m")
    } else {
        text.to_string()
    }
}

fn say(text: &str) {
    println!("{text}");
}

fn step(ctx: &Ctx, text: &str) {
    let tag = if ctx.dry {
        paint("33", "would")
    } else {
        paint("32", "ok   ")
    };
    say(&format!("{tag} {text}"));
}

const SERVICE_USER: &str = "_agentvault";
const CLIENT_GROUP: &str = "_agentvault_users";
const LAUNCHD_LABEL: &str = "com.agentvault.daemon";

fn is_mac() -> bool {
    cfg!(target_os = "macos")
}

fn root_dir() -> PathBuf {
    // A non-root dry run may relocate the tree so tests never touch the real
    // install. The privileged install does not read this variable. An unknown
    // uid (`id` failed) is treated as root, so the relocation stays closed.
    if current_uid().is_some_and(|uid| uid != 0) {
        if let Ok(path) = std::env::var("AGENT_VAULT_SETUP_DRY_ROOT") {
            if !path.is_empty() {
                return PathBuf::from(path);
            }
        }
    }
    if is_mac() {
        PathBuf::from("/var/db/agent-vault")
    } else {
        PathBuf::from("/usr/libexec/agent-vault")
    }
}

fn vault_dir() -> PathBuf {
    if is_mac() {
        root_dir().join("vault")
    } else {
        PathBuf::from("/var/lib/agent-vault")
    }
}

fn run_dir() -> PathBuf {
    if is_mac() {
        root_dir().join("run")
    } else {
        PathBuf::from("/run/agent-vault")
    }
}

fn app_dir() -> PathBuf {
    root_dir().join("app")
}

fn state_path() -> PathBuf {
    root_dir().join("state.json")
}

fn plist_path() -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons").join(format!("{LAUNCHD_LABEL}.plist"))
}

const SYSTEMD_UNIT: &str = "/etc/systemd/system/agent-vault.service";

/// Fixed environment for every privileged helper. PATH is not inherited.
const SAFE_ENV_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

fn safe_env() -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("PATH".into(), SAFE_ENV_PATH.into());
    env.insert("LC_ALL".into(), "C".into());
    env
}

/// Allow-list of privileged helpers. A name that is not here is never run.
fn bin_candidates(cmd: &str) -> Option<&'static [&'static str]> {
    Some(match cmd {
        "id" => &["/usr/bin/id"],
        "dscl" => &["/usr/bin/dscl"],
        "dseditgroup" => &["/usr/sbin/dseditgroup"],
        "getent" => &["/usr/bin/getent"],
        "useradd" => &["/usr/sbin/useradd"],
        "usermod" => &["/usr/sbin/usermod"],
        "groupadd" => &["/usr/sbin/groupadd"],
        "chown" => &["/usr/sbin/chown", "/bin/chown"],
        "chmod" => &["/bin/chmod"],
        "setfacl" => &["/usr/bin/setfacl", "/bin/setfacl"],
        "launchctl" => &["/bin/launchctl"],
        "systemctl" => &["/usr/bin/systemctl", "/bin/systemctl"],
        "sleep" => &["/bin/sleep"],
        _ => return None,
    })
}

/// Resolve a helper to an absolute allow-listed path. Never a PATH lookup.
pub(crate) fn resolve_bin(cmd: &str) -> Result<PathBuf, String> {
    let Some(candidates) = bin_candidates(cmd) else {
        return Err(format!(
            "refusing to run \"{cmd}\": not in the allow-list of privileged helpers"
        ));
    };
    if let Some(found) = candidates.iter().map(Path::new).find(|p| p.exists()) {
        return Ok(found.to_path_buf());
    }
    Err(format!(
        "cannot find {cmd} at {}. Refusing to fall back to PATH: this process is root, and PATH came from a user account an agent may control.",
        candidates.join(" or ")
    ))
}

fn run(ctx: &Ctx, cmd: &str, args: &[&str]) -> Result<String, Die> {
    run_opts(ctx, cmd, args, false)
}

fn run_opts(ctx: &Ctx, cmd: &str, args: &[&str], allow_fail: bool) -> Result<String, Die> {
    if ctx.dry {
        say(&format!(
            "       {}",
            paint("2", &format!("{cmd} {}", args.join(" ")))
        ));
        return Ok(String::new());
    }
    let bin = resolve_bin(cmd).map_err(Die::msg)?;
    let output = Command::new(&bin)
        .args(args)
        .env_clear()
        .envs(safe_env())
        .output()
        .map_err(|e| Die::msg(format!("{cmd} {} failed: {e}", args.join(" "))))?;
    if output.status.success() || allow_fail {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(Die::msg(format!(
        "{cmd} {} failed: {}",
        args.join(" "),
        stderr.trim()
    )))
}

fn is_root() -> bool {
    current_uid() == Some(0)
}

/// `None` when `id -u` fails. Callers treat that as root (fail closed).
fn current_uid() -> Option<u32> {
    Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| text.trim().parse().ok())
}

fn username() -> String {
    std::env::var("USER").unwrap_or_else(|_| "user".into())
}

fn require_root(ctx: &Ctx) -> Result<(), Die> {
    // A dry run must be readable without sudo.
    if ctx.dry {
        return Ok(());
    }
    match current_uid() {
        Some(0) => Ok(()),
        None => Err(Die::msg(
            "cannot tell whether this process is root (`id -u` failed). Refusing to continue.",
        )),
        Some(_) => {
            let exe =
                std::env::current_exe().unwrap_or_else(|_| PathBuf::from("agent-vault-setup"));
            Err(Die::new(
                "this must run as root.",
                format!("try: sudo {} {}", exe.display(), ctx.verb),
            ))
        }
    }
}

struct Enrolled {
    name: String,
    uid: u32,
}

fn enrolled_user(ctx: &Ctx) -> Result<Enrolled, Die> {
    let name = value(&ctx.args, "user")
        .map(str::to_string)
        .or_else(|| std::env::var("SUDO_USER").ok())
        .or_else(|| if ctx.dry { Some(username()) } else { None });
    let Some(name) = name.filter(|n| !n.is_empty()) else {
        return Err(Die::new(
            "cannot tell which account to enrol.",
            "Run this through sudo from your own account, or pass --user <name>.",
        ));
    };
    if name == "root" {
        return Err(Die::new(
            "refusing to enrol root.",
            "Run sudo from your normal account.",
        ));
    }
    let uid = if ctx.dry {
        if name == username() {
            current_uid().unwrap_or(0)
        } else {
            0
        }
    } else {
        let bin = resolve_bin("id").map_err(Die::msg)?;
        let output = Command::new(bin)
            .args(["-u", &name])
            .env_clear()
            .envs(safe_env())
            .output()
            .map_err(|_| Die::msg(format!("no such user: {name}")))?;
        if !output.status.success() {
            return Err(Die::msg(format!("no such user: {name}")));
        }
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .map_err(|_| Die::msg(format!("no such user: {name}")))?
    };
    Ok(Enrolled { name, uid })
}

fn is_root_owned(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => meta.uid() == 0 && (meta.mode() & 0o022) == 0,
        Err(_) => false,
    }
}

fn assert_root_owned_chain(path: &Path, what: &str) -> Result<(), Die> {
    let mut current = path.to_path_buf();
    loop {
        if current.exists() {
            let meta = std::fs::metadata(&current)?;
            let group_or_other = (meta.mode() & 0o022) != 0;
            let sticky = (meta.mode() & 0o1000) != 0;
            if meta.uid() != 0 || (group_or_other && !sticky) {
                return Err(Die::new(
                    format!(
                        "{what} sits under {}, which is writable by uid {}.",
                        current.display(),
                        meta.uid()
                    ),
                    "Anything there can be replaced by a process running as you, so root must not execute from it.",
                ));
            }
        }
        let Some(parent) = current.parent() else {
            return Ok(());
        };
        if parent == current {
            return Ok(());
        }
        current = parent.to_path_buf();
    }
}

fn user_exists(ctx: &Ctx, name: &str) -> Result<bool, Die> {
    if is_mac() {
        Ok(run_opts(
            ctx,
            "dscl",
            &[".", "-read", &format!("/Users/{name}"), "UniqueID"],
            true,
        )?
        .contains("UniqueID"))
    } else {
        Ok(!run_opts(ctx, "getent", &["passwd", name], true)?
            .trim()
            .is_empty())
    }
}

fn group_exists(ctx: &Ctx, name: &str) -> Result<bool, Die> {
    if is_mac() {
        Ok(run_opts(
            ctx,
            "dscl",
            &[".", "-read", &format!("/Groups/{name}")],
            true,
        )?
        .contains("RecordName"))
    } else {
        Ok(!run_opts(ctx, "getent", &["group", name], true)?
            .trim()
            .is_empty())
    }
}

/// One thing `record` noted, so uninstall can remove it. Field order matches
/// the JS `{ kind, id }` object.
struct CreatedItem {
    kind: String,
    id: String,
}

/// The installer's `state.json` document. `version` is 1. `retired` is set
/// when uninstall moves the vault aside.
struct InstallState {
    created: Vec<CreatedItem>,
    version: u32,
    retired: Option<String>,
}

fn empty_state() -> InstallState {
    InstallState {
        created: Vec::new(),
        version: 1,
        retired: None,
    }
}

fn record(state: &mut InstallState, kind: &str, id: &str) {
    if !state
        .created
        .iter()
        .any(|item| item.kind == kind && item.id == id)
    {
        state.created.push(CreatedItem {
            kind: kind.to_string(),
            id: id.to_string(),
        });
    }
}

fn load_state() -> InstallState {
    let text = match std::fs::read_to_string(state_path()) {
        Ok(text) => text,
        Err(_) => return empty_state(),
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return empty_state();
    };
    let mut state = empty_state();
    if let Some(version) = value.get("version").and_then(|v| v.as_u64()) {
        state.version = version as u32;
    }
    if let Some(retired) = value.get("retired").and_then(|v| v.as_str()) {
        state.retired = Some(retired.to_string());
    }
    if let Some(created) = value.get("created").and_then(|v| v.as_array()) {
        for item in created {
            let kind = item.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if !kind.is_empty() && !id.is_empty() {
                record(&mut state, kind, id);
            }
        }
    }
    state
}

/// `JSON.stringify(state, null, 2)`: `created`, then `version`, then
/// `retired` when uninstall set it.
pub(crate) fn state_document(
    created: &[(String, String)],
    version: u32,
    retired: Option<&str>,
) -> String {
    let mut items = Vec::new();
    for (kind, id) in created {
        let mut obj = serde_json::Map::new();
        obj.insert("kind".into(), serde_json::Value::String(kind.clone()));
        obj.insert("id".into(), serde_json::Value::String(id.clone()));
        items.push(serde_json::Value::Object(obj));
    }
    let mut root = serde_json::Map::new();
    root.insert("created".into(), serde_json::Value::Array(items));
    root.insert("version".into(), serde_json::json!(version));
    if let Some(retired) = retired {
        root.insert(
            "retired".into(),
            serde_json::Value::String(retired.to_string()),
        );
    }
    serde_json::to_string_pretty(&serde_json::Value::Object(root)).unwrap_or_else(|_| "{}".into())
}

fn save_state(ctx: &Ctx, state: &InstallState) -> Result<(), Die> {
    if ctx.dry {
        return Ok(());
    }
    let created: Vec<(String, String)> = state
        .created
        .iter()
        .map(|item| (item.kind.clone(), item.id.clone()))
        .collect();
    let body = state_document(&created, state.version, state.retired.as_deref());
    write_root_file(ctx, &state_path(), &body)
}

/// Remove recorded dirs (except the vault, which uninstall retired) and
/// files. Returns the paths it removed or would remove.
pub(crate) fn delete_recorded(dry: bool, items: &[(String, String)], vault: &Path) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    for (kind, id) in items.iter().rev() {
        let path = PathBuf::from(id);
        if kind == "dir" && path != vault {
            if !dry {
                let _ = std::fs::remove_dir_all(&path);
            }
            removed.push(path);
        } else if kind == "file" {
            if !dry {
                let _ = std::fs::remove_file(&path);
            }
            removed.push(path);
        }
    }
    removed
}

fn create_service_user(ctx: &Ctx, state: &mut InstallState) -> Result<(), Die> {
    // Under a dry run the service user was only described, not created, so
    // the plan shows this step anyway.
    if ctx.dry || user_exists(ctx, SERVICE_USER)? {
        step(ctx, &format!("service user {SERVICE_USER} already exists"));
        return Ok(());
    }
    if is_mac() {
        let uid = mac_free_uid(ctx)?;
        let user = format!("/Users/{SERVICE_USER}");
        run(ctx, "dscl", &[".", "-create", &user])?;
        run(
            ctx,
            "dscl",
            &[".", "-create", &user, "UniqueID", &uid.to_string()],
        )?;
        run(
            ctx,
            "dscl",
            &[".", "-create", &user, "PrimaryGroupID", &uid.to_string()],
        )?;
        run(
            ctx,
            "dscl",
            &[".", "-create", &user, "UserShell", "/usr/bin/false"],
        )?;
        run(
            ctx,
            "dscl",
            &[".", "-create", &user, "NFSHomeDirectory", "/var/empty"],
        )?;
        run(
            ctx,
            "dscl",
            &[".", "-create", &user, "RealName", "agent-vault daemon"],
        )?;
        run(ctx, "dscl", &[".", "-create", &user, "IsHidden", "1"])?;
        let _ = run_opts(
            ctx,
            "dscl",
            &[".", "-create", &format!("/Groups/{SERVICE_USER}")],
            true,
        );
        let _ = run_opts(
            ctx,
            "dscl",
            &[
                ".",
                "-create",
                &format!("/Groups/{SERVICE_USER}"),
                "PrimaryGroupID",
                &uid.to_string(),
            ],
            true,
        );
    } else {
        let vault = vault_dir();
        run(
            ctx,
            "useradd",
            &[
                "--system",
                "--user-group",
                "--home-dir",
                &vault.to_string_lossy(),
                "--shell",
                "/usr/sbin/nologin",
                "--comment",
                "agent-vault daemon",
                SERVICE_USER,
            ],
        )?;
    }
    record(state, "user", SERVICE_USER);
    step(
        ctx,
        &format!(
            "created service user {} {}",
            paint("1", SERVICE_USER),
            paint("2", "(no shell, no home, hidden)")
        ),
    );
    Ok(())
}

fn mac_free_uid(ctx: &Ctx) -> Result<u32, Die> {
    if ctx.dry {
        return Ok(399);
    }
    let listed = run(ctx, "dscl", &[".", "-list", "/Users", "UniqueID"])?;
    let used: Vec<u32> = listed
        .lines()
        .filter_map(|line| line.split_whitespace().last()?.parse().ok())
        .collect();
    for uid in 300..400 {
        if !used.contains(&uid) {
            return Ok(uid);
        }
    }
    Err(Die::msg("no free system uid between 300 and 399."))
}

fn create_client_group(
    ctx: &Ctx,
    enrolled: &Enrolled,
    state: &mut InstallState,
) -> Result<(), Die> {
    if !group_exists(ctx, CLIENT_GROUP)? {
        if is_mac() {
            run(
                ctx,
                "dseditgroup",
                &["-o", "create", "-r", "agent-vault clients", CLIENT_GROUP],
            )?;
        } else {
            run(ctx, "groupadd", &["--system", CLIENT_GROUP])?;
        }
        record(state, "group", CLIENT_GROUP);
        step(
            ctx,
            &format!("created client group {}", paint("1", CLIENT_GROUP)),
        );
    } else {
        step(ctx, &format!("client group {CLIENT_GROUP} already exists"));
    }
    if is_mac() {
        run(
            ctx,
            "dseditgroup",
            &[
                "-o",
                "edit",
                "-a",
                &enrolled.name,
                "-t",
                "user",
                CLIENT_GROUP,
            ],
        )?;
    } else {
        run(ctx, "usermod", &["-aG", CLIENT_GROUP, &enrolled.name])?;
    }
    record(
        state,
        "group-member",
        &format!("{CLIENT_GROUP}:{}", enrolled.name),
    );
    step(
        ctx,
        &format!(
            "added {} to {CLIENT_GROUP} {}",
            paint("1", &enrolled.name),
            paint("2", "(effective at next login; an ACL covers this session)")
        ),
    );
    // The daemon sets the group on each socket. A process cannot chown to a
    // group it is not a member of.
    if ctx.dry || user_exists(ctx, SERVICE_USER)? {
        if is_mac() {
            let _ = run_opts(
                ctx,
                "dseditgroup",
                &["-o", "edit", "-a", SERVICE_USER, "-t", "user", CLIENT_GROUP],
                true,
            );
        } else {
            let _ = run_opts(ctx, "usermod", &["-aG", CLIENT_GROUP, SERVICE_USER], true);
        }
        step(
            ctx,
            &format!(
                "added {} to {CLIENT_GROUP} {}",
                paint("1", SERVICE_USER),
                paint("2", "so it can group-own the sockets it creates")
            ),
        );
    }
    Ok(())
}

fn service_ids(ctx: &Ctx) -> Result<(u32, u32), Die> {
    if ctx.dry {
        return Ok((399, 399));
    }
    let uid: u32 = run(ctx, "id", &["-u", SERVICE_USER])?
        .trim()
        .parse()
        .unwrap_or(0);
    let gid: u32 = run(ctx, "id", &["-g", SERVICE_USER])?
        .trim()
        .parse()
        .unwrap_or(0);
    Ok((uid, gid))
}

fn client_gid(ctx: &Ctx) -> Result<u32, Die> {
    if ctx.dry {
        return Ok(399);
    }
    if is_mac() {
        let out = run(
            ctx,
            "dscl",
            &[
                ".",
                "-read",
                &format!("/Groups/{CLIENT_GROUP}"),
                "PrimaryGroupID",
            ],
        )?;
        Ok(out
            .split(':')
            .next_back()
            .unwrap_or("0")
            .trim()
            .parse()
            .unwrap_or(0))
    } else {
        let out = run(ctx, "getent", &["group", CLIENT_GROUP])?;
        Ok(out.split(':').nth(2).unwrap_or("0").parse().unwrap_or(0))
    }
}

fn make_dir(ctx: &Ctx, path: &Path, mode: u32, uid: u32, gid: u32) -> Result<(), Die> {
    let octal = format!("0{mode:o}");
    if ctx.dry {
        say(&format!(
            "       {}",
            paint(
                "2",
                &format!("mkdir -m {octal} {}  (owner {uid}:{gid})", path.display())
            )
        ));
        return Ok(());
    }
    std::fs::create_dir_all(path)?;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms)?;
    run(
        ctx,
        "chown",
        &[&format!("{uid}:{gid}"), &path.to_string_lossy()],
    )?;
    Ok(())
}

fn build_tree(ctx: &Ctx, enrolled: &Enrolled, state: &mut InstallState) -> Result<(), Die> {
    let root = root_dir();
    assert_root_owned_chain(root.parent().unwrap_or(&root), "the install root")?;
    make_dir(ctx, &root, 0o755, 0, 0)?;
    record(state, "dir", &root.display().to_string());
    let (uid, gid) = service_ids(ctx)?;
    let vault = vault_dir();
    make_dir(ctx, &vault, 0o700, uid, gid)?;
    record(state, "dir", &vault.display().to_string());
    step(
        ctx,
        &format!(
            "{} {}",
            paint("1", &vault.display().to_string()),
            paint("2", &format!("0700 {SERVICE_USER} - this is the boundary"))
        ),
    );
    let run_path = run_dir();
    make_dir(ctx, &run_path, 0o2750, uid, client_gid(ctx)?)?;
    record(state, "dir", &run_path.display().to_string());
    if is_mac() {
        let _ = run_opts(
            ctx,
            "chmod",
            &[
                "+a",
                &format!(
                    "user:{} allow read,write,execute,search,add_file,delete_child",
                    enrolled.name
                ),
                &run_path.to_string_lossy(),
            ],
            true,
        );
    } else {
        let _ = run_opts(
            ctx,
            "setfacl",
            &[
                "-m",
                &format!("u:{}:rwx", enrolled.name),
                &run_path.to_string_lossy(),
            ],
            true,
        );
    }
    step(
        ctx,
        &format!(
            "{} {}",
            paint("1", &run_path.display().to_string()),
            paint(
                "2",
                &format!(
                    "2750 {SERVICE_USER}:{CLIENT_GROUP} setgid + ACL for {}",
                    enrolled.name
                )
            )
        ),
    );
    Ok(())
}

fn checkout_from(ctx: &Ctx) -> Result<PathBuf, Die> {
    if let Some(from) = value(&ctx.args, "from") {
        return Ok(PathBuf::from(from)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(from)));
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        while let Some(current) = dir {
            if current.join("src").is_dir()
                && current.join("bin").is_dir()
                && current.join("package.json").is_file()
            {
                return Ok(current);
            }
            dir = current.parent().map(Path::to_path_buf);
        }
    }
    Err(Die::msg(
        "could not find an agent-vault checkout. Pass --from <path to your checkout>.",
    ))
}

/// Resolve every existing prefix, so `/var` and `/private/var` compare equal
/// on macOS even when the final component does not exist yet.
pub(crate) fn canonical_prefix(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            std::path::Component::RootDir => out.push("/"),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(part) => {
                out.push(part);
                if let Ok(real) = out.canonicalize() {
                    out = real;
                }
            }
        }
    }
    if out.as_os_str().is_empty() {
        path.to_path_buf()
    } else {
        out
    }
}

/// True when installing `source` would delete or overwrite the source itself.
/// Both sides are canonicalized. Equality, source-inside-app, and
/// app-inside-source all refuse.
pub(crate) fn refuses_self_install(source: &Path, app: &Path) -> bool {
    let source = canonical_prefix(source);
    let app = canonical_prefix(app);
    source == app || source.starts_with(&app) || app.starts_with(&source)
}

/// True when this process's executable resolves inside `app`. Deleting `app`
/// would delete the binary that is doing the delete.
fn binary_inside(app: &Path) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    canonical_prefix(&exe).starts_with(canonical_prefix(app))
}

fn install_app(ctx: &Ctx, state: &mut InstallState) -> Result<(), Die> {
    let source = checkout_from(ctx)?;
    for required in ["src", "bin", "package.json"] {
        if !source.join(required).exists() {
            return Err(Die::msg(format!(
                "{} does not look like an agent-vault checkout (no {required}).",
                source.display()
            )));
        }
    }
    let app = app_dir();
    if refuses_self_install(&source, &app) || binary_inside(&app) {
        return Err(Die::new(
            "refusing to install the app directory over itself.",
            "Pass --from <path to your checkout> so there is something new to install.",
        ));
    }
    assert_no_symlinks(&source, &["src", "bin", "package.json"])?;
    if !ctx.dry {
        // Never delete a path that resolves into the source. The guard above
        // already refused that; this is the last check before the unlink.
        if refuses_self_install(&source, &app) {
            return Err(Die::new(
                "refusing to install the app directory over itself.",
                "Pass --from <path to your checkout> so there is something new to install.",
            ));
        }
        if app.exists() {
            std::fs::remove_dir_all(&app)?;
        }
        std::fs::create_dir_all(&app)?;
        for part in ["src", "bin", "package.json"] {
            // dereference: copy the target of a link, never the link itself.
            copy_dereference(&source.join(part), &app.join(part))?;
        }
        copy_rust_bins(&app)?;
        if is_mac() {
            let _ = run_opts(
                ctx,
                "chown",
                &["-R", "root:wheel", &app.to_string_lossy()],
                true,
            );
        } else {
            run(ctx, "chown", &["-R", "root:root", &app.to_string_lossy()])?;
        }
        run(
            ctx,
            "chmod",
            &["-R", "u-s,g-s,go-w", &app.to_string_lossy()],
        )?;
    }
    record(state, "dir", &app.display().to_string());
    step(
        ctx,
        &format!(
            "copied the daemon into {} {}",
            paint("1", &app.display().to_string()),
            paint("2", &format!("from {}", source.display()))
        ),
    );
    Ok(())
}

fn copy_rust_bins(app: &Path) -> Result<(), Die> {
    let exe = std::env::current_exe().map_err(|_| {
        Die::msg("the daemon binary is missing: this process has no executable path")
    })?;
    let Some(dir) = exe.parent() else {
        return Err(Die::msg(
            "the daemon binary is missing: this process has no directory",
        ));
    };
    let dest = app.join("bin");
    std::fs::create_dir_all(&dest)?;
    for name in ["agent-vault", "agent-vault-daemon", "agent-vault-setup"] {
        let src = dir.join(name);
        if name == "agent-vault-daemon" {
            require_regular_daemon(&src)?;
        } else if let Err(error) = require_regular_daemon(&src) {
            if error.message.contains("missing") {
                continue;
            }
            return Err(error);
        }
        if is_root() && !is_root_owned(&src) {
            eprintln!(
                "\nwarning  the binary being copied ({}) is writable by uid {}, not root.",
                src.display(),
                std::fs::metadata(&src).map(|m| m.uid()).unwrap_or(0)
            );
        }
        copy_dereference(&src, &dest.join(name))?;
    }
    Ok(())
}

/// The daemon binary must be a regular file. A symlink would leave the unit
/// running code outside the root-owned tree; a missing file leaves the unit
/// pointing at nothing.
pub(crate) fn require_regular_daemon(src: &Path) -> Result<(), Die> {
    let meta = match std::fs::symlink_metadata(src) {
        Ok(meta) => meta,
        Err(_) => {
            return Err(Die::msg(format!(
                "the daemon binary is missing at {}",
                src.display()
            )));
        }
    };
    if meta.file_type().is_symlink() {
        return Err(Die::new(
            format!("refusing to install: {} is a symbolic link.", src.display()),
            "The service must run a regular file copied into the install, not a link.",
        ));
    }
    if !meta.is_file() {
        return Err(Die::msg(format!(
            "the daemon binary is missing at {}",
            src.display()
        )));
    }
    Ok(())
}

/// Copy `src` onto `dst`, following links. A symlink becomes a regular file
/// (or a directory) holding the target's bytes.
pub(crate) fn copy_dereference(src: &Path, dst: &Path) -> Result<(), Die> {
    let meta = std::fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(src)?;
        let abs = if target.is_absolute() {
            target
        } else {
            src.parent().unwrap_or(Path::new(".")).join(target)
        };
        return copy_dereference(&abs, dst);
    }
    if meta.is_dir() {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            copy_dereference(&entry.path(), &dst.join(entry.file_name()))?;
        }
        return Ok(());
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, dst)?;
    strip_special_bits(dst)?;
    Ok(())
}

/// Drop setuid, setgid and the sticky bit. `std::fs::copy` keeps them for
/// root, and `chmod -R go-w` does not clear them.
fn strip_special_bits(path: &Path) -> Result<(), Die> {
    let meta = std::fs::metadata(path)?;
    let mut perms = meta.permissions();
    perms.set_mode(perms.mode() & !0o7000);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

fn assert_no_symlinks(source: &Path, parts: &[&str]) -> Result<(), Die> {
    fn walk(abs: &Path, shown: &str) -> Result<(), Die> {
        let meta = std::fs::symlink_metadata(abs)?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(abs).unwrap_or_default();
            return Err(Die::new(
                format!("refusing to install: {shown} is a symbolic link."),
                format!(
                    "It points at {}, which is outside the tree root is about to own.",
                    target.display()
                ),
            ));
        }
        if meta.is_dir() {
            for entry in std::fs::read_dir(abs)? {
                let entry = entry?;
                let name = entry.file_name();
                let child = format!("{shown}/{}", name.to_string_lossy());
                walk(&entry.path(), &child)?;
            }
        }
        Ok(())
    }
    for part in parts {
        walk(&source.join(part), part)?;
    }
    Ok(())
}

fn daemon_program() -> PathBuf {
    app_dir().join("bin").join("agent-vault-daemon")
}

fn installed_setup() -> PathBuf {
    app_dir().join("bin").join("agent-vault-setup")
}

/// systemd restarts the unit so a reinstall picks up the new binary.
pub(crate) fn systemd_start_args() -> &'static [&'static str] {
    &["restart", "agent-vault.service"]
}

/// `--port` written into a unit file. Only an integer 1–65535 is accepted,
/// so the value cannot break out of the plist or the unit text.
pub(crate) fn service_port(raw: Option<&str>) -> Result<String, Die> {
    let text = raw.unwrap_or("7411");
    match text.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port.to_string()),
        _ => Err(Die::msg(format!(
            "--port must be an integer from 1 to 65535, not {text}"
        ))),
    }
}

/// launchd plist. The program is the Rust daemon. Every other line matches
/// `installService` in `bin/agent-vault-setup.js`, including a core soft
/// limit of zero and ProcessType Adaptive.
pub(crate) fn launchd_plist(
    program: &Path,
    vault: &Path,
    run: &Path,
    uid: u32,
    port: &str,
) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n  \
<key>Label</key><string>{LAUNCHD_LABEL}</string>\n  \
<key>ProgramArguments</key>\n  \
<array><string>{}</string></array>\n  \
<key>UserName</key><string>{SERVICE_USER}</string>\n  \
<key>GroupName</key><string>{SERVICE_USER}</string>\n  \
<key>RunAtLoad</key><true/>\n  \
<key>KeepAlive</key><true/>\n  \
<key>ProcessType</key><string>Adaptive</string>\n  \
<key>EnvironmentVariables</key>\n  \
<dict>\n    \
<key>AV_VAULT_DIR</key><string>{}</string>\n    \
<key>AV_RUN_DIR</key><string>{}</string>\n    \
<key>AV_ENROLLED_UID</key><string>{uid}</string>\n    \
<key>AV_CLIENT_GROUP</key><string>{CLIENT_GROUP}</string>\n    \
<key>AV_PORT</key><string>{port}</string>\n  \
</dict>\n  \
<key>StandardOutPath</key><string>{}/daemon.out</string>\n  \
<key>StandardErrorPath</key><string>{}/daemon.err</string>\n  \
<key>SoftResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>\n\
</dict>\n\
</plist>\n",
        program.display(),
        vault.display(),
        run.display(),
        vault.display(),
        vault.display(),
    )
}

/// systemd unit. ExecStart is the Rust daemon with no trailing space.
/// Hardening matches `installService` in `bin/agent-vault-setup.js`.
pub(crate) fn systemd_unit(
    program: &Path,
    vault: &Path,
    run: &Path,
    uid: u32,
    port: &str,
) -> String {
    format!(
        "[Unit]\n\
Description=agent-vault daemon\n\
After=network.target\n\
\n\
[Service]\n\
Type=simple\n\
User={SERVICE_USER}\n\
Group={SERVICE_USER}\n\
SupplementaryGroups={CLIENT_GROUP}\n\
ExecStart={}\n\
Environment=AV_VAULT_DIR={}\n\
Environment=AV_RUN_DIR={}\n\
Environment=AV_ENROLLED_UID={uid}\n\
Environment=AV_CLIENT_GROUP={CLIENT_GROUP}\n\
Environment=AV_PORT={port}\n\
RuntimeDirectory=agent-vault\n\
RuntimeDirectoryMode=0750\n\
RuntimeDirectoryPreserve=yes\n\
NoNewPrivileges=yes\n\
ProtectSystem=strict\n\
ProtectHome=yes\n\
PrivateTmp=yes\n\
ReadWritePaths={} {}\n\
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\
CapabilityBoundingSet=\n\
MemoryDenyWriteExecute=yes\n\
LockPersonality=yes\n\
LimitCORE=0\n\
Restart=always\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n",
        program.display(),
        vault.display(),
        run.display(),
        vault.display(),
        run.display(),
    )
}

fn install_service(ctx: &Ctx, enrolled: &Enrolled, state: &mut InstallState) -> Result<(), Die> {
    let program = daemon_program();
    let port = service_port(value(&ctx.args, "port"))?;
    let vault = vault_dir();
    let run_path = run_dir();
    if is_mac() {
        let body = launchd_plist(&program, &vault, &run_path, enrolled.uid, &port);
        let plist = plist_path();
        write_root_file(ctx, &plist, &body)?;
        record(state, "file", &plist.display().to_string());
        bootstrap_launchd(ctx)?;
        step(
            ctx,
            &format!(
                "installed and started the launchd service {}",
                paint("2", LAUNCHD_LABEL)
            ),
        );
    } else {
        let body = systemd_unit(&program, &vault, &run_path, enrolled.uid, &port);
        let unit_path = PathBuf::from(SYSTEMD_UNIT);
        write_root_file(ctx, &unit_path, &body)?;
        record(state, "file", SYSTEMD_UNIT);
        run(ctx, "systemctl", &["daemon-reload"])?;
        let _ = run_opts(ctx, "systemctl", &["enable", "agent-vault.service"], true);
        let args = systemd_start_args();
        run(ctx, "systemctl", args)?;
        step(ctx, "installed and started the systemd service");
    }
    Ok(())
}

/// Write a root-owned mode-0644 file. A dry run prints the path and writes
/// nothing. `chown 0:0` matches `chownSync(path, 0, 0)` in the JS installer.
fn write_root_file(ctx: &Ctx, path: &Path, body: &str) -> Result<(), Die> {
    if ctx.dry {
        say(&format!(
            "       {}",
            paint("2", &format!("write {}", path.display()))
        ));
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, body)?;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(path, perms)?;
    run(ctx, "chown", &["0:0", &path.to_string_lossy()])?;
    Ok(())
}

/// Is the service currently known to launchd?
fn service_loaded() -> bool {
    if !is_root() {
        return false;
    }
    let Ok(bin) = resolve_bin("launchctl") else {
        return false;
    };
    Command::new(bin)
        .args(["print", &format!("system/{LAUNCHD_LABEL}")])
        .env_clear()
        .envs(safe_env())
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn sleep_ms(ms: u64) -> Result<(), Die> {
    let bin = resolve_bin("sleep").map_err(Die::msg)?;
    let _ = Command::new(bin)
        .arg(format!("{}", ms as f64 / 1000.0))
        .env_clear()
        .envs(safe_env())
        .status();
    Ok(())
}

/// Load the service, tolerating the teardown race.
///
/// `launchctl bootout` returns before the job is actually gone, so an
/// immediate bootstrap fails. Waiting, then kickstart when it is still
/// registered, is what makes a reinstall reliable.
fn bootstrap_launchd(ctx: &Ctx) -> Result<(), Die> {
    if ctx.dry {
        say(&format!(
            "       {}",
            paint(
                "2",
                &format!("launchctl bootout system/{LAUNCHD_LABEL}  (then wait for teardown)")
            )
        ));
        say(&format!(
            "       {}",
            paint("2", &format!("launchctl enable system/{LAUNCHD_LABEL}"))
        ));
        say(&format!(
            "       {}",
            paint(
                "2",
                &format!("launchctl bootstrap system {}", plist_path().display())
            )
        ));
        return Ok(());
    }
    let _ = run_opts(
        ctx,
        "launchctl",
        &["bootout", &format!("system/{LAUNCHD_LABEL}")],
        true,
    );
    let mut spins = 0;
    while spins < 40 && service_loaded() {
        sleep_ms(250)?;
        spins += 1;
    }
    let _ = run_opts(
        ctx,
        "launchctl",
        &["enable", &format!("system/{LAUNCHD_LABEL}")],
        true,
    );
    let mut last_error = None;
    for attempt in 1..=5 {
        let bin = resolve_bin("launchctl").map_err(Die::msg)?;
        let output = Command::new(bin)
            .args(["bootstrap", "system", &plist_path().to_string_lossy()])
            .env_clear()
            .envs(safe_env())
            .output()?;
        if output.status.success() || service_loaded() {
            last_error = None;
            break;
        }
        last_error = Some(String::from_utf8_lossy(&output.stderr).trim().to_string());
        sleep_ms(500 * attempt)?;
    }
    if last_error.is_some() && !service_loaded() {
        let bin = resolve_bin("launchctl").map_err(Die::msg)?;
        let kicked = Command::new(bin)
            .args(["kickstart", "-k", &format!("system/{LAUNCHD_LABEL}")])
            .env_clear()
            .envs(safe_env())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if kicked || service_loaded() {
            last_error = None;
        }
    }
    if let Some(error) = last_error {
        if !service_loaded() {
            return Err(Die::new(
                format!("could not start the service: {error}"),
                format!(
                    "The files are installed. Start it with:\n    sudo launchctl bootout system/{LAUNCHD_LABEL} ; sudo launchctl bootstrap system {}",
                    plist_path().display()
                ),
            ));
        }
    }
    for _ in 0..20 {
        if run_dir().join("control.sock").exists() {
            return Ok(());
        }
        sleep_ms(250)?;
    }
    say(&format!(
        "  {}  the service loaded but its socket has not appeared yet; check: agent-vault status",
        paint("33", "warn")
    ));
    Ok(())
}

fn install(ctx: &Ctx) -> Result<(), Die> {
    require_root(ctx)?;
    if value(&ctx.args, "use-node").is_some() {
        return Err(Die::msg(
            "this installer ships the Rust daemon and does not install a Node runtime.",
        ));
    }
    let enrolled = enrolled_user(ctx)?;
    say(&format!(
        "\n{}{}",
        paint("1", "agent-vault install"),
        if ctx.dry {
            paint("33", "  (dry run: nothing will change)")
        } else {
            String::new()
        }
    ));
    let os = if is_mac() { "macOS" } else { "Linux" };
    say(&paint(
        "2",
        &format!(
            "  enrolling {} (uid {}) on {os}\n",
            enrolled.name, enrolled.uid
        ),
    ));
    let mut state = load_state();
    create_service_user(ctx, &mut state)?;
    create_client_group(ctx, &enrolled, &mut state)?;
    build_tree(ctx, &enrolled, &mut state)?;
    install_app(ctx, &mut state)?;
    step(
        ctx,
        "not installing a Node runtime; the service runs the Rust daemon",
    );
    install_service(ctx, &enrolled, &mut state)?;
    save_state(ctx, &state)?;
    say(&format!("\n{}", paint("1", "done")));
    say(&format!(
        "  The daemon runs as {}. Your account cannot read {}.",
        paint("1", SERVICE_USER),
        vault_dir().display()
    ));
    say(&format!(
        "  Check it: {} {}",
        paint("1", &format!("cat {}/vault.json", vault_dir().display())),
        paint("2", "should say Permission denied")
    ));
    say("");
    say(&format!("  Next, as {}:", enrolled.name));
    say(&format!("    {}", paint("1", "agent-vault status")));
    say(&format!(
        "    {}",
        paint("1", "agent-vault cred add gh --kind github")
    ));
    say("");
    say(&paint(
        "2",
        &format!(
            "  To remove everything: sudo {} uninstall",
            installed_setup().display()
        ),
    ));
    say(&paint(
        "2",
        "  (the installed binary is root-owned; there is no Node runtime on root's PATH)",
    ));
    say("");
    Ok(())
}

fn uninstall(ctx: &Ctx) -> Result<(), Die> {
    require_root(ctx)?;
    let purge = flag(&ctx.args, "purge");
    let mut state = load_state();
    say(&format!(
        "\n{}{}\n",
        paint("1", "agent-vault uninstall"),
        if ctx.dry {
            paint("33", "  (dry run)")
        } else {
            String::new()
        }
    ));
    if is_mac() {
        let _ = run_opts(
            ctx,
            "launchctl",
            &["bootout", &format!("system/{LAUNCHD_LABEL}")],
            true,
        );
    } else {
        let _ = run_opts(
            ctx,
            "systemctl",
            &["disable", "--now", "agent-vault.service"],
            true,
        );
    }
    step(ctx, "stopped the service");
    let vault = vault_dir();
    if vault.exists() && !ctx.dry {
        if purge {
            std::fs::remove_dir_all(&vault)?;
            step(
                ctx,
                &paint("31", "deleted the vault and every credential in it"),
            );
        } else {
            // Deliberately outside ROOT: the last step removes ROOT, and on
            // macOS the vault lives inside it.
            let retired = retired_vault_path();
            if retired.starts_with(root_dir()) {
                return Err(Die::msg(format!(
                    "refusing to remove {}: your retired vault is inside it at {}",
                    root_dir().display(),
                    retired.display()
                )));
            }
            std::fs::rename(&vault, &retired)?;
            state.retired = Some(retired.display().to_string());
            step(
                ctx,
                &format!(
                    "kept your credentials at {} {}",
                    paint("1", &retired.display().to_string()),
                    paint("2", "(--purge deletes them instead)")
                ),
            );
        }
    }
    let recorded: Vec<(String, String)> = state
        .created
        .iter()
        .map(|item| (item.kind.clone(), item.id.clone()))
        .collect();
    for path in delete_recorded(ctx.dry, &recorded, &vault) {
        step(ctx, &format!("removed {}", path.display()));
    }
    if ctx.dry || user_exists(ctx, SERVICE_USER)? {
        say(&paint(
            "2",
            &format!("       left the {SERVICE_USER} account in place; removing it would free its uid for reuse"),
        ));
    }
    let root = root_dir();
    if !ctx.dry && root.exists() {
        if let Some(retired) = &state.retired {
            if Path::new(retired).starts_with(&root) {
                return Err(Die::msg(format!(
                    "refusing to remove {}: your retired vault is inside it at {retired}",
                    root.display()
                )));
            }
        }
        std::fs::remove_dir_all(&root)?;
    }
    say(&format!(
        "\n{}  Your own ~/.agent-vault dev vault, if any, is untouched.\n",
        paint("1", "done")
    ));
    Ok(())
}

/// The path a retired vault moves to. It is a sibling of the install root,
/// never a child of it.
pub(crate) fn retired_vault_path() -> PathBuf {
    let root = root_dir();
    let parent = root.parent().unwrap_or(Path::new("/"));
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    parent.join(format!("agent-vault-retired-{millis}"))
}

fn status(_ctx: &Ctx) -> Result<(), Die> {
    let installed = state_path().is_file();
    say(&format!("\n{}\n", paint("1", "agent-vault system install")));
    if !installed {
        say(&format!(
            "  {}  no {}",
            paint("33", "not installed"),
            state_path().display()
        ));
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("agent-vault-setup"));
        say(&format!(
            "  {}\n",
            paint(
                "2",
                &format!("install with: sudo {} install", exe.display())
            )
        ));
        return Ok(());
    }
    let quiet = Ctx {
        args: Vec::new(),
        dry: false,
        verb: "status".into(),
    };
    let mut checks: Vec<(String, bool, String)> = Vec::new();
    let user_ok = user_exists(&quiet, SERVICE_USER).unwrap_or(false);
    checks.push(("service user".into(), user_ok, SERVICE_USER.into()));
    let vault = vault_dir();
    if vault.exists() {
        match std::fs::metadata(&vault) {
            Ok(meta) => {
                let mode = meta.mode() & 0o777;
                checks.push((
                    "vault mode 0700".into(),
                    mode == 0o700,
                    format!("0{mode:o}"),
                ));
                let uid = current_uid().unwrap_or(0);
                checks.push((
                    "vault owned by service user".into(),
                    meta.uid() != 0 && meta.uid() != uid,
                    format!("uid {}", meta.uid()),
                ));
            }
            Err(error) => checks.push(("vault directory".into(), false, error.to_string())),
        }
    } else {
        checks.push(("vault directory".into(), false, "missing".into()));
    }
    let unit = if is_mac() {
        plist_path()
    } else {
        PathBuf::from(SYSTEMD_UNIT)
    };
    checks.push((
        "service unit".into(),
        unit.exists(),
        unit.display().to_string(),
    ));
    let run_path = run_dir();
    checks.push((
        "socket directory".into(),
        run_path.exists(),
        run_path.display().to_string(),
    ));
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("agent-vault-setup"));
    let trusted = canonical_prefix(&exe).starts_with(canonical_prefix(&app_dir()));
    checks.push((
        "running the root-owned installer".into(),
        trusted,
        if trusted {
            app_dir().display().to_string()
        } else {
            exe.display().to_string()
        },
    ));
    for (name, ok, note) in &checks {
        let mark = if *ok {
            paint("32", "ok  ")
        } else {
            paint("33", "warn")
        };
        say(&format!("  {mark} {:<32} {}", name, paint("2", note)));
    }
    say("");
    Ok(())
}

fn help() {
    say(&format!(
        "\n{}  the privileged installer\n\n  {} [--user <name>] [--port 7411] [--dry-run]\n  {} [--purge] [--dry-run]\n  {}\n\n  install creates the {SERVICE_USER} system user and a root-owned tree, so the\n  vault is unreadable to anything running as you. --dry-run prints every change\n  it would make and touches nothing.\n  --use-node is refused: this installer ships the Rust daemon and does not copy a Node runtime.\n",
        paint("1", "agent-vault-setup"),
        paint("1", "sudo agent-vault-setup install"),
        paint("1", "sudo agent-vault-setup uninstall"),
        paint("1", "agent-vault-setup status"),
    ));
}

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
