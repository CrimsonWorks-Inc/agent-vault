//! The command handlers defined in `src/cli/index.js` (`COMMANDS`), one
//! function per key. The handlers merged in from `controlCommands` are in
//! [`crate::control_commands`]. Each returns an [`Outcome`].

use crate::cli::{
    ApprovalsArgs, ApproveArgs, AuditTailArgs, CredAddArgs, DaemonArgs, DenyArgs, DocsArgs,
    EnvArgs, ExecArgs, ListenAddArgs, ListenIdArg, McpInstallArgs, MigrateArgs, PhCheckArgs,
    PhNextArgs, SessionSpecArgs, SetupArgs, SidArg, SlugArg, TlsSetupArgs, UiArgs, UpgradeArgs,
    WatchArgs,
};
use crate::{Context, Outcome};

/// Ports `COMMANDS.setup(args)` in `src/cli/index.js`.
pub async fn setup(ctx: &Context, args: &SetupArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.daemon(args)` in `src/cli/index.js`.
pub async fn daemon(ctx: &Context, args: &DaemonArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.upgrade(args)` in `src/cli/index.js`.
pub async fn upgrade(ctx: &Context, args: &UpgradeArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.quickstart()` in `src/cli/index.js`.
pub async fn quickstart(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.status()` in `src/cli/index.js`.
pub async fn status(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['cred:add'](args)` in `src/cli/index.js`.
pub async fn cred_add(ctx: &Context, args: &CredAddArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['cred:list']()` in `src/cli/index.js`.
pub async fn cred_list(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['cred:rm'](args)` in `src/cli/index.js`.
pub async fn cred_rm(ctx: &Context, args: &SlugArg) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['session:create'](args)` in `src/cli/index.js`.
pub async fn session_create(ctx: &Context, args: &SessionSpecArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['session:list']()` in `src/cli/index.js`.
pub async fn session_list(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['session:revoke'](args)` in `src/cli/index.js`.
pub async fn session_revoke(ctx: &Context, args: &SidArg) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['ph:next'](args)` in `src/cli/index.js`.
pub async fn ph_next(ctx: &Context, args: &PhNextArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['ph:check'](args)` in `src/cli/index.js`.
pub async fn ph_check(ctx: &Context, args: &PhCheckArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['ph:pattern']()` in `src/cli/index.js`.
pub async fn ph_pattern(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.env(args)` (with `legacyEnv`, `parseMappings`,
/// `resolveMappings`, `inspectTarget`, `gitWouldCommit`) in
/// `src/cli/index.js`.
pub async fn env(ctx: &Context, args: &EnvArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.exec(args)` (with `looksLikeCredential`,
/// `urlHasPassword`, `VAULT_CONFIG`, `VAULT_GENERATED`) in
/// `src/cli/index.js`.
pub async fn exec(ctx: &Context, args: &ExecArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.approvals(args)` in `src/cli/index.js`.
pub async fn approvals(ctx: &Context, args: &ApprovalsArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.approve(args)` (`decide(args, true)`) in
/// `src/cli/index.js`.
pub async fn approve(ctx: &Context, args: &ApproveArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.deny(args)` (`decide(args, false)`) in
/// `src/cli/index.js`.
pub async fn deny(ctx: &Context, args: &DenyArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['audit:tail'](args)` in `src/cli/index.js`.
pub async fn audit_tail(ctx: &Context, args: &AuditTailArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['listen:add'](args)` in `src/cli/index.js`.
pub async fn listen_add(ctx: &Context, args: &ListenAddArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['listen:list']()` in `src/cli/index.js`.
pub async fn listen_list(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['listen:rm'](args)` in `src/cli/index.js`.
pub async fn listen_rm(ctx: &Context, args: &ListenIdArg) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['tls:setup'](args)` in `src/cli/index.js`.
pub async fn tls_setup(ctx: &Context, args: &TlsSetupArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['tls:status']()` in `src/cli/index.js`.
pub async fn tls_status(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['mcp:install'](args)` in `src/cli/index.js`.
pub async fn mcp_install(ctx: &Context, args: &McpInstallArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['mcp:url']()` in `src/cli/index.js`.
pub async fn mcp_url(ctx: &Context) -> Outcome {
    todo!()
}

/// The stdio MCP bridge to the daemon, resending calls refused for want of
/// a session once one exists ([`crate::session_retry`]). Ports
/// `COMMANDS.mcp()` in `src/cli/index.js`.
pub async fn mcp(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.ui(args, { hash })` in `src/cli/index.js`; `hash` is the
/// fragment `docs` opens on.
pub async fn ui(ctx: &Context, args: &UiArgs, hash: &str) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.docs(args)` in `src/cli/index.js`.
pub async fn docs(ctx: &Context, args: &DocsArgs) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['passphrase:set']()` in `src/cli/index.js`.
pub async fn passphrase_set(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS['passphrase:remove']()` in `src/cli/index.js`.
pub async fn passphrase_remove(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.lock()` in `src/cli/index.js`.
pub async fn lock(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.unlock()` in `src/cli/index.js`.
pub async fn unlock(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.profiles()` in `src/cli/index.js`.
pub async fn profiles(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.doctor()` (with `appFingerprint`) in `src/cli/index.js`.
pub async fn doctor(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `COMMANDS.watch(args)` in `src/cli/index.js`.
pub async fn watch(ctx: &Context, args: &WatchArgs) -> Outcome {
    todo!()
}

/// Convert a JSON vault into `vault.db` (or report what would happen with
/// `--dry-run`). New in the Rust port; the steps are in PLAN.md,
/// "`agent-vault migrate`". No JS handler.
pub async fn migrate(ctx: &Context, args: &MigrateArgs) -> Outcome {
    todo!()
}
