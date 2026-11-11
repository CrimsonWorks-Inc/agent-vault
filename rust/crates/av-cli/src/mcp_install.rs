//! `agent-vault mcp install`: merge the server into an agent's MCP config,
//! leaving everything else in the file alone. Ports `src/cli/mcp-install.js`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// One agent's config layout. Ports the values of `AGENTS` in
/// `src/cli/mcp-install.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentSpec {
    /// The key (`claude-code`, `cursor`, `gemini`, `codex`).
    pub key: &'static str,
    /// Shown name.
    pub label: &'static str,
    /// `json` or `toml`.
    pub format: &'static str,
    /// The table/object the servers live under.
    pub servers_key: &'static str,
    /// Config path relative to the project, if project scope exists.
    pub project_path: Option<&'static str>,
    /// Config path relative to home, if user scope exists.
    pub user_path: Option<&'static str>,
    /// Scope used when none is given (`project` unless set).
    pub default_scope: Option<&'static str>,
    /// Note printed for project scope.
    pub project_note: Option<&'static str>,
    /// Note printed for user scope.
    pub user_note: Option<&'static str>,
}

/// Ports `AGENTS` in `src/cli/mcp-install.js`.
pub const AGENTS: [AgentSpec; 4] = [
    AgentSpec {
        key: "claude-code",
        label: "Claude Code",
        format: "json",
        servers_key: "mcpServers",
        project_path: Some(".mcp.json"),
        user_path: Some(".claude.json"),
        default_scope: None,
        project_note: Some(
            "Project scope puts it in .mcp.json, which you can commit for your team.",
        ),
        user_note: Some("User scope makes it available in every project on this machine."),
    },
    AgentSpec {
        key: "cursor",
        label: "Cursor",
        format: "json",
        servers_key: "mcpServers",
        project_path: Some(".cursor/mcp.json"),
        user_path: Some(".cursor/mcp.json"),
        default_scope: None,
        project_note: None,
        user_note: None,
    },
    AgentSpec {
        key: "gemini",
        label: "Gemini CLI",
        format: "json",
        servers_key: "mcpServers",
        project_path: Some(".gemini/settings.json"),
        user_path: Some(".gemini/settings.json"),
        default_scope: None,
        project_note: Some("Merged into your existing Gemini settings; other keys are left alone."),
        user_note: Some("Merged into your existing Gemini settings; other keys are left alone."),
    },
    AgentSpec {
        key: "codex",
        label: "Codex CLI",
        format: "toml",
        servers_key: "mcp_servers",
        project_path: None,
        user_path: Some(".codex/config.toml"),
        default_scope: Some("user"),
        project_note: None,
        user_note: Some("Codex picks stdio when `command` is present and HTTP when `url` is."),
    },
];

/// The spec for an agent key. Ports `AGENTS[agent]` in
/// `src/cli/mcp-install.js`.
pub fn agent(key: &str) -> Option<&'static AgentSpec> {
    todo!()
}

/// Where the config for this agent and scope lives (`CODEX_HOME` honored
/// for codex). Ports `targetPath(agent, scope, { cwd, home, env })` in
/// `src/cli/mcp-install.js`.
pub fn target_path(
    agent: &str,
    scope: &str,
    cwd: &Path,
    home: &Path,
    env: &BTreeMap<String, String>,
) -> Result<PathBuf, String> {
    todo!()
}

/// The server entry to write. Ports the argument of
/// `serverEntry({ transport, command, args, url, tokenEnv, format })` in
/// `src/cli/mcp-install.js`.
#[derive(Debug, Clone, Default)]
pub struct EntrySpec {
    /// `stdio` (default) or `http`.
    pub transport: String,
    /// The command (stdio).
    pub command: Option<String>,
    /// Its arguments (stdio).
    pub args: Vec<String>,
    /// The URL (http).
    pub url: Option<String>,
    /// Environment variable holding the token (default
    /// `AGENT_VAULT_SESSION`).
    pub token_env: Option<String>,
    /// `json` (default) or `toml`.
    pub format: String,
}

/// The entry object for a config. Ports `serverEntry(...)` in
/// `src/cli/mcp-install.js`.
pub fn server_entry(spec: &EntrySpec) -> Value {
    todo!()
}

/// Merge a server into a JSON config, leaving every other key untouched;
/// returns `(text, unchanged)`. Ports
/// `mergeJson(existingText, { key, name, entry })` in
/// `src/cli/mcp-install.js`.
pub fn merge_json(
    existing_text: &str,
    key: &str,
    name: &str,
    entry: &Value,
) -> Result<(String, bool), String> {
    todo!()
}

/// Merge a server into a TOML config by replacing or appending its table
/// (text-level, so comments survive). Ports
/// `mergeToml(existingText, { key, name, entry })` in
/// `src/cli/mcp-install.js`.
pub fn merge_toml(
    existing_text: &str,
    key: &str,
    name: &str,
    entry: &Value,
) -> Result<String, String> {
    todo!()
}

/// What [`install`] did. Ports the `{ path, block, wrote, unchanged,
/// backup }` result of `install` in `src/cli/mcp-install.js`.
#[derive(Debug, Clone, Default)]
pub struct InstallResult {
    /// The config file.
    pub path: PathBuf,
    /// The block written (or that would be, with `print`).
    pub block: String,
    /// Whether the file was written.
    pub wrote: bool,
    /// Whether the entry was already there as is.
    pub unchanged: bool,
    /// The backup of the previous file, if one was made.
    pub backup: Option<PathBuf>,
}

/// The arguments of [`install`]. Ports the argument of
/// `install({ agent, scope, name, entry, print, cwd, home, env })` in
/// `src/cli/mcp-install.js`.
#[derive(Debug, Clone, Default)]
pub struct InstallSpec {
    /// Agent key.
    pub agent: String,
    /// `project` or `user`.
    pub scope: String,
    /// Server name (default `agent-vault`; checked before it reaches a TOML
    /// header).
    pub name: String,
    /// From [`server_entry`].
    pub entry: Value,
    /// Only compute the block.
    pub print: bool,
    /// Working directory.
    pub cwd: PathBuf,
    /// Home directory.
    pub home: PathBuf,
    /// Environment.
    pub env: BTreeMap<String, String>,
}

/// Write the server into the agent's config. Ports `install(...)` in
/// `src/cli/mcp-install.js`.
pub fn install(spec: &InstallSpec) -> Result<InstallResult, String> {
    todo!()
}
