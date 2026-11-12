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
    AGENTS.iter().find(|a| a.key == key)
}

/// Where the config for this agent and scope lives (`CODEX_HOME` honored
/// for codex). Ports `targetPath(agent, scope, { cwd, home, env })` in
/// `src/cli/mcp-install.js`.
pub fn target_path(
    agent_key: &str,
    scope: &str,
    cwd: &Path,
    home: &Path,
    env: &BTreeMap<String, String>,
) -> Result<PathBuf, String> {
    let spec = agent(agent_key).ok_or_else(|| {
        format!(
            "unknown agent: {agent_key}. Known: {}",
            AGENTS.iter().map(|a| a.key).collect::<Vec<_>>().join(", ")
        )
    })?;
    let rel = match scope {
        "project" => spec.project_path,
        "user" => spec.user_path,
        _ => None,
    };
    let Some(rel) = rel else {
        return Err(format!("{} has no {scope} scope", spec.label));
    };
    if agent_key == "codex" {
        if let Some(home_dir) = env.get("CODEX_HOME").filter(|s| !s.is_empty()) {
            return Ok(PathBuf::from(home_dir).join("config.toml"));
        }
    }
    if Path::new(rel).is_absolute() {
        return Ok(PathBuf::from(rel));
    }
    let base = if scope == "user" { home } else { cwd };
    Ok(base.join(rel))
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
    use serde_json::{Map, Value};
    let transport = if spec.transport.is_empty() {
        "stdio"
    } else {
        spec.transport.as_str()
    };
    let format = if spec.format.is_empty() {
        "json"
    } else {
        spec.format.as_str()
    };
    let token_env = spec
        .token_env
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("AGENT_VAULT_SESSION");
    if transport == "http" {
        if format == "toml" {
            let mut row = Map::new();
            row.insert(
                "url".into(),
                Value::from(spec.url.clone().unwrap_or_default()),
            );
            row.insert("bearer_token_env_var".into(), Value::from(token_env));
            return Value::Object(row);
        }
        let mut headers = Map::new();
        headers.insert(
            "Authorization".into(),
            Value::from(format!("Bearer ${{{token_env}}}")),
        );
        let mut row = Map::new();
        row.insert("type".into(), Value::from("http"));
        row.insert(
            "url".into(),
            Value::from(spec.url.clone().unwrap_or_default()),
        );
        row.insert("headers".into(), Value::Object(headers));
        return Value::Object(row);
    }
    let mut row = Map::new();
    row.insert(
        "command".into(),
        Value::from(spec.command.clone().unwrap_or_default()),
    );
    row.insert("args".into(), Value::from(spec.args.clone()));
    Value::Object(row)
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
    use serde_json::{Map, Value};
    let mut doc = Map::new();
    if !existing_text.trim().is_empty() {
        let parsed: Value = serde_json::from_str(existing_text).map_err(|e| {
            format!("the existing file is not valid JSON ({e}); fix or move it first")
        })?;
        match parsed {
            Value::Object(map) => doc = map,
            _ => return Err("the existing file is not a JSON object".into()),
        }
    }
    let mut servers = match doc.get(key) {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };
    let already = servers
        .get(name)
        .is_some_and(|old| serde_json::to_string(old).ok() == serde_json::to_string(entry).ok());
    servers.insert(name.into(), entry.clone());
    doc.insert(key.into(), Value::Object(servers));
    let text = serde_json::to_string_pretty(&Value::Object(doc)).map_err(|e| e.to_string())?;
    Ok((format!("{text}\n"), already))
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
    Ok(merge_toml_both(existing_text, key, name, entry)?.0)
}

fn toml_value(v: &Value) -> String {
    match v {
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(toml_value).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into()),
        other => serde_json::to_string(&other.to_string()).unwrap_or_else(|_| "\"\"".into()),
    }
}

pub(crate) fn render_toml_table(key: &str, name: &str, entry: &Value) -> String {
    let mut lines = vec![format!("[{key}.{name}]")];
    let mut sub = Vec::new();
    let Some(obj) = entry.as_object() else {
        return format!("{}\n", lines.join("\n"));
    };
    for (k, v) in obj {
        if let Some(inner) = v.as_object() {
            sub.push(format!("\n[{key}.{name}.{k}]"));
            for (ek, ev) in inner {
                sub.push(format!("{ek} = {}", toml_value(ev)));
            }
            continue;
        }
        lines.push(format!("{k} = {}", toml_value(v)));
    }
    lines.extend(sub);
    format!("{}\n", lines.join("\n"))
}

fn is_table_line(line: &str) -> bool {
    line.trim_start().starts_with('[')
}

pub(crate) fn merge_toml_both(
    existing_text: &str,
    key: &str,
    name: &str,
    entry: &Value,
) -> Result<(String, bool), String> {
    let header = format!("[{key}.{name}]");
    let block = render_toml_table(key, name, entry);
    let text = existing_text;
    let lines: Vec<&str> = text.split('\n').collect();
    let start = lines.iter().position(|l| l.trim() == header);
    let Some(start) = start else {
        let joined = text.trim_end();
        let text = if joined.is_empty() {
            block
        } else {
            format!("{joined}\n\n{block}")
        };
        return Ok((text, false));
    };
    let mut end = start + 1;
    while end < lines.len() && !is_table_line(lines[end]) {
        end += 1;
    }
    let nested = format!("[{key}.{name}.");
    while end < lines.len() && lines[end].trim().starts_with(&nested) {
        end += 1;
        while end < lines.len() && !is_table_line(lines[end]) {
            end += 1;
        }
    }
    let current = lines[start..end].join("\n").trim().to_string();
    let mut replaced: Vec<&str> = Vec::new();
    replaced.extend_from_slice(&lines[..start]);
    let block_lines: Vec<&str> = block.trim_end().split('\n').collect();
    replaced.extend(block_lines);
    replaced.extend_from_slice(&lines[end..]);
    let text = format!("{}\n", replaced.join("\n").trim_end());
    Ok((text, current == block.trim()))
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
    let agent_spec = agent(&spec.agent).ok_or_else(|| {
        format!(
            "unknown agent: {}. Known: {}",
            spec.agent,
            AGENTS.iter().map(|a| a.key).collect::<Vec<_>>().join(", ")
        )
    })?;
    if !server_name_ok(&spec.name) {
        let shown = serde_json::to_string(&spec.name).unwrap_or_else(|_| spec.name.clone());
        return Err(format!(
            "invalid server name {shown}: letters, digits, dash and underscore only, up to 64 characters"
        ));
    }
    let scope = if spec.scope.is_empty() {
        agent_spec.default_scope.unwrap_or("project")
    } else {
        spec.scope.as_str()
    };
    let path = target_path(&spec.agent, scope, &spec.cwd, &spec.home, &spec.env)?;
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let (text, unchanged) = if agent_spec.format == "toml" {
        merge_toml_both(&existing, agent_spec.servers_key, &spec.name, &spec.entry)?
    } else {
        merge_json(&existing, agent_spec.servers_key, &spec.name, &spec.entry)?
    };
    let block = if agent_spec.format == "toml" {
        render_toml_table(agent_spec.servers_key, &spec.name, &spec.entry)
    } else {
        let mut inner = serde_json::Map::new();
        inner.insert(spec.name.clone(), spec.entry.clone());
        let mut outer = serde_json::Map::new();
        outer.insert(agent_spec.servers_key.into(), Value::Object(inner));
        format!(
            "{}\n",
            serde_json::to_string_pretty(&Value::Object(outer)).unwrap_or_default()
        )
    };
    if spec.print {
        return Ok(InstallResult {
            path,
            block,
            wrote: false,
            unchanged,
            backup: None,
        });
    }
    let backup = if existing.is_empty() {
        None
    } else {
        let backup = PathBuf::from(format!("{}.agent-vault-bak", path.display()));
        crate::files::write_file_exclusive(&backup, &existing, true, 0o600)
            .map_err(|e| e.to_string())?;
        Some(backup)
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    crate::files::write_file_exclusive(&path, &text, true, 0o600).map_err(|e| e.to_string())?;
    Ok(InstallResult {
        path,
        block,
        wrote: true,
        unchanged,
        backup,
    })
}

/// `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`, scanned by hand.
pub(crate) fn server_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    let mut n = 1usize;
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return false;
        }
        n += 1;
        if n > 64 {
            return false;
        }
    }
    true
}
