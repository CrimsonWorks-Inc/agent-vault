//! The MCP server: tool definitions, JSON-RPC dispatch, and the stdio
//! transport. Ports `src/daemon/mcp.js`.
//!
//! Tool names, input schemas, descriptions and the server instructions are
//! frozen (PLAN.md, "Frozen external contract" item 3). Copy them from the JS
//! verbatim.

use std::sync::{Arc, Weak};

use serde_json::Value;

use crate::pipeline::Pipeline;
use crate::server::Daemon;
use crate::VaultRef;

/// MCP protocol versions the server speaks, newest first. Ports
/// `PROTOCOL_VERSIONS` in `src/daemon/mcp.js`.
pub const PROTOCOL_VERSIONS: [&str; 2] = ["2025-06-18", "2025-03-26"];

/// The version offered when the client asks for one we do not speak. Ports
/// `LATEST_PROTOCOL` in `src/daemon/mcp.js`.
pub const LATEST_PROTOCOL: &str = PROTOCOL_VERSIONS[0];

/// `serverInfo.name`. Ports `SERVER_INFO.name` (module-private) in
/// `src/daemon/mcp.js`; the version is the crate version.
pub const SERVER_NAME: &str = "agent-vault";

/// Transport sessions held at once. Ports `MAX_MCP_SESSIONS` (module-private)
/// in `src/daemon/mcp.js`.
pub const MAX_MCP_SESSIONS: usize = 256;

/// The server instructions sent on `initialize`. Ports `INSTRUCTIONS`
/// (module-private) in `src/daemon/mcp.js`; frozen text.
pub const INSTRUCTIONS: &str = "Credentials are placeholders, never real secrets. Never ask the user for a real secret. \
Prefer vault_http for API calls; use vault_get_placeholder only for tools that must run natively. \
Put a placeholder only where the usage field says. A placeholder anywhere else is refused. \
On AV_PH_EXHAUSTED or AV_PH_STALE, call vault_get_placeholder again and retry. \
On a denial, call vault_explain_denial with the request_id to learn the rule and the allowed alternatives. \
Before a write you are unsure of, call vault_preflight; to learn your limits, call vault_describe_access.";

/// What `vault_request_session` forwards. Ports `REQUEST_ARGS`
/// (module-private) in `src/daemon/mcp.js`.
pub const REQUEST_ARGS: [&str; 10] = [
    "cred",
    "methods",
    "paths",
    "budget",
    "uses",
    "ttl_minutes",
    "routes",
    "grant_ttl_minutes",
    "template",
    "reason",
];

/// Largest tool-call body `vault_http` accepts, in bytes. Ports
/// `MAX_TOOL_BODY` (module-private) in `src/daemon/mcp.js`.
pub const MAX_TOOL_BODY: usize = 256 * 1024;

/// Returns the agent session bound to this transport, if any. Ports the
/// `resolveSession` constructor argument of `McpServer` in
/// `src/daemon/mcp.js`.
pub type SessionResolver = Box<dyn Fn() -> Option<Value> + Send + Sync>;

/// The MCP server shared by the stdio bridge and Streamable HTTP. Ports
/// `class McpServer` in `src/daemon/mcp.js`.
pub struct McpServer {
    _private: (),
}

impl McpServer {
    /// Ports `new McpServer(vault, pipeline, resolveSession, daemon)` in
    /// `src/daemon/mcp.js`. The daemon owns the session-request store, so
    /// it is passed in (weakly) when there is one.
    pub fn new(
        vault: VaultRef,
        pipeline: Arc<Pipeline>,
        resolve_session: SessionResolver,
        daemon: Option<Weak<Daemon>>,
    ) -> Self {
        todo!()
    }

    /// Open a transport session and return its id; `record` writes the audit
    /// record. Ports `McpServer.openSession({ record })` in
    /// `src/daemon/mcp.js`.
    pub fn open_session(&self, record: bool) -> String {
        todo!()
    }

    /// Close a transport session; returns whether it existed. Ports
    /// `McpServer.closeSession(sid, { record })` in `src/daemon/mcp.js`.
    pub fn close_session(&self, sid: &str, record: bool) -> bool {
        todo!()
    }

    /// Whether a transport session id is open. Ports
    /// `McpServer.hasSession(sid)` in `src/daemon/mcp.js`.
    pub fn has_session(&self, sid: &str) -> bool {
        todo!()
    }

    /// The `tools/list` array: names, descriptions and input schemas (frozen).
    /// Ports the `McpServer.tools` getter in `src/daemon/mcp.js`.
    pub fn tools(&self) -> Vec<Value> {
        todo!()
    }

    /// Handle one JSON-RPC message (or batch) and return the reply, or `None`
    /// for a notification. Ports
    /// `McpServer.handle(message, forSession, forToken, forListener)` in
    /// `src/daemon/mcp.js`.
    pub async fn handle(
        &self,
        message: Value,
        for_session: Option<Value>,
        for_token: Option<&str>,
        for_listener: Option<&str>,
    ) -> Option<Value> {
        todo!()
    }
}

/// Serve the MCP server over newline-delimited JSON-RPC on stdio. Ports
/// `serveStdio(server, input, output)` in `src/daemon/mcp.js`.
pub async fn serve_stdio<R, W>(server: Arc<McpServer>, input: R, output: W) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    todo!()
}
