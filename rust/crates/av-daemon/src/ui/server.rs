//! The local web UI server: serves `web/dist`, proxies the page's API calls
//! to the control socket, gates changes on a WebAuthn assertion over the exact
//! operation, and withholds every capability from the page. Ports
//! `src/ui/server.js`.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// The UI exits after this long idle. Ports `IDLE_EXIT_MS` (module-private)
/// in `src/ui/server.js`.
pub const IDLE_EXIT_MS: u64 = 30 * 60_000;

/// The Content-Security-Policy on every page. Ports `STRICT_CSP` in
/// `src/ui/server.js`; frozen.
pub const STRICT_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'";

/// Calls that need a WebAuthn assertion over the operation. Ports
/// `static UiServer.GATED` in `src/ui/server.js`.
pub const GATED: [&str; 21] = [
    "POST credentials",
    "DELETE credentials",
    "POST sessions",
    "DELETE sessions",
    "POST approvals",
    "POST session-requests/decide",
    "POST pending/decide-many",
    "POST lock",
    "POST touchid/enroll",
    "POST touchid/remove",
    "POST sessions/narrow",
    "POST credentials/rotate",
    "POST credentials/scrub",
    "DELETE credentials/scrub",
    "POST credentials/expiry",
    "POST credentials/release",
    "POST tripwires",
    "POST templates",
    "DELETE templates",
    "DELETE credentials/pins",
    "POST presence/rotate",
];

/// Gated calls whose signature the daemon checks again itself (so this
/// process must not advance the counter). Ports
/// `static UiServer.DAEMON_VERIFIED` in `src/ui/server.js`.
pub const DAEMON_VERIFIED: [&str; 14] = [
    "POST credentials",
    "DELETE credentials",
    "POST sessions",
    "POST session-requests/decide",
    "POST pending/decide-many",
    "POST credentials/rotate",
    "POST credentials/scrub",
    "DELETE credentials/scrub",
    "POST credentials/expiry",
    "POST credentials/release",
    "POST tripwires",
    "POST templates",
    "DELETE credentials/pins",
    "POST presence/rotate",
];

/// The one response that may carry a capability to the page. Ports
/// `static UiServer.HANDOFF` in `src/ui/server.js`.
pub const HANDOFF: [&str; 1] = ["POST sessions"];

/// Keys dropped at any depth from anything sent to the page. Ports
/// `WITHHELD_KEYS` (module-private) in `src/ui/server.js`.
pub const WITHHELD_KEYS: [&str; 9] = [
    "token",
    "placeholder",
    "value",
    "secret",
    "prf_secret",
    "recovery_passphrase",
    "passphrase",
    "bundle",
    "webhook_url",
];

/// Top-level fields of the hand-off card. Ports `HANDOFF_FIELDS`
/// (module-private) in `src/ui/server.js`.
pub const HANDOFF_FIELDS: [&str; 6] = [
    "token",
    "session_id",
    "expires_at",
    "infinite",
    "label",
    "cli",
];

/// Per-grant fields of the hand-off card. Ports `HANDOFF_GRANT_FIELDS`
/// (module-private) in `src/ui/server.js`.
pub const HANDOFF_GRANT_FIELDS: [&str; 6] =
    ["placeholder", "base_url", "usage", "cred", "sites", "probe"];

/// Construction options. Ports the options of
/// `new UiServer(socketPath, { port, idleMs, cli, statePath, distDir })` in
/// `src/ui/server.js`.
#[derive(Debug, Clone, Default)]
pub struct UiServerOptions {
    /// Port (0 picks one).
    pub port: u16,
    /// Idle exit; default [`IDLE_EXIT_MS`].
    pub idle_ms: Option<u64>,
    /// How the CLI is invoked, for printed commands. Default `agent-vault`.
    pub cli: Option<String>,
    /// The client-state file the hand-off writes.
    pub state_path: Option<PathBuf>,
    /// The built UI; default the install's `web/dist`.
    pub dist_dir: Option<PathBuf>,
}

/// The UI server. Ports `class UiServer` in `src/ui/server.js`.
pub struct UiServer {
    _private: (),
}

impl UiServer {
    /// Ports `new UiServer(socketPath, opts)` in `src/ui/server.js`.
    pub fn new(socket_path: &Path, opts: UiServerOptions) -> Self {
        todo!()
    }

    /// Bind `127.0.0.1:<port>` and start serving. Ports `UiServer.start()`
    /// in `src/ui/server.js`.
    pub async fn start(&self) -> std::io::Result<()> {
        todo!()
    }

    /// Stop serving. Ports `UiServer.stop()` in `src/ui/server.js`.
    pub async fn stop(&self) {
        todo!()
    }

    /// `http://localhost:<port>`. Ports the `UiServer.origin` property in
    /// `src/ui/server.js`.
    pub fn origin(&self) -> String {
        todo!()
    }

    /// The bound port. Ports the `UiServer.boundPort` property in
    /// `src/ui/server.js`.
    pub fn bound_port(&self) -> u16 {
        todo!()
    }

    /// The single-use launch link `<origin>/?t=<launch token>`. Ports the
    /// `UiServer.url` getter in `src/ui/server.js`.
    pub fn url(&self) -> String {
        todo!()
    }
}

/// Whether the raw request path is exactly the parsed path, absolute, with
/// no `\`, encoded `.`/`/`/`\`, dot segments or empty inner segments. Ports
/// `literalPath(rawUrl, pathname)` in `src/ui/server.js`.
pub fn literal_path(raw_url: &str, pathname: &str) -> bool {
    todo!()
}

/// The built UI, read once and checked (regular files only, no symlinks),
/// keyed by URL path. Ports the result of `loadDist(distDir)` in
/// `src/ui/server.js`.
#[derive(Debug, Clone, Default)]
pub struct Dist {
    /// `(url path, content type, bytes)`.
    pub files: Vec<(String, String, Vec<u8>)>,
}

/// Load the built UI; `Ok(None)` when the directory does not exist. Ports
/// `loadDist(distDir)` in `src/ui/server.js`.
pub fn load_dist(dist_dir: &Path) -> std::io::Result<Option<Dist>> {
    todo!()
}

/// A daemon answer as the page may see it: [`WITHHELD_KEYS`] dropped at any
/// depth, token- and placeholder-shaped text replaced. Ports
/// `towardPage(value, depth)` in `src/ui/server.js`.
pub fn toward_page(value: &Value, depth: usize) -> Value {
    todo!()
}

/// A session-create answer for the hand-off card: [`toward_page`], then the
/// card's scalar fields copied back. Ports `handoffTowardPage(created)` in
/// `src/ui/server.js`.
pub fn handoff_toward_page(created: &Value) -> Value {
    todo!()
}
