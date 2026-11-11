//! The daemon: control socket (`#onControl`), gateway, discovery routes,
//! Streamable HTTP MCP, extra listeners, presence gating and the session
//! request flow. Ports `src/daemon/server.js`.
//!
//! Every control route in `#onControl`, with its request and response
//! shapes, status codes and `AV_*` codes, is frozen (PLAN.md, "Frozen
//! external contract" items 1 and 2).

use std::net::IpAddr;
use std::path::PathBuf;

use serde_json::Value;

use crate::VaultRef;

/// The port the web UI listens on by default, and the one UI origin the
/// daemon trusts without being told. Ports `DEFAULT_UI_PORT` in
/// `src/daemon/server.js`.
pub const DEFAULT_UI_PORT: u16 = 7412;

/// The gateway's default port. Ports the `port = 7411` default of
/// `new Daemon(...)` in `src/daemon/server.js`.
pub const DEFAULT_GATEWAY_PORT: u16 = 7411;

/// Largest request body read. Ports `MAX_BODY` (module-private) in
/// `src/daemon/server.js`.
pub const MAX_BODY: usize = 16 * 1024 * 1024;
/// Most grants in one session. Ports `MAX_GRANTS` (module-private) in
/// `src/daemon/server.js`.
pub const MAX_GRANTS: usize = 16;
/// Most items in one batch decision. Ports `MAX_BATCH` (module-private) in
/// `src/daemon/server.js`.
pub const MAX_BATCH: usize = 32;
/// Most headers in a preflight. Ports `MAX_PREFLIGHT_HEADERS`
/// (module-private) in `src/daemon/server.js`.
pub const MAX_PREFLIGHT_HEADERS: usize = 100;
/// Open WebAuthn challenges at once. Ports `MAX_OPEN_CHALLENGES`
/// (module-private) in `src/daemon/server.js`.
pub const MAX_OPEN_CHALLENGES: usize = 64;
/// Largest signed operation. Ports `MAX_OPERATION_BYTES` (module-private) in
/// `src/daemon/server.js`.
pub const MAX_OPERATION_BYTES: usize = 8 * 1024;
/// Passphrase attempts before backoff. Ports `PASSPHRASE_FREE_ATTEMPTS`
/// (module-private) in `src/daemon/server.js`.
pub const PASSPHRASE_FREE_ATTEMPTS: u32 = 5;
/// Cap on the doubling passphrase backoff. Ports `PASSPHRASE_MAX_BACKOFF_MS`
/// (module-private) in `src/daemon/server.js`.
pub const PASSPHRASE_MAX_BACKOFF_MS: u64 = 30_000;
/// Largest audit page. Ports `AUDIT_PAGE_MAX` (module-private) in
/// `src/daemon/server.js`.
pub const AUDIT_PAGE_MAX: usize = 500;

/// The class name recorded for a fault: the `AV_*` code of a registered
/// `VaultError`, a built-in error class name, or `other`. The Rust port maps
/// its own error kinds onto the same strings. Ports `errorClass(err)` in
/// `src/daemon/server.js`.
pub fn error_class(err: &(dyn std::error::Error + 'static)) -> String {
    todo!()
}

/// A parsed `allow_cidr` list. Ports the `BlockList` returned by
/// `parseAllowCidr` in `src/daemon/server.js`.
#[derive(Debug, Clone, Default)]
pub struct AllowList {
    /// `(network, prefix length)` blocks.
    pub blocks: Vec<(IpAddr, u8)>,
}

impl AllowList {
    /// Whether a peer address (an IPv4-mapped `::ffff:a.b.c.d` counts as
    /// IPv4) falls inside the list. Ports `peerAllowed(allow, address)`
    /// (module-private) in `src/daemon/server.js`.
    pub fn allows(&self, address: &str) -> bool {
        todo!()
    }
}

/// A listener's `allow_cidr` as an allow list; `None` means no restriction.
/// Anything that is not a list of `<address>/<prefix>` blocks is an error.
/// Ports `parseAllowCidr(list)` in `src/daemon/server.js`.
pub fn parse_allow_cidr(list: Option<&Value>) -> Result<Option<AllowList>, String> {
    todo!()
}

/// `iface:port`, where iface may be a name, an IPv4 literal, or `[v6]`.
/// Returns `(host, port)`. Ports `parseAddress(address)` in
/// `src/daemon/server.js`.
pub fn parse_address(address: &str) -> Result<(String, u16), String> {
    todo!()
}

/// Whether a host is loopback: the literal names, or a real dotted quad in
/// 127.0.0.0/8 (never a name starting `127.`). Ports `isLoopbackHost(host)`
/// in `src/daemon/server.js`.
pub fn is_loopback_host(host: &str) -> bool {
    todo!()
}

/// Construction options. Ports the options object of
/// `new Daemon(vault, { port, socketPath, host, socketGroup, enrolledUid,
/// uiPort, uiOrigins, notifyFetch })` in `src/daemon/server.js`.
#[derive(Debug, Clone)]
pub struct DaemonOptions {
    /// Gateway port (0 picks one). Default [`DEFAULT_GATEWAY_PORT`].
    pub port: u16,
    /// Control socket path.
    pub socket_path: PathBuf,
    /// Gateway bind host. Default `127.0.0.1`.
    pub host: String,
    /// Group that may connect to the control socket (`AV_CLIENT_GROUP`).
    pub socket_group: Option<String>,
    /// The enrolled user's uid (`AV_ENROLLED_UID`).
    pub enrolled_uid: Option<u32>,
    /// The trusted UI port. Default [`DEFAULT_UI_PORT`].
    pub ui_port: u16,
    /// Extra trusted UI origins.
    pub ui_origins: Vec<String>,
}

/// The daemon. Ports `class Daemon` in `src/daemon/server.js`.
pub struct Daemon {
    _private: (),
}

impl Daemon {
    /// Ports `new Daemon(vault, opts)` in `src/daemon/server.js`.
    pub fn new(vault: VaultRef, opts: DaemonOptions) -> Self {
        todo!()
    }

    /// Bind the gateway, the control socket (mode and group as in
    /// `#secureSocket`) and every configured listener. Ports
    /// `Daemon.start()` in `src/daemon/server.js`.
    pub async fn start(&self) -> std::io::Result<()> {
        todo!()
    }

    /// Close every listener, the notifier and pending work. Ports
    /// `Daemon.stop()` in `src/daemon/server.js`.
    pub async fn stop(&self) {
        todo!()
    }

    /// The gateway's bound port, once started. Ports the `gatewayPort`
    /// property set in `Daemon.start()` in `src/daemon/server.js`.
    pub fn gateway_port(&self) -> Option<u16> {
        todo!()
    }

    /// An agent's request for a session, held for a human. Ports
    /// `Daemon.proposeSessionRequest(input)` in `src/daemon/server.js`.
    pub fn propose_session_request(&self, input: &Value) -> av_core::errors::Result<Value> {
        todo!()
    }

    /// The UI origins trusted for WebAuthn assertions. Ports
    /// `Daemon.uiOrigins()` in `src/daemon/server.js`.
    pub fn ui_origins(&self) -> Vec<String> {
        todo!()
    }

    /// Trust one more `http://localhost:<port>` UI origin. Ports
    /// `Daemon.allowUiOrigin(origin)` in `src/daemon/server.js`.
    pub fn allow_ui_origin(&self, origin: &str) -> av_core::errors::Result<Vec<String>> {
        todo!()
    }
}
