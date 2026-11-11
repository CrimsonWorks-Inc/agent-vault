//! The agent-vault daemon: control socket, gateway, MCP, web UI server and
//! connectors. Ports `src/daemon/*`, `src/ui/server.js`, `src/ui/webauthn.js`,
//! `src/ui/list-paging.js` and `src/connectors/*`.
//!
//! `unsafe` is denied crate-wide. The one exception is [`peercred`], which
//! wraps the socket peer-credential calls; nothing else may opt out.
#![deny(unsafe_code)]
// Scaffold: bodies are `todo!()` until the next wave fills them in. Remove
// this allow when the last `todo!()` in the crate is gone.
#![allow(unused_variables)]

pub mod connectors;
pub mod mcp;
pub mod notify;
#[allow(unsafe_code)]
pub mod peercred;
pub mod pipeline;
pub mod server;
pub mod session_requests;
pub mod tls;
pub mod tripwire;
pub mod ui;

use av_core::errors::Exit;

/// Stand-in for the open vault handle (`Vault` in `src/store/vault.js`) that
/// every daemon component is constructed with. The daemon worker replaces it
/// with the av-store type once that API is settled; it exists so the
/// skeleton's signatures say where the vault goes.
#[derive(Clone)]
pub struct VaultRef {
    _private: (),
}

/// The service entry point: read `AV_VAULT_DIR`, `AV_RUN_DIR`, `AV_PORT`,
/// `AV_ENROLLED_UID` and `AV_CLIENT_GROUP`, refuse to run as root, open (or
/// create, factor `none`) the vault in its recorded lock state, start the
/// [`server::Daemon`] and run until SIGINT/SIGTERM. Returns the process exit
/// code (`Exit::Usage`, i.e. 2, when the environment is missing or the uid is
/// 0). Ports the whole of `bin/agent-vault-daemon.js`.
pub fn run_from_env() -> Exit {
    todo!()
}
