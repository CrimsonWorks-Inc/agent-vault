//! The web UI's server side. Ports `src/ui/server.js`, `src/ui/webauthn.js`
//! and `src/ui/list-paging.js`. The React app in `web/` is not ported; the
//! Rust server serves the same built `web/dist`.

pub mod list_paging;
pub mod server;
pub mod webauthn;
