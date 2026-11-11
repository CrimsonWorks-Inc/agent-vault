//! Socket peer credentials for the control socket: who is on the other end of
//! an accepted Unix-domain connection. The JS relied on file mode and group
//! ownership of `control.sock` (`#secureSocket` in `src/daemon/server.js`);
//! the Rust daemon also checks the peer uid against `AV_ENROLLED_UID`.
//!
//! **This is the only module in av-daemon where `unsafe` is allowed** (the
//! crate root is `#![deny(unsafe_code)]` and opts this module out). Rules:
//! each `unsafe` block makes exactly one libc call (`getpeereid` on macOS/BSD,
//! `getsockopt(SO_PEERCRED)` on Linux), carries a `// SAFETY:` comment saying
//! why its pointers and lengths are valid, and checks the return value before
//! reading any out-parameter. No other code in the crate may add `unsafe`.

use std::os::unix::io::AsRawFd;

/// The uid and gid of the process on the other end of a Unix socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// Effective uid of the peer.
    pub uid: u32,
    /// Effective gid of the peer.
    pub gid: u32,
}

/// Read the peer's credentials from a connected Unix-domain socket:
/// `getpeereid(2)` on macOS, `SO_PEERCRED` on Linux. New in the Rust port; no
/// JS function (the JS trusted the socket's mode and group,
/// `#secureSocket` in `src/daemon/server.js`).
pub fn peer_cred(socket: &impl AsRawFd) -> std::io::Result<PeerCred> {
    todo!()
}

/// The uid of the current process (`geteuid`), used to refuse running as root
/// (`process.getuid() === 0` in `bin/agent-vault-daemon.js`).
pub fn effective_uid() -> u32 {
    todo!()
}
