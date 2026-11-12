//! Socket peer credentials for the control socket: who is on the other end of
//! an accepted Unix-domain connection, this process's uid, the umask the
//! control socket is bound under, and the core-dump limits set at startup. The JS relied on file mode and group
//! ownership of `control.sock` (`#secureSocket` in `src/daemon/server.js`);
//! the Rust daemon also checks the peer uid against `AV_ENROLLED_UID`.
//!
//! **This is the only module in av-daemon where `unsafe` is allowed** (the
//! crate root is `#![deny(unsafe_code)]` and opts this module out). Rules:
//! each `unsafe` block makes exactly one libc call, carries a `// SAFETY:`
//! comment saying why its pointers and lengths are valid, and checks the
//! return value before reading any out-parameter. No other code in the crate
//! may add `unsafe`.

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
/// `getpeereid(2)` on macOS and the BSDs, `SO_PEERCRED` on Linux.
pub fn peer_cred(socket: &impl AsRawFd) -> std::io::Result<PeerCred> {
    let fd = socket.as_raw_fd();
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: `fd` is a live descriptor borrowed from `socket` for the
        // duration of the call; `uid` and `gid` are valid, aligned, writable
        // locals the kernel fills in. The return value is checked before
        // either is read.
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(PeerCred { uid, gid })
    }
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `fd` is a live descriptor borrowed from `socket`; `cred` is
        // a valid, aligned `ucred` and `len` is exactly its size, as
        // `SO_PEERCRED` requires. The return value and the returned length
        // are checked before `cred` is read.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc != 0 || len as usize != std::mem::size_of::<libc::ucred>() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(PeerCred {
            uid: cred.uid,
            gid: cred.gid,
        })
    }
}

/// The uid of the current process (`geteuid`), used to refuse running as root
/// (`process.getuid() === 0` in `bin/agent-vault-daemon.js`).
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, cannot fail and touches no memory.
    unsafe { libc::geteuid() }
}

/// Run `f` with the process umask set to `mask`, then restore it. Used to
/// bind the control socket so it is never created connectable by others
/// (`process.umask(0o077)` around `listen` in `Daemon.start()`).
pub fn with_umask<T>(mask: u32, f: impl FnOnce() -> T) -> T {
    // SAFETY: `umask` takes a mode value, cannot fail and touches no memory.
    let previous = unsafe { libc::umask(mask as libc::mode_t) };
    let out = f();
    // SAFETY: as above; restores the value `umask` returned.
    unsafe { libc::umask(previous) };
    out
}

/// Keep the daemon's memory (decrypted secrets, the vault key) out of core
/// files: `RLIMIT_CORE` 0/0 everywhere and, on Linux, `PR_SET_DUMPABLE` 0,
/// which also stops other processes of the same user from attaching. The
/// service units set the same limit; this covers a daemon started by hand.
/// The JS set none, so a failure is reported, never fatal.
pub fn disable_core_dumps() -> std::io::Result<()> {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `none` is a valid, initialised rlimit that outlives the call;
    // setrlimit only reads it.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes plain integer arguments and touches
        // no memory of ours.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// This process's core-file limit, `(soft, hard)`.
pub fn core_limit() -> std::io::Result<(u64, u64)> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable rlimit that outlives the call.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((lim.rlim_cur, lim.rlim_max))
}

/// Whether this process may leave a core file (`PR_GET_DUMPABLE`; always
/// reported as dumpable off Linux, where there is no such flag).
#[cfg(target_os = "linux")]
pub fn dumpable() -> bool {
    // SAFETY: PR_GET_DUMPABLE takes no pointers and only returns a value.
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_leaves_no_core_file_limit_to_raise() {
        disable_core_dumps().unwrap();
        assert_eq!(core_limit().unwrap(), (0, 0));
        // The hard limit is gone too: an unprivileged process cannot raise it back.
        let back = libc::rlimit {
            rlim_cur: 1 << 20,
            rlim_max: 1 << 20,
        };
        // SAFETY: as in disable_core_dumps.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &back) };
        if effective_uid() != 0 {
            assert_ne!(rc, 0, "the hard limit was raised back");
        }
        #[cfg(target_os = "linux")]
        assert!(!dumpable());
    }

    #[test]
    fn a_socket_pair_reports_this_process() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let c = peer_cred(&a).unwrap();
        assert_eq!(c.uid, effective_uid());
    }
}
