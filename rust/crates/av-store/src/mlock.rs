//! Locked memory for the VMK (rust/PLAN.md, "Intended changes": "the VMK held
//! in `mlock`ed memory"). New in the Rust port; the JS has no equivalent.
//!
//! This is the only module in av-store allowed to use `unsafe`. Each `unsafe`
//! block is a single libc call with a `// SAFETY:` comment, and the module
//! stays small enough to review in one sitting.
//!
//! [`LockedKey`] is how the vault holds its VMK: the 32 bytes live in a heap
//! box that never moves, are locked into RAM for as long as the box lives,
//! and are zeroed before they are unlocked and freed.

use av_core::secret::Key32;
use zeroize::Zeroize;

/// Lock `len` bytes at `ptr`-backed `buf` into RAM so they are never swapped.
/// Returns `false` when the OS refuses (e.g. `RLIMIT_MEMLOCK`); callers keep
/// going and log once. No JS source: new in the Rust port.
pub fn lock(buf: &mut [u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    // SAFETY: `buf` is a live, exclusively borrowed slice, so the pointer and
    // length describe valid memory for the whole call. mlock(2) only changes
    // the paging of the pages that contain it; it reads and writes nothing.
    let rc = unsafe { libc::mlock(buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    rc == 0
}

/// Undo [`lock`] after the buffer has been zeroized. No JS source: new in the
/// Rust port.
pub fn unlock(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: as in `lock`: a live slice, and munlock(2) touches only the
    // paging state of its pages. Failure (pages that were never locked) is
    // harmless and ignored.
    let _ = unsafe { libc::munlock(buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
}

/// A 32-byte key in locked memory, zeroed and unlocked on drop. Never
/// `Debug` with its bytes, never `Clone`: there is one copy of the VMK.
pub struct LockedKey {
    bytes: Box<[u8; 32]>,
    locked: bool,
}

impl LockedKey {
    /// Move a key into locked memory. The source `Key32` zeroizes itself
    /// when the caller drops it.
    pub fn new(key: &Key32) -> LockedKey {
        let mut bytes = Box::new([0u8; 32]);
        let locked = lock(bytes.as_mut_slice());
        bytes.copy_from_slice(key.expose());
        LockedKey { bytes, locked }
    }

    /// Whether the OS agreed to lock the page.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// A short-lived copy for an API that takes a `Key32` (it zeroizes
    /// itself on drop).
    pub fn key(&self) -> Key32 {
        Key32::from_bytes(*self.bytes)
    }

    /// The bytes, borrowed.
    pub fn expose(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
        if self.locked {
            unlock(self.bytes.as_mut_slice());
        }
    }
}

impl std::fmt::Debug for LockedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LockedKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_and_unlock_a_buffer() {
        let mut b = vec![0u8; 64];
        // A page or two is far under any default RLIMIT_MEMLOCK.
        assert!(lock(&mut b));
        unlock(&mut b);
        assert!(lock(&mut []));
    }

    #[test]
    fn a_locked_key_keeps_its_bytes_and_hides_them() {
        let k = Key32::from_bytes([0x5a; 32]);
        let l = LockedKey::new(&k);
        assert_eq!(l.expose(), &[0x5a; 32]);
        assert_eq!(l.key().expose(), &[0x5a; 32]);
        assert!(!format!("{l:?}").contains("5a"));
    }
}
