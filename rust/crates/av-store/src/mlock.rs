//! Locked memory for the VMK (rust/PLAN.md, "Intended changes": "the VMK held
//! in `mlock`ed memory"). New in the Rust port; the JS has no equivalent.
//!
//! This is the only module in av-store allowed to use `unsafe`. Each `unsafe`
//! block must be a single libc call with a `// SAFETY:` comment, and the
//! module must stay small enough to review in one sitting. It is a stub until
//! the store wave fills it in.

/// Lock `len` bytes at `ptr`-backed `buf` into RAM so they are never swapped.
/// Returns `false` when the OS refuses (e.g. `RLIMIT_MEMLOCK`); callers keep
/// going and log once. No JS source: new in the Rust port.
pub fn lock(buf: &mut [u8]) -> bool {
    let _ = buf;
    todo!()
}

/// Undo [`lock`] after the buffer has been zeroized. No JS source: new in the
/// Rust port.
pub fn unlock(buf: &mut [u8]) {
    let _ = buf;
    todo!()
}
