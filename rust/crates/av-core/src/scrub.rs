//! Response scrubbing: every encoding of every secret is replaced before a
//! response reaches the agent. Ports `src/core/scrub.js`.

/// The streaming scrubber. Ports `class Scrubber` in `src/core/scrub.js`.
/// Holds secret material, so it has no `Debug` of its contents.
pub struct Scrubber {}

impl std::fmt::Debug for Scrubber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Scrubber([REDACTED])")
    }
}
