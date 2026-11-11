//! Response scrubbing: every encoding of every secret is replaced before a
//! response reaches the agent. Ports `src/core/scrub.js`.
//!
//! Text here is a JS string: a response body is read byte-for-byte as latin1
//! (each byte one `char` U+0000..=U+00FF), exactly as the JS does with
//! `toString('latin1')`, so callers map bytes to chars before scrubbing.
//!
//! The JS derived-token patterns start with the lookbehind
//! `(?<![A-Za-z0-9_-])`, which the `regex` crate does not support. Here each
//! pattern is stored without it and the implementation must check
//! [`BOUNDARY_CLASS`] on the preceding character by hand.
//!
//! Honest limit: byte-and-encoding based. A secret split across markup,
//! re-encoded in a scheme not listed, or transformed upstream is not caught.

// `VaultError` (errors.rs, not owned here) is ~208 bytes, so clippy's
// `result_large_err` fires on every `Result<T>` signature. The fix belongs in
// errors.rs (box the extras); until then it is allowed in this module only.
#![allow(clippy::result_large_err)]

use crate::errors::Result;
use crate::secret::SecretString;

/// Secrets shorter than this are not matched in the bulk set. Ports
/// `MIN_SECRET_LEN` in `src/core/scrub.js`.
pub const MIN_SECRET_LEN: usize = 8;

/// The character class a derived token must not follow. Ports `BOUNDARY`
/// (`(?<![A-Za-z0-9_-])`) in `src/core/scrub.js`.
pub const BOUNDARY_CLASS: &str = "[A-Za-z0-9_-]";

/// A token shape redacted even when the vault never stored it. Ports the
/// `{ name, re }` entries of `DERIVED_PATTERNS` in `src/core/scrub.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedPattern {
    /// Pattern name.
    pub name: &'static str,
    /// The pattern without the leading boundary lookbehind (regex-crate
    /// syntax).
    pub pattern: &'static str,
}

/// Token shapes worth redacting even when the vault never stored them, as
/// `[[av:derived]]`. Ports `DERIVED_PATTERNS` in `src/core/scrub.js`.
pub const DERIVED_PATTERNS: &[DerivedPattern] = &[
    DerivedPattern {
        name: "github",
        pattern: "gh[pousr]_[A-Za-z0-9]{20,}",
    },
    DerivedPattern {
        name: "github-pat",
        pattern: "github_pat_[A-Za-z0-9_]{40,}",
    },
    DerivedPattern {
        name: "slack",
        pattern: "xox[abpors]-[0-9A-Za-z-]{10,}",
    },
    DerivedPattern {
        name: "aws",
        pattern: "AKIA[0-9A-Z]{16}",
    },
    DerivedPattern {
        name: "google-oauth",
        pattern: "ya29\\.[0-9A-Za-z_-]{20,}",
    },
    DerivedPattern {
        name: "google-api",
        pattern: "AIza[0-9A-Za-z_-]{35}",
    },
    DerivedPattern {
        name: "anthropic",
        pattern: "sk-ant-[A-Za-z0-9_-]{20,}",
    },
    DerivedPattern {
        name: "openai",
        pattern: "sk-(?:proj-)?[A-Za-z0-9_-]{20,}",
    },
    // No boundary in the JS for this one.
    DerivedPattern {
        name: "private-key",
        pattern: "-----BEGIN [A-Z ]*PRIVATE KEY-----",
    },
];

/// Ordinary text no extra scrub pattern may match. Ports
/// `SCRUB_PATTERN_CORPUS` in `src/core/scrub.js`.
pub const SCRUB_PATTERN_CORPUS: &[&str] = &[
    "The quick brown fox jumps over the lazy dog.",
    "Please read the repository and return the result of the task.",
    "disk-usage_by_repository_over_time",
    "task-oriented_approach_to_the_problem",
    "This is an ordinary response with no credentials or secrets.",
];

/// Escapes a scrub pattern may use. Ports `SCRUB_ESCAPES` in
/// `src/core/scrub.js`.
pub const SCRUB_ESCAPES: &str = "dwsDWS\\.[]{}()*+?|^$-/";

/// Where a derived token can begin (boundary checked by hand). Ports
/// `DERIVED_START` in `src/core/scrub.js`.
pub const DERIVED_START_PATTERN: &str =
    "(?:gh[pousr]_|github_pat_|xox[abpors]-|AKIA|ya29\\.|AIza|sk-)";
/// What a derived token is made of. Ports `TOKEN_CHAR` in `src/core/scrub.js`.
pub const TOKEN_CHAR_PATTERN: &str = "[A-Za-z0-9_.-]";
/// How far before a stream cut a token may begin and still be held back.
/// Ports `MAX_DERIVED_HOLD` in `src/core/scrub.js`.
pub const MAX_DERIVED_HOLD: usize = 512;

/// How deep a stack of distinct encodings is peeled. Ports `DECODE_DEPTH` in
/// `src/core/scrub.js`.
pub const DECODE_DEPTH: usize = 3;
/// Default ceiling on nested (depth >= 2) decoded views. Ports
/// `NESTED_VIEW_BUDGET` in `src/core/scrub.js`.
pub const NESTED_VIEW_BUDGET: usize = 32;
/// Default ceiling on nested decoded bytes. Ports `NESTED_BYTE_BUDGET` in
/// `src/core/scrub.js`.
pub const NESTED_BYTE_BUDGET: usize = 32 * 1024 * 1024;

/// A line break inside a wrapped hex/base64 run, real or JSON-escaped, with
/// indentation either side. Ports `LINE_BREAK` in `src/core/scrub.js`.
pub const LINE_BREAK_PATTERN: &str = "[ \\t]*(?:\\r\\n|\\r|\\n|\\\\r\\\\n|\\\\n|\\\\r)[ \\t]*";
/// Quick test for any line break. Ports `HAS_BREAK` in `src/core/scrub.js`.
pub const HAS_BREAK_PATTERN: &str = "[\\r\\n]|\\\\[rn]";
/// Blob (base64/hex) characters. Ports `BLOB_CHAR` in `src/core/scrub.js`.
pub const BLOB_CHAR_PATTERN: &str = "[A-Za-z0-9+/=_-]";

/// One stored secret and the label it is redacted under. Ports the
/// `{ secret, label }` entries of `vault.allSecrets()` read by `redactStored`
/// and `untrustedText` in `src/core/scrub.js`.
#[derive(Clone)]
pub struct StoredSecret {
    /// The secret value.
    pub secret: SecretString,
    /// Credential name, shown as `[[av:redacted:<label>]]`.
    pub label: String,
}

impl std::fmt::Debug for StoredSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredSecret")
            .field("secret", &"[REDACTED]")
            .field("label", &self.label)
            .finish()
    }
}

/// `text` with every stored secret of at least [`MIN_SECRET_LEN`] replaced
/// by `[[av:redacted:<label>]]`. Ports `redactStored` in `src/core/scrub.js`.
pub fn redact_stored(text: &str, secrets: &[StoredSecret]) -> String {
    todo!()
}

/// Agent-written text as it may be stored: stored secrets redacted, every
/// placeholder replaced by `«placeholder»`, then cut to `max` chars (the JS
/// default is 200). `None` for empty input. Ports `untrustedText` in
/// `src/core/scrub.js`.
pub fn untrusted_text(text: Option<&str>, secrets: &[StoredSecret], max: usize) -> Option<String> {
    todo!()
}

/// A human's extra scrub pattern, compiled. Ports the `{ re }` returned by
/// `compileScrubPattern` (and the `scrubMeta` it records) in
/// `src/core/scrub.js`.
#[derive(Debug, Clone)]
pub struct CompiledScrubPattern {
    /// The pattern source as the human wrote it (without the boundary).
    pub source: String,
    /// The compiled pattern (no boundary; checked by hand).
    pub regex: regex::Regex,
    /// The longest text it can match (at most 512), which bounds what the
    /// stream scrubber holds back.
    pub max_len: usize,
}

/// Compile a human's extra scrub pattern under the bounded grammar (C5):
/// 3–256 chars, at most 16 branches, each starting with three literals, one
/// variable quantifier followed only by literals, bounded repetition, no
/// groups/anchors/`.`, longest match ≤ 512, matching none of
/// [`SCRUB_PATTERN_CORPUS`]. Refuses `AV_POLICY_DENIED` rule `scrub_pattern`
/// naming the first rule broken. Ports `compileScrubPattern` in
/// `src/core/scrub.js`.
pub fn compile_scrub_pattern(source: &str) -> Result<CompiledScrubPattern> {
    todo!()
}

/// Every encoding of `secret` a response might carry (raw, latin1 view of
/// its UTF-8, `encodeURIComponent`, `\/`-escaped, JSON-escaped, `\u`-escaped,
/// HTML-entity, and [`blob_encodings`]), each at least `min_len` long,
/// de-duplicated. The result is secret material. Ports `encodings` in
/// `src/core/scrub.js`.
pub fn encodings(secret: &SecretString, min_len: usize) -> Vec<SecretString> {
    todo!()
}

/// The hex (both cases) and base64 (three alignments, standard and URL-safe)
/// forms of `secret`. Secret material. Ports `blobEncodings` in
/// `src/core/scrub.js`.
pub fn blob_encodings(secret: &SecretString) -> Vec<SecretString> {
    todo!()
}

/// One secret the scrubber matches. Ports the
/// `{ secret, label, replacement, always }` entries passed to
/// `new Scrubber(entries)` in `src/core/scrub.js`.
#[derive(Clone)]
pub struct ScrubEntry {
    /// The secret value.
    pub secret: SecretString,
    /// Credential name.
    pub label: String,
    /// What the agent sees instead (the placeholder it used, for this
    /// request's own secret); default `[[av:redacted:<label>]]`.
    pub replacement: Option<String>,
    /// Injected by this request, so redacted at any length (floor 1 instead
    /// of [`MIN_SECRET_LEN`]).
    pub always: bool,
}

impl std::fmt::Debug for ScrubEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScrubEntry")
            .field("secret", &"[REDACTED]")
            .field("label", &self.label)
            .field("always", &self.always)
            .finish_non_exhaustive()
    }
}

/// A stored extra pattern handed to the scrubber; recompiled by
/// [`Scrubber::new`], so nothing reaches the response path that the bounded
/// grammar did not accept. Ports the `{ name, re }` entries of
/// `opts.extraPatterns` in `src/core/scrub.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraPattern {
    /// Pattern name.
    pub name: String,
    /// The pattern source (as accepted by [`compile_scrub_pattern`]).
    pub source: String,
}

/// Options for [`Scrubber::new`]. Ports the `opts` argument
/// `{ extraPatterns, nestedViews, nestedBytes }` of `new Scrubber` in
/// `src/core/scrub.js`.
#[derive(Debug, Clone, Default)]
pub struct ScrubberOptions {
    /// Human-added patterns.
    pub extra_patterns: Vec<ExtraPattern>,
    /// Override of [`NESTED_VIEW_BUDGET`] (tests).
    pub nested_views: Option<usize>,
    /// Override of [`NESTED_BYTE_BUDGET`] (tests).
    pub nested_bytes: Option<usize>,
}

/// The outcome of [`Scrubber::scrub`]. Ports the
/// `{ text, redactions, unscannable }` object returned by `Scrubber#scrub` in
/// `src/core/scrub.js`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScrubResult {
    /// The scrubbed text.
    pub text: String,
    /// How many replacements were made.
    pub redactions: usize,
    /// The layered decoder ran out of budget with a secret-bearing candidate
    /// undecoded: the caller must fail closed and not forward `text`.
    pub unscannable: bool,
}

/// A raw span a secret occupies: `[start, end)` and its replacement. Ports
/// the `[rawStart, rawEnd, replacement]` triples of `src/core/scrub.js`.
pub type ScrubSpan = (usize, usize, String);

/// One needle: an encoding of a secret and its replacement. Ports the
/// `{ needle, replacement }` entries of `src/core/scrub.js`.
// Read only by the `todo!()` method bodies until the core wave fills them in.
#[allow(dead_code)]
#[derive(Clone)]
struct Needle {
    needle: SecretString,
    replacement: String,
}

/// The streaming scrubber. Ports `class Scrubber` in `src/core/scrub.js`.
/// Holds secret material, so it has no `Debug` of its contents.
// Fields are read only by the method bodies, which are `todo!()` until the
// core wave fills them in.
#[allow(dead_code)]
pub struct Scrubber {
    /// Recompiled extra patterns (`extraPatterns`).
    extra_patterns: Vec<(String, CompiledScrubPattern)>,
    /// Longest extra-pattern match (`extraHold`).
    extra_hold: usize,
    /// Every fixed encoding, longest first (`patterns`).
    patterns: Vec<Needle>,
    /// The secret and its latin1 view (`plain`).
    plain: Vec<Needle>,
    /// Hex/base64 forms (`blobs`).
    blobs: Vec<Needle>,
    /// Lowercase hex of each secret (`hex`).
    hex: Vec<Needle>,
    /// Longest fixed needle (`maxLen`).
    max_len: usize,
    /// Shortest blob needle (`minBlob`).
    min_blob: usize,
    /// Shortest hex needle (`minHex`).
    min_hex: usize,
    /// Shortest base64 run worth decoding (`b64Min`).
    b64_min: usize,
    /// Shortest hex run worth decoding (`hexMin`).
    hex_min: usize,
    /// Nested view budget (`nestedViewBudget`).
    nested_view_budget: usize,
    /// Nested byte budget (`nestedByteBudget`).
    nested_byte_budget: usize,
    /// Names of derived patterns that matched (`derivedSeen`).
    derived_seen: std::collections::BTreeSet<String>,
}

impl std::fmt::Debug for Scrubber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Scrubber([REDACTED])")
    }
}

impl Scrubber {
    /// Build the match set from the entries. Refuses `AV_UNSCANNABLE` (rule
    /// `scrub_pattern_invalid`) if a stored extra pattern does not recompile.
    /// Ports the `Scrubber` constructor in `src/core/scrub.js`.
    pub fn new(entries: &[ScrubEntry], opts: &ScrubberOptions) -> Result<Scrubber> {
        todo!()
    }

    /// True when any encoding (≥ [`MIN_SECRET_LEN`]) of any secret appears
    /// in `text` with case ignored, for text whose case is already lost (a
    /// header name). Ports `Scrubber#containsIgnoringCase` in
    /// `src/core/scrub.js`.
    pub fn contains_ignoring_case(&self, text: &str) -> bool {
        todo!()
    }

    /// Lookbehind a streaming caller must keep between chunks:
    /// `max(maxLen, 64) - 1`. Ports the `Scrubber#overlap` getter in
    /// `src/core/scrub.js`.
    pub fn overlap(&self) -> usize {
        todo!()
    }

    /// Scrub a complete string: fixed needles, then decoded/unwrapped/folded
    /// spans, then derived patterns (recording which matched). Ports
    /// `Scrubber#scrub` in `src/core/scrub.js`.
    pub fn scrub(&mut self, text: &str) -> ScrubResult {
        todo!()
    }

    /// The raw spans a secret occupies in `text` once escapes are decoded or
    /// a wrapped blob joined, without the fail-closed flag. Ports
    /// `Scrubber#viewSpans` in `src/core/scrub.js`.
    pub fn view_spans(&self, text: &str) -> Vec<ScrubSpan> {
        todo!()
    }

    /// The raw spans and whether the layered decoder ran out of budget.
    /// Ports `Scrubber#collectSpans` in `src/core/scrub.js`.
    pub fn collect_spans(&self, text: &str) -> (Vec<ScrubSpan>, bool) {
        todo!()
    }

    /// Names of the derived patterns that have matched so far. Ports
    /// `Scrubber#derivedSeen` in `src/core/scrub.js`.
    pub fn derived_seen(&self) -> &std::collections::BTreeSet<String> {
        &self.derived_seen
    }

    /// A streaming scrubber over this one. Ports `Scrubber#stream` in
    /// `src/core/scrub.js`.
    pub fn stream(&mut self) -> ScrubStream<'_> {
        todo!()
    }
}

/// A streaming scrubber: feed chunks; it holds back enough that a secret or
/// derived token split across a chunk boundary is still matched, and
/// [`ScrubStream::flush`] returns the tail. Ports the object returned by
/// `Scrubber#stream` in `src/core/scrub.js`. The held tail may contain secret
/// material, so `Debug` is redacted.
// Fields are read only by the method bodies (`todo!()` for now).
#[allow(dead_code)]
pub struct ScrubStream<'a> {
    scrubber: &'a mut Scrubber,
    held: String,
    redactions: usize,
}

impl std::fmt::Debug for ScrubStream<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScrubStream([REDACTED])")
    }
}

impl ScrubStream<'_> {
    /// Add a chunk; returns the scrubbed text safe to emit now. Ports
    /// `push` in `src/core/scrub.js`.
    pub fn push(&mut self, chunk: &str) -> String {
        todo!()
    }

    /// Scrub and return everything still held. Ports `flush` in
    /// `src/core/scrub.js`.
    pub fn flush(&mut self) -> String {
        todo!()
    }

    /// Total replacements so far. Ports the `redactions` getter in
    /// `src/core/scrub.js`.
    pub fn redactions(&self) -> usize {
        todo!()
    }
}
