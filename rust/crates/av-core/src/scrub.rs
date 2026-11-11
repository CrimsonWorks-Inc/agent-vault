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
    use crate::secret::ExposeSecret;
    let mut out = text.to_owned();
    for e in secrets {
        let secret = e.secret.expose_secret();
        if secret.encode_utf16().count() >= MIN_SECRET_LEN {
            out = out.replace(secret, &format!("[[av:redacted:{}]]", e.label));
        }
    }
    out
}

/// Agent-written text as it may be stored: stored secrets redacted, every
/// placeholder replaced by `«placeholder»`, then cut to `max` chars (the JS
/// default is 200). `None` for empty input. Ports `untrustedText` in
/// `src/core/scrub.js`.
pub fn untrusted_text(text: Option<&str>, secrets: &[StoredSecret], max: usize) -> Option<String> {
    let text = text.filter(|s| !s.is_empty())?;
    let mut out = redact_stored(text, secrets);
    for hit in crate::placeholder::find_all(&out).into_iter().rev() {
        out.replace_range(hit.offset..hit.end, "«placeholder»");
    }
    Some(String::from_utf16_lossy(
        &out.encode_utf16().take(max).collect::<Vec<_>>(),
    ))
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
    compile_pattern(source)
}

/// Every encoding of `secret` a response might carry (raw, latin1 view of
/// its UTF-8, `encodeURIComponent`, `\/`-escaped, JSON-escaped, `\u`-escaped,
/// HTML-entity, and [`blob_encodings`]), each at least `min_len` long,
/// de-duplicated. The result is secret material. Ports `encodings` in
/// `src/core/scrub.js`.
pub fn encodings(secret: &SecretString, min_len: usize) -> Vec<SecretString> {
    use crate::secret::ExposeSecret;
    let secret = secret.expose_secret();
    let mut out = Vec::new();
    let mut add = |s: String| {
        if !s.is_empty() && s.encode_utf16().count() >= min_len && !out.contains(&s) {
            out.push(s);
        }
    };
    add(secret.into());
    add(secret.as_bytes().iter().copied().map(char::from).collect());
    add(uri_encode(secret));
    add(secret.replace('/', "\\/"));
    let quoted = serde_json::to_string(secret).expect("string");
    add(quoted[1..quoted.len() - 1].into());
    add(secret
        .chars()
        .map(|c| format!("\\u{:04x}", c.encode_utf16(&mut [0; 2])[0]))
        .collect());
    add(secret
        .chars()
        .map(|c| {
            if "<>&\"'".contains(c) {
                format!("&#{};", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect());
    for b in blob_encodings(&SecretString::from(secret.to_owned())) {
        add(b.expose_secret().to_owned());
    }
    out.into_iter().map(SecretString::from).collect()
}

/// The hex (both cases) and base64 (three alignments, standard and URL-safe)
/// forms of `secret`. Secret material. Ports `blobEncodings` in
/// `src/core/scrub.js`.
pub fn blob_encodings(secret: &SecretString) -> Vec<SecretString> {
    use crate::secret::ExposeSecret;
    use base64::Engine;
    let secret = secret.expose_secret();
    let mut out = Vec::new();
    let hex: String = secret
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    out.push(hex.clone());
    if !out.contains(&hex.to_uppercase()) {
        out.push(hex.to_uppercase());
    }
    for pad in 0..3 {
        let mut bytes = vec![b' '; pad];
        bytes.extend_from_slice(secret.as_bytes());
        let std = base64::engine::general_purpose::STANDARD.encode(bytes);
        let start = (pad * 4usize).div_ceil(3);
        let end = 4 * (pad + secret.len()) / 3;
        let core = std[start..end].to_owned();
        for v in [core.clone(), core.replace('+', "-").replace('/', "_")] {
            if !out.contains(&v) {
                out.push(v);
            }
        }
    }
    out.into_iter().map(SecretString::from).collect()
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

#[allow(dead_code)]
#[derive(Clone)]
struct Needle {
    needle: SecretString,
    replacement: String,
}

/// The streaming scrubber. Ports `class Scrubber` in `src/core/scrub.js`.
/// Holds secret material, so it has no `Debug` of its contents.

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
        use crate::secret::ExposeSecret;
        let mut extra_patterns = Vec::new();
        for e in &opts.extra_patterns {
            let compiled = compile_scrub_pattern(&e.source).map_err(|_| {
                crate::errors::deny(
                    crate::errors::ErrorCode::Unscannable,
                    "a stored scrub pattern is not valid, so the response could not be scrubbed",
                    crate::errors::DenyExtra {
                        rule: Some("scrub_pattern_invalid".into()),
                        ..Default::default()
                    },
                )
            })?;
            extra_patterns.push((e.name.clone(), compiled));
        }
        let extra_hold = extra_patterns
            .iter()
            .map(|(_, p)| p.max_len)
            .max()
            .unwrap_or(0);
        let mut patterns = Vec::new();
        let mut plain = Vec::new();
        let mut blobs = Vec::new();
        let mut hex = Vec::new();
        let mut max_len = 0;
        for e in entries {
            let secret = e.secret.expose_secret();
            let floor = if e.always { 1 } else { MIN_SECRET_LEN };
            if secret.is_empty() || secret.encode_utf16().count() < floor {
                continue;
            }
            let replacement = e
                .replacement
                .clone()
                .unwrap_or_else(|| format!("[[av:redacted:{}]]", e.label));
            for enc in encodings(&e.secret, floor) {
                max_len = max_len.max(enc.expose_secret().encode_utf16().count());
                patterns.push(Needle {
                    needle: enc,
                    replacement: replacement.clone(),
                });
            }
            let latin: String = secret.as_bytes().iter().copied().map(char::from).collect();
            for needle in if latin == secret {
                vec![secret.to_owned()]
            } else {
                vec![secret.to_owned(), latin]
            } {
                if needle.encode_utf16().count() >= floor {
                    plain.push(Needle {
                        needle: needle.into(),
                        replacement: replacement.clone(),
                    });
                }
            }
            for needle in blob_encodings(&e.secret) {
                if needle.expose_secret().len() >= floor {
                    blobs.push(Needle {
                        needle,
                        replacement: replacement.clone(),
                    });
                }
            }
            hex.push(Needle {
                needle: secret
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    .into(),
                replacement,
            });
        }
        for list in [&mut patterns, &mut plain, &mut blobs, &mut hex] {
            list.sort_by_key(|n| std::cmp::Reverse(n.needle.expose_secret().len()));
        }
        let min_blob = blobs
            .iter()
            .map(|n| n.needle.expose_secret().len())
            .min()
            .unwrap_or(usize::MAX);
        let min_hex = hex
            .iter()
            .map(|n| n.needle.expose_secret().len())
            .min()
            .unwrap_or(usize::MAX);
        let min_plain = plain
            .iter()
            .map(|n| n.needle.expose_secret().encode_utf16().count())
            .min();
        Ok(Self {
            extra_patterns,
            extra_hold,
            patterns,
            plain,
            blobs,
            hex,
            max_len,
            min_blob,
            min_hex,
            b64_min: min_plain.map_or(usize::MAX, |n| (4 * n).div_ceil(3).max(8)),
            hex_min: min_plain.map_or(usize::MAX, |n| (2 * n).max(8)),
            nested_view_budget: opts.nested_views.unwrap_or(NESTED_VIEW_BUDGET),
            nested_byte_budget: opts.nested_bytes.unwrap_or(NESTED_BYTE_BUDGET),
            derived_seen: Default::default(),
        })
    }

    /// True when any encoding (≥ [`MIN_SECRET_LEN`]) of any secret appears
    /// in `text` with case ignored, for text whose case is already lost (a
    /// header name). Ports `Scrubber#containsIgnoringCase` in
    /// `src/core/scrub.js`.
    pub fn contains_ignoring_case(&self, text: &str) -> bool {
        use crate::secret::ExposeSecret;
        let t = text.to_lowercase();
        self.patterns.iter().any(|p| {
            p.needle.expose_secret().encode_utf16().count() >= MIN_SECRET_LEN
                && t.contains(&p.needle.expose_secret().to_lowercase())
        })
    }

    /// Lookbehind a streaming caller must keep between chunks:
    /// `max(maxLen, 64) - 1`. Ports the `Scrubber#overlap` getter in
    /// `src/core/scrub.js`.
    pub fn overlap(&self) -> usize {
        self.max_len.max(64) - 1
    }

    /// Scrub a complete string: fixed needles, then decoded/unwrapped/folded
    /// spans, then derived patterns (recording which matched). Ports
    /// `Scrubber#scrub` in `src/core/scrub.js`.
    pub fn scrub(&mut self, text: &str) -> ScrubResult {
        use crate::secret::ExposeSecret;
        let mut out = text.to_owned();
        let mut redactions = 0;
        for n in &self.patterns {
            let needle = n.needle.expose_secret();
            let count = out.matches(needle).count();
            if count > 0 {
                redactions += count;
                out = out.replace(needle, &n.replacement);
            }
        }
        let (spans, unscannable) = self.collect_spans(&out);
        let (next, count) = splice_spans(&out, spans);
        out = next;
        redactions += count;
        for p in DERIVED_PATTERNS {
            let re = regex::Regex::new(p.pattern).expect("derived pattern");
            let spans: Vec<_> = re
                .find_iter(&out)
                .filter(|m| p.name == "private-key" || boundary(&out, m.start()))
                .map(|m| (m.start(), m.end(), "[[av:derived]]".into()))
                .collect();
            if !spans.is_empty() {
                self.derived_seen.insert(p.name.into());
                let (next, count) = splice_spans(&out, spans);
                out = next;
                redactions += count;
            }
        }
        for (name, p) in &self.extra_patterns {
            let spans: Vec<_> = p
                .regex
                .find_iter(&out)
                .filter(|m| boundary(&out, m.start()))
                .map(|m| (m.start(), m.end(), "[[av:derived]]".into()))
                .collect();
            if !spans.is_empty() {
                self.derived_seen.insert(name.clone());
                let (next, count) = splice_spans(&out, spans);
                out = next;
                redactions += count;
            }
        }
        ScrubResult {
            text: out,
            redactions,
            unscannable,
        }
    }

    /// The raw spans a secret occupies in `text` once escapes are decoded or
    /// a wrapped blob joined, without the fail-closed flag. Ports
    /// `Scrubber#viewSpans` in `src/core/scrub.js`.
    pub fn view_spans(&self, text: &str) -> Vec<ScrubSpan> {
        self.collect_spans(text).0
    }

    /// The raw spans and whether the layered decoder ran out of budget.
    /// Ports `Scrubber#collectSpans` in `src/core/scrub.js`.
    pub fn collect_spans(&self, text: &str) -> (Vec<ScrubSpan>, bool) {
        collect(self, text)
    }

    /// Names of the derived patterns that have matched so far. Ports
    /// `Scrubber#derivedSeen` in `src/core/scrub.js`.
    pub fn derived_seen(&self) -> &std::collections::BTreeSet<String> {
        &self.derived_seen
    }

    /// A streaming scrubber over this one. Ports `Scrubber#stream` in
    /// `src/core/scrub.js`.
    pub fn stream(&mut self) -> ScrubStream<'_> {
        ScrubStream {
            scrubber: self,
            held: String::new(),
            redactions: 0,
        }
    }
}

/// A streaming scrubber: feed chunks; it holds back enough that a secret or
/// derived token split across a chunk boundary is still matched, and
/// [`ScrubStream::flush`] returns the tail. Ports the object returned by
/// `Scrubber#stream` in `src/core/scrub.js`. The held tail may contain secret
/// material, so `Debug` is redacted.

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
        use crate::secret::ExposeSecret;
        let combined = std::mem::take(&mut self.held) + chunk;
        let keep = self
            .scrubber
            .overlap()
            .max(self.scrubber.extra_hold)
            .min(combined.len());
        let mut cut = combined.len() - keep;
        while !combined.is_char_boundary(cut) {
            cut -= 1;
        }
        if cut == 0 {
            self.held = combined;
            return String::new();
        }
        let re = regex::Regex::new(DERIVED_START_PATTERN).expect("derived start");
        for m in re.find_iter(&combined) {
            if m.start() >= cut {
                break;
            }
            if m.start() < cut.saturating_sub(MAX_DERIVED_HOLD) || !boundary(&combined, m.start()) {
                continue;
            }
            if combined.as_bytes()[m.start()..cut]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(b))
            {
                cut = m.start();
                break;
            }
        }
        for (_, p) in &self.scrubber.extra_patterns {
            for m in p.regex.find_iter(&combined) {
                if m.start() < cut && m.end() > cut && boundary(&combined, m.start()) {
                    cut = m.end();
                }
            }
        }
        for n in &self.scrubber.patterns {
            for (i, needle) in combined.match_indices(n.needle.expose_secret()) {
                if i < cut && i + needle.len() > cut {
                    cut = i + needle.len();
                }
            }
        }
        for (start, end, _) in self.scrubber.view_spans(&combined) {
            if start < cut && end > cut {
                cut = end;
            }
        }
        let r = self.scrubber.scrub(&combined[..cut]);
        self.redactions += r.redactions;
        self.held = combined[cut..].into();
        r.text
    }

    /// Scrub and return everything still held. Ports `flush` in
    /// `src/core/scrub.js`.
    pub fn flush(&mut self) -> String {
        let r = self.scrubber.scrub(&self.held);
        self.redactions += r.redactions;
        self.held.clear();
        r.text
    }

    /// Total replacements so far. Ports the `redactions` getter in
    /// `src/core/scrub.js`.
    pub fn redactions(&self) -> usize {
        self.redactions
    }
}

fn boundary(text: &str, start: usize) -> bool {
    start == 0
        || !text[..start]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}
fn uri_encode(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
fn scrub_bad(message: &str) -> crate::errors::VaultError {
    crate::errors::deny(
        crate::errors::ErrorCode::PolicyDenied,
        format!("scrub pattern refused: {message}"),
        crate::errors::DenyExtra {
            rule: Some("scrub_pattern".into()),
            ..Default::default()
        },
    )
}
fn compile_pattern(source: &str) -> Result<CompiledScrubPattern> {
    let chars: Vec<_> = source.chars().collect();
    if source.encode_utf16().count() < 3 || source.encode_utf16().count() > 256 {
        return Err(scrub_bad("it must be 3 to 256 characters"));
    }
    if chars.iter().any(|c| (*c as u32) < 32 || *c == '\u{7f}') {
        return Err(scrub_bad("control characters are not allowed"));
    }
    let mut i = 0;
    let mut branches = 0;
    let mut max_len = 0;
    loop {
        branches += 1;
        if branches > 16 {
            return Err(scrub_bad("it has more than sixteen branches"));
        }
        let mut literals = 0;
        let mut variables = 0;
        let mut length = 0;
        let mut atoms = 0;
        while i < chars.len() && chars[i] != '|' {
            let c = chars[i];
            i += 1;
            let after_variable = variables > 0;
            let mut literal = true;
            if c == '\\' {
                let e = chars.get(i).copied().ok_or_else(|| {
                    scrub_bad(
                        "it uses an escape outside \\d \\w \\s \\D \\W \\S and escaped punctuation",
                    )
                })?;
                i += 1;
                if !SCRUB_ESCAPES.contains(e) {
                    return Err(scrub_bad(
                        "it uses an escape outside \\d \\w \\s \\D \\W \\S and escaped punctuation",
                    ));
                }
                literal = !"dwsDWS".contains(e);
            } else if c == '[' {
                literal = false;
                if chars.get(i) == Some(&'^') {
                    i += 1;
                }
                let mut members = 0;
                let mut closed = false;
                while i < chars.len() {
                    let x = chars[i];
                    i += 1;
                    if x == ']' {
                        closed = true;
                        break;
                    }
                    if x == '[' {
                        return Err(scrub_bad("a class may not contain another"));
                    }
                    if x == '\\' {
                        let e = chars
                            .get(i)
                            .copied()
                            .ok_or_else(|| scrub_bad("a class uses an unsupported escape"))?;
                        i += 1;
                        if !SCRUB_ESCAPES.contains(e) {
                            return Err(scrub_bad("a class uses an unsupported escape"));
                        }
                    }
                    members += 1;
                }
                if !closed || members == 0 {
                    return Err(scrub_bad("a class must be closed and not empty"));
                }
            } else if "()^$.*+?{}]".contains(c) {
                return Err(scrub_bad(
                    "groups, anchors, `.` and stray operators are not allowed",
                ));
            }
            atoms += 1;
            let mut upper = 1;
            let mut quantified = false;
            if matches!(chars.get(i), Some('*' | '+')) {
                return Err(scrub_bad("unbounded repetition is not allowed; use {n,m}"));
            }
            if chars.get(i) == Some(&'?') {
                quantified = true;
                i += 1;
                variables += 1;
                if variables > 1 {
                    return Err(scrub_bad("a branch may have only one variable quantifier"));
                }
            } else if chars.get(i) == Some(&'{') {
                let tail: String = chars[i..].iter().collect();
                let re = regex::Regex::new(r"^\{(\d{1,3})(?:,(\d{0,3}))?\}").expect("quantifier");
                let m = re
                    .captures(&tail)
                    .ok_or_else(|| scrub_bad("a quantifier must be {n} or {n,m}"))?;
                let n = m[1].parse::<usize>().expect("digits");
                let max = if let Some(c) = m.get(2) {
                    if c.as_str().is_empty() {
                        return Err(scrub_bad("unbounded repetition is not allowed; use {n,m}"));
                    }
                    c.as_str().parse::<usize>().expect("digits")
                } else {
                    n
                };
                if n > 256 || max > 256 {
                    return Err(scrub_bad("a repetition bound is over 256"));
                }
                if max < n {
                    return Err(scrub_bad("a quantifier is out of order"));
                }
                if max > n {
                    variables += 1;
                    if variables > 1 {
                        return Err(scrub_bad("a branch may have only one variable quantifier"));
                    }
                }
                quantified = true;
                upper = max;
                i += m[0].len();
            }
            if quantified && chars.get(i) == Some(&'?') {
                return Err(scrub_bad("lazy and possessive quantifiers are not allowed"));
            }
            if after_variable && (!literal || quantified) {
                return Err(scrub_bad(
                    "only literal characters may follow the variable quantifier",
                ));
            }
            if literals < 3 {
                if !literal || quantified {
                    return Err(scrub_bad(
                        "each branch must start with three literal characters",
                    ));
                }
                literals += 1;
            }
            length += upper;
        }
        if atoms == 0 {
            return Err(scrub_bad("a branch is empty"));
        }
        if literals < 3 {
            return Err(scrub_bad(
                "each branch must start with three literal characters",
            ));
        }
        if length > 512 {
            return Err(scrub_bad("a branch can match more than 512 characters"));
        }
        max_len = max_len.max(length);
        if i >= chars.len() {
            break;
        }
        i += 1;
        if i == chars.len() {
            return Err(scrub_bad("a branch is empty"));
        }
    }
    // JS character classes are ASCII for \d and \w; keep that property.
    let normalized = source
        .replace(r"\d", "[0-9]")
        .replace(r"\w", "[A-Za-z0-9_]");
    let regex =
        regex::Regex::new(&normalized).map_err(|_| scrub_bad("it is not a valid expression"))?;
    for line in std::iter::once("").chain(SCRUB_PATTERN_CORPUS.iter().copied()) {
        if regex.find_iter(line).any(|m| boundary(line, m.start())) {
            return Err(scrub_bad("it matches ordinary text"));
        }
    }
    Ok(CompiledScrubPattern {
        source: source.into(),
        regex,
        max_len,
    })
}
fn splice_spans(text: &str, mut spans: Vec<ScrubSpan>) -> (String, usize) {
    spans.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let mut merged: Vec<ScrubSpan> = Vec::new();
    for s in spans {
        if let Some(last) = merged.last_mut() {
            if s.0 < last.1 {
                last.1 = last.1.max(s.1);
                continue;
            }
        }
        merged.push(s);
    }
    let mut out = String::new();
    let mut last = 0;
    for (s, e, replacement) in &merged {
        out.push_str(&text[last..*s]);
        out.push_str(replacement);
        last = *e;
    }
    out.push_str(&text[last..]);
    (out, merged.len())
}
#[derive(Clone)]
struct Piece {
    start: usize,
    end: usize,
    raw_start: usize,
    raw_end: usize,
    block: bool,
}
struct View {
    text: String,
    parent: Option<std::rc::Rc<View>>,
    pieces: Vec<Piece>,
}
impl View {
    fn raw_span(&self, lo: usize, hi: usize) -> (usize, usize) {
        let Some(parent) = &self.parent else {
            return (lo, hi);
        };
        let first = self.pieces.partition_point(|p| p.end <= lo);
        let last = self.pieces.partition_point(|p| p.end < hi);
        let a = &self.pieces[first];
        let b = &self.pieces[last];
        let start = if a.block {
            a.raw_start
        } else {
            a.raw_start + lo - a.start
        };
        let end = if b.block {
            b.raw_end
        } else {
            b.raw_start + hi - b.start
        };
        parent.raw_span(start, end)
    }
}
fn transform(
    parent: &std::rc::Rc<View>,
    re: &regex::Regex,
    decode: impl Fn(&str) -> String,
) -> std::rc::Rc<View> {
    let mut text = String::new();
    let mut pieces = Vec::new();
    let mut raw = 0;
    for m in re.find_iter(&parent.text) {
        if m.start() > raw {
            let start = text.len();
            text.push_str(&parent.text[raw..m.start()]);
            pieces.push(Piece {
                start,
                end: text.len(),
                raw_start: raw,
                raw_end: m.start(),
                block: false,
            });
        }
        let dec = decode(m.as_str());
        let start = text.len();
        text.push_str(&dec);
        if text.len() > start {
            pieces.push(Piece {
                start,
                end: text.len(),
                raw_start: m.start(),
                raw_end: m.end(),
                block: true,
            });
        }
        raw = m.end();
    }
    if raw < parent.text.len() {
        let start = text.len();
        text.push_str(&parent.text[raw..]);
        pieces.push(Piece {
            start,
            end: text.len(),
            raw_start: raw,
            raw_end: parent.text.len(),
            block: false,
        });
    }
    std::rc::Rc::new(View {
        text,
        parent: Some(parent.clone()),
        pieces,
    })
}
fn find_view(
    view: &View,
    needles: impl Iterator<Item = impl AsRef<Needle>>,
    spans: &mut Vec<ScrubSpan>,
    base: usize,
) {
    use crate::secret::ExposeSecret;
    for n in needles {
        let n = n.as_ref();
        for (i, s) in view.text.match_indices(n.needle.expose_secret()) {
            let (lo, hi) = view.raw_span(i, i + s.len());
            spans.push((base + lo, base + hi, n.replacement.clone()));
        }
    }
}
impl AsRef<Needle> for Needle {
    fn as_ref(&self) -> &Self {
        self
    }
}
fn decode_b64(s: &str) -> String {
    use base64::{
        alphabet,
        engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
        Engine,
    };
    let engine = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let s = s.replace('-', "+").replace('_', "/");
    let s = s.trim_end_matches('=');
    let s = if s.len() % 4 == 1 {
        &s[..s.len() - 1]
    } else {
        s
    };
    engine
        .decode(s)
        .unwrap_or_default()
        .into_iter()
        .map(char::from)
        .collect()
}
fn decode_json_escape(s: &str) -> String {
    if let Some(s) = s.strip_prefix(r"\u") {
        u32::from_str_radix(s, 16)
            .ok()
            .and_then(char::from_u32)
            .unwrap_or('\u{fffd}')
            .to_string()
    } else {
        match s.as_bytes()[1] {
            b'"' => "\"",
            b'\\' => "\\",
            b'/' => "/",
            b'b' => "\u{8}",
            b'f' => "\u{c}",
            b'n' => "\n",
            b'r' => "\r",
            b't' => "\t",
            _ => s,
        }
        .into()
    }
}
fn collect(scrubber: &Scrubber, text: &str) -> (Vec<ScrubSpan>, bool) {
    use std::rc::Rc;
    let root = Rc::new(View {
        text: text.into(),
        parent: None,
        pieces: vec![],
    });
    let mut spans = Vec::new();
    let mut unscannable = false;
    if !scrubber.plain.is_empty() || !scrubber.blobs.is_empty() {
        let mut seen = std::collections::HashSet::from([text.to_owned()]);
        let mut queue = std::collections::VecDeque::from([(root.clone(), 0, 0u8)]);
        let mut nested_views = 0;
        let mut nested_bytes = 0;
        let regexes = [
            regex::Regex::new(r#"\\u[0-9a-fA-F]{4}|\\["\\/bfnrt]"#).expect("JSON"),
            regex::Regex::new(r"%[0-9a-fA-F]{2}").expect("percent"),
            regex::Regex::new(&format!(
                r"[A-Za-z0-9+/=_-]{{{},}}",
                scrubber.b64_min.min(usize::MAX / 2)
            ))
            .unwrap_or_else(|_| regex::Regex::new(r"\b\B").unwrap()),
            regex::Regex::new(&format!(
                r"[0-9a-fA-F]{{{},}}",
                scrubber.hex_min.min(usize::MAX / 2)
            ))
            .unwrap_or_else(|_| regex::Regex::new(r"\b\B").unwrap()),
        ];
        while let Some((view, depth, used)) = queue.pop_front() {
            if depth >= 1 && used != 4 && used != 8 {
                find_view(
                    &view,
                    scrubber.plain.iter().chain(scrubber.blobs.iter()),
                    &mut spans,
                    0,
                );
            }
            if depth >= DECODE_DEPTH {
                continue;
            }
            for (d, re) in regexes.iter().enumerate() {
                if used & (1 << d) != 0 || !re.is_match(&view.text) {
                    continue;
                }
                if depth + 1 >= 2
                    && (nested_views + 1 > scrubber.nested_view_budget
                        || nested_bytes + view.text.encode_utf16().count()
                            > scrubber.nested_byte_budget)
                {
                    unscannable = true;
                    break;
                }
                let decoded = transform(&view, re, |s| match d {
                    0 => decode_json_escape(s),
                    1 => {
                        char::from(u8::from_str_radix(&s[1..], 16).expect("hex escape")).to_string()
                    }
                    2 => decode_b64(s),
                    _ => s
                        .as_bytes()
                        .chunks_exact(2)
                        .map(|pair| {
                            char::from(
                                u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap(),
                            )
                        })
                        .collect(),
                });
                if decoded.text == view.text || !seen.insert(decoded.text.clone()) {
                    continue;
                }
                if depth + 1 >= 2 {
                    nested_views += 1;
                    nested_bytes += decoded.text.encode_utf16().count();
                }
                queue.push_back((decoded, depth + 1, used | (1 << d)));
            }
            if unscannable {
                break;
            }
        }
    }
    // Wrapped runs use an iterative scanner: one fixed-cost walk per break,
    // without recursive repeated groups or rescanning prior lines.
    let breaks = regex::Regex::new(LINE_BREAK_PATTERN).expect("line breaks");
    let blob = |b: u8| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b);
    let mut runs = Vec::new();
    let mut current: Option<(usize, usize)> = None;
    for m in breaks.find_iter(text) {
        let after = m.end();
        if m.start() == 0
            || after == text.len()
            || !blob(text.as_bytes()[m.start() - 1])
            || !blob(text.as_bytes()[after])
        {
            continue;
        }
        let start = if let Some((start, end)) = current {
            if end == m.start() {
                start
            } else {
                runs.push((start, end));
                let mut start = m.start();
                while start > 0 && blob(text.as_bytes()[start - 1]) {
                    start -= 1;
                }
                start
            }
        } else {
            let mut start = m.start();
            while start > 0 && blob(text.as_bytes()[start - 1]) {
                start -= 1;
            }
            start
        };
        let mut end = after;
        while end < text.len() && blob(text.as_bytes()[end]) {
            end += 1;
        }
        current = Some((start, end));
    }
    if let Some(run) = current {
        runs.push(run);
    }
    for (start, end) in runs {
        let raw = Rc::new(View {
            text: text[start..end].into(),
            parent: None,
            pieces: vec![],
        });
        let joined = transform(&raw, &breaks, |_| String::new());
        if joined.text.len() >= scrubber.min_blob {
            find_view(&joined, scrubber.blobs.iter(), &mut spans, start);
        }
        if joined.text.len() >= scrubber.min_hex && mixed_case(&joined.text) {
            let lower = View {
                text: joined.text.to_ascii_lowercase(),
                parent: joined.parent.clone(),
                pieces: joined.pieces.clone(),
            };
            find_view(&lower, scrubber.hex.iter(), &mut spans, start);
        }
    }
    let mut start = None;
    for (i, b) in text.bytes().chain(std::iter::once(b' ')).enumerate() {
        if b.is_ascii_hexdigit() {
            start.get_or_insert(i);
        } else if let Some(start) = start.take() {
            if i - start >= scrubber.min_hex && mixed_case(&text[start..i]) {
                let lower = View {
                    text: text[start..i].to_ascii_lowercase(),
                    parent: None,
                    pieces: vec![],
                };
                find_view(&lower, scrubber.hex.iter(), &mut spans, start);
            }
        }
    }
    (spans, unscannable)
}
fn mixed_case(s: &str) -> bool {
    s.bytes().any(|b| matches!(b, b'a'..=b'f')) && s.bytes().any(|b| matches!(b, b'A'..=b'F'))
}
