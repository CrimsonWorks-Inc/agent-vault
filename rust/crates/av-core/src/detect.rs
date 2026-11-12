//! The detector: where does a placeholder appear in the request, in any
//! encoding a tool might have applied? Ports `src/core/detect.js`.
//!
//! Deliberately a superset of what the substituter understands: it also sees
//! percent-encoding, JSON string escapes and base64 anywhere.

use serde::{Deserialize, Serialize};

use crate::placeholder::ParsedPlaceholder;

/// The base64-ish character class a run is made of. Ports `B64_CHARS` in
/// `src/core/detect.js`.
pub const B64_CHARS_PATTERN: &str = "[A-Za-z0-9+/=_-]";

/// How a detected placeholder was encoded. Ports the `encoding` strings
/// pushed by `detectAll` in `src/core/detect.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HitEncoding {
    /// `'raw'`
    #[serde(rename = "raw")]
    Raw,
    /// `'percent'`
    #[serde(rename = "percent")]
    Percent,
    /// `'percent-double'`
    #[serde(rename = "percent-double")]
    PercentDouble,
    /// `'json-escape'`
    #[serde(rename = "json-escape")]
    JsonEscape,
    /// `'base64'`
    #[serde(rename = "base64")]
    Base64,
}

impl HitEncoding {
    /// The JS string, e.g. `"percent-double"`. Ports the `encoding` values in
    /// `src/core/detect.js`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Percent => "percent",
            Self::PercentDouble => "percent-double",
            Self::JsonEscape => "json-escape",
            Self::Base64 => "base64",
        }
    }
}

/// One placeholder found in text, with how it was encoded. Ports the
/// `{ ...parsed, encoding }` objects returned by `detectAll` in
/// `src/core/detect.js`. `parsed.offset`/`parsed.end` are meaningful only for
/// [`HitEncoding::Raw`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectHit {
    /// The parsed placeholder.
    pub parsed: ParsedPlaceholder,
    /// The encoding it was carried in.
    pub encoding: HitEncoding,
}

/// A maximal run of base64-ish characters. Ports the `{ start, text }`
/// objects returned by `base64Runs` in `src/core/detect.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base64Run {
    /// Byte offset where the run starts.
    pub start: usize,
    /// The run itself.
    pub text: String,
}

/// Tolerant percent-decoder: never fails, leaves malformed escapes in place,
/// and maps each decoded byte to the char of the same code (latin1), as
/// `String.fromCharCode` does. Ports `percentDecode` in `src/core/detect.js`.
pub fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s.as_bytes()[i] == b'%' && i + 2 < s.len() {
            if let Ok(h) = u8::from_str_radix(s.get(i + 1..i + 3).unwrap_or(""), 16) {
                out.push(char::from(h));
                i += 3;
                continue;
            }
        }
        let c = s[i..].chars().next().expect("character");
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// Undo the JSON string escapes that can hide a placeholder: `\uXXXX` and
/// `\/`. Ports `jsonUnescape` in `src/core/detect.js`.
pub fn json_unescape(s: &str) -> String {
    let mut units = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i..].starts_with("\\u") && i + 6 <= s.len() {
            if let Ok(h) = u16::from_str_radix(s.get(i + 2..i + 6).unwrap_or(""), 16) {
                units.push(h);
                i += 6;
                continue;
            }
        }
        let c = s[i..].chars().next().expect("character");
        let mut b = [0; 2];
        units.extend_from_slice(c.encode_utf16(&mut b));
        i += c.len_utf8();
    }
    String::from_utf16_lossy(&units).replace("\\/", "/")
}

/// Every maximal run of base64-ish characters at least `min` long (the JS
/// default is [`crate::placeholder::B64_MIN_RUN`]). Ports `base64Runs` in
/// `src/core/detect.js`.
pub fn base64_runs(s: &str, min: usize) -> Vec<Base64Run> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, b) in s.bytes().chain(std::iter::once(b' ')).enumerate() {
        let yes = b.is_ascii_alphanumeric() || b"+/=_-".contains(&b);
        if yes {
            start.get_or_insert(i);
        } else if let Some(begin) = start.take() {
            if i - begin >= min {
                out.push(Base64Run {
                    start: begin,
                    text: s[begin..i].into(),
                });
            }
        }
    }
    out
}

/// Every placeholder in `text`, in any encoding (raw, percent, double
/// percent, JSON escape, base64 at every alignment and in both alphabets,
/// including whitespace-wrapped base64), de-duplicated. Ports `detectAll` in
/// `src/core/detect.js`.
pub fn detect_all(text: &str) -> Vec<DetectHit> {
    use crate::placeholder::{find_all, B64_MIN_RUN};
    let mut hits = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push = |s: &str, encoding: HitEncoding| {
        for parsed in find_all(s) {
            let key = (
                encoding,
                parsed.text.clone(),
                if encoding == HitEncoding::Raw {
                    parsed.offset
                } else {
                    0
                },
            );
            if seen.insert(key) {
                hits.push(DetectHit { parsed, encoding });
            }
        }
    };
    push(text, HitEncoding::Raw);
    let pct1 = percent_decode(text);
    if pct1 != text {
        push(&pct1, HitEncoding::Percent);
        let pct2 = percent_decode(&pct1);
        if pct2 != pct1 {
            push(&pct2, HitEncoding::PercentDouble);
        }
    }
    let unescaped = json_unescape(text);
    if unescaped != text {
        push(&unescaped, HitEncoding::JsonEscape);
    }
    let mut variants = vec![text.to_owned(), pct1, unescaped];
    let re = regex::Regex::new(r"\\[nrtbf]|\s+").expect("fixed pattern");
    for v in variants.clone() {
        let folded = re.replace_all(&v, "").into_owned();
        if folded != v {
            variants.push(folded);
        }
    }
    let mut unique = std::collections::HashSet::new();
    for v in variants {
        if !unique.insert(v.clone()) {
            continue;
        }
        for run in base64_runs(&v, B64_MIN_RUN) {
            for decoded in base64_decodings(&run.text) {
                push(&decoded, HitEncoding::Base64);
            }
        }
    }
    hits
}

/// True when any encoding other than raw text carried a placeholder. Ports
/// `hasEncodedHit` in `src/core/detect.js`.
pub fn has_encoded_hit(hits: &[DetectHit]) -> bool {
    hits.iter().any(|h| h.encoding != HitEncoding::Raw)
}

// Node Buffer base64 decoding is tolerant of padding and unused trailing bits.
pub(crate) fn base64_decodings(run: &str) -> Vec<String> {
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
    let normalized = run.replace('-', "+").replace('_', "/");
    let mut out = Vec::new();
    for skip in 0..4 {
        let Some(s) = normalized.get(skip..) else {
            continue;
        };
        let mut s = s.split('=').next().unwrap_or("").to_owned();
        if s.len() < 8 {
            continue;
        }
        if s.len() % 4 == 1 {
            s.pop();
        }
        s.extend(std::iter::repeat_n('=', (4 - s.len() % 4) % 4));
        if let Ok(bytes) = engine.decode(&s) {
            let text: String = bytes.into_iter().map(char::from).collect();
            if text.contains(crate::placeholder::PREFIX) {
                out.push(text);
            }
        }
    }
    out
}
