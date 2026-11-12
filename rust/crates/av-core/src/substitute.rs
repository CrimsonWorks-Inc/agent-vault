//! The substitution engine: location-bound, fail-closed. Ports
//! `src/core/substitute.js`.
//!
//! [`locate`] finds every placeholder occurrence anywhere in the request, in
//! any encoding, and labels where it is; [`apply`] replaces a placeholder at
//! one declared site. Between them the pipeline checks each occurrence's
//! location against the field's declared sites; anywhere else is
//! `AV_BAD_LOCATION` and the request never reaches an upstream.

use serde::{Deserialize, Serialize};

use crate::detect::{DetectHit, HitEncoding};
use crate::errors::Result;
use crate::placeholder::ParsedPlaceholder;
use crate::secret::SecretString;
use crate::sites::Site;

/// Largest body buffered and scanned (16 MiB); request-body streaming is not
/// implemented. Ports `MAX_BUFFERED_BODY` in `src/core/substitute.js`.
pub const MAX_BUFFERED_BODY: usize = 16 * 1024 * 1024;

/// The `unscannable` reason for an oversized body. Ports the string returned
/// by `locate` in `src/core/substitute.js`.
pub const UNSCANNABLE_TOO_LARGE: &str = "body exceeds the 16 MiB buffered limit, and request-body streaming is not implemented, so this body cannot be scanned for placeholders";

/// The request being proxied. Ports the `Req` typedef
/// `{ method, path, query, headers, body }` of `src/core/substitute.js`.
/// After [`apply`] it carries a real secret, so `Debug` is redacted.
#[derive(Clone, Default)]
pub struct ProxyRequest {
    /// Method.
    pub method: String,
    /// Path, as sent.
    pub path: String,
    /// Query without `?`.
    pub query: String,
    /// Header pairs in order, repeats kept.
    pub headers: Vec<(String, String)>,
    /// Body, if any.
    pub body: Option<Vec<u8>>,
}

impl std::fmt::Debug for ProxyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyRequest")
            .field("method", &self.method)
            .field("headers", &self.headers.len())
            .finish_non_exhaustive()
    }
}

/// Where in the request an occurrence sits. Ports the `region` strings of
/// the `Location` typedef in `src/core/substitute.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Region {
    /// `path`: never a site.
    Path,
    /// `query-key`: never a site.
    QueryKey,
    /// `query`
    Query,
    /// `header-name`: never a site.
    HeaderName,
    /// `header`
    Header,
    /// `basic`: inside `Authorization: Basic`.
    Basic,
    /// `json`
    Json,
    /// `form-key`: never a site.
    FormKey,
    /// `form`
    Form,
    /// `body`: never a site.
    Body,
}

/// Where an occurrence was found. Ports the `Location` typedef
/// `{ region, name, key, pointer, part, scheme, index, encoding, hidden_by }`
/// in `src/core/substitute.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// The region.
    pub region: Region,
    /// Header name, lowercased (`header`, `header-name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Decoded query or form key (`query`, `query-key`, `form`, `form-key`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// RFC 6901 pointer (`json`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    /// `user` or `pass` (`basic`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part: Option<String>,
    /// The scheme token before a raw header hit, e.g. `Bearer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Which header entry (`header`, `header-name`, `basic`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
    /// How it was encoded.
    pub encoding: HitEncoding,
    /// For a body hit the parser did not expose: `the body parser`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden_by: Option<String>,
}

/// One placeholder occurrence. Ports the `{ text, parsed, location }`
/// objects of `locate` in `src/core/substitute.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    /// The placeholder text.
    pub text: String,
    /// The parsed placeholder.
    pub parsed: ParsedPlaceholder,
    /// Where it is.
    pub location: Location,
}

impl Occurrence {
    /// Build from a detector hit. Ports `add` inside `locate` in
    /// `src/core/substitute.js`.
    pub fn from_hit(hit: DetectHit, location: Location) -> Self {
        Self {
            text: hit.parsed.text.clone(),
            parsed: hit.parsed,
            location,
        }
    }
}

/// The result of [`locate`]. Ports `{ occurrences, unscannable? }` in
/// `src/core/substitute.js`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocateResult {
    /// Every occurrence found, in scan order.
    pub occurrences: Vec<Occurrence>,
    /// Why the body could not be scanned, if it could not.
    pub unscannable: Option<String>,
}

/// The first header value named `name`, case-insensitively. Ports
/// `getHeader` in `src/core/substitute.js`.
pub fn get_header<'a>(req: &'a ProxyRequest, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Find every placeholder occurrence in the request (path, query keys and
/// values, header names and values, Basic auth parts, JSON/form/raw body,
/// including those a body parser hides) and label its location. Ports
/// `locate` in `src/core/substitute.js`.
pub fn locate(req: &ProxyRequest) -> LocateResult {
    locate_request(req)
}

/// The first occurrence still in `req` whose nonce is one of `nonces`, or
/// `None`. Run on the request about to be sent. Ports `unsubstituted` in
/// `src/core/substitute.js`.
pub fn unsubstituted(req: &ProxyRequest, nonces: &[String]) -> Option<Occurrence> {
    locate(req)
        .occurrences
        .into_iter()
        .find(|o| nonces.contains(&o.parsed.nonce))
}

/// Whether an occurrence sits at a declared site; only raw (unencoded) text
/// ever does. Ports `matchesSite` in `src/core/substitute.js`.
pub fn matches_site(location: &Location, site: &Site) -> bool {
    use crate::sites::SiteKind;
    if location.encoding != HitEncoding::Raw {
        return false;
    }
    match site.kind {
        SiteKind::Header => {
            location.region == Region::Header
                && location.name == site.name
                && (site.scheme.as_deref().is_none_or(|s| s.is_empty())
                    || location
                        .scheme
                        .as_deref()
                        .unwrap_or("")
                        .eq_ignore_ascii_case(site.scheme.as_deref().unwrap_or("")))
        }
        SiteKind::Basic => location.region == Region::Basic && location.part == site.part,
        SiteKind::Query => location.region == Region::Query && location.key == site.key,
        SiteKind::Form => location.region == Region::Form && location.key == site.key,
        SiteKind::Json => location.region == Region::Json && location.pointer == site.pointer,
        _ => false,
    }
}

/// A short agent-readable description, e.g. `header authorization` or
/// `request body (base64-encoded)`. Ports `describeLocation` in
/// `src/core/substitute.js`.
pub fn describe_location(location: &Location) -> String {
    let enc = if location.encoding == HitEncoding::Raw {
        String::new()
    } else {
        format!(" ({}-encoded)", location.encoding.as_str())
    };
    let text = match location.region {
        Region::Header => format!("header {}", location.name.as_deref().unwrap_or("")),
        Region::HeaderName => "the NAME of a request header".into(),
        Region::Basic => format!(
            "Authorization: Basic {} field",
            location.part.as_deref().unwrap_or("")
        ),
        Region::Query => format!("query parameter {}", location.key.as_deref().unwrap_or("")),
        Region::QueryKey => "the NAME of a query parameter".into(),
        Region::Form => format!("form field {}", location.key.as_deref().unwrap_or("")),
        Region::FormKey => "the NAME of a form field".into(),
        Region::Json => format!("JSON body at {}", location.pointer.as_deref().unwrap_or("")),
        Region::Body => location
            .hidden_by
            .as_ref()
            .map_or("request body".into(), |s| {
                format!("request body, in a position {s} does not expose")
            }),
        Region::Path => "request path".into(),
    };
    text + &enc
}

/// Replace one placeholder with `secret` at one location already checked
/// against a declared site (not re-checked here). Returns a new request; the
/// input is untouched. Headers are written by index, query/form values
/// percent-encoded in place, JSON spliced into the one string literal, and
/// `content-length` updated for body changes. Fails (`AV_INTERNAL`) for a
/// region that is never a site or a JSON pointer with no string. Ports
/// `apply` in `src/core/substitute.js`.
pub fn apply(
    req: &ProxyRequest,
    location: &Location,
    placeholder_text: &str,
    secret: &SecretString,
) -> Result<ProxyRequest> {
    use crate::secret::ExposeSecret;
    use base64::Engine;
    let secret = secret.expose_secret();
    let mut out = req.clone();
    let internal = |detail: String| {
        crate::errors::deny(
            crate::errors::ErrorCode::Internal,
            detail,
            Default::default(),
        )
    };
    match location.region {
        Region::Header => {
            let name = location.name.as_deref().unwrap_or("");
            let at = location
                .index
                .filter(|i| {
                    out.headers
                        .get(*i)
                        .is_some_and(|(n, _)| n.eq_ignore_ascii_case(name))
                })
                .or_else(|| {
                    out.headers
                        .iter()
                        .position(|(n, _)| n.eq_ignore_ascii_case(name))
                });
            if let Some(at) = at {
                out.headers[at].1 = out.headers[at].1.replace(placeholder_text, secret);
            }
        }
        Region::Basic => {
            let indexed = location.index.filter(|i| {
                out.headers
                    .get(*i)
                    .is_some_and(|(n, _)| n.eq_ignore_ascii_case("authorization"))
            });
            let current = indexed
                .map(|i| out.headers[i].1.as_str())
                .or_else(|| get_header(&out, "authorization"))
                .unwrap_or("");
            let b64 = strip_basic(current).unwrap_or(current).trim();
            let decoded = basic_decode(b64);
            let (user, pass) = decoded.split_once(':').unwrap_or((&decoded, ""));
            let (user, pass) = if location.part.as_deref() == Some("user") {
                (user.replace(placeholder_text, secret), pass.to_owned())
            } else {
                (user.to_owned(), pass.replace(placeholder_text, secret))
            };
            let rebuilt = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
            );
            if let Some(i) = indexed {
                out.headers[i].1 = rebuilt;
            } else {
                set_header(&mut out, "authorization", rebuilt);
            }
        }
        Region::Query => {
            let pairs = parse_query(&out.query);
            out.query = pairs
                .into_iter()
                .map(|(k, v, _)| {
                    let v = if safe_decode(&k) == location.key.as_deref().unwrap_or("") {
                        v.replace(placeholder_text, &uri_encode(secret))
                    } else {
                        v
                    };
                    if v.is_empty() {
                        k
                    } else {
                        format!("{k}={v}")
                    }
                })
                .collect::<Vec<_>>()
                .join("&");
        }
        Region::Form => {
            let text = String::from_utf8_lossy(out.body.as_deref().unwrap_or_default());
            let pairs = parse_query(&text);
            let body = pairs
                .into_iter()
                .map(|(k, v, eq)| {
                    let v = if safe_decode(&k) == location.key.as_deref().unwrap_or("") {
                        replace_encoded(&v, placeholder_text, &uri_encode(secret))
                    } else {
                        v
                    };
                    if v.is_empty() && !eq {
                        k
                    } else {
                        format!("{k}={v}")
                    }
                })
                .collect::<Vec<_>>()
                .join("&")
                .into_bytes();
            let len = body.len();
            out.body = Some(body);
            set_header(&mut out, "content-length", len.to_string());
        }
        Region::Json => {
            let text = String::from_utf8_lossy(out.body.as_deref().unwrap_or_default());
            let (spans, _) = json_string_spans(&text);
            let pointer = location.pointer.as_deref().unwrap_or("");
            let (s, e) = spans
                .get(pointer)
                .copied()
                .ok_or_else(|| internal(format!("no JSON string at {pointer}")))?;
            let value: String = serde_json::from_str(&text[s..e])
                .map_err(|_| internal(format!("no JSON string at {pointer}")))?;
            let replaced =
                serde_json::to_string(&value.replace(placeholder_text, secret)).expect("string");
            let body = format!("{}{replaced}{}", &text[..s], &text[e..]).into_bytes();
            let len = body.len();
            out.body = Some(body);
            set_header(&mut out, "content-length", len.to_string());
        }
        _ => {
            return Err(internal(format!(
                "cannot substitute into {}",
                serde_json::to_value(location.region)
                    .unwrap()
                    .as_str()
                    .unwrap()
            )))
        }
    }
    Ok(out)
}

fn location(region: Region, encoding: HitEncoding) -> Location {
    Location {
        region,
        encoding,
        name: None,
        key: None,
        pointer: None,
        part: None,
        scheme: None,
        index: None,
        hidden_by: None,
    }
}
fn add_hits(occurrences: &mut Vec<Occurrence>, text: &str, at: Location) {
    for hit in crate::detect::detect_all(text) {
        let mut at = at.clone();
        at.encoding = hit.encoding;
        occurrences.push(Occurrence::from_hit(hit, at));
    }
}
fn parse_query(s: &str) -> Vec<(String, String, bool)> {
    s.split('&')
        .filter(|s| !s.is_empty())
        .map(|p| {
            p.split_once('=').map_or_else(
                || (p.into(), String::new(), false),
                |(k, v)| (k.into(), v.into(), true),
            )
        })
        .collect()
}
fn safe_decode(s: &str) -> String {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s.as_bytes()[i] == b'%' {
            let Some(hex) = s.get(i + 1..i + 3) else {
                return s.into();
            };
            let Ok(byte) = u8::from_str_radix(hex, 16) else {
                return s.into();
            };
            out.push(byte);
            i += 3;
        } else {
            out.push(s.as_bytes()[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.into())
}
fn strip_basic(s: &str) -> Option<&str> {
    let i = s.find(char::is_whitespace)?;
    if s[..i].eq_ignore_ascii_case("basic") {
        Some(s[i..].trim_start())
    } else {
        None
    }
}
fn basic_decode(s: &str) -> String {
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
    let normalized: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "+/=_-".contains(*c))
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    let s = normalized.split('=').next().unwrap_or("");
    let s = if s.len() % 4 == 1 {
        &s[..s.len() - 1]
    } else {
        s
    };
    String::from_utf8_lossy(&engine.decode(s).unwrap_or_default()).into_owned()
}
fn set_header(req: &mut ProxyRequest, name: &str, value: String) {
    if let Some((_, v)) = req
        .headers
        .iter_mut()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
    {
        *v = value;
    } else {
        req.headers.push((name.into(), value));
    }
}
fn uri_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
fn replace_encoded(value: &str, placeholder: &str, replacement: &str) -> String {
    let mut decoded = Vec::new();
    let mut at = Vec::new();
    let mut i = 0;
    while i < value.len() {
        at.push(i);
        if value.as_bytes()[i] == b'%' {
            if let Some(hex) = value.get(i + 1..i + 3) {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    decoded.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        decoded.push(value.as_bytes()[i]);
        i += 1;
    }
    at.push(value.len());
    let mut out = String::new();
    let mut last = 0;
    let mut i = 0;
    while i + placeholder.len() <= decoded.len() {
        if decoded[i..].starts_with(placeholder.as_bytes()) {
            out.push_str(&value[last..at[i]]);
            out.push_str(replacement);
            last = at[i + placeholder.len()];
            i += placeholder.len();
        } else {
            i += 1;
        }
    }
    out.push_str(&value[last..]);
    out
}
fn json_strings(value: &serde_json::Value, pointer: &str, out: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::String(s) => out.push((pointer.into(), s.clone())),
        serde_json::Value::Array(a) => {
            for (i, v) in a.iter().enumerate() {
                json_strings(v, &format!("{pointer}/{i}"), out);
            }
        }
        serde_json::Value::Object(o) => {
            for (k, v) in o {
                json_strings(
                    v,
                    &format!("{pointer}/{}", k.replace('~', "~0").replace('/', "~1")),
                    out,
                );
            }
        }
        _ => {}
    }
}
type JsonSpans = std::collections::BTreeMap<String, (usize, usize)>;
struct Literal {
    span: (usize, usize),
    pointer: Option<String>,
}
fn json_string_spans(text: &str) -> (JsonSpans, Vec<Literal>) {
    struct Parser<'a> {
        text: &'a str,
        i: usize,
        spans: JsonSpans,
        literals: Vec<Literal>,
    }
    impl Parser<'_> {
        fn space(&mut self) {
            while self.i < self.text.len() && b" \t\n\r".contains(&self.text.as_bytes()[self.i]) {
                self.i += 1;
            }
        }
        fn string(&mut self) -> (usize, usize) {
            let start = self.i;
            self.i += 1;
            while self.i < self.text.len() && self.text.as_bytes()[self.i] != b'"' {
                self.i += if self.text.as_bytes()[self.i] == b'\\' {
                    2
                } else {
                    1
                };
            }
            self.i = (self.i + 1).min(self.text.len());
            (start, self.i)
        }
        fn value(&mut self, pointer: String) {
            self.space();
            let Some(&c) = self.text.as_bytes().get(self.i) else {
                return;
            };
            if c == b'"' {
                let span = self.string();
                self.spans.insert(pointer.clone(), span);
                self.literals.push(Literal {
                    span,
                    pointer: Some(pointer),
                });
                return;
            }
            if c == b'{' || c == b'[' {
                let object = c == b'{';
                let close = if object { b'}' } else { b']' };
                self.i += 1;
                self.space();
                if self.text.as_bytes().get(self.i) == Some(&close) {
                    self.i += 1;
                    return;
                }
                let mut n = 0;
                loop {
                    let key = if object {
                        self.space();
                        let span = self.string();
                        self.literals.push(Literal {
                            span,
                            pointer: None,
                        });
                        let key: String =
                            serde_json::from_str(&self.text[span.0..span.1]).unwrap_or_default();
                        self.space();
                        self.i += 1;
                        key.replace('~', "~0").replace('/', "~1")
                    } else {
                        n.to_string()
                    };
                    self.value(format!("{pointer}/{key}"));
                    self.space();
                    if self.i >= self.text.len() {
                        return;
                    }
                    let c = self.text.as_bytes()[self.i];
                    self.i += 1;
                    if c == close {
                        return;
                    }
                    n += 1;
                }
            }
            while self.i < self.text.len() && !b",]} \t\n\r".contains(&self.text.as_bytes()[self.i])
            {
                self.i += 1;
            }
        }
    }
    let mut p = Parser {
        text,
        i: 0,
        spans: Default::default(),
        literals: vec![],
    };
    p.value(String::new());
    (p.spans, p.literals)
}
fn locate_request(req: &ProxyRequest) -> LocateResult {
    let scheme_re = regex::Regex::new(r"([A-Za-z][A-Za-z0-9-]*)$").expect("scheme");
    let mut occurrences = Vec::new();
    add_hits(
        &mut occurrences,
        &req.path,
        location(Region::Path, HitEncoding::Raw),
    );
    for (k, v, _) in parse_query(&req.query) {
        let key = safe_decode(&k);
        let mut at = location(Region::QueryKey, HitEncoding::Raw);
        at.key = Some(key.clone());
        add_hits(&mut occurrences, &key, at);
        let mut at = location(Region::Query, HitEncoding::Raw);
        at.key = Some(key);
        add_hits(&mut occurrences, &v, at);
    }
    for (index, (name, value)) in req.headers.iter().enumerate() {
        let lower = name.to_lowercase();
        let mut at = location(Region::HeaderName, HitEncoding::Raw);
        at.name = Some(lower.clone());
        at.index = Some(index);
        add_hits(&mut occurrences, name, at);
        let mut handled_as_basic = false;
        if lower == "authorization" {
            if let Some(b64) = strip_basic(value) {
                let decoded = basic_decode(b64.trim());
                if decoded.contains(crate::placeholder::PREFIX) {
                    let (user, pass) = decoded.split_once(':').unwrap_or((&decoded, ""));
                    for (part, v) in [("user", user), ("pass", pass)] {
                        for parsed in crate::placeholder::find_all(v) {
                            let mut at = location(Region::Basic, HitEncoding::Raw);
                            at.part = Some(part.into());
                            at.index = Some(index);
                            occurrences.push(Occurrence {
                                text: parsed.text.clone(),
                                parsed,
                                location: at,
                            });
                        }
                    }
                    handled_as_basic = true;
                }
            }
        }
        for hit in crate::detect::detect_all(value) {
            if handled_as_basic && hit.encoding == HitEncoding::Base64 {
                continue;
            }
            let mut at = location(Region::Header, hit.encoding);
            at.name = Some(lower.clone());
            at.index = Some(index);
            if hit.encoding == HitEncoding::Raw {
                let before = value[..hit.parsed.offset].trim_end();
                let re = &scheme_re;
                at.scheme = re.captures(before).map(|c| c[1].into());
            }
            occurrences.push(Occurrence::from_hit(hit, at));
        }
    }
    if let Some(body) = req.body.as_ref().filter(|b| !b.is_empty()) {
        if body.len() > MAX_BUFFERED_BODY {
            return LocateResult {
                occurrences,
                unscannable: Some(UNSCANNABLE_TOO_LARGE.into()),
            };
        }
        let text = String::from_utf8_lossy(body);
        let ct = get_header(req, "content-type")
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_lowercase();
        let first = occurrences.len();
        let mut structured = false;
        if ct == "application/json" {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                structured = true;
                let mut strings = Vec::new();
                json_strings(&parsed, "", &mut strings);
                let exposed: std::collections::HashSet<_> =
                    strings.iter().map(|(p, _)| p.clone()).collect();
                for (pointer, value) in strings {
                    let mut at = location(Region::Json, HitEncoding::Raw);
                    at.pointer = Some(pointer);
                    add_hits(&mut occurrences, &value, at);
                }
                let (spans, literals) = json_string_spans(&text);
                for literal in literals {
                    let (s, e) = literal.span;
                    if e - s - 2 < crate::placeholder::PH_MIN_LEN {
                        continue;
                    }
                    let live = literal.pointer.as_ref().is_some_and(|p| {
                        exposed.contains(p) && spans.get(p).is_some_and(|span| span.0 == s)
                    });
                    if live {
                        continue;
                    }
                    let mut at = location(Region::Body, HitEncoding::Raw);
                    at.hidden_by = Some("the body parser".into());
                    add_hits(&mut occurrences, &text[s + 1..e - 1], at);
                }
            }
        } else if ct == "application/x-www-form-urlencoded" {
            structured = true;
            for (k, v, _) in parse_query(&text) {
                let key = safe_decode(&k);
                let mut at = location(Region::FormKey, HitEncoding::Raw);
                at.key = Some(key.clone());
                add_hits(&mut occurrences, &key, at);
                let mut at = location(Region::Form, HitEncoding::Raw);
                at.key = Some(key);
                add_hits(&mut occurrences, &crate::detect::percent_decode(&v), at);
            }
        }
        if structured {
            let accounted: std::collections::HashSet<_> = occurrences[first..]
                .iter()
                .map(|o| o.parsed.nonce.clone())
                .collect();
            let mut reported = std::collections::HashSet::new();
            for hit in crate::detect::detect_all(&text) {
                if accounted.contains(&hit.parsed.nonce)
                    || !reported.insert(hit.parsed.nonce.clone())
                {
                    continue;
                }
                let mut at = location(Region::Body, hit.encoding);
                at.hidden_by = Some("the body parser".into());
                occurrences.push(Occurrence::from_hit(hit, at));
            }
        } else {
            add_hits(
                &mut occurrences,
                &text,
                location(Region::Body, HitEncoding::Raw),
            );
        }
    }
    LocateResult {
        occurrences,
        unscannable: None,
    }
}
