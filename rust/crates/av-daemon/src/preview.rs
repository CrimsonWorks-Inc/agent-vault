//! F13: a held request as a human may safely read it. Ports
//! `approvalPreview` and `previewPart` in `src/daemon/pipeline.js`.

use av_core::request_view::{query_params, QuerySeparator};
use av_core::scrub::{ScrubEntry, Scrubber, ScrubberOptions};
use av_core::secret::SecretString;
use av_core::substitute::Region;
use serde_json::Value;

use crate::pipeline::{HOP_BY_HOP, PREVIEW_MAX};
use crate::util::{js_stringify, obj};

/// One substitution as the preview labels it.
#[derive(Debug, Clone)]
pub struct PreviewSub {
    /// The placeholder text.
    pub text: String,
    /// `slug.field`.
    pub label: String,
    /// `describeLocation(location)`.
    pub location: String,
    /// `previewPart(region)`.
    pub part: &'static str,
}

/// The request a preview is built from: the folded request as the agent
/// sent it, before substitution.
pub struct PreviewRequest<'a> {
    /// Query, without `?`.
    pub query: &'a str,
    /// Headers in order.
    pub headers: &'a [(String, String)],
    /// Body.
    pub body: Option<&'a [u8]>,
}

/// The decided method, host and path.
pub struct PreviewDecision<'a> {
    /// Method.
    pub method: &'a str,
    /// Host.
    pub host: &'a str,
    /// Path.
    pub path: &'a str,
}

/// `previewPart(region)`.
pub fn preview_part(region: Region) -> &'static str {
    match region {
        Region::Header | Region::HeaderName | Region::Basic => "headers",
        Region::Query | Region::QueryKey => "query",
        Region::Path => "path",
        _ => "body",
    }
}

const PREVIEW_OMITTED: &[&str] = &["authorization", "proxy-authorization", "cookie", "x-api-key", "x-goog-api-key"];

/// `text.slice(0, n)` in UTF-16 units.
fn slice16(text: &str, n: usize) -> String {
    let mut units = 0;
    let mut out = String::new();
    for c in text.chars() {
        if units + c.len_utf16() > n {
            break;
        }
        units += c.len_utf16();
        out.push(c);
    }
    out
}

fn len16(text: &str) -> usize {
    text.encode_utf16().count()
}

fn cap(text: String, n: usize) -> String {
    if len16(&text) > n {
        format!("{}…", slice16(&text, n))
    } else {
        text
    }
}

/// Build the preview. `scrub` is the error scrubber's text view.
pub fn approval_preview(
    req: &PreviewRequest<'_>,
    decision: &PreviewDecision<'_>,
    subs: &[PreviewSub],
    scrub: &mut dyn FnMut(&str) -> String,
) -> Value {
    let session_re = av_core::jsre::compile(r"avs1\.[0-9a-z]{12}\.[A-Za-z0-9_-]{20,}").expect("token pattern");
    let mut clean = |value: &str, part: &str| -> String {
        let mut text = value.to_string();
        let hits = av_core::detect::detect_all(&text);
        let ordered = subs.iter().filter(|s| s.part == part).chain(subs.iter().filter(|s| s.part != part));
        for s in ordered {
            if !s.text.is_empty() {
                text = text.replace(&s.text, &format!("«{} @ {}»", s.label, s.location));
            }
        }
        if !hits.is_empty() {
            let entries: Vec<ScrubEntry> = hits
                .iter()
                .map(|h| ScrubEntry {
                    secret: SecretString::from(h.parsed.text.clone()),
                    label: "placeholder".into(),
                    replacement: Some("«placeholder»".into()),
                    always: true,
                })
                .collect();
            text = match Scrubber::new(&entries, &ScrubberOptions::default()) {
                Ok(mut sc) => {
                    let r = sc.scrub(&text);
                    if r.unscannable {
                        "«placeholder»".into()
                    } else {
                        r.text
                    }
                }
                Err(_) => "«placeholder»".into(),
            };
        }
        text = session_re.replace_all(&text, "«session token»").into_owned();
        scrub(&text)
    };

    let raw = req.body.unwrap_or(&[]);
    let ty = req
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty());
    let mut kind = if raw.is_empty() { "none" } else { "text" };
    let mut text: Option<String> = (!raw.is_empty()).then(|| String::from_utf8_lossy(raw).into_owned());
    if let Some(t) = &text {
        let controls = t.chars().any(|c| matches!(c as u32, 0..=8 | 0x0b | 0x0c | 0x0e..=0x1f));
        if t.as_bytes() != raw || controls {
            kind = "binary";
            text = None;
        }
    }
    let json_re = av_core::jsre::compile(r"(?i)^application/(?:json|[^/;]+\+json)\s*(?:;|$)").expect("json type");
    let form_re = av_core::jsre::compile(r"(?i)^application/x-www-form-urlencoded\s*(?:;|$)").expect("form type");
    let ty_s = ty.clone().unwrap_or_default();
    if text.is_some() && json_re.is_match(&ty_s) {
        kind = "json";
        if let Ok(v) = av_core::payload::parse_strict_json(text.as_deref().unwrap_or("")) {
            text = Some(crate::util::js_pretty(&v));
        }
    } else if text.is_some() && form_re.is_match(&ty_s) {
        kind = "form";
    }

    let full = text.as_deref().map(|t| clean(t, "body"));
    let mut shown: Option<String> = full.as_deref().map(|f| {
        let b = f.as_bytes();
        String::from_utf8_lossy(&b[..b.len().min(4096)]).into_owned()
    });
    let mut headers: Vec<Value> = Vec::new();
    for (name, value) in req.headers {
        let lower = name.to_lowercase();
        if PREVIEW_OMITTED.contains(&lower.as_str()) || HOP_BY_HOP.contains(&lower.as_str()) || lower.starts_with("av-") {
            continue;
        }
        if headers.len() == 32 {
            break;
        }
        let n = clean(name, "headers");
        let v = cap(clean(value, "headers"), 256);
        headers.push(Value::Array(vec![n.into(), v.into()]));
    }
    let query: Vec<Value> = query_params(req.query, QuerySeparator::AmpersandOrSemicolon)
        .into_iter()
        .take(64)
        .map(|p| {
            Value::Array(vec![
                cap(clean(&p.name, "query"), 256).into(),
                cap(clean(&p.value, "query"), 256).into(),
            ])
        })
        .collect();
    let method = clean(decision.method, "path");
    let host = clean(decision.host, "path");
    let path = cap(clean(decision.path, "path"), 1024);
    let content_type = ty.as_deref().map(|t| cap(clean(t, "headers"), 256));
    let truncated = full.is_some() && full != shown;
    let placeholders: Vec<Value> = subs
        .iter()
        .map(|s| obj([("label", s.label.clone().into()), ("location", s.location.clone().into())]))
        .collect();

    let mut p = Preview {
        method,
        host,
        path,
        query,
        headers,
        content_type,
        shown: shown.take(),
        bytes: raw.len(),
        truncated,
        kind,
        placeholders,
    };
    while js_stringify(&p.value()).len() > PREVIEW_MAX {
        if let Some(t) = p.shown.as_ref().filter(|t| !t.is_empty()) {
            let n = len16(t).saturating_sub(256);
            p.shown = Some(slice16(t, n));
            p.truncated = true;
        } else if !p.headers.is_empty() {
            p.headers.pop();
        } else if !p.query.is_empty() {
            p.query.pop();
        } else if !p.placeholders.is_empty() {
            p.placeholders.pop();
        } else {
            p.path = cap(p.path.clone(), 256);
            break;
        }
    }
    p.value()
}

struct Preview {
    method: String,
    host: String,
    path: String,
    query: Vec<Value>,
    headers: Vec<Value>,
    content_type: Option<String>,
    shown: Option<String>,
    bytes: usize,
    truncated: bool,
    kind: &'static str,
    placeholders: Vec<Value>,
}

impl Preview {
    fn value(&self) -> Value {
        obj([
            ("method", self.method.clone().into()),
            ("host", self.host.clone().into()),
            ("path", self.path.clone().into()),
            ("query", Value::Array(self.query.clone())),
            ("headers", Value::Array(self.headers.clone())),
            ("content_type", self.content_type.clone().map_or(Value::Null, Value::from)),
            (
                "body",
                obj([
                    ("text", self.shown.clone().map_or(Value::Null, Value::from)),
                    ("bytes", Value::from(self.bytes as u64)),
                    ("shown_bytes", Value::from(self.shown.as_ref().map_or(0, |s| s.len()) as u64)),
                    ("truncated", Value::Bool(self.truncated)),
                    ("kind", Value::from(self.kind)),
                ]),
            ),
            ("placeholders", Value::Array(self.placeholders.clone())),
            ("untrusted", Value::Bool(true)),
        ])
    }
}
