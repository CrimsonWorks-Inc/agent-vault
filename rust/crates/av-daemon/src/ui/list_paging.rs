//! Paged, searchable list answers for the UI (U3): the paging request,
//! sealed cursors, and the list specs. Ports `src/ui/list-paging.js`.

use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::util::{b64url, b64url_lenient, ct_eq, js_number, js_stringify};

/// Page size when none is asked for. Ports `LIMIT_DEFAULT`.
pub const LIMIT_DEFAULT: usize = 25;
/// Largest page. Ports `LIMIT_MAX`.
pub const LIMIT_MAX: usize = 200;
/// Cursor MAC length. Ports `MAC_BYTES`.
pub const MAC_BYTES: usize = 16;
/// Longest cursor accepted. Ports `CURSOR_MAX_CHARS`.
pub const CURSOR_MAX_CHARS: usize = 2048;

/// A paging refusal (status 400). Ports `class PagingError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct PagingError {
    /// `AV_BAD_LIMIT` or `AV_BAD_CURSOR`.
    pub code: &'static str,
    /// What was wrong.
    pub message: String,
}

impl PagingError {
    /// Ports the constructor.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        PagingError { code, message: message.into() }
    }
    /// Always 400.
    pub fn status(&self) -> u16 {
        400
    }
    /// `{ code, detail }`.
    pub fn problem(&self) -> Value {
        json!({"code": self.code, "detail": self.message})
    }
}

fn bad_limit(why: &str) -> PagingError {
    PagingError::new("AV_BAD_LIMIT", format!("limit {why}; give a whole number from 1 to {LIMIT_MAX}"))
}

fn bad_cursor(why: &str) -> PagingError {
    PagingError::new("AV_BAD_CURSOR", format!("that cursor {why}; start the list again from the first page"))
}

/// A paged request. Ports the result of `pagingOf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paging {
    /// Page size.
    pub limit: usize,
    /// The cursor, if any.
    pub cursor: Option<String>,
    /// The search, trimmed and lower-cased.
    pub q: String,
}

/// Ports `pagingOf(params)`.
pub fn paging_of(params: &[(String, String)]) -> Result<Option<Paging>, PagingError> {
    let all = |k: &str| params.iter().filter(|(n, _)| n == k).map(|(_, v)| v.clone()).collect::<Vec<_>>();
    let paged = all("paged");
    if paged.is_empty() {
        if params.iter().any(|(n, _)| n == "cursor") {
            return Err(bad_cursor("was sent without paged=1"));
        }
        return Ok(None);
    }
    if paged.len() != 1 || paged[0] != "1" {
        return Err(PagingError::new("AV_BAD_LIMIT", "paged is 1 or absent"));
    }
    let limits = all("limit");
    if limits.len() > 1 {
        return Err(bad_limit("was given more than once"));
    }
    let mut limit = LIMIT_DEFAULT;
    if let Some(l) = limits.first() {
        let plain = !l.is_empty() && l.len() <= 3 && !l.starts_with('0') && l.bytes().all(|b| b.is_ascii_digit());
        if !plain {
            return Err(bad_limit("is not a whole number written plainly"));
        }
        limit = l.parse().unwrap_or(LIMIT_DEFAULT);
        if limit > LIMIT_MAX {
            return Err(bad_limit(&format!("is more than {LIMIT_MAX}")));
        }
    }
    let cursors = all("cursor");
    if cursors.len() > 1 {
        return Err(bad_cursor("was given more than once"));
    }
    let qs = all("q");
    if qs.len() > 1 {
        return Err(PagingError::new("AV_BAD_LIMIT", "q was given more than once"));
    }
    Ok(Some(Paging {
        limit,
        cursor: cursors.into_iter().next(),
        q: crate::pipeline::js_trim(qs.first().map(String::as_str).unwrap_or("")).to_lowercase(),
    }))
}

/// An opened cursor: its direction and the sort key it points at.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenedCursor {
    /// `next` or `prev`.
    pub dir: String,
    /// The key.
    pub key: Vec<Value>,
}

/// Cursors sealed with a key that lives only in this process. Ports
/// `class Cursors`.
pub struct Cursors {
    key: av_core::secret::Key32,
}

fn is_key_part(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.encode_utf16().count() <= 512,
        Value::Number(n) => n.as_f64().is_some_and(f64::is_finite),
        _ => false,
    }
}

fn js_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// `digestOf(filters)`.
fn digest_of(filters: &Value) -> String {
    let mut keys: Vec<&String> = filters.as_object().map(|m| m.keys().collect()).unwrap_or_default();
    keys.sort_by(|a, b| js_cmp(a, b));
    let flat: Vec<Value> = keys.iter().map(|k| json!([k, filters[k.as_str()].clone()])).collect();
    let d = Sha256::digest(js_stringify(&Value::Array(flat)).as_bytes());
    b64url(&d)[..22].to_string()
}

impl Cursors {
    /// A fresh random key.
    pub fn new() -> Self {
        Cursors { key: av_core::secret::Key32::from_bytes(crate::util::random_bytes::<32>()) }
    }

    /// A given key (tests).
    pub fn with_key(key: av_core::secret::Key32) -> Self {
        Cursors { key }
    }

    fn mac(&self, body: &[u8]) -> Vec<u8> {
        let mut m = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.key.expose()).expect("hmac key");
        m.update(b"agent-vault ui cursor\n");
        m.update(body);
        m.finalize().into_bytes()[..MAC_BYTES].to_vec()
    }

    /// Ports `seal(list, filters, dir, key)`.
    pub fn seal(&self, list: &str, filters: &Value, dir: &str, key: &[Value]) -> String {
        let body = js_stringify(&json!({"v": 1, "l": list, "f": digest_of(filters), "d": dir, "k": key}));
        let mut out = self.mac(body.as_bytes());
        out.extend_from_slice(body.as_bytes());
        b64url(&out)
    }

    /// Ports `open(text, list, filters)`.
    pub fn open(&self, text: &str, list: &str, filters: &Value) -> Result<OpenedCursor, PagingError> {
        let made = || bad_cursor("is not one this server made");
        if text.encode_utf16().count() > CURSOR_MAX_CHARS || text.is_empty() || !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            return Err(made());
        }
        let raw = b64url_lenient(text);
        if raw.len() <= MAC_BYTES {
            return Err(made());
        }
        let (mac, body) = raw.split_at(MAC_BYTES);
        if !ct_eq(mac, &self.mac(body)) {
            return Err(bad_cursor("is not one this server made, or has expired"));
        }
        let c: Value = serde_json::from_slice(body).map_err(|_| made())?;
        if !c.is_object() || c["v"] != json!(1) {
            return Err(made());
        }
        if c["l"].as_str() != Some(list) {
            return Err(bad_cursor("belongs to a different list"));
        }
        if c["f"].as_str() != Some(digest_of(filters).as_str()) {
            return Err(bad_cursor("was made for a different search or filter"));
        }
        let dir = c["d"].as_str().filter(|d| *d == "next" || *d == "prev").ok_or_else(made)?.to_string();
        let key = c["k"].as_array().filter(|k| !k.is_empty() && k.len() <= 4 && k.iter().all(is_key_part)).cloned().ok_or_else(made)?;
        Ok(OpenedCursor { dir, key })
    }
}

impl Default for Cursors {
    fn default() -> Self {
        Self::new()
    }
}

/// One paged list. Ports the entries of `LISTS`.
pub struct ListSpec {
    /// The cursor's list name.
    pub name: &'static str,
    /// The sort key of an item at an index.
    pub key: fn(&Value, usize) -> Vec<Value>,
    /// Sort direction per key part.
    pub dirs: &'static [i8],
    /// What `q` searches.
    pub fields: fn(&Value) -> Vec<Value>,
}

fn g(v: &Value, k: &str) -> Value {
    v.get(k).cloned().unwrap_or(Value::Null)
}

fn slugs_of(v: &Value) -> Value {
    match v.get("creds") {
        Some(Value::Array(a)) => Value::Array(a.iter().map(|c| g(c, "slug")).collect()),
        _ => Value::Array(Vec::new()),
    }
}

static LISTS: [ListSpec; 9] = [
    ListSpec { name: "credentials", key: |c, _| vec![g(c, "slug"), g(c, "id")], dirs: &[1, 1], fields: |c| vec![g(c, "slug"), g(c, "id"), g(c, "kind"), g(c, "label")] },
    ListSpec { name: "sessions", key: |s, _| vec![g(s, "created_at"), g(s, "id")], dirs: &[-1, -1], fields: |s| vec![g(s, "id"), g(s, "label"), g(s, "state"), slugs_of(s)] },
    ListSpec { name: "pending", key: |p, _| vec![g(p, "created_at"), g(p, "kind"), g(p, "id")], dirs: &[-1, 1, -1], fields: |p| vec![g(p, "id"), g(p, "kind"), g(p, "headline"), g(p, "grant_id")] },
    ListSpec { name: "templates", key: |t, _| vec![g(t, "name")], dirs: &[1], fields: |t| vec![g(t, "name"), g(t, "creds")] },
    ListSpec { name: "listeners", key: |l, _| vec![g(l, "id"), g(l, "address")], dirs: &[1, 1], fields: |l| vec![g(l, "id"), g(l, "address"), g(l, "state"), g(l, "surfaces")] },
    ListSpec { name: "tripwires", key: |_, i| vec![Value::from(i as u64)], dirs: &[1], fields: |r| vec![g(r, "id"), g(r, "action"), g(r, "codes"), g(r, "rule_prefix")] },
    ListSpec { name: "sessions/detail", key: |x, _| vec![g(x, "cred"), g(x, "grant_id")], dirs: &[1, 1], fields: |x| vec![g(x, "grant_id"), g(x, "cred"), g(x, "state")] },
    ListSpec { name: "report/access:sessions", key: |s, _| vec![g(s, "last_seen_at"), g(s, "id")], dirs: &[-1, 1], fields: |s| vec![g(s, "id"), g(s, "label"), g(s, "state"), g(s, "creds")] },
    ListSpec { name: "report/access:credentials", key: |c, _| vec![g(c, "slug")], dirs: &[1], fields: |c| vec![g(c, "slug")] },
];

/// The spec for a JS `LISTS` key (`credentials`, `sessions`, `pending`,
/// `templates`, `listeners`, `tripwireRules`, `detailGrants`,
/// `reportSessions`, `reportCredentials`).
pub fn list_spec(name: &str) -> Option<&'static ListSpec> {
    let i = match name {
        "credentials" => 0,
        "sessions" => 1,
        "pending" => 2,
        "templates" => 3,
        "listeners" => 4,
        "tripwireRules" => 5,
        "detailGrants" => 6,
        "reportSessions" => 7,
        "reportCredentials" => 8,
        _ => return None,
    };
    Some(&LISTS[i])
}

/// Ports `AUDIT_FIELDS(r)`.
pub fn audit_fields(r: &Value) -> Vec<Value> {
    ["kind", "seq", "session_id", "request_id", "grant_id", "approval_id", "credential_slug", "reason_code", "code", "rule", "rule_id", "actor"]
        .iter()
        .map(|k| g(r, k))
        .collect()
}

/// Ports `matches(item, fields, q)`.
pub fn matches(item: &Value, fields: fn(&Value) -> Vec<Value>, q: &str) -> bool {
    if q.is_empty() {
        return true;
    }
    let empty = json!({});
    let item = if item.is_null() { &empty } else { item };
    for v in fields(item) {
        let xs = match v {
            Value::Array(a) => a,
            other => vec![other],
        };
        for x in xs {
            let s = match &x {
                Value::String(s) => s.clone(),
                Value::Number(n) => js_number(n),
                _ => continue,
            };
            if s.to_lowercase().contains(q) {
                return true;
            }
        }
    }
    false
}

/// Ports `compareKeys(a, b, dirs)`.
pub fn compare_keys(a: &[Value], b: &[Value], dirs: &[i8]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    for (i, d) in dirs.iter().enumerate() {
        let x = a.get(i).filter(|v| !v.is_null()).cloned().unwrap_or(Value::from(""));
        let y = b.get(i).filter(|v| !v.is_null()).cloned().unwrap_or(Value::from(""));
        let c = match (&x, &y) {
            (Value::Number(p), Value::Number(q)) => p.as_f64().partial_cmp(&q.as_f64()).unwrap_or(Ordering::Equal),
            _ => js_cmp(&crate::util::js_string(&x), &crate::util::js_string(&y)),
        };
        if c != Ordering::Equal {
            return if *d < 0 { c.reverse() } else { c };
        }
    }
    Ordering::Equal
}

/// Ports `pageList(items, spec, paging, filters, cursors)`.
pub fn page_list(items: &[Value], spec: &ListSpec, paging: &Paging, filters: &Value, cursors: &Cursors) -> Result<Value, PagingError> {
    let empty = json!({});
    let mut sorted: Vec<(Value, Vec<Value>)> = items
        .iter()
        .enumerate()
        .map(|(i, it)| {
            let base = if it.is_null() { &empty } else { it };
            let k = (spec.key)(base, i).into_iter().map(|p| if is_key_part(&p) { p } else { Value::Null }).collect();
            (it.clone(), k)
        })
        .filter(|(it, _)| matches(it, spec.fields, &paging.q))
        .collect();
    sorted.sort_by(|a, b| compare_keys(&a.1, &b.1, spec.dirs));
    let mut f = filters.as_object().cloned().unwrap_or_default();
    f.insert("q".into(), Value::from(paging.q.clone()));
    let f = Value::Object(f);
    let mut start = 0usize;
    if let Some(c) = &paging.cursor {
        let c = cursors.open(c, spec.name, &f)?;
        if c.dir == "next" {
            start = sorted.iter().position(|e| compare_keys(&e.1, &c.key, spec.dirs).is_gt()).unwrap_or(sorted.len());
        } else {
            let end = sorted.iter().position(|e| compare_keys(&e.1, &c.key, spec.dirs).is_ge()).unwrap_or(sorted.len());
            start = end.saturating_sub(paging.limit);
        }
    }
    let page: Vec<&(Value, Vec<Value>)> = sorted.iter().skip(start).take(paging.limit).collect();
    let next = (!page.is_empty() && start + paging.limit < sorted.len()).then(|| cursors.seal(spec.name, &f, "next", &page[page.len() - 1].1));
    let prev = (!page.is_empty() && start > 0).then(|| cursors.seal(spec.name, &f, "prev", &page[0].1));
    Ok(json!({
        "items": page.iter().map(|e| e.0.clone()).collect::<Vec<_>>(),
        "next_cursor": next, "prev_cursor": prev, "total": sorted.len(),
    }))
}

/// Ports `pageAnswer(shown, spec, paging, { within, drop, filters }, cursors)`.
pub fn page_answer(shown: &Value, spec: &ListSpec, paging: &Paging, within: Option<&str>, drop: &[&str], filters: &Value, cursors: &Cursors) -> Result<Value, PagingError> {
    let Some(within) = within else {
        let items = shown.as_array().cloned().unwrap_or_default();
        return page_list(&items, spec, paging, filters, cursors);
    };
    let mut beside = Map::new();
    let mut inner = Vec::new();
    if let Value::Object(m) = shown {
        for (k, v) in m {
            if k != within && !drop.contains(&k.as_str()) {
                beside.insert(k.clone(), v.clone());
            }
        }
        inner = m.get(within).and_then(Value::as_array).cloned().unwrap_or_default();
    }
    let page = page_list(&inner, spec, paging, filters, cursors)?;
    if let Value::Object(p) = page {
        for (k, v) in p {
            beside.insert(k, v);
        }
    }
    Ok(Value::Object(beside))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(q: &str) -> Vec<(String, String)> {
        crate::util::search_params(q)
    }

    #[test]
    fn walks_a_list_both_ways_and_refuses_foreign_cursors() {
        let items: Vec<Value> = (0..7).map(|i| json!({"slug": format!("c{i}"), "id": format!("cr_{i}")})).collect();
        let c = Cursors::new();
        let spec = list_spec("credentials").unwrap();
        let p = paging_of(&params("paged=1&limit=3")).unwrap().unwrap();
        let first = page_list(&items, spec, &p, &json!({}), &c).unwrap();
        assert_eq!(first["items"].as_array().unwrap().len(), 3);
        assert_eq!(first["total"], 7);
        assert!(first["prev_cursor"].is_null());
        let next = first["next_cursor"].as_str().unwrap().to_string();
        let p2 = Paging { cursor: Some(next), ..p.clone() };
        let second = page_list(&items, spec, &p2, &json!({}), &c).unwrap();
        assert_eq!(second["items"][0]["slug"], "c3");
        let prev = second["prev_cursor"].as_str().unwrap().to_string();
        let back = page_list(&items, spec, &Paging { cursor: Some(prev.clone()), ..p.clone() }, &json!({}), &c).unwrap();
        assert_eq!(back["items"][0]["slug"], "c0");
        // Another process's key, another list, another search.
        assert_eq!(page_list(&items, spec, &Paging { cursor: Some(prev.clone()), ..p.clone() }, &json!({}), &Cursors::new()).unwrap_err().code, "AV_BAD_CURSOR");
        assert!(page_list(&items, list_spec("templates").unwrap(), &Paging { cursor: Some(prev.clone()), ..p.clone() }, &json!({}), &c).is_err());
        assert!(page_list(&items, spec, &Paging { cursor: Some(prev), q: "c1".into(), ..p }, &json!({}), &c).is_err());
    }

    #[test]
    fn paging_params_are_strict() {
        assert!(paging_of(&params("")).unwrap().is_none());
        assert_eq!(paging_of(&params("cursor=x")).unwrap_err().code, "AV_BAD_CURSOR");
        assert_eq!(paging_of(&params("paged=2")).unwrap_err().code, "AV_BAD_LIMIT");
        assert!(paging_of(&params("paged=1&limit=01")).is_err());
        assert!(paging_of(&params("paged=1&limit=201")).is_err());
        assert!(paging_of(&params("paged=1&limit=1&limit=2")).is_err());
        assert_eq!(paging_of(&params("paged=1&q=%20ABC%20")).unwrap().unwrap().q, "abc");
    }
}
