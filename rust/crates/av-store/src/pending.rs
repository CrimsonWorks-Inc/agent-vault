//! Ports `src/pending.js`: everything waiting for a human, and how to
//! describe it, once, for the CLI and the web UI alike.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A kind of decision. Ports the `kind` values of `SOURCES` in
/// `src/pending.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PendingKind {
    /// A held request (one call).
    Request,
    /// A session request (hours of access).
    Session,
}

/// Where one kind of decision is listed. Ports the entries of `SOURCES` in
/// `src/pending.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingSource {
    /// The kind.
    pub kind: PendingKind,
    /// The control route that lists it.
    pub path: &'static str,
}

/// Where to look. Ports `SOURCES` in `src/pending.js`.
pub const SOURCES: [PendingSource; 2] = [
    PendingSource {
        kind: PendingKind::Request,
        path: "/v1/approvals",
    },
    PendingSource {
        kind: PendingKind::Session,
        path: "/v1/session-requests",
    },
];

/// The dimensions a human may narrow on a session request. Ports the
/// `narrowable` list in `describe` in `src/pending.js`.
pub const SESSION_NARROWABLE: [&str; 14] = [
    "methods",
    "paths",
    "budget",
    "uses",
    "ttl_minutes",
    "rate",
    "max_concurrent",
    "quota",
    "routes",
    "payload",
    "redirects",
    "spend_tokens",
    "spend_usd",
    "grant_ttl_minutes",
];

/// What only the owner can add to a session request. Ports the
/// `owner_settable` list in `describe` in `src/pending.js`.
pub const SESSION_OWNER_SETTABLE: [&str; 2] = ["approval", "infinite"];

/// The caution shown on a session request. Ports the `caution` literal in
/// `describe` in `src/pending.js`.
pub const SESSION_CAUTION: &str = "This grants hours of access, not one call.";

/// The route that answers a decision. Ports `decide` in `describe` in
/// `src/pending.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecideRoute {
    /// Control route.
    pub path: String,
    /// The body key the id goes under.
    #[serde(rename = "idField")]
    pub id_field: String,
}

/// One decision, in the terms a human needs to make it. Session items carry
/// `proposal`; request items carry `grant_id` and `preview` (both possibly
/// null, and then serialized as null). Ports the objects `describe` returns
/// in `src/pending.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingItem {
    /// Id.
    pub id: String,
    /// Kind.
    pub kind: PendingKind,
    /// The summary.
    pub headline: Value,
    /// Whatever the agent typed. Shown, never believed.
    pub claim: Option<String>,
    /// ISO time.
    pub created_at: Value,
    /// A warning, for sessions.
    pub caution: Option<String>,
    /// Narrowable dimensions.
    pub narrowable: Vec<String>,
    /// Owner-only additions.
    pub owner_settable: Vec<String>,
    /// The agent's proposal (session items).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<Value>,
    /// The grant a held request would spend (request items; null allowed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<Option<String>>,
    /// Scrubbed preview (request items; null allowed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<Value>,
    /// Where to answer.
    pub decide: DecideRoute,
}

/// One decision from a raw route row. Ports `describe` in `src/pending.js`.
pub fn describe(kind: PendingKind, raw: &Value) -> PendingItem {
    let get = |k: &str| raw.get(k).cloned().unwrap_or(Value::Null);
    let text = |k: &str| match raw.get(k) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(v) if truthy(v) => Some(js_string(v)),
        _ => None,
    };
    match kind {
        PendingKind::Session => PendingItem {
            id: raw.get("id").map(js_string).unwrap_or_default(),
            kind,
            headline: get("summary"),
            // Whatever the agent typed. Shown, never believed.
            claim: text("agent_reason_untrusted"),
            created_at: get("created_at"),
            caution: Some(SESSION_CAUTION.to_string()),
            narrowable: SESSION_NARROWABLE.iter().map(|s| s.to_string()).collect(),
            owner_settable: SESSION_OWNER_SETTABLE.iter().map(|s| s.to_string()).collect(),
            proposal: Some(match raw.get("proposal") {
                Some(v) if truthy(v) => v.clone(),
                _ => Value::Object(Map::new()),
            }),
            grant_id: None,
            preview: None,
            decide: DecideRoute {
                path: "/v1/session-requests/decide".into(),
                id_field: "id".into(),
            },
        },
        PendingKind::Request => PendingItem {
            id: raw.get("id").map(js_string).unwrap_or_default(),
            kind,
            headline: get("summary"),
            claim: text("reason"),
            created_at: get("created_at"),
            caution: None,
            narrowable: Vec::new(),
            owner_settable: Vec::new(),
            proposal: None,
            grant_id: Some(text("grant_id")),
            preview: Some(get("preview")),
            decide: DecideRoute {
                path: "/v1/approvals".into(),
                id_field: "id".into(),
            },
        },
    }
}

/// JS truthiness for a JSON value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `String(v)` for a JSON value, as the JS template literals print it.
fn js_string(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) => i.to_string(),
            (_, Some(u), _) => u.to_string(),
            (_, _, Some(f)) if f.fract() == 0.0 && f.abs() < 1e21 => format!("{f:.0}"),
            (_, _, Some(f)) => f.to_string(),
            _ => n.to_string(),
        },
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(|x| match x {
            Value::Null => String::new(),
            other => js_string(other),
        }).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

/// Everything waiting, oldest first. `get(path)` is the caller's transport;
/// a source it cannot read (`None`) is treated as empty. Sync: an async
/// caller fetches each of [`SOURCES`] itself and uses [`collect_pending`].
/// Ports `fetchPending` in `src/pending.js`.
pub fn fetch_pending<F>(get: F) -> Vec<PendingItem>
where
    F: FnMut(&str) -> Option<Vec<Value>>,
{
    let mut get = get;
    let rows = SOURCES
        .iter()
        .map(|source| (source.kind, get(source.path).unwrap_or_default()))
        .collect();
    collect_pending(rows)
}

/// Describe already-fetched rows per kind and sort oldest first. No JS
/// function: the body of `fetchPending` in `src/pending.js` without the
/// transport.
pub fn collect_pending(rows: Vec<(PendingKind, Vec<Value>)>) -> Vec<PendingItem> {
    let mut out: Vec<PendingItem> = rows
        .iter()
        .flat_map(|(kind, raws)| raws.iter().map(|raw| describe(*kind, raw)))
        .collect();
    // Oldest first: the thing waiting longest is the one to answer.
    out.sort_by(|a, b| sort_key(&a.created_at).cmp(&sort_key(&b.created_at)));
    out
}

/// `String(created_at)`, the JS sort key (`undefined` when absent).
fn sort_key(v: &Value) -> String {
    match v {
        Value::Null => "undefined".into(),
        other => js_string(other),
    }
}

/// The control call that answers one decision. Ports the return value of
/// `decision` in `src/pending.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionCall {
    /// Route.
    pub path: String,
    /// `{ <idField>: id, granted, overrides? }`.
    pub body: Value,
}

/// The call that answers one decision; overrides are included only when
/// non-empty. The verdict is a `bool` by type (the JS throws a TypeError
/// otherwise). Ports `decision` in `src/pending.js`.
pub fn decision(
    item: &PendingItem,
    granted: bool,
    overrides: Option<&Map<String, Value>>,
) -> DecisionCall {
    let mut body = Map::new();
    body.insert(item.decide.id_field.clone(), Value::from(item.id.clone()));
    body.insert("granted".into(), Value::Bool(granted));
    if let Some(o) = overrides.filter(|o| !o.is_empty()) {
        body.insert("overrides".into(), Value::Object(o.clone()));
    }
    DecisionCall {
        path: item.decide.path.clone(),
        body: Value::Object(body),
    }
}

/// The keys `parse_overrides` reads. Ports `OVERRIDE_KEYS` in
/// `src/pending.js`.
pub const OVERRIDE_KEYS: [&str; 23] = [
    "methods",
    "paths",
    "budget",
    "uses",
    "ttl_minutes",
    "ttl-minutes",
    "grant_ttl_minutes",
    "grant-ttl",
    "grant_ttl",
    "max_concurrent",
    "concurrency",
    "redirects",
    "spend_tokens",
    "spend-tokens",
    "spend_usd",
    "spend-usd",
    "rate",
    "quota",
    "routes",
    "route",
    "payload",
    "approval",
    "infinite",
];

/// A narrowing value that cannot be one. Never dropped: a dropped narrowing
/// approves what the agent asked for. Ports the `TypeError` with `field`
/// that `parseOverrides` throws in `src/pending.js`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{field}: {why}")]
pub struct OverrideError {
    /// The key at fault.
    pub field: String,
    /// Why.
    pub why: String,
}

/// Narrowing flags, normalized. Serializes with only the keys set. Ports
/// the `out` object of `parseOverrides` in `src/pending.js`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Overrides {
    /// Upper-cased methods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    /// Path globs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    /// Budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<f64>,
    /// Placeholder uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses: Option<f64>,
    /// Session lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_minutes: Option<f64>,
    /// Grant lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ttl_minutes: Option<f64>,
    /// Concurrency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent: Option<f64>,
    /// Redirects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirects: Option<f64>,
    /// Token spend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend_tokens: Option<f64>,
    /// USD spend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend_usd: Option<f64>,
    /// Rate (`60/min`, passed through for the daemon).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<Value>,
    /// Quota (passed through).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<Value>,
    /// Routes (JSON or `METHODS:/path` pairs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes: Option<Value>,
    /// Payload rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// Approval mode (owner only, validated by the daemon).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
    /// Never expires (owner only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub infinite: Option<bool>,
}

/// Parse narrowing flags the same way wherever they are typed; an unknown
/// key or an unusable value is an error naming the field. Ports
/// `parseOverrides` in `src/pending.js`.
pub fn parse_overrides(args: &Map<String, Value>) -> Result<Overrides, OverrideError> {
    let fail = |field: &str, why: String| OverrideError {
        field: field.to_string(),
        why,
    };
    for k in args.keys() {
        if !OVERRIDE_KEYS.contains(&k.as_str()) {
            return Err(fail(k, "not a narrowing an approval applies".into()));
        }
    }
    // Split on commas and trimmed, as every surface reads them.
    let list = |v: &Value| -> Vec<String> {
        let items: Vec<String> = match v {
            Value::Array(a) => a.iter().map(js_string).collect(),
            other => js_string(other).split(',').map(str::to_string).collect(),
        };
        items
            .into_iter()
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    };
    let given = |v: Option<&Value>| match v {
        None | Some(Value::Null) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    };
    // A number, or a string that reads as one; anything else is refused.
    let num = |field: &str, v: &Value| -> Result<f64, OverrideError> {
        let n = match v {
            Value::Number(n) => n.as_f64(),
            Value::String(s) if !s.trim().is_empty() => js_parse_number(s.trim()),
            _ => None,
        };
        match n {
            Some(n) if n.is_finite() => Ok(n),
            _ => Err(fail(field, format!("not a number: {v}"))),
        }
    };
    let json = |field: &str, v: &Value| -> Result<Value, OverrideError> {
        let Value::String(s) = v else {
            return Ok(v.clone());
        };
        let parsed: Value =
            serde_json::from_str(s).map_err(|_| fail(field, "not valid JSON".into()))?;
        if !(parsed.is_object() || parsed.is_array()) {
            return Err(fail(field, "must be a JSON object or list".into()));
        }
        Ok(parsed)
    };
    let route_of = |v: &Value| -> Value {
        let s = js_string(v);
        match s.find(':') {
            Some(at) if at > 0 => {
                let methods: Vec<Value> = s[..at]
                    .split(',')
                    .map(|m| m.trim().to_uppercase())
                    .filter(|m| !m.is_empty())
                    .map(Value::from)
                    .collect();
                serde_json::json!({ "methods": methods, "paths": [s[at + 1..].trim()] })
            }
            _ => Value::from(s),
        }
    };
    let shape = |v: &Value| match v {
        Value::String(s) => Value::from(s.trim()),
        other => other.clone(),
    };
    let pick = |names: &[&str]| -> Option<Value> {
        names
            .iter()
            .map(|n| args.get(*n))
            .find(|v| given(*v))
            .flatten()
            .cloned()
    };

    let mut out = Overrides::default();
    if let Some(v) = args.get("methods").filter(|v| truthy(v)) {
        out.methods = Some(list(v).into_iter().map(|m| m.to_uppercase()).collect());
    }
    if let Some(v) = args.get("paths").filter(|v| truthy(v)) {
        out.paths = Some(list(v));
    }
    if let Some(v) = args.get("budget").filter(|v| given(Some(v))) {
        out.budget = Some(num("budget", v)?);
    }
    if let Some(v) = args.get("uses").filter(|v| given(Some(v))) {
        out.uses = Some(num("uses", v)?);
    }
    if let Some(v) = pick(&["ttl_minutes", "ttl-minutes"]) {
        out.ttl_minutes = Some(num("ttl_minutes", &v)?);
    }
    if let Some(v) = pick(&["grant_ttl_minutes", "grant-ttl", "grant_ttl"]) {
        out.grant_ttl_minutes = Some(num("grant_ttl_minutes", &v)?);
    }
    if let Some(v) = pick(&["max_concurrent", "concurrency"]) {
        out.max_concurrent = Some(num("max_concurrent", &v)?);
    }
    if let Some(v) = args.get("redirects").filter(|v| given(Some(v))) {
        out.redirects = Some(num("redirects", v)?);
    }
    if let Some(v) = pick(&["spend_tokens", "spend-tokens"]) {
        out.spend_tokens = Some(num("spend_tokens", &v)?);
    }
    if let Some(v) = pick(&["spend_usd", "spend-usd"]) {
        out.spend_usd = Some(num("spend_usd", &v)?);
    }
    if let Some(v) = args.get("rate").filter(|v| given(Some(v))) {
        out.rate = Some(shape(v));
    }
    if let Some(v) = args.get("quota").filter(|v| given(Some(v))) {
        out.quota = Some(shape(v));
    }
    if let Some(v) = args.get("routes").filter(|v| given(Some(v))) {
        out.routes = Some(json("routes", v)?);
    } else if let Some(v) = args.get("route").filter(|v| given(Some(v))) {
        let items: Vec<Value> = match v {
            Value::Array(a) => a.iter().map(route_of).collect(),
            other => vec![route_of(other)],
        };
        out.routes = Some(Value::Array(items));
    }
    if let Some(v) = args.get("payload").filter(|v| given(Some(v))) {
        out.payload = Some(json("payload", v)?);
    }
    if let Some(Value::String(a)) = args.get("approval") {
        if !a.is_empty() {
            out.approval = Some(a.clone());
        }
    }
    match args.get("infinite") {
        Some(Value::Bool(true)) => out.infinite = Some(true),
        Some(Value::String(s)) if s == "true" => out.infinite = Some(true),
        _ => {}
    }
    Ok(out)
}

/// `Number(s)` for a trimmed, non-empty string: decimal (with exponent),
/// `0x`/`0o`/`0b` integers, and `Infinity`; anything else is not a number.
fn js_parse_number(s: &str) -> Option<f64> {
    let radix = |p: &str, r: u32| u64::from_str_radix(p, r).ok().map(|n| n as f64);
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return radix(h, 16);
    }
    if let Some(o) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        return radix(o, 8);
    }
    if let Some(b) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        return radix(b, 2);
    }
    match s {
        "Infinity" | "+Infinity" => return Some(f64::INFINITY),
        "-Infinity" => return Some(f64::NEG_INFINITY),
        _ => {}
    }
    // Rust also reads "inf" and "nan", which JS does not.
    if s.bytes().any(|c| c.is_ascii_alphabetic() && c != b'e' && c != b'E') {
        return None;
    }
    s.parse::<f64>().ok()
}

/// Record an approved session where local clients look: calls `remember`
/// with `answered.session` when the item is a session and it carries a
/// token, and returns it. Ports `collectApproved` in `src/pending.js`.
pub fn collect_approved<F>(item: &PendingItem, answered: &Value, remember: F) -> Option<Value>
where
    F: FnOnce(&Value),
{
    if item.kind != PendingKind::Session {
        return None;
    }
    let got = answered.get("session")?;
    if !got.get("token").is_some_and(truthy) {
        return None;
    }
    remember(got);
    Some(got.clone())
}

/// What a human granted, in their own words (`session for <cred> · …`).
/// Takes the raw grant summary. Ports `describeGranted` in `src/pending.js`.
pub fn describe_granted(granted: &Value) -> String {
    let field = |k: &str| granted.get(k).filter(|v| truthy(v));
    let cred = granted
        .get("cred")
        .map(js_string)
        .unwrap_or_else(|| "undefined".into());
    let mut bits = vec![format!("session for {cred}")];
    let join = |v: &Value, sep: &str| match v {
        Value::Array(a) => a.iter().map(js_string).collect::<Vec<_>>().join(sep),
        other => js_string(other),
    };
    if let Some(m) = field("methods") {
        bits.push(join(m, ","));
    }
    if let Some(p) = field("paths") {
        bits.push(join(p, " "));
    }
    if let Some(b) = field("budget") {
        bits.push(format!("{} requests", js_string(b)));
    }
    if let Some(u) = field("uses") {
        bits.push(format!("{}-use placeholder", js_string(u)));
    }
    if let Some(a) = field("approval") {
        bits.push(format!("approval {}", js_string(a)));
    }
    if let Some(t) = field("grant_ttl_minutes") {
        bits.push(format!("grant ends after {} min", js_string(t)));
    }
    if granted.get("infinite") == Some(&Value::Bool(true)) {
        bits.push("never expires".into());
    } else if let Some(t) = field("ttl_minutes") {
        bits.push(format!("lasts {} min", js_string(t)));
    }
    bits.join(" · ")
}

/// Most decisions one act of presence may answer. Ports
/// `MAX_BULK_DECISIONS` in `src/pending.js`.
pub const MAX_BULK_DECISIONS: usize = 25;

/// Keys a bulk decision may have. Ports `DECISION_KEYS` in `src/pending.js`.
pub const DECISION_KEYS: [&str; 4] = ["id", "kind", "granted", "overrides"];

/// Why a bulk decision list is not usable, or none. Validation only: the
/// signature binds the bytes as sent. Ports `checkDecisions` in
/// `src/pending.js`.
pub fn check_decisions(raw: &Value) -> Option<String> {
    let Value::Array(list) = raw else {
        return Some("decisions must be a list".into());
    };
    if list.is_empty() {
        return Some("nothing was selected".into());
    }
    if list.len() > MAX_BULK_DECISIONS {
        return Some(format!(
            "too many at once ({}); {MAX_BULK_DECISIONS} is the most a person can actually read",
            list.len()
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for d in list {
        let Value::Object(d) = d else {
            return Some("each decision must be an object".into());
        };
        for k in d.keys() {
            if !DECISION_KEYS.contains(&k.as_str()) {
                return Some(format!("a decision cannot carry {}", Value::from(k.clone())));
            }
        }
        let id = match d.get("id") {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            _ => return Some("each decision needs an id".into()),
        };
        let kind_ok = matches!(d.get("kind"), Some(Value::String(k)) if k == "request" || k == "session");
        if !kind_ok {
            let shown = d.get("kind").map(|k| k.to_string()).unwrap_or_else(|| "undefined".into());
            return Some(format!("unknown kind {shown}"));
        }
        if !matches!(d.get("granted"), Some(Value::Bool(_))) {
            return Some(format!("the verdict for {id} must be true or false"));
        }
        if let Some(o) = d.get("overrides") {
            if !o.is_object() {
                return Some(format!("the narrowing for {id} must be an object"));
            }
        }
        if !seen.insert(id.clone()) {
            return Some(format!("{id} appears twice, with no way to say which verdict wins"));
        }
    }
    None
}
