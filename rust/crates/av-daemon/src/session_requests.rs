//! Agent-proposed sessions held for a human: the proposal shape, elevation,
//! template resolution, and the persisted request store. Ports
//! `src/daemon/session-requests.js`.

use av_core::errors::VaultError;
use av_core::policy::{self, Checked, Policy};
use av_store::model::{SessionRequestRecord, SessionRequestState};
use av_store::vault::Vault;
use serde_json::{json, Map, Value};

use crate::err::{d, dr, DenyExt, C};
use crate::state::{Core, StoreResult};
use crate::util::{
    as_finite, as_integer, ct_eq, iso_now, js_number, js_string, js_stringify, js_stringify_keys,
    now_ms, num, parse_iso_ms, random_b64url, sha256_hex,
};

/// Session requests pending at once. Ports `MAX_PENDING`.
pub const MAX_PENDING: usize = 64;
/// A pending request nobody answered expires after this. Ports `PENDING_TTL_MS`.
pub const PENDING_TTL_MS: u64 = 30 * 60_000;
/// An approved request's token can be collected for this long. Ports `COLLECT_TTL_MS`.
pub const COLLECT_TTL_MS: u64 = 5 * 60_000;
/// Settled requests are kept visible for this long. Ports `SETTLED_TTL_MS`.
pub const SETTLED_TTL_MS: u64 = 30 * 60_000;
/// Requests stored at once, any state. Ports `MAX_ITEMS`.
pub const MAX_ITEMS: usize = MAX_PENDING * 4;
/// Default session lifetime for a request, hours. Ports `DEFAULT_TTL_HOURS`.
pub const DEFAULT_TTL_HOURS: u64 = 8;

/// The fields an agent may propose. Ports `FIELDS`.
pub const FIELDS: [&str; 15] = [
    "cred",
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

/// The fields only the owner may set. Ports `OWNER_FIELDS`.
pub const OWNER_FIELDS: [&str; 2] = ["approval", "infinite"];

/// What a template override may name. Ports `TEMPLATE_OVERRIDES`.
pub const TEMPLATE_OVERRIDES: [&str; 9] = [
    "methods",
    "paths",
    "budget",
    "uses",
    "grant_ttl_minutes",
    "approval",
    "ttl_hours",
    "infinite",
    "label",
];

const APPROVAL_MODES: [&str; 4] = ["each", "on-write", "first-use", "auto"];

fn set(v: &Value, k: &str) -> bool {
    v.get(k).is_some_and(|x| !x.is_null())
}

/// `proposalOf(input)`.
pub fn proposal_of(input: &Value) -> Value {
    let mut out = Map::new();
    for f in FIELDS {
        if let Some(v) = input.get(f).filter(|v| !v.is_null()) {
            out.insert(f.into(), v.clone());
        }
    }
    Value::Object(out)
}

/// `overridesOf(input)`.
pub fn overrides_of(input: &Value) -> Value {
    let mut out = proposal_of(input);
    for f in OWNER_FIELDS {
        if let Some(v) = input.get(f).filter(|v| !v.is_null()) {
            out[f] = v.clone();
        }
    }
    out
}

/// `overridesProblem(input)`.
pub fn overrides_problem(input: Option<&Value>) -> Option<String> {
    let input = input.filter(|v| !v.is_null())?;
    let Value::Object(m) = input else {
        return Some("the narrowing must be an object".into());
    };
    let unread: Vec<String> = m
        .keys()
        .filter(|k| !FIELDS.contains(&k.as_str()) && !OWNER_FIELDS.contains(&k.as_str()))
        .map(|k| js_stringify(&Value::from(k.clone())))
        .collect();
    (!unread.is_empty()).then(|| {
        format!(
            "a decision cannot narrow {}; nothing was decided",
            unread.join(", ")
        )
    })
}

/// `shapeOf(p)`: `{ fields, counts }`.
pub fn shape_of(p: &Value) -> Value {
    let fields: Vec<&str> = FIELDS
        .iter()
        .chain(OWNER_FIELDS.iter())
        .copied()
        .filter(|f| set(p, f))
        .collect();
    let mut counts = Map::new();
    for f in &fields {
        if let Some(a) = p.get(*f).and_then(Value::as_array) {
            counts.insert(f.to_string(), Value::from(a.len() as u64));
        }
    }
    json!({"fields": fields, "counts": counts})
}

/// `narrowedOf(proposal, final)`.
pub fn narrowed_of(proposal: &Value, final_: &Value) -> Vec<String> {
    let text = |v: &Value, f: &str| v.get(f).map(js_stringify);
    FIELDS
        .iter()
        .chain(OWNER_FIELDS.iter())
        .filter(|f| text(proposal, f) != text(final_, f))
        .map(|f| f.to_string())
        .collect()
}

fn names(v: &Value) -> bool {
    v.as_array().is_some_and(|a| a.iter().all(Value::is_string))
}

fn readable(g: &Value) -> bool {
    if !g.is_object() {
        return false;
    }
    if set(g, "methods") && !names(&g["methods"]) {
        return false;
    }
    if set(g, "routes") {
        let ok = g["routes"].as_array().is_some_and(|rs| {
            rs.iter()
                .all(|r| crate::util::truthy(r) && r.get("methods").is_some_and(names))
        });
        if !ok {
            return false;
        }
    }
    true
}

fn permits_write(g: &Value) -> bool {
    let mut named: Vec<String> = if set(g, "methods") {
        g["methods"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|m| m.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec!["GET".into(), "HEAD".into()]
    };
    if let Some(rs) = g.get("routes").and_then(Value::as_array) {
        for r in rs {
            if let Some(ms) = r.get("methods").and_then(Value::as_array) {
                named.extend(ms.iter().filter_map(|m| m.as_str().map(str::to_string)));
            }
        }
    }
    named
        .iter()
        .any(|m| !["GET", "HEAD", "OPTIONS"].contains(&m.to_uppercase().as_str()))
}

/// `elevationOf(spec)`: why a session spec needs fresh presence. Fail-closed.
pub fn elevation_of(spec: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if !spec.is_object() {
        return vec!["approval_auto_writes".into()];
    }
    if spec.get("infinite") == Some(&Value::Bool(true)) {
        out.push("infinite".into());
    }
    if let Some(g) = spec.get("grants") {
        if !g.is_array() {
            out.push("approval_auto_writes".into());
            return out;
        }
    }
    let grants: Vec<Value> = match spec.get("grants") {
        Some(Value::Array(a)) => a.clone(),
        _ => vec![spec.clone()],
    };
    let unasked = |g: &Value| {
        matches!(
            g.get("approval").and_then(Value::as_str),
            Some("auto") | Some("first-use")
        )
    };
    if grants
        .iter()
        .any(|g| !readable(g) || (unasked(g) && permits_write(g)))
    {
        out.push("approval_auto_writes".into());
    }
    out
}

/// `fingerprint(proposal)`.
pub fn fingerprint(proposal: &Value) -> String {
    let mut keys: Vec<String> = proposal
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    sha256_hex(js_stringify_keys(proposal, &keys).as_bytes())[..16].to_string()
}

/// A template-literal interpolation: `${v}`, `undefined` when absent.
fn tl(v: Option<&Value>) -> String {
    v.map_or_else(|| "undefined".into(), js_string)
}

fn list_of(v: Option<&Value>, fallback: &[&str]) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().map(js_string).collect(),
        _ => fallback.iter().map(|s| s.to_string()).collect(),
    }
}

fn window_text(w: &Value, key: &str) -> String {
    if w.is_object() || w.is_array() {
        format!("{}/{}", tl(w.get("count")), tl(w.get(key)))
    } else {
        js_string(w)
    }
}

/// `summarize(p)`.
pub fn summarize(p: &Value) -> String {
    let truthy = |k: &str| p.get(k).is_some_and(crate::util::truthy);
    let mut bits = vec![format!("session for {}", tl(p.get("cred")))];
    bits.push(list_of(p.get("methods"), &["GET"]).join(","));
    bits.push(list_of(p.get("paths"), &["/**"]).join(" "));
    if truthy("budget") {
        bits.push(format!("{} requests", tl(p.get("budget"))));
    }
    if truthy("uses") {
        bits.push(format!("{}-use placeholder", tl(p.get("uses"))));
    }
    if truthy("ttl_minutes") {
        bits.push(format!("{}m", tl(p.get("ttl_minutes"))));
    }
    if let Some(Value::Array(routes)) = p.get("routes") {
        let rs: Vec<String> = routes
            .iter()
            .map(|r| {
                format!(
                    "{} {}",
                    list_of(r.get("methods"), &[]).join(","),
                    list_of(r.get("paths"), &[]).join(" ")
                )
            })
            .collect();
        bits.push(format!("routes {}", rs.join(" | ")));
    }
    if set(p, "rate") {
        bits.push(format!("rate {}", window_text(&p["rate"], "per")));
    }
    if set(p, "max_concurrent") {
        bits.push(format!("{} at once", tl(p.get("max_concurrent"))));
    }
    if set(p, "quota") {
        bits.push(format!("quota {}", window_text(&p["quota"], "window")));
    }
    if set(p, "redirects") {
        bits.push(format!("follows {} redirects", tl(p.get("redirects"))));
    }
    if set(p, "spend_tokens") {
        bits.push(format!("{} tokens", tl(p.get("spend_tokens"))));
    }
    if set(p, "spend_usd") {
        bits.push(format!("${}", tl(p.get("spend_usd"))));
    }
    if set(p, "grant_ttl_minutes") {
        bits.push(format!("grant {}m", tl(p.get("grant_ttl_minutes"))));
    }
    if set(p, "payload") {
        bits.push("payload rules".into());
    }
    if set(p, "approval") {
        bits.push(format!("approval {}", tl(p.get("approval"))));
    }
    if p.get("infinite") == Some(&Value::Bool(true)) {
        bits.push("never expires".into());
    }
    let line = bits.join(" · ");
    match p.get("template").and_then(Value::as_str) {
        Some(t) => format!("template {t} v{} · {line}", tl(p.get("template_version"))),
        None => line,
    }
}

/// The profile's default budget for a grant spec, if it has one. Ports the
/// `budgetDefault` option of `resolveTemplate`.
pub type BudgetDefault<'a> = &'a dyn Fn(&Value) -> Option<u64>;

fn is_names(v: &Value) -> bool {
    v.as_array()
        .is_some_and(|a| a.iter().all(|x| x.as_str().is_some_and(|s| !s.is_empty())))
}

/// `resolveTemplate(template, overrides, { budgetDefault })`: narrowing only.
pub fn resolve_template(
    template_spec: &Value,
    overrides: &Value,
    budget_default: Option<BudgetDefault<'_>>,
) -> Result<Value, VaultError> {
    let refuse = |detail: &str, rule: &str| {
        dr(C::PolicyDenied, detail, rule).hinted(format!(
            "A template can only be narrowed. Overrides are: {}.",
            TEMPLATE_OVERRIDES.join(", ")
        ))
    };
    if !template_spec.is_object() {
        return Err(refuse(
            "that template has no readable spec",
            "session_shape",
        ));
    }
    let Value::Object(o) = overrides else {
        return Err(refuse("overrides must be an object", "template_override"));
    };
    for k in o.keys() {
        if !TEMPLATE_OVERRIDES.contains(&k.as_str()) {
            return Err(refuse(
                &format!("a template cannot be overridden with {k}"),
                "template_override",
            ));
        }
    }
    let has = |k: &str| o.get(k).is_some();
    let mut spec = template_spec.clone();
    let single = spec.get("grants").is_none();
    {
        let grants_ok = if single {
            true
        } else {
            spec["grants"]
                .as_array()
                .is_some_and(|a| a.iter().all(Value::is_object))
        };
        if !grants_ok {
            return Err(refuse(
                "the template's grants cannot be read",
                "session_shape",
            ));
        }
    }
    if has("methods") && !is_names(&o["methods"]) {
        return Err(refuse(
            "methods must be a list of method names",
            "policy_invalid",
        ));
    }
    if has("paths") && !is_names(&o["paths"]) {
        return Err(refuse(
            "paths must be a list of path globs",
            "policy_invalid",
        ));
    }
    if has("approval")
        && !o["approval"]
            .as_str()
            .is_some_and(|a| APPROVAL_MODES.contains(&a))
    {
        return Err(dr(
            C::PolicyDenied,
            "approval is not one of the four modes",
            "approval",
        )
        .hinted("approval is one of: each, on-write, first-use, auto"));
    }
    let budget = if has("budget") {
        policy::budget_integer(&o["budget"])
    } else {
        None
    };
    if has("budget") && budget.is_none() {
        return Err(refuse(
            "budget must be a whole number of requests, 0 or more",
            "policy_invalid",
        ));
    }
    for k in ["uses", "grant_ttl_minutes"] {
        if has(k)
            && !o[k].as_i64().filter(|n| *n >= 1).is_some()
            && !as_integer(&o[k]).is_some_and(|n| n >= 1)
        {
            return Err(refuse(
                &format!("{k} must be a whole number, 1 or more"),
                if k == "uses" {
                    "policy_invalid"
                } else {
                    "grant_ttl"
                },
            ));
        }
    }
    let grant_count = if single {
        1
    } else {
        spec["grants"].as_array().map_or(0, Vec::len)
    };
    for i in 0..grant_count {
        let g: &mut Value = if single {
            &mut spec
        } else {
            &mut spec["grants"][i]
        };
        if has("methods") {
            let base = if set(g, "methods") {
                g["methods"].clone()
            } else {
                json!(["GET", "HEAD"])
            };
            if !is_names(&base) {
                return Err(refuse(
                    "the template's methods cannot be read",
                    "policy_invalid",
                ));
            }
            let base: Vec<Value> = base.as_array().cloned().unwrap_or_default();
            let kept: Vec<Value> = o["methods"]
                .as_array()
                .map(|a| a.iter().filter(|m| base.contains(m)).cloned().collect())
                .unwrap_or_default();
            g["methods"] = Value::Array(kept);
        }
        if has("paths") {
            let base = if set(g, "paths") {
                g["paths"].clone()
            } else {
                json!(["/**"])
            };
            if !is_names(&base) {
                return Err(refuse(
                    "the template's paths cannot be read",
                    "policy_invalid",
                ));
            }
            let a = Policy {
                paths: Some(Checked::Valid(strings(&base))),
                ..Default::default()
            };
            let b = Policy {
                paths: Some(Checked::Valid(strings(&o["paths"]))),
                ..Default::default()
            };
            let both = policy::intersect(&[Some(&a), Some(&b)]);
            g["paths"] = serde_json::to_value(&both.paths).unwrap_or(Value::Null);
        }
        if has("budget") {
            let mut base = g.get("budget").filter(|v| !v.is_null()).cloned();
            if base.is_none() {
                let dflt = budget_default.and_then(|f| f(g));
                match dflt {
                    Some(n) => base = Some(Value::from(n)),
                    None => {
                        return Err(refuse(
                            "this template names no budget to narrow",
                            "policy_invalid",
                        ))
                    }
                }
            }
            let base_int = policy::budget_integer(base.as_ref().expect("base"))
                .ok_or_else(|| refuse("the template's budget cannot be read", "policy_invalid"))?;
            g["budget"] = Value::from(base_int.min(budget.expect("budget")));
        }
        for k in ["uses", "grant_ttl_minutes"] {
            if !has(k) {
                continue;
            }
            if set(g, k) && !as_integer(&g[k]).is_some_and(|n| n >= 1) {
                return Err(refuse(
                    &format!("the template's {k} cannot be read"),
                    "policy_invalid",
                ));
            }
            let ov = as_integer(&o[k]).unwrap_or(1);
            g[k] = Value::from(match g.get(k).and_then(as_integer) {
                Some(b) if set(g, k) => b.min(ov),
                _ => ov,
            });
        }
        if has("approval") {
            let base = g
                .get("approval")
                .and_then(Value::as_str)
                .unwrap_or("on-write")
                .to_string();
            let base_raw = g.get("approval").filter(|v| !v.is_null()).cloned();
            let order = policy::APPROVAL_ORDER;
            let ov = o["approval"].as_str().unwrap_or("each");
            let known = base_raw
                .as_ref()
                .is_none_or(|b| b.as_str().is_some_and(|s| order.contains(&s)));
            g["approval"] = Value::from(if !known {
                "each".to_string()
            } else {
                let bi = order.iter().position(|m| *m == base).unwrap_or(0);
                let oi = order.iter().position(|m| *m == ov).unwrap_or(0);
                if oi > bi {
                    ov.to_string()
                } else {
                    base
                }
            });
        }
    }
    if has("infinite") {
        let Some(inf) = o["infinite"].as_bool() else {
            return Err(refuse("infinite is true or false", "ttl"));
        };
        if inf && spec.get("infinite") != Some(&Value::Bool(true)) {
            return Err(refuse(
                "an override cannot remove a template's lifetime",
                "template_override",
            ));
        }
        if !inf {
            if let Some(m) = spec.as_object_mut() {
                m.remove("infinite");
            }
        }
    }
    if has("ttl_hours") {
        let Some(ov) = as_finite(&o["ttl_hours"]).filter(|h| *h > 0.0) else {
            return Err(dr(
                C::PolicyDenied,
                "ttl_hours must be a positive number of hours",
                "ttl",
            ));
        };
        if spec.get("infinite") == Some(&Value::Bool(true)) {
            if let Some(m) = spec.as_object_mut() {
                m.remove("infinite");
            }
            spec["ttl_hours"] = o["ttl_hours"].clone();
        } else {
            let base = match spec.get("ttl_hours") {
                None | Some(Value::Null) => Some(DEFAULT_TTL_HOURS as f64),
                Some(v) => as_finite(v).filter(|h| *h > 0.0),
            };
            let Some(base) = base else {
                return Err(refuse("the template's ttl_hours cannot be read", "ttl"));
            };
            spec["ttl_hours"] = num(base.min(ov));
        }
    }
    if has("label") {
        let ok = o["label"]
            .as_str()
            .is_some_and(|l| l.encode_utf16().count() <= 80);
        if !ok {
            return Err(refuse(
                "label is a string of at most 80 characters",
                "policy_invalid",
            ));
        }
        spec["label"] = o["label"].clone();
    }
    Ok(spec)
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// `grantSpecsOf(spec)`.
pub fn grant_specs_of(spec: &Value) -> Vec<Value> {
    if !spec.is_object() {
        return Vec::new();
    }
    match spec.get("grants") {
        Some(Value::Array(a)) => a.iter().filter(|g| g.is_object()).cloned().collect(),
        Some(_) => Vec::new(),
        None => vec![spec.clone()],
    }
}

/// `templateCreds(spec)`.
pub fn template_creds(spec: &Value) -> Vec<String> {
    grant_specs_of(spec)
        .iter()
        .filter_map(|g| g.get("cred").and_then(Value::as_str).map(str::to_string))
        .collect()
}

/// `templateSummary(spec)`.
pub fn template_summary(spec: &Value) -> String {
    grant_specs_of(spec)
        .iter()
        .map(|g| {
            let mut x = g.clone();
            if spec.get("infinite") == Some(&Value::Bool(true)) {
                x["infinite"] = Value::Bool(true);
            } else if let Some(m) = x.as_object_mut() {
                m.remove("infinite");
            }
            match spec.get("ttl_hours").and_then(Value::as_f64) {
                Some(h) if spec["ttl_hours"].is_number() => {
                    x["ttl_minutes"] = num((h * 60.0 + 0.5).floor())
                }
                _ => {
                    if let Some(m) = x.as_object_mut() {
                        m.remove("ttl_minutes");
                    }
                }
            }
            summarize(&x)
        })
        .collect::<Vec<_>>()
        .join(" + ")
}

// ----------------------------------------------------------- the store

/// One session request in memory. Ports the records `propose` makes.
#[derive(Debug, Clone)]
pub struct SrRecord {
    /// `sr_<ulid>`.
    pub id: String,
    /// SHA-256 of the collect secret.
    pub collect_hash: String,
    /// What was proposed.
    pub proposal: Value,
    /// `fingerprint(proposal)`.
    pub fingerprint: String,
    /// `summarize(proposal)`.
    pub summary: String,
    /// The agent's reason.
    pub reason_untrusted: Option<String>,
    /// `pending | approved | denied | collected | expired`.
    pub state: String,
    /// ISO.
    pub created_at: String,
    /// ISO.
    pub decided_at: Option<String>,
    /// The created session, until collected (never persisted).
    pub result: Option<Value>,
    /// What the human approved.
    pub granted_proposal: Option<Value>,
}

impl SrRecord {
    /// `SessionRequests.redact(r)`.
    pub fn redact(&self) -> Value {
        json!({
            "id": self.id, "summary": self.summary, "proposal": self.proposal, "fingerprint": self.fingerprint,
            "agent_reason_untrusted": self.reason_untrusted, "state": self.state, "created_at": self.created_at,
            "decided_at": self.decided_at,
        })
    }

    fn stored(&self) -> Option<SessionRequestRecord> {
        let state = match self.state.as_str() {
            "pending" => SessionRequestState::Pending,
            "denied" => SessionRequestState::Denied,
            _ => return None,
        };
        Some(SessionRequestRecord {
            id: self.id.clone(),
            collect_hash: self.collect_hash.clone(),
            proposal: self.proposal.clone(),
            fingerprint: self.fingerprint.clone(),
            summary: self.summary.clone(),
            reason_untrusted: self.reason_untrusted.clone(),
            state,
            created_at: self.created_at.clone(),
            decided_at: self.decided_at.clone(),
        })
    }

    /// `SessionRequests.mayCollect(record, secret)`.
    pub fn may_collect(&self, secret: Option<&str>) -> bool {
        let Some(secret) = secret.filter(|s| !s.is_empty()) else {
            return false;
        };
        if self.collect_hash.is_empty() {
            return false;
        }
        ct_eq(
            self.collect_hash.as_bytes(),
            sha256_hex(secret.as_bytes()).as_bytes(),
        )
    }
}

/// The store. Ports `class SessionRequests`.
#[derive(Debug, Default)]
pub struct SessionRequestStore {
    items: Vec<SrRecord>,
    saved: Option<String>,
}

impl SessionRequestStore {
    /// `#load()`: read back the persisted questions (without results).
    pub fn load(vault: &Vault) -> SessionRequestStore {
        let rows = vault.session_requests().unwrap_or_default();
        let items: Vec<SrRecord> = rows
            .into_iter()
            .map(|r| SrRecord {
                id: r.id,
                collect_hash: r.collect_hash,
                proposal: r.proposal,
                fingerprint: r.fingerprint,
                summary: r.summary,
                reason_untrusted: r.reason_untrusted,
                state: match r.state {
                    SessionRequestState::Pending => "pending",
                    SessionRequestState::Approved => "approved",
                    SessionRequestState::Denied => "denied",
                    SessionRequestState::Expired => "expired",
                }
                .into(),
                created_at: r.created_at,
                decided_at: r.decided_at,
                result: None,
                granted_proposal: None,
            })
            .collect();
        let mut s = SessionRequestStore { items, saved: None };
        s.saved = Some(s.snapshot());
        s
    }

    fn snapshot(&self) -> String {
        let keep: Vec<Value> = self
            .items
            .iter()
            .filter_map(SrRecord::stored)
            .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
            .collect();
        js_stringify(&Value::Array(keep))
    }

    /// A record by id (no sweep).
    pub fn find_mut(&mut self, id: &str) -> Option<&mut SrRecord> {
        self.items.iter_mut().find(|r| r.id == id)
    }
}

impl Core {
    /// `#save()`.
    pub fn sr_save(&mut self) {
        let now = self.sr.snapshot();
        if self.sr.saved.as_deref() == Some(now.as_str()) {
            return;
        }
        let rows: Vec<SessionRequestRecord> =
            self.sr.items.iter().filter_map(SrRecord::stored).collect();
        if self.vault.save_session_requests(&rows).is_ok() {
            self.sr.saved = Some(now);
        }
    }

    fn sr_sweep(&mut self) {
        let now = now_ms();
        let before: Vec<(String, String)> = self
            .sr
            .items
            .iter()
            .map(|r| (r.id.clone(), r.state.clone()))
            .collect();
        let mut uncollected = Vec::new();
        self.sr.items.retain_mut(|r| {
            let age = now - parse_iso_ms(&r.created_at).unwrap_or(0);
            if r.state == "pending" && age > PENDING_TTL_MS as i64 {
                return false;
            }
            let settled_for =
                now - parse_iso_ms(r.decided_at.as_deref().unwrap_or(&r.created_at)).unwrap_or(0);
            if r.state != "pending" && r.result.is_none() && settled_for > SETTLED_TTL_MS as i64 {
                return false;
            }
            if r.state == "approved"
                && r.result.is_some()
                && now - parse_iso_ms(r.decided_at.as_deref().unwrap_or("")).unwrap_or(0)
                    > COLLECT_TTL_MS as i64
            {
                r.result = None;
                r.state = "expired".into();
                uncollected.push(r.id.clone());
            }
            true
        });
        for id in uncollected {
            self.audit_opt("session_request.uncollected", json!({"request_id": id}));
        }
        let after: Vec<(String, String)> = self
            .sr
            .items
            .iter()
            .map(|r| (r.id.clone(), r.state.clone()))
            .collect();
        if before != after {
            self.sr_save();
        }
    }

    /// `SessionRequests.propose({ proposal, reason, fromTemplate })`:
    /// returns the record and the one-time collect secret.
    pub fn sr_propose(
        &mut self,
        proposal: Value,
        reason: Option<String>,
        from_template: bool,
    ) -> Result<(SrRecord, String), VaultError> {
        let templated = from_template && proposal.get("template").is_some_and(Value::is_string);
        if !templated && OWNER_FIELDS.iter().any(|f| proposal.get(*f).is_some()) {
            return Err(d(
                C::OwnerOnly,
                "only the owner can choose the approval mode or an unlimited lifetime",
            ));
        }
        self.sr_sweep();
        let waiting = self
            .sr
            .items
            .iter()
            .filter(|r| r.state == "pending")
            .count();
        if waiting >= MAX_PENDING {
            return Err(d(
                C::TooManyRequests,
                "too many session requests are already waiting",
            ));
        }
        while self.sr.items.len() >= MAX_ITEMS {
            let Some(pos) = self.sr.items.iter().position(|r| r.state != "pending") else {
                break;
            };
            self.sr.items.remove(pos);
        }
        let secret = random_b64url(24);
        let record = SrRecord {
            id: av_store::ids::id::session_request(),
            collect_hash: sha256_hex(secret.as_bytes()),
            fingerprint: fingerprint(&proposal),
            summary: summarize(&proposal),
            proposal: proposal.clone(),
            reason_untrusted: reason.filter(|r| !r.is_empty()),
            state: "pending".into(),
            created_at: iso_now(),
            decided_at: None,
            result: None,
            granted_proposal: None,
        };
        self.sr.items.push(record.clone());
        self.sr_save();
        let shape = shape_of(&proposal);
        let cred = match proposal.get("cred").and_then(Value::as_str) {
            Some(c) => self.vault.find_credential(c).v()?.map(|c| c.slug),
            None => None,
        };
        self.audit_opt(
            "session_request.opened",
            json!({
                "request_id": record.id, "actor": "agent", "cred": cred,
                "template": proposal.get("template").and_then(Value::as_str),
                "proposed": shape["fields"], "counts": shape["counts"],
            }),
        );
        self.notify_pending(json!({"kind": "session", "id": record.id, "headline": record.summary, "created_at": record.created_at}));
        Ok((record, secret))
    }

    /// `SessionRequests.get(id)`: after a sweep.
    pub fn sr_get(&mut self, id: &str) -> Option<SrRecord> {
        self.sr_sweep();
        self.sr.items.iter().find(|r| r.id == id).cloned()
    }

    /// Replace a record (the JS mutates its objects in place).
    pub fn sr_put(&mut self, record: SrRecord) {
        if let Some(r) = self.sr.find_mut(&record.id) {
            *r = record;
        }
    }

    /// `SessionRequests.pending()`.
    pub fn sr_pending(&mut self) -> Vec<SrRecord> {
        self.sr_sweep();
        self.sr
            .items
            .iter()
            .filter(|r| r.state == "pending")
            .cloned()
            .collect()
    }
}

/// `js_number` re-export for summaries' tests.
pub fn number_text(n: &serde_json::Number) -> String {
    js_number(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_reads_like_the_js() {
        let p = json!({"cred": "gh", "methods": ["GET", "POST"], "budget": 5, "ttl_minutes": 30});
        assert_eq!(
            summarize(&p),
            "session for gh · GET,POST · /** · 5 requests · 30m"
        );
        let p = json!({"cred": "gh", "rate": {"count": 2, "per": "minute"}, "template": "t", "template_version": 3});
        assert_eq!(
            summarize(&p),
            "template t v3 · session for gh · GET · /** · rate 2/minute"
        );
    }

    #[test]
    fn elevation_is_fail_closed() {
        assert_eq!(
            elevation_of(&json!({"cred": "a", "approval": "auto", "methods": ["POST"]})),
            vec!["approval_auto_writes"]
        );
        assert!(elevation_of(&json!({"cred": "a", "approval": "auto"})).is_empty());
        assert_eq!(
            elevation_of(&json!({"cred": "a", "methods": "GET"})),
            vec!["approval_auto_writes"]
        );
        assert_eq!(
            elevation_of(&json!({"infinite": true, "grants": 1})),
            vec!["infinite", "approval_auto_writes"]
        );
        assert_eq!(elevation_of(&json!(null)), vec!["approval_auto_writes"]);
    }

    #[test]
    fn fingerprint_uses_sorted_top_level_keys_at_every_depth() {
        // JSON.stringify({b:{a:1,z:2},a:1}, ['a','b']) === '{"a":1,"b":{"a":1}}'
        let want = sha256_hex(br#"{"a":1,"b":{"a":1}}"#)[..16].to_string();
        assert_eq!(fingerprint(&json!({"b": {"a": 1, "z": 2}, "a": 1})), want);
    }

    #[test]
    fn templates_only_narrow() {
        let spec = json!({"cred": "gh", "methods": ["GET", "POST"], "budget": 10, "ttl_hours": 4});
        let out = resolve_template(
            &spec,
            &json!({"methods": ["GET", "DELETE"], "budget": 50, "ttl_hours": 12}),
            None,
        )
        .unwrap();
        assert_eq!(out["methods"], json!(["GET"]));
        assert_eq!(out["budget"], json!(10));
        assert_eq!(out["ttl_hours"], json!(4));
        assert!(resolve_template(&spec, &json!({"hosts": ["x"]}), None).is_err());
        assert!(
            resolve_template(&json!({"cred": "gh"}), &json!({"infinite": true}), None).is_err()
        );
    }
}
