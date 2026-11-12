//! Policy layers, intersection, host/path matching and evaluation. Ports
//! `src/core/policy.js`.
//!
//! Effective policy = profile ceiling ∩ workspace ∩ session ∩ grant, where ∩
//! intersects lists, takes the minimum of numeric limits, the stricter
//! approval mode and the narrower enum. A child can never widen.
//!
//! A stored layer may hold a value of the wrong shape (an old vault, or the
//! poison markers `intersect` writes for an invalid layer, such as
//! `methods: false` or `route_sets: [null]`). Every field is therefore a
//! [`Checked`]: the typed value when it has the right shape, otherwise the raw
//! JSON, which `validate` reports and every evaluation refuses.

use serde::{Deserialize, Deserializer, Serialize};

use crate::errors::Result;
use crate::payload::PayloadRuleSet;
use crate::profiles::Profile;

/// Approval modes, least to most strict. Ports `APPROVAL_ORDER` in
/// `src/core/policy.js`.
pub const APPROVAL_ORDER: &[&str] = &["auto", "first-use", "on-write", "each"];
/// SQL profiles, narrowest first. Ports `SQL_ORDER`.
pub const SQL_ORDER: &[&str] = &["read-only", "read-write", "raw"];
/// SSH modes, narrowest first. Ports `SSH_MODE_ORDER`.
pub const SSH_MODE_ORDER: &[&str] = &["run", "agent"];

/// Rate units in milliseconds. Ports `PER_MS` in `src/core/policy.js`.
pub const PER_MS: &[(&str, u64)] = &[("second", 1_000), ("minute", 60_000), ("hour", 3_600_000)];
/// Quota windows in milliseconds. Ports `WINDOW_MS` in `src/core/policy.js`.
pub const WINDOW_MS: &[(&str, u64)] = &[("hour", 3_600_000), ("day", 86_400_000)];

/// Methods a policy may name. Ports `METHODS` (module-private) in
/// `src/core/policy.js`.
pub const METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];
/// Methods that cannot write. Ports `SAFE_METHODS` (module-private) in
/// `src/core/policy.js`.
pub const SAFE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

/// Suffixes where a wildcard host would span unrelated tenants. Ports
/// `MULTI_TENANT_SUFFIXES` in `src/core/policy.js`.
pub const MULTI_TENANT_SUFFIXES: &[&str] = &[
    "s3.amazonaws.com",
    "cloudfront.net",
    "github.io",
    "herokuapp.com",
    "ngrok.io",
    "azurewebsites.net",
    "vercel.app",
    "pages.dev",
    "workers.dev",
    "blob.core.windows.net",
    "storage.googleapis.com",
    "firebaseapp.com",
];

/// Largest `rate.count`. Ports the `1_000_000` bound in `src/core/policy.js`.
pub const RATE_COUNT_MAX: u64 = 1_000_000;
/// Largest `quota.count`. Ports the `100_000_000` bound.
pub const QUOTA_COUNT_MAX: u64 = 100_000_000;
/// Largest `max_concurrent`. Ports the `1024` bound.
pub const MAX_CONCURRENT_MAX: u64 = 1024;
/// Largest `redirects.max`. Ports the `5` bound in `validRedirects`.
pub const REDIRECTS_MAX: u64 = 5;
/// Default `placeholder_policy.max_active` during intersection. Ports the
/// `?? 8` in `intersectPh`.
pub const DEFAULT_MAX_ACTIVE: u64 = 8;
/// Default grant budget when the profile names none. Ports the `?? 500` in
/// `grantPolicyFromInput`.
pub const DEFAULT_GRANT_BUDGET: u64 = 500;
/// The largest integer JS represents exactly (`Number.MAX_SAFE_INTEGER`);
/// every integer field is bounded by it.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// A field value that either has the expected shape or is kept raw so it can
/// be reported and refused. There is no JS counterpart: it carries the JS
/// fact that a policy field may hold any JSON value (`src/core/policy.js`,
/// `validate` and `intersect`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Checked<T> {
    /// The value has the expected shape (range checks are still `validate`'s).
    Valid(T),
    /// Anything else, verbatim (including `null` where `null` is not allowed).
    Invalid(serde_json::Value),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Checked<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = serde_json::Value::deserialize(d)?;
        Ok(
            match T::deserialize(crate::canon::js_numbers(raw.clone())) {
                Ok(value) => Checked::Valid(value),
                Err(_) => Checked::Invalid(raw),
            },
        )
    }
}

/// Deserialize a present field, so `null` becomes `Some(Checked::Invalid)`
/// rather than `None` for the fields where JS treats `null` as invalid (a
/// `budget: null` must refuse, not mean "no limit").
fn present<'de, D, T>(d: D) -> std::result::Result<Option<Checked<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Checked::<T>::deserialize(d).map(Some)
}

// Optional schema members are absent when omitted; an explicit null is not
// absence in the JS validators. Let Checked preserve those invalid objects.
pub(crate) fn non_null<'de, D, T>(d: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

/// An approval mode. Ports the values of `APPROVAL_ORDER` in
/// `src/core/policy.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Approval {
    /// `auto`
    Auto,
    /// `first-use`
    FirstUse,
    /// `on-write`
    OnWrite,
    /// `each`
    Each,
}

/// A SQL profile. Ports the values of `SQL_ORDER` in `src/core/policy.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SqlProfile {
    /// `read-only`
    ReadOnly,
    /// `read-write`
    ReadWrite,
    /// `raw`
    Raw,
}

/// An SSH mode. Ports the values of `SSH_MODE_ORDER` in `src/core/policy.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshMode {
    /// `run`
    Run,
    /// `agent`
    Agent,
}

/// A rate unit. Ports the keys of `PER_MS` in `src/core/policy.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PerUnit {
    /// `second`
    Second,
    /// `minute`
    Minute,
    /// `hour`
    Hour,
}

/// A quota window. Ports the keys of `WINDOW_MS` in `src/core/policy.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowUnit {
    /// `hour`
    Hour,
    /// `day`
    Day,
}

/// A sustained rate, `{ count, per }`. Ports the `rate` shape checked by
/// `validWindow` in `src/core/policy.js` (count 1..=1 000 000).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rate {
    /// Requests per unit.
    pub count: u64,
    /// The unit.
    pub per: PerUnit,
}

/// A quota, `{ count, window }`. Ports the `quota` shape checked by
/// `validWindow` in `src/core/policy.js` (count 1..=100 000 000).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quota {
    /// Requests per window.
    pub count: u64,
    /// The window.
    pub window: WindowUnit,
}

/// A budget limit as written: a number, or a canonical decimal string such
/// as `"50"`. Ports the values `budgetInteger` in `src/core/policy.js`
/// accepts before checking them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BudgetValue {
    /// A JSON number.
    Number(u64),
    /// A JSON string (valid only when canonical decimal).
    Text(String),
}

/// A request budget, `{ unit, limit }`. Ports the shape checked by
/// `validBudget` in `src/core/policy.js`: unit absent or `requests`, limit
/// absent or a safe non-negative integer. A legacy layer may state only the
/// unit.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    /// `requests`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "non_null"
    )]
    pub unit: Option<String>,
    /// The limit.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "non_null"
    )]
    pub limit: Option<BudgetValue>,
}

/// A spend limit, `{ tokens, usd_micros }`. Ports the shape checked by
/// `validSpend` in `src/core/policy.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spend {
    /// Token limit.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "non_null"
    )]
    pub tokens: Option<u64>,
    /// USD micros limit.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "non_null"
    )]
    pub usd_micros: Option<u64>,
}

/// Redirect following, `{ max }` with max 0..=5. Ports the shape checked by
/// `validRedirects` in `src/core/policy.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redirects {
    /// Most redirects followed.
    pub max: u64,
}

/// One allowed route, `{ methods, paths }`. Ports the pairs checked by
/// `validRoutes` in `src/core/policy.js` (1..=7 methods from [`METHODS`],
/// 1..=64 non-empty globs; at most 64 routes per set).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Methods.
    pub methods: Vec<String>,
    /// Path globs.
    pub paths: Vec<String>,
}

/// Placeholder limits, `{ max_uses, ttl, max_active }`, each a positive
/// integer. Ports the `placeholder_policy` shape in `src/core/policy.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaceholderPolicy {
    /// Uses per placeholder.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "non_null"
    )]
    pub max_uses: Option<u64>,
    /// Lifetime.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "non_null"
    )]
    pub ttl: Option<u64>,
    /// Live placeholders at once.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "non_null"
    )]
    pub max_active: Option<u64>,
}

/// One policy layer (credential ceiling, workspace, session or grant) or an
/// effective policy, as stored in the vault and accepted by
/// `validate`/`intersect`. Ports the policy object shape used throughout
/// `src/core/policy.js`; field names are the JS keys.
///
/// For `hosts`, `methods`, `paths`, `databases`, `rcpt` and `commands`,
/// absent and `null` both mean "no constraint at this level" (`None`). For
/// every other field `null` is kept as `Checked::Invalid(null)`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// Connector kind.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub kind: Option<Checked<String>>,
    /// Allowed host patterns (`*.example.com` wildcards).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Checked<Vec<String>>>,
    /// Allowed methods (intersect writes `false` here for an invalid layer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Checked<Vec<String>>>,
    /// Allowed path globs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Checked<Vec<String>>>,
    /// Denied path globs (concatenated across layers).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub deny_paths: Option<Checked<Vec<String>>>,
    /// Approval mode.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub approval: Option<Checked<Approval>>,
    /// SQL profile.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub sql_profile: Option<Checked<SqlProfile>>,
    /// SSH mode.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub mode: Option<Checked<SshMode>>,
    /// Sustained rate.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub rate: Option<Checked<Rate>>,
    /// Request budget (intersect writes `{ unit, invalid: true }` for an
    /// unreadable one).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub budget: Option<Checked<Budget>>,
    /// Spend limit (`{ invalid: true }` when unreadable).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub spend: Option<Checked<Spend>>,
    /// Placeholder limits.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub placeholder_policy: Option<Checked<PlaceholderPolicy>>,
    /// Concurrent requests, 1..=1024.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub max_concurrent: Option<Checked<u64>>,
    /// Quota.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub quota: Option<Checked<Quota>>,
    /// Redirect following.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub redirects: Option<Checked<Redirects>>,
    /// A writable layer's own routes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub routes: Option<Checked<Vec<Route>>>,
    /// Every layer's routes, outermost first (effective policies;
    /// `[null]` when a layer's routes were invalid).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub route_sets: Option<Checked<Vec<Vec<Route>>>>,
    /// A writable layer's own payload rules.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub payload: Option<Checked<PayloadRuleSet>>,
    /// Every layer's payload rules (effective policies; `[null]` when
    /// invalid).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub payload_sets: Option<Checked<Vec<PayloadRuleSet>>>,
    /// Allowed databases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub databases: Option<Checked<Vec<String>>>,
    /// Allowed mail recipients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcpt: Option<Checked<Vec<String>>>,
    /// Allowed commands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commands: Option<Checked<Vec<String>>>,
    /// GraphQL settings (any object; carried, outermost wins).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub graphql: Option<Checked<serde_json::Map<String, serde_json::Value>>>,
    /// Request-body streaming; on only when every layer agrees. Carried but
    /// not read: streaming is not implemented.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub stream_bodies: Option<Checked<bool>>,
    /// Any key the JS does not know; `validate` reports each as invalid.
    #[serde(flatten)]
    pub unknown: std::collections::BTreeMap<String, serde_json::Value>,
}

/// One validation problem. Ports the `{ field, message }` objects returned
/// by `validate` in `src/core/policy.js` and `validatePayload` in
/// `src/core/payload.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    /// The field (`routes` for `route_sets`, `payload` for `payload_sets`,
    /// `policy` for a non-object).
    pub field: String,
    /// E.g. `invalid <field>`.
    pub message: String,
}

/// Options for [`validate`] and [`lint`]. Ports the `{ kind } = {}` argument
/// of `validate` and `lint` in `src/core/policy.js`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidateOptions {
    /// The connector kind, when known (`spend` is valid only for metered
    /// kinds).
    pub kind: Option<String>,
}

/// Pure validation of a writable layer or a stored effective policy; empty
/// means valid. Ports `validate` in `src/core/policy.js`.
pub fn validate(layer: &Policy, opts: &ValidateOptions) -> Vec<Problem> {
    validate_raw(
        &serde_json::to_value(layer).expect("policy serializes"),
        opts,
    )
}

/// [`validate`] on raw JSON: a non-object is
/// `[{ field: 'policy', message: 'policy must be an object' }]`. Ports
/// `validate` in `src/core/policy.js` for callers holding unparsed input.
pub fn validate_json(layer: &serde_json::Value, opts: &ValidateOptions) -> Vec<Problem> {
    validate_raw(layer, opts)
}

/// Intersect a chain of layers, outermost (ceiling) first; `None` layers are
/// skipped. An invalid field poisons the result so evaluation refuses (see
/// the module docs). Ports `intersect` in `src/core/policy.js`.
pub fn intersect(layers: &[Option<&Policy>]) -> Policy {
    let mut out = serde_json::json!({});
    let mut invalid = serde_json::Map::new();
    for layer in layers.iter().flatten() {
        let mut v = serde_json::to_value(layer).expect("policy");
        for problem in validate(layer, &ValidateOptions::default()) {
            let f = problem.field;
            match f.as_str() {
                "redirects" => v["redirects"] = serde_json::json!({"max":0}),
                "budget" | "spend" => {
                    invalid.insert(f.clone(), serde_json::json!({"invalid":true}));
                    v.as_object_mut().unwrap().remove(&f);
                }
                "routes" | "payload" => {
                    let e = if f == "routes" {
                        "route_sets"
                    } else {
                        "payload_sets"
                    };
                    invalid.insert(e.into(), serde_json::json!([null]));
                    v.as_object_mut().unwrap().remove(&f);
                    v.as_object_mut().unwrap().remove(e);
                }
                _ => {
                    invalid.insert(f.clone(), v[&f].clone());
                    v.as_object_mut().unwrap().remove(&f);
                }
            }
        }
        out = intersect_raw(&out, &v);
    }
    out.as_object_mut().unwrap().extend(invalid);
    serde_json::from_value(out).expect("intersection policy shape")
}

/// A budget limit read as a whole number: a JSON integer or canonical
/// decimal string within the safe integers, else `None`. Ports
/// `budgetInteger` in `src/core/policy.js`.
pub fn budget_integer(value: &serde_json::Value) -> Option<u64> {
    let n = match value {
        serde_json::Value::Number(n) => n.as_u64().or_else(|| {
            n.as_f64()
                .filter(|n| {
                    n.is_finite() && *n >= 0.0 && n.fract() == 0.0 && *n <= MAX_SAFE_INTEGER as f64
                })
                .map(|n| n as u64)
        }),
        serde_json::Value::String(s)
            if s == "0"
                || (!s.starts_with('0')
                    && !s.is_empty()
                    && s.bytes().all(|b| b.is_ascii_digit())) =>
        {
            s.parse().ok()
        }
        _ => None,
    }?;
    (n <= MAX_SAFE_INTEGER).then_some(n)
}

/// One budget layer's request limit, as the gateway and the store read it.
/// Ports the three outcomes of `budgetLimit` in `src/core/policy.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetLimit {
    /// No limit stated (JS `Infinity`): no budget, or a unit-only layer.
    Unlimited,
    /// The stated whole number.
    Limit(u64),
    /// Cannot be read (JS `null`); refuses, never means "no limit".
    Unreadable,
}

/// Read one budget layer's request limit (C4). `None` is an absent budget.
/// Ports `budgetLimit` in `src/core/policy.js`.
pub fn budget_limit(budget: Option<&Checked<Budget>>) -> BudgetLimit {
    match budget {
        None => BudgetLimit::Unlimited,
        Some(Checked::Invalid(_)) => BudgetLimit::Unreadable,
        Some(Checked::Valid(b)) => {
            if b.unit.as_deref().is_some_and(|u| u != "requests") {
                return BudgetLimit::Unreadable;
            }
            match &b.limit {
                None => BudgetLimit::Unlimited,
                Some(v) => budget_integer(&serde_json::to_value(v).expect("budget"))
                    .map_or(BudgetLimit::Unreadable, BudgetLimit::Limit),
            }
        }
    }
}

/// Normalize a destination host before any grant match: trimmed,
/// lowercased, trailing dot dropped, parsed as a URL hostname. Refuses
/// (`AV_POLICY_DENIED`) an empty host, userinfo, `\`, NUL, or anything
/// unparseable. Ports `normalizeHost` in `src/core/policy.js`.
pub fn normalize_host(host: &str) -> Result<String> {
    if host.is_empty() {
        return Err(policy_deny("no destination host", None, None));
    }
    let h = host.trim().to_lowercase();
    if h.contains('@') {
        return Err(policy_deny("destination contains userinfo", None, None));
    }
    if h.contains(['\\', '\0']) {
        return Err(policy_deny(
            "destination contains an illegal character",
            None,
            None,
        ));
    }
    let h = h.strip_suffix('.').unwrap_or(&h);
    url::Url::parse(&format!("https://{h}"))
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .ok_or_else(|| policy_deny(format!("unparseable host: {host}"), None, None))
}

/// Characters left bare in a wire path segment (RFC 3986 pchar). Ports
/// `PCHAR_SAFE` in `src/core/policy.js`.
pub const PCHAR_SAFE_PATTERN: &str = "[A-Za-z0-9\\-._~!$&'()*+,;=:@]";

/// Percent-encode one decided path segment for the wire: everything outside
/// pchar, as uppercase `%XX` of its UTF-8 bytes. Ports `encodePathSegment` in
/// `src/core/policy.js`.
pub fn encode_path_segment(segment: &str) -> String {
    let mut out = String::new();
    for b in segment.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A whole decided path for the wire, segment by segment. Ports
/// `encodePathForWire` in `src/core/policy.js`.
pub fn encode_path_for_wire(path: &str) -> String {
    path.split('/')
        .map(encode_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

/// The path a request names, decoded exactly once and normalized (`?`/`#`
/// cut, `.` and `..` resolved), or a refusal: invalid escape, encoded slash
/// or backslash (`path_ambiguous_separator`), an escape that still decodes
/// (`path_ambiguous_encoding`), a control character (`path_control_char`),
/// traversal above the root. An empty path is `/`. Ports `normalizePath` in
/// `src/core/policy.js`.
pub fn normalize_path(path: &str) -> Result<String> {
    let raw = if path.is_empty() { "/" } else { path };
    let p = strict_percent_decode(raw)
        .ok_or_else(|| policy_deny("path contains an invalid percent-escape", None, None))?;
    let sep = crate::jsre::compile(r"(?i)%2f|%5c|\\").expect("fixed regex");
    if sep.is_match(raw) || sep.is_match(&p) {
        return Err(policy_deny("path contains an encoded slash or a backslash",Some("path_ambiguous_separator"),Some("Whether that names one segment or two depends on the upstream, so the path checked here may not be the path served.")));
    }
    if crate::jsre::compile(r"(?i)%(?:[0-9a-f]{2}|u[0-9a-f]{4})")
        .expect("fixed regex")
        .is_match(&p)
    {
        return Err(policy_deny("path is percent-encoded too many times: decoding it again would change it",Some("path_ambiguous_encoding"),Some("An upstream that decodes the path twice would serve a different path from the one checked here. Encode the path once.")));
    }
    let p = p.split(['?', '#']).next().unwrap_or("");
    if let Some(b) = p.bytes().find(|b| *b < 32 || *b == 127) {
        return Err(policy_deny(format!("path contains a control character (0x{b:02x})"),Some("path_control_char"),Some("A URL parser strips or reinterprets these, so the path checked here would not be the path requested.")));
    }
    let mut segments = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    return Err(policy_deny("path traverses above its root", None, None));
                }
            }
            _ => segments.push(seg),
        }
    }
    Ok(format!("/{}", segments.join("/")))
}

/// Segment-wise glob match (`*` within a segment, `**` across segments),
/// linear time with no backtracking. Ports `matchPath` in
/// `src/core/policy.js`.
pub fn match_path(pattern: &str, path: &str) -> bool {
    glob_segments(pattern, path, false)
}

/// Exact host match, or `*.suffix` matching a strictly longer host. Ports
/// `matchHost` in `src/core/policy.js`.
pub fn match_host(pattern: &str, host: &str) -> bool {
    pattern == host
        || pattern
            .strip_prefix("*.")
            .is_some_and(|s| host.ends_with(&format!(".{s}")) && host.len() > s.len() + 1)
}

/// The hosts a credential may ever reach: its connector host plus the
/// profile's hosts, each reduced to a lowercase hostname without port or
/// trailing dot, de-duplicated. Ports `credentialHostCeiling` in
/// `src/core/policy.js` (`cred.connector.host` is passed directly).
pub fn credential_host_ceiling(
    connector_host: Option<&str>,
    profile_hosts: &[String],
) -> Vec<String> {
    let mut out = Vec::new();
    for h in connector_host
        .into_iter()
        .chain(profile_hosts.iter().map(String::as_str))
    {
        let mut h = h.to_lowercase();
        if h.starts_with('[') {
            h = h.find(']').map_or(String::new(), |end| h[..=end].into());
        } else {
            let name = h.split(':').next().unwrap_or("");
            h = name.strip_suffix('.').unwrap_or(name).into();
        }
        if !h.is_empty() && !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

/// Hostname only: lowercased, trimmed, port and trailing dot removed, IPv6
/// brackets kept. Ports `hostOnly` in `src/core/policy.js`.
pub fn host_only(authority: &str) -> String {
    let h = authority.trim().to_lowercase();
    if h.starts_with('[') {
        return h.find(']').map_or(String::new(), |end| h[..=end].into());
    }
    let name = h.split(':').next().unwrap_or("");
    name.strip_suffix('.').unwrap_or(name).into()
}

/// Confine requested hosts to a credential's ceiling; `None` or empty means
/// the whole ceiling. Refuses (`credential_host`) an empty ceiling or a host
/// outside it. Ports `confineHosts` in `src/core/policy.js`.
pub fn confine_hosts(requested: Option<&[String]>, ceiling: &[String]) -> Result<Vec<String>> {
    if ceiling.is_empty() {
        return Err(policy_deny(
            "this credential declares no host it may reach",
            Some("credential_host"),
            None,
        ));
    }
    let Some(requested) = requested.filter(|r| !r.is_empty()) else {
        return Ok(ceiling.to_vec());
    };
    let mut out = Vec::new();
    for req in requested {
        let h = host_only(req);
        if !ceiling.iter().any(|c| match_host(c, &h)) {
            return Err(policy_deny(
                format!(
                    "host {h} is outside what credential permits ({})",
                    ceiling.join(", ")
                ),
                Some("credential_host"),
                Some("A grant can only reach the hosts the credential itself declares."),
            ));
        }
        if !out.contains(&h) {
            out.push(h);
        }
    }
    Ok(out)
}

/// True when a `*.` pattern spans a shared multi-tenant suffix. Ports
/// `isMultiTenantWildcard` in `src/core/policy.js`.
pub fn is_multi_tenant_wildcard(pattern: &str) -> bool {
    pattern.strip_prefix("*.").is_some_and(|suffix| {
        MULTI_TENANT_SUFFIXES
            .iter()
            .any(|s| suffix == *s || suffix.ends_with(&format!(".{s}")))
    })
}

/// The request line [`evaluate_http`] checks. Ports the
/// `{ method, host, path }` argument of `evaluateHttp` in
/// `src/core/policy.js`.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpTarget<'a> {
    /// Method (`GET` when absent).
    pub method: Option<&'a str>,
    /// Destination host, before normalization.
    pub host: &'a str,
    /// Path, before normalization.
    pub path: &'a str,
}

/// What allowed a request. Ports the
/// `{ host, path, method, path_rule, route_rule }` object returned by
/// `evaluateHttp` in `src/core/policy.js`. Rules are named by index, never by
/// their text (C27).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpDecision {
    /// Normalized host.
    pub host: String,
    /// Normalized path.
    pub path: String,
    /// Uppercased method.
    pub method: String,
    /// Index of the `paths` glob that matched, if `paths` is set.
    pub path_rule: Option<usize>,
    /// Index of the matching route in the innermost route set, if any.
    pub route_rule: Option<usize>,
}

/// Evaluate an HTTP request against an effective policy. Refuses with
/// `AV_NO_GRANT` (rule `hosts`) or `AV_POLICY_DENIED` (rules
/// `<field>_invalid`, `methods`, `deny_paths:<i>`, `paths`, `routes`, or a
/// normalization rule). Ports `evaluateHttp` in `src/core/policy.js`.
pub fn evaluate_http(policy: &Policy, target: &HttpTarget<'_>) -> Result<HttpDecision> {
    for problem in validate(policy, &Default::default()) {
        if problem.field == "redirects" {
            continue;
        }
        return Err(policy_deny(
            if problem.field == "budget" {
                "budget limit is not a number in the accepted integer format".into()
            } else {
                format!("invalid policy field {}", problem.field)
            },
            Some(&format!("{}_invalid", problem.field)),
            None,
        ));
    }
    let m = target
        .method
        .filter(|s| !s.is_empty())
        .unwrap_or("GET")
        .to_uppercase();
    let h = normalize_host(target.host)?;
    let p = normalize_path(target.path)?;
    if let Some(Checked::Valid(hosts)) = &policy.hosts {
        if !hosts.iter().any(|pat| match_host(pat, &h)) {
            return Err(crate::errors::deny(
                crate::errors::ErrorCode::NoGrant,
                format!("no grant allows host {h}"),
                crate::errors::DenyExtra {
                    rule: Some("hosts".into()),
                    hint: Some(if hosts.is_empty() {
                        "This session has no host grants at all.".into()
                    } else {
                        format!("This session may reach: {}.", hosts.join(", "))
                    }),
                    ..Default::default()
                },
            ));
        }
    }
    if let Some(Checked::Valid(methods)) = &policy.methods {
        if !methods.contains(&m) {
            return Err(policy_deny(
                format!("method {m} is not allowed"),
                Some("methods"),
                Some(&format!(
                    "Allowed methods: {}.",
                    if methods.is_empty() {
                        "none".into()
                    } else {
                        methods.join(", ")
                    }
                )),
            ));
        }
    }
    if let Some(Checked::Valid(deny)) = &policy.deny_paths {
        for (i, dp) in deny.iter().enumerate() {
            if match_path(dp, &p) {
                return Err(policy_deny(
                    format!("path {p} is on a deny list"),
                    Some(&format!("deny_paths:{i}")),
                    Some("This path is denied by the connector profile and cannot be granted."),
                ));
            }
        }
    }
    let mut path_rule = None;
    if let Some(Checked::Valid(paths)) = &policy.paths {
        path_rule = paths.iter().position(|pat| match_path(pat, &p));
        if path_rule.is_none() {
            return Err(policy_deny(
                format!("path {p} is outside the grant"),
                Some("paths"),
                Some(&format!(
                    "Allowed paths: {}.",
                    if paths.is_empty() {
                        "none".into()
                    } else {
                        paths.join(", ")
                    }
                )),
            ));
        }
    }
    let sets = route_sets(policy);
    let mut route_rule = None;
    for set in sets {
        let i = set.iter().position(|pair| {
            pair.methods.contains(&m) && pair.paths.iter().any(|g| match_path(g, &p))
        });
        if i.is_none() {
            return Err(policy_deny(
                "request is outside the allowed routes",
                Some("routes"),
                Some(&format!(
                    "Allowed here: {}",
                    set.iter()
                        .flat_map(|pair| pair.methods.iter().flat_map(|method| pair
                            .paths
                            .iter()
                            .map(move |glob| format!("{method} {glob}"))))
                        .collect::<Vec<_>>()
                        .join(" | ")
                )),
            ));
        }
        route_rule = i;
    }
    Ok(HttpDecision {
        host: h,
        path: p,
        method: m,
        path_rule,
        route_rule,
    })
}

/// Input to [`needs_approval`]. Ports the `{ method, firstUse }` argument of
/// `needsApproval` in `src/core/policy.js`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApprovalQuery<'a> {
    /// Method (`GET` when absent).
    pub method: Option<&'a str>,
    /// First use of this grant.
    pub first_use: bool,
}

/// Whether the request needs a human approval: `auto` never, `first-use` on
/// first use, `on-write` for unsafe methods, `each` and anything unknown
/// always. Ports `needsApproval` in `src/core/policy.js`.
pub fn needs_approval(policy: &Policy, query: &ApprovalQuery<'_>) -> bool {
    match &policy.approval {
        None | Some(Checked::Valid(Approval::Auto)) => false,
        Some(Checked::Valid(Approval::FirstUse)) => query.first_use,
        Some(Checked::Valid(Approval::OnWrite)) => !SAFE_METHODS.contains(
            &query
                .method
                .filter(|m| !m.is_empty())
                .unwrap_or("GET")
                .to_uppercase()
                .as_str(),
        ),
        _ => true,
    }
}

/// Severity of a lint finding. Ports the `level` strings of `lint` in
/// `src/core/policy.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LintLevel {
    /// `error`
    Error,
    /// `warn`
    Warn,
}

/// One lint finding. Ports the `{ level, rule, message }` objects returned
/// by `lint` in `src/core/policy.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LintProblem {
    /// Severity.
    pub level: LintLevel,
    /// The field or rule.
    pub rule: String,
    /// Explanation.
    pub message: String,
}

/// Static checks run before a policy is stored (`policy lint`): missing
/// budget, multi-tenant wildcards, root `**`, low `max_uses`, writes on
/// `auto`, every `validate` problem, and write routes over every path. Ports
/// `lint` in `src/core/policy.js`.
pub fn lint(policy: &Policy, opts: &ValidateOptions) -> Vec<LintProblem> {
    let mut problems = Vec::new();
    let mut add = |level, rule: &str, message: String| {
        problems.push(LintProblem {
            level,
            rule: rule.into(),
            message,
        })
    };
    if !matches!(
        &policy.budget,
        Some(Checked::Valid(Budget { limit: Some(_), .. }))
    ) {
        add(
            LintLevel::Error,
            "budget",
            "every grant must set a budget; add budget: { requests: N }".into(),
        );
    }
    if let Some(Checked::Valid(hosts)) = &policy.hosts {
        for h in hosts {
            if is_multi_tenant_wildcard(h) {
                add(
                    LintLevel::Error,
                    "hosts",
                    format!("{h} spans a shared multi-tenant suffix; name exact hosts"),
                );
            }
        }
    }
    if let Some(Checked::Valid(paths)) = &policy.paths {
        for p in paths {
            if p == "/**" || p == "**" {
                add(
                    LintLevel::Warn,
                    "paths",
                    "a root ** grant allows every path this connector permits".into(),
                );
            }
        }
    }
    if let Some(Checked::Valid(ph)) = &policy.placeholder_policy {
        if ph.max_uses.is_some_and(|n| n < 100)
            && opts
                .kind
                .as_deref()
                .is_some_and(|k| ["http", "github", "slack"].contains(&k))
        {
            add(LintLevel::Warn,"placeholder_policy","a low max_uses breaks SDK pagination and retries; session-lifetime is the default for a reason".into());
        }
    }
    if matches!(&policy.methods,Some(Checked::Valid(m)) if m.iter().any(|x|!SAFE_METHODS.contains(&x.as_str())))
        && matches!(policy.approval, None | Some(Checked::Valid(Approval::Auto)))
    {
        add(
            LintLevel::Warn,
            "approval",
            "write methods with approval: auto; on-write is the default for a reason".into(),
        );
    }
    for p in validate(policy, opts) {
        add(LintLevel::Error, &p.field, p.message);
    }
    for set in route_sets(policy) {
        if set.iter().any(|r| {
            r.methods
                .iter()
                .any(|m| !SAFE_METHODS.contains(&m.as_str()))
                && r.paths.iter().any(|p| p == "/**" || p == "**")
        }) {
            add(
                LintLevel::Warn,
                "routes",
                "write route permits every path".into(),
            );
        }
    }
    problems
}

/// [`lint`] on raw JSON; a non-object yields the `validate` errors. Ports
/// `lint` in `src/core/policy.js` for callers holding unparsed input.
pub fn lint_json(policy: &serde_json::Value, opts: &ValidateOptions) -> Vec<LintProblem> {
    if !policy.is_object() {
        return validate_json(policy, opts)
            .into_iter()
            .map(|p| LintProblem {
                level: LintLevel::Error,
                rule: p.field,
                message: p.message,
            })
            .collect();
    }
    match serde_json::from_value(policy.clone()) {
        Ok(p) => lint(&p, opts),
        Err(_) => validate_json(policy, opts)
            .into_iter()
            .map(|p| LintProblem {
                level: LintLevel::Error,
                rule: p.field,
                message: p.message,
            })
            .collect(),
    }
}

/// The host ceiling for [`grant_policy_from_input`]. Ports the `ceiling`
/// option of `grantPolicyFromInput` in `src/core/policy.js`, which is either
/// a host array or a layer whose `hosts` is read (falling back to the
/// profile's ceiling hosts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantCeiling {
    /// A host list (the JS default is `[]`).
    Hosts(Vec<String>),
    /// A layer: its `hosts`, or the profile ceiling's when `None`.
    Layer {
        /// The layer's hosts.
        hosts: Option<Vec<String>>,
    },
}

impl Default for GrantCeiling {
    fn default() -> Self {
        GrantCeiling::Hosts(Vec::new())
    }
}

/// Options for [`grant_policy_from_input`]. Ports
/// `{ profile = {}, ceiling = [], defaults = true }` in `src/core/policy.js`.
#[derive(Debug, Clone)]
pub struct GrantPolicyOptions<'a> {
    /// The credential's profile (`kind`, ceiling hosts, default budget).
    pub profile: Option<&'a Profile>,
    /// The host ceiling.
    pub ceiling: GrantCeiling,
    /// Fill in defaults (hosts, `GET`/`HEAD`, `/**`, `on-write`, budget,
    /// `redirects: {max: 0}`) for fields the input omits.
    pub defaults: bool,
}

impl Default for GrantPolicyOptions<'_> {
    fn default() -> Self {
        GrantPolicyOptions {
            profile: None,
            ceiling: GrantCeiling::default(),
            defaults: true,
        }
    }
}

/// Convert the public grant input (a JSON object from the control API or
/// MCP: `hosts, methods, paths, approval, budget, deny_paths, max_concurrent,
/// routes, payload, sql_profile, mode, databases, rcpt, commands, graphql,
/// stream_bodies, placeholder_policy, rate, quota, redirects, spend_tokens,
/// spend_usd`) to a policy layer, without mutating it. Rates and quotas may be
/// strings like `"10/min"`. Refuses `credential_host` or `policy_invalid`.
/// Ports `grantPolicyFromInput` in `src/core/policy.js`.
pub fn grant_policy_from_input(
    spec: &serde_json::Value,
    opts: &GrantPolicyOptions<'_>,
) -> Result<Policy> {
    grant_from_raw(spec, opts)
}

/// The budget as described publicly. Ports the `budget` value built by
/// `describeEffective` in `src/core/policy.js`
/// (`{ limit: null, invalid: true }` or `{ limit }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescribedBudget {
    /// The limit as stored (`null` when none or invalid).
    pub limit: Option<serde_json::Value>,
    /// Present (true) only for an unreadable budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalid: Option<bool>,
}

/// A detached, public description of an effective policy with no runtime
/// counters or secrets. Every key is always present (`null` when unset).
/// Ports the object returned by `describeEffective` in `src/core/policy.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EffectiveDescription {
    /// Hosts.
    pub hosts: Option<Checked<Vec<String>>>,
    /// Methods.
    pub methods: Option<Checked<Vec<String>>>,
    /// Paths.
    pub paths: Option<Checked<Vec<String>>>,
    /// Denied paths.
    pub deny_paths: Option<Checked<Vec<String>>>,
    /// Approval mode.
    pub approval: Option<Checked<Approval>>,
    /// Spend.
    pub spend: Option<Checked<Spend>>,
    /// Rate.
    pub rate: Option<Checked<Rate>>,
    /// Max concurrent.
    pub max_concurrent: Option<Checked<u64>>,
    /// Quota.
    pub quota: Option<Checked<Quota>>,
    /// `route_sets`, or `[routes]`, or `[]`.
    pub routes: Checked<Vec<Vec<Route>>>,
    /// `payload_sets`, or `[payload]`, or `[]`.
    pub payload: Checked<Vec<PayloadRuleSet>>,
    /// Budget.
    pub budget: Option<DescribedBudget>,
    /// Redirects when valid, else `{ max: 0 }`.
    pub redirects: Redirects,
}

/// Describe an effective policy for an agent or the UI. Ports
/// `describeEffective` in `src/core/policy.js`.
pub fn describe_effective(effective: &Policy) -> EffectiveDescription {
    EffectiveDescription {
        hosts: effective.hosts.clone(),
        methods: effective.methods.clone(),
        paths: effective.paths.clone(),
        deny_paths: effective.deny_paths.clone(),
        approval: effective.approval.clone(),
        spend: effective.spend.clone(),
        rate: effective.rate.clone(),
        max_concurrent: effective.max_concurrent.clone(),
        quota: effective.quota.clone(),
        routes: effective
            .route_sets
            .clone()
            .unwrap_or_else(|| match &effective.routes {
                Some(Checked::Valid(r)) => Checked::Valid(vec![r.clone()]),
                Some(Checked::Invalid(v)) => Checked::Invalid(serde_json::json!([v])),
                None => Checked::Valid(vec![]),
            }),
        payload: effective
            .payload_sets
            .clone()
            .unwrap_or_else(|| match &effective.payload {
                Some(Checked::Valid(p)) => Checked::Valid(vec![p.clone()]),
                Some(Checked::Invalid(v)) => Checked::Invalid(serde_json::json!([v])),
                None => Checked::Valid(vec![]),
            }),
        budget: effective.budget.as_ref().map(|b| match b {
            Checked::Invalid(_) => DescribedBudget {
                limit: None,
                invalid: Some(true),
            },
            Checked::Valid(b) => DescribedBudget {
                limit: b
                    .limit
                    .as_ref()
                    .map(|v| serde_json::to_value(v).expect("budget")),
                invalid: None,
            },
        }),
        redirects: match effective.redirects {
            Some(Checked::Valid(r)) if r.max <= 5 => r,
            _ => Redirects { max: 0 },
        },
    }
}

fn policy_deny(
    detail: impl Into<String>,
    rule: Option<&str>,
    hint: Option<&str>,
) -> crate::errors::VaultError {
    crate::errors::deny(
        crate::errors::ErrorCode::PolicyDenied,
        detail,
        crate::errors::DenyExtra {
            rule: rule.map(str::to_owned),
            hint: hint.map(str::to_owned),
            ..Default::default()
        },
    )
}
fn strict_percent_decode(s: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s.as_bytes()[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            bytes.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            bytes.push(s.as_bytes()[i]);
            i += 1;
        }
    }
    String::from_utf8(bytes).ok()
}
fn match_segment(pattern: &str, segment: &str) -> bool {
    let p: Vec<_> = pattern.encode_utf16().collect();
    let s: Vec<_> = segment.encode_utf16().collect();
    let mut dp = vec![false; s.len() + 1];
    dp[0] = true;
    for c in p {
        if c == 42 {
            let mut seen = false;
            for v in &mut dp {
                seen |= *v;
                *v = seen;
            }
        } else {
            for j in (0..=s.len()).rev() {
                dp[j] = j > 0 && dp[j - 1] && s[j - 1] == c;
            }
        }
    }
    dp[s.len()]
}
fn glob_segments(pattern: &str, path: &str, containment: bool) -> bool {
    let pats: Vec<_> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let segs: Vec<_> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut dp = vec![false; segs.len() + 1];
    dp[0] = true;
    for pat in pats {
        let mut next = vec![false; segs.len() + 1];
        if pat == "**" {
            let mut seen = false;
            for j in 0..=segs.len() {
                seen |= dp[j];
                next[j] = seen;
            }
        } else {
            for j in 1..=segs.len() {
                let seg = segs[j - 1];
                let yes = if containment {
                    pat == seg
                        || (!seg.contains('*') && match_segment(pat, seg))
                        || (pat == "*" && seg != "**")
                } else {
                    match_segment(pat, seg)
                };
                next[j] = dp[j - 1] && yes;
            }
        }
        dp = next;
    }
    dp[segs.len()]
}
fn route_sets(p: &Policy) -> Vec<&[Route]> {
    match &p.route_sets {
        Some(Checked::Valid(sets)) => sets.iter().map(Vec::as_slice).collect(),
        _ => match &p.routes {
            Some(Checked::Valid(r)) => vec![r.as_slice()],
            _ => vec![],
        },
    }
}
fn validate_raw(layer: &serde_json::Value, opts: &ValidateOptions) -> Vec<Problem> {
    use serde_json::Value as V;
    let Some(o) = layer.as_object() else {
        return vec![Problem {
            field: "policy".into(),
            message: "policy must be an object".into(),
        }];
    };
    let mut problems = Vec::new();
    let keys = |v: &V, allowed: &[&str]| {
        v.as_object()
            .is_some_and(|o| o.keys().all(|k| allowed.contains(&k.as_str())))
    };
    let int = |v: &V, min: u64, max: u64| {
        v.is_number() && budget_integer(v).is_some_and(|n| n >= min && n <= max)
    };
    let strings = |v: &V| {
        v.as_array()
            .is_some_and(|a| a.iter().all(|v| v.as_str().is_some_and(|s| !s.is_empty())))
    };
    let routes = |v: &V| {
        v.as_array().is_some_and(|a| {
            a.len() <= 64
                && a.iter().all(|p| {
                    keys(p, &["methods", "paths"])
                        && strings(&p["methods"])
                        && p["methods"].as_array().is_some_and(|m| {
                            !m.is_empty()
                                && m.len() <= 7
                                && m.iter()
                                    .all(|m| METHODS.contains(&m.as_str().unwrap_or("")))
                        })
                        && strings(&p["paths"])
                        && p["paths"]
                            .as_array()
                            .is_some_and(|a| !a.is_empty() && a.len() <= 64)
                })
        })
    };
    for (field, value) in o {
        if ["hosts", "methods", "paths", "databases", "rcpt", "commands"].contains(&field.as_str())
            && value.is_null()
        {
            continue;
        }
        let (name, ok) = match field.as_str() {
            "kind" => (
                field.as_str(),
                value.as_str().is_some_and(|s| !s.is_empty()),
            ),
            "hosts" | "paths" | "deny_paths" | "databases" | "rcpt" | "commands" => {
                (field.as_str(), strings(value))
            }
            "methods" => (
                field.as_str(),
                strings(value)
                    && value
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|m| METHODS.contains(&m.as_str().unwrap_or(""))),
            ),
            "approval" => (
                field.as_str(),
                value.as_str().is_some_and(|s| APPROVAL_ORDER.contains(&s)),
            ),
            "sql_profile" => (
                field.as_str(),
                value.as_str().is_some_and(|s| SQL_ORDER.contains(&s)),
            ),
            "mode" => (
                field.as_str(),
                value.as_str().is_some_and(|s| SSH_MODE_ORDER.contains(&s)),
            ),
            "budget" => (
                field.as_str(),
                keys(value, &["unit", "limit"])
                    && value.get("unit").is_none_or(|v| v == "requests")
                    && value
                        .get("limit")
                        .is_none_or(|v| budget_integer(v).is_some()),
            ),
            "spend" => (
                field.as_str(),
                keys(value, &["tokens", "usd_micros"])
                    && value
                        .as_object()
                        .unwrap()
                        .values()
                        .all(|v| int(v, 0, MAX_SAFE_INTEGER)),
            ),
            "rate" => (
                field.as_str(),
                keys(value, &["count", "per"])
                    && int(&value["count"], 1, RATE_COUNT_MAX)
                    && value["per"]
                        .as_str()
                        .is_some_and(|u| PER_MS.iter().any(|(s, _)| *s == u)),
            ),
            "quota" => (
                field.as_str(),
                keys(value, &["count", "window"])
                    && int(&value["count"], 1, QUOTA_COUNT_MAX)
                    && value["window"]
                        .as_str()
                        .is_some_and(|u| WINDOW_MS.iter().any(|(s, _)| *s == u)),
            ),
            "max_concurrent" => (field.as_str(), int(value, 1, MAX_CONCURRENT_MAX)),
            "redirects" => (
                field.as_str(),
                keys(value, &["max"]) && int(&value["max"], 0, 5),
            ),
            "routes" => (field.as_str(), routes(value)),
            "route_sets" => (
                "routes",
                value.as_array().is_some_and(|a| a.iter().all(routes)),
            ),
            "payload" => (field.as_str(), valid_payload_raw(value)),
            "payload_sets" => (
                "payload",
                value
                    .as_array()
                    .is_some_and(|a| a.iter().all(valid_payload_raw)),
            ),
            "stream_bodies" => (field.as_str(), value.is_boolean()),
            "graphql" => (field.as_str(), value.is_object()),
            "placeholder_policy" => (
                field.as_str(),
                keys(value, &["max_uses", "ttl", "max_active"])
                    && value
                        .as_object()
                        .unwrap()
                        .values()
                        .all(|v| int(v, 1, MAX_SAFE_INTEGER)),
            ),
            _ => (field.as_str(), false),
        };
        if !ok {
            problems.push(Problem {
                field: name.into(),
                message: format!("invalid {name}"),
            });
        }
    }
    if o.contains_key("spend")
        && opts
            .kind
            .as_deref()
            .is_some_and(|k| !["anthropic", "openai", "google-genai"].contains(&k))
    {
        problems.push(Problem {
            field: "spend".into(),
            message: "spend applies only to anthropic, openai and google-genai".into(),
        });
    }
    problems
}
fn valid_payload_raw(v: &serde_json::Value) -> bool {
    // Typed rule shapes carry invalid inputs explicitly.
    // Full payload validation is shared with the payload module.
    crate::payload::validate_payload(v).is_empty()
}
fn intersect_raw(a: &serde_json::Value, b: &serde_json::Value) -> serde_json::Value {
    use serde_json::{json, Value as V};
    let mut out = serde_json::Map::new();
    let min = |a: &V, b: &V| {
        if a.is_null() {
            b.clone()
        } else if b.is_null() || a.as_f64() <= b.as_f64() {
            a.clone()
        } else {
            b.clone()
        }
    };
    for key in ["kind", "graphql"] {
        let v = if a[key].is_null() { &b[key] } else { &a[key] };
        if !v.is_null() {
            out.insert(key.into(), v.clone());
        }
    }
    for key in ["hosts", "paths", "methods", "databases", "rcpt", "commands"] {
        let v = match (a[key].as_array(), b[key].as_array()) {
            (None, None) => V::Null,
            (Some(a), None) => V::Array(a.clone()),
            (None, Some(b)) => V::Array(b.clone()),
            (Some(aa), Some(bb)) => {
                let allows = |x: &V, y: &V| {
                    let x = x.as_str().unwrap_or("");
                    let y = y.as_str().unwrap_or("");
                    match key {
                        "hosts" => x == y || (x.starts_with("*.") && y.ends_with(&x[1..])),
                        "paths" => glob_segments(x, y, true),
                        _ => x == y,
                    }
                };
                let mut keep = Vec::new();
                if key == "hosts" || key == "paths" {
                    for x in bb {
                        if aa.iter().any(|y| allows(y, x)) && !keep.contains(x) {
                            keep.push(x.clone());
                        }
                    }
                    for x in aa {
                        if bb.iter().any(|y| allows(y, x)) && !keep.contains(x) {
                            keep.push(x.clone());
                        }
                    }
                } else {
                    keep.extend(aa.iter().filter(|x| bb.contains(x)).cloned());
                }
                V::Array(keep)
            }
        };
        out.insert(key.into(), v);
    }
    for key in ["deny_paths", "route_sets", "payload_sets"] {
        let mut v = a[key].as_array().cloned().unwrap_or_default();
        v.extend(b[key].as_array().cloned().unwrap_or_default());
        let own = match key {
            "route_sets" => Some("routes"),
            "payload_sets" => Some("payload"),
            _ => None,
        };
        if let Some(own) = own {
            if !b[own].is_null() {
                v.push(b[own].clone());
            }
        }
        out.insert(key.into(), v.into());
    }
    for (key, order, stricter) in [
        ("approval", APPROVAL_ORDER, true),
        ("sql_profile", SQL_ORDER, false),
        ("mode", SSH_MODE_ORDER, false),
    ] {
        let v = if a[key].is_null() {
            b[key].clone()
        } else if b[key].is_null() {
            a[key].clone()
        } else {
            let ai = order
                .iter()
                .position(|x| Some(*x) == a[key].as_str())
                .unwrap_or(usize::MAX);
            let bi = order
                .iter()
                .position(|x| Some(*x) == b[key].as_str())
                .unwrap_or(usize::MAX);
            if (stricter && ai >= bi) || (!stricter && ai <= bi) {
                a[key].clone()
            } else {
                b[key].clone()
            }
        };
        if !v.is_null() {
            out.insert(key.into(), v);
        }
    }
    for key in ["rate", "quota"] {
        let unit = if key == "rate" { "per" } else { "window" };
        let units = if key == "rate" { PER_MS } else { WINDOW_MS };
        let v = if a[key].is_null() {
            b[key].clone()
        } else if b[key].is_null() {
            a[key].clone()
        } else {
            let duration = |v: &V| {
                units
                    .iter()
                    .find(|(u, _)| Some(*u) == v[unit].as_str())
                    .map_or(1., |(_, n)| *n as f64)
            };
            let ac = a[key]["count"].as_f64().unwrap_or(0.);
            let bc = b[key]["count"].as_f64().unwrap_or(0.);
            let ar = ac / duration(&a[key]);
            let br = bc / duration(&b[key]);
            if ar < br || (ar == br && ac <= bc) {
                a[key].clone()
            } else {
                b[key].clone()
            }
        };
        if !v.is_null() {
            out.insert(key.into(), v);
        }
    }
    {
        let key = "max_concurrent";
        let v = min(&a[key], &b[key]);
        if !v.is_null() {
            out.insert(key.into(), v);
        }
    }
    if !a["budget"].is_null() || !b["budget"].is_null() {
        let aa = budget_integer(&a["budget"]["limit"]);
        let bb = budget_integer(&b["budget"]["limit"]);
        let n = match (aa, bb) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let mut v = json!({"unit":"requests"});
        if let Some(n) = n {
            v["limit"] = n.into();
        }
        out.insert("budget".into(), v);
    }
    for (key, fields) in [
        ("spend", &["tokens", "usd_micros"][..]),
        ("placeholder_policy", &["max_uses", "ttl", "max_active"][..]),
        ("redirects", &["max"][..]),
    ] {
        if a[key].is_null() && b[key].is_null() {
            continue;
        }
        let mut v = serde_json::Map::new();
        for f in fields {
            let mut aa = a[key][*f].clone();
            let mut bb = b[key][*f].clone();
            if key == "placeholder_policy"
                && *f == "max_active"
                && !a[key].is_null()
                && !b[key].is_null()
            {
                if aa.is_null() {
                    aa = 8.into();
                }
                if bb.is_null() {
                    bb = 8.into();
                }
            }
            let n = min(&aa, &bb);
            if !n.is_null() {
                v.insert((*f).into(), n);
            }
        }
        out.insert(key.into(), V::Object(v));
    }
    out.insert(
        "stream_bodies".into(),
        json!(
            a["stream_bodies"].as_bool().unwrap_or(false)
                && b["stream_bodies"].as_bool().unwrap_or(false)
        ),
    );
    V::Object(out)
}
fn grant_from_raw(spec: &serde_json::Value, opts: &GrantPolicyOptions<'_>) -> Result<Policy> {
    use serde_json::{json, Value as V};
    let has = |k: &str| spec.get(k).is_some();
    let mut out = json!({});
    let profile_hosts = opts
        .profile
        .map_or(vec![], |p| p.hosts.iter().map(|s| s.to_string()).collect());
    let ceiling = match &opts.ceiling {
        GrantCeiling::Hosts(h) => h,
        GrantCeiling::Layer { hosts } => hosts.as_ref().unwrap_or(&profile_hosts),
    };
    if opts.defaults || has("hosts") {
        let requested: Option<Vec<String>> = spec
            .get("hosts")
            .filter(|v| !v.is_null())
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|_| policy_deny("invalid policy field hosts", Some("policy_invalid"), None))?;
        out["hosts"] = json!(confine_hosts(requested.as_deref(), ceiling)?);
    }
    for (k, fallback) in [
        ("methods", json!(["GET", "HEAD"])),
        ("paths", json!(["/**"])),
        ("approval", json!("on-write")),
    ] {
        if opts.defaults || has(k) {
            out[k] = spec.get(k).cloned().unwrap_or(fallback);
        }
    }
    if opts.defaults || has("budget") {
        out["budget"] = json!({"unit":opts.profile.map_or("requests",|p|p.default_budget.unit),"limit":if has("budget"){budget_integer(&spec["budget"]).map_or_else(||spec["budget"].clone(),V::from)}else{opts.profile.map_or(500,|p|p.default_budget.limit).into()}});
    }
    for k in [
        "deny_paths",
        "max_concurrent",
        "routes",
        "payload",
        "sql_profile",
        "mode",
        "databases",
        "rcpt",
        "commands",
        "graphql",
        "stream_bodies",
        "placeholder_policy",
    ] {
        if has(k) {
            out[k] = spec[k].clone();
        }
    }
    for (k, key) in [("rate", "per"), ("quota", "window")] {
        if !has(k) {
            continue;
        }
        let mut v = spec[k].clone();
        if let Some((count, unit)) = v.as_str().and_then(|s| s.split_once('/')) {
            let unit = match unit {
                "s" | "sec" | "second" => "second",
                "m" | "min" | "minute" => "minute",
                "h" | "hour" => "hour",
                "d" | "day" => "day",
                _ => "",
            };
            if !count.is_empty()
                && count.bytes().all(|b| b.is_ascii_digit())
                && ((k == "rate" && ["second", "minute", "hour"].contains(&unit))
                    || (k == "quota" && ["hour", "day"].contains(&unit)))
            {
                if let Ok(n) = count.parse::<u64>() {
                    v = json!({"count":n,key:unit});
                }
            }
        }
        out[k] = v;
    }
    if opts.defaults || has("redirects") {
        out["redirects"] = json!({"max":spec.get("redirects").cloned().unwrap_or(json!(0))});
    }
    if has("spend_tokens") || has("spend_usd") {
        out["spend"] = json!({});
        if has("spend_tokens") {
            out["spend"]["tokens"] = spec["spend_tokens"].clone();
        }
        if has("spend_usd") {
            let usd = spec["spend_usd"]
                .as_f64()
                .filter(|u| {
                    u.is_finite() && *u >= 0. && (u * 1e6 - (u * 1e6).round()).abs() <= 1e-7
                })
                .ok_or_else(|| policy_deny("invalid spend_usd", Some("policy_invalid"), None))?;
            out["spend"]["usd_micros"] = json!((usd * 1e6).round() as u64);
        }
    }
    let problems = validate_json(
        &out,
        &ValidateOptions {
            kind: opts.profile.map(|p| p.kind.into()),
        },
    );
    if let Some(p) = problems.first() {
        return Err(policy_deny(
            format!("invalid policy field {}", p.field),
            Some("policy_invalid"),
            None,
        ));
    }
    serde_json::from_value(out)
        .map_err(|_| policy_deny("invalid policy", Some("policy_invalid"), None))
}
