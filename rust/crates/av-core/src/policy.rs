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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Checked<T> {
    /// The value has the expected shape (range checks are still `validate`'s).
    Valid(T),
    /// Anything else, verbatim (including `null` where `null` is not allowed).
    Invalid(serde_json::Value),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// The limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<BudgetValue>,
}

/// A spend limit, `{ tokens, usd_micros }`. Ports the shape checked by
/// `validSpend` in `src/core/policy.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spend {
    /// Token limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<u64>,
    /// USD micros limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
    /// Lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    /// Live placeholders at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    todo!()
}

/// [`validate`] on raw JSON: a non-object is
/// `[{ field: 'policy', message: 'policy must be an object' }]`. Ports
/// `validate` in `src/core/policy.js` for callers holding unparsed input.
pub fn validate_json(layer: &serde_json::Value, opts: &ValidateOptions) -> Vec<Problem> {
    todo!()
}

/// Intersect a chain of layers, outermost (ceiling) first; `None` layers are
/// skipped. An invalid field poisons the result so evaluation refuses (see
/// the module docs). Ports `intersect` in `src/core/policy.js`.
pub fn intersect(layers: &[Option<&Policy>]) -> Policy {
    todo!()
}

/// A budget limit read as a whole number: a JSON integer or canonical
/// decimal string within the safe integers, else `None`. Ports
/// `budgetInteger` in `src/core/policy.js`.
pub fn budget_integer(value: &serde_json::Value) -> Option<u64> {
    todo!()
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
    todo!()
}

/// Normalize a destination host before any grant match: trimmed,
/// lowercased, trailing dot dropped, parsed as a URL hostname. Refuses
/// (`AV_POLICY_DENIED`) an empty host, userinfo, `\`, NUL, or anything
/// unparseable. Ports `normalizeHost` in `src/core/policy.js`.
pub fn normalize_host(host: &str) -> Result<String> {
    todo!()
}

/// Characters left bare in a wire path segment (RFC 3986 pchar). Ports
/// `PCHAR_SAFE` in `src/core/policy.js`.
pub const PCHAR_SAFE_PATTERN: &str = "[A-Za-z0-9\\-._~!$&'()*+,;=:@]";

/// Percent-encode one decided path segment for the wire: everything outside
/// pchar, as uppercase `%XX` of its UTF-8 bytes. Ports `encodePathSegment` in
/// `src/core/policy.js`.
pub fn encode_path_segment(segment: &str) -> String {
    todo!()
}

/// A whole decided path for the wire, segment by segment. Ports
/// `encodePathForWire` in `src/core/policy.js`.
pub fn encode_path_for_wire(path: &str) -> String {
    todo!()
}

/// The path a request names, decoded exactly once and normalized (`?`/`#`
/// cut, `.` and `..` resolved), or a refusal: invalid escape, encoded slash
/// or backslash (`path_ambiguous_separator`), an escape that still decodes
/// (`path_ambiguous_encoding`), a control character (`path_control_char`),
/// traversal above the root. An empty path is `/`. Ports `normalizePath` in
/// `src/core/policy.js`.
pub fn normalize_path(path: &str) -> Result<String> {
    todo!()
}

/// Segment-wise glob match (`*` within a segment, `**` across segments),
/// linear time with no backtracking. Ports `matchPath` in
/// `src/core/policy.js`.
pub fn match_path(pattern: &str, path: &str) -> bool {
    todo!()
}

/// Exact host match, or `*.suffix` matching a strictly longer host. Ports
/// `matchHost` in `src/core/policy.js`.
pub fn match_host(pattern: &str, host: &str) -> bool {
    todo!()
}

/// The hosts a credential may ever reach: its connector host plus the
/// profile's hosts, each reduced to a lowercase hostname without port or
/// trailing dot, de-duplicated. Ports `credentialHostCeiling` in
/// `src/core/policy.js` (`cred.connector.host` is passed directly).
pub fn credential_host_ceiling(
    connector_host: Option<&str>,
    profile_hosts: &[String],
) -> Vec<String> {
    todo!()
}

/// Hostname only: lowercased, trimmed, port and trailing dot removed, IPv6
/// brackets kept. Ports `hostOnly` in `src/core/policy.js`.
pub fn host_only(authority: &str) -> String {
    todo!()
}

/// Confine requested hosts to a credential's ceiling; `None` or empty means
/// the whole ceiling. Refuses (`credential_host`) an empty ceiling or a host
/// outside it. Ports `confineHosts` in `src/core/policy.js`.
pub fn confine_hosts(requested: Option<&[String]>, ceiling: &[String]) -> Result<Vec<String>> {
    todo!()
}

/// True when a `*.` pattern spans a shared multi-tenant suffix. Ports
/// `isMultiTenantWildcard` in `src/core/policy.js`.
pub fn is_multi_tenant_wildcard(pattern: &str) -> bool {
    todo!()
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
    todo!()
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
    todo!()
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
    todo!()
}

/// [`lint`] on raw JSON; a non-object yields the `validate` errors. Ports
/// `lint` in `src/core/policy.js` for callers holding unparsed input.
pub fn lint_json(policy: &serde_json::Value, opts: &ValidateOptions) -> Vec<LintProblem> {
    todo!()
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
    todo!()
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
    todo!()
}
