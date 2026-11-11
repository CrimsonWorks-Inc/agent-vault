//! Payload rules: constraints on a request's JSON, form and query fields and
//! its GraphQL operations. Ports `src/core/payload.js`.
//!
//! No refusal repeats a value from the request; a rule names a key by its
//! index in the rule set, never by its text (C28).

use serde::{Deserialize, Serialize};

use crate::errors::Result;
use crate::policy::{Checked, Problem};
use crate::request_view::RequestView;

/// The keys a rule set may have. Ports the key list checked by
/// `validatePayload` in `src/core/payload.js`.
pub const RULE_SET_KEYS: &[&str] = &[
    "json",
    "form",
    "query",
    "query_strict",
    "graphql",
    "max_body_bytes",
];

/// The keys a field constraint may have. Ports the key list checked by
/// `validatePayload` in `src/core/payload.js`.
pub const CONSTRAINT_KEYS: &[&str] = &["required", "absent", "one_of", "min", "max", "max_length"];

/// Default `max_body_bytes` (1 MiB). Ports the `?? 1024*1024` in
/// `evaluatePayload` in `src/core/payload.js`.
pub const DEFAULT_MAX_BODY_BYTES: u64 = 1024 * 1024;

/// Deepest JSON nesting accepted. Ports the `depth > 64` check in
/// `parseStrictJson` in `src/core/payload.js`.
pub const MAX_JSON_DEPTH: usize = 64;

/// Largest GraphQL document scanned (256 KiB). Ports the bound in
/// `scanGraphQL` in `src/core/payload.js`.
pub const MAX_GRAPHQL_BYTES: usize = 256 * 1024;

/// Most GraphQL tokens scanned. Ports the `t.length > 100000` bound in
/// `scanGraphQL` in `src/core/payload.js`.
pub const MAX_GRAPHQL_TOKENS: usize = 100_000;

/// The refusal text for each fixed payload rule, verbatim. Ports `DETAIL` in
/// `src/core/payload.js`.
pub const DETAIL: &[(&str, &str)] = &[
    ("payload_invalid", "this grant carries a payload rule that is not valid, so nothing can be checked against it"),
    ("payload_size", "the request body is larger than this grant allows"),
    ("payload_content_type", "this grant constrains the body, and the content-type is not one those constraints can read"),
    ("payload_duplicate_key", "a name appears twice, so two readers could disagree about which value counts"),
    ("payload_depth", "the JSON body nests more than 64 levels deep"),
    ("payload_unparseable", "the body could not be read as strict JSON, form data or UTF-8 text"),
    ("graphql_persisted", "a persisted GraphQL query cannot be checked; send the query text"),
    ("graphql_unreadable", "this grant checks GraphQL operations, and no query could be read from this request"),
    ("graphql_unparseable", "the GraphQL document could not be read within the bounds this check allows"),
    ("payload:graphql:operation", "the GraphQL document contains an operation type this grant does not allow"),
    ("payload:graphql:deny_field", "the GraphQL document names a field this grant denies"),
];

/// The refusal text for any rule not in [`DETAIL`]. Ports the `??` fallback
/// of `fail` in `src/core/payload.js`.
pub const DETAIL_FALLBACK: &str = "a query parameter is not one this grant names";

/// Refusal text for a request two upstreams could read differently (rule
/// `request_ambiguous`). Ports `AMBIGUOUS` in `src/core/payload.js`.
pub const AMBIGUOUS: &[(&str, &str)] = &[
    ("semicolon", "the query separates parameters with ;, which some servers split on and others do not"),
    ("form_semicolon", "the form body separates fields with ;, which some servers split on and others do not"),
    ("spelling", "a parameter name differs from one this grant names only by case, percent-encoding or punctuation a server may fold"),
];

/// Hint attached to every `request_ambiguous` refusal. Ports the `hint` of
/// `ambiguous` in `src/core/payload.js`.
pub const AMBIGUOUS_HINT: &str =
    "Send each parameter once, separated by &, under exactly the name the grant uses.";

/// Where a refusal says it happened. Ports `WHERE` in `src/core/payload.js`.
pub const WHERE: &[(&str, &str)] = &[
    ("json", "the JSON field"),
    ("form", "the form field"),
    ("query", "the query parameter"),
];

/// What each broken constraint says. Ports `BROKE` in `src/core/payload.js`.
pub const BROKE: &[(&str, &str)] = &[
    (
        "absent",
        "is present, and this grant requires it to be absent",
    ),
    ("required", "is missing, and this grant requires it"),
    ("one_of", "is not one of the values this grant allows"),
    (
        "min",
        "is below the minimum this grant allows, or is not a number",
    ),
    (
        "max",
        "is above the maximum this grant allows, or is not a number",
    ),
    (
        "max_length",
        "is longer than this grant allows, or is not a string or list",
    ),
];

/// A JSON object whose key order is kept, because a rule is named by its
/// index (`payload:<kind>:<index>:<constraint>`). Ports the insertion-ordered
/// objects `Object.entries(set[kind])` walks in `src/core/payload.js`.
/// Serializes as a JSON object.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OrderedMap<V>(pub Vec<(String, V)>);

impl<V: Serialize> Serialize for OrderedMap<V> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for OrderedMap<V> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visit<V>(std::marker::PhantomData<V>);
        impl<'de, V: Deserialize<'de>> serde::de::Visitor<'de> for Visit<V> {
            type Value = OrderedMap<V>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some((k, v)) = a.next_entry::<String, V>()? {
                    out.push((k, v));
                }
                Ok(OrderedMap(out))
            }
        }
        d.deserialize_map(Visit(std::marker::PhantomData))
    }
}

/// One field constraint. Ports the constraint objects
/// `{ required, absent, one_of, min, max, max_length }` validated by
/// `validatePayload` in `src/core/payload.js`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldConstraint {
    /// The field must be present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    /// The field must be absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absent: Option<bool>,
    /// Allowed values: null, booleans, finite numbers or strings of at most
    /// 256 chars; at most 64 of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<serde_json::Value>>,
    /// Inclusive numeric minimum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    /// Inclusive numeric maximum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    /// Longest string or list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u64>,
}

/// A GraphQL operation type. Ports the `operations` values accepted by
/// `validatePayload` in `src/core/payload.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GraphqlOperation {
    /// `query`
    Query,
    /// `mutation`
    Mutation,
    /// `subscription`
    Subscription,
}

/// GraphQL rules. Ports the `graphql` object `{ operations, deny_fields }`
/// validated by `validatePayload` and read by `scanGraphQL` in
/// `src/core/payload.js`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphqlRules {
    /// Operation types allowed.
    pub operations: Vec<GraphqlOperation>,
    /// Field names refused anywhere in the document (at most 64 GraphQL
    /// names).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_fields: Option<Vec<String>>,
}

/// One layer's payload rule set. Ports the `RuleSet` objects
/// `{ json, form, query, query_strict, graphql, max_body_bytes }` of
/// `src/core/payload.js`. `json` keys are RFC 6901 pointers; each map holds at
/// most 32 entries.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadRuleSet {
    /// JSON body constraints by pointer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<OrderedMap<FieldConstraint>>,
    /// Form body constraints by field name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form: Option<OrderedMap<FieldConstraint>>,
    /// Query constraints by parameter name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<OrderedMap<FieldConstraint>>,
    /// Refuse any query parameter the `query` rules do not name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_strict: Option<bool>,
    /// GraphQL rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graphql: Option<GraphqlRules>,
    /// Largest body allowed (default [`DEFAULT_MAX_BODY_BYTES`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
}

/// Pure validation of one layer's rule set, given as raw JSON because a
/// stored or proposed set may be any shape. Each problem is
/// `{ field: 'payload', message: 'invalid payload constraint' }`; empty means
/// valid. Ports `validatePayload` in `src/core/payload.js`.
pub fn validate_payload(set: &serde_json::Value) -> Vec<Problem> {
    todo!()
}

/// Strict JSON: recursive descent that refuses a duplicate key
/// (`payload_duplicate_key`) before any value is lost, nesting past 64
/// (`payload_depth`), and anything else malformed (`payload_unparseable`), all
/// as `AV_POLICY_DENIED`. Ports `parseStrictJson` in `src/core/payload.js`.
pub fn parse_strict_json(text: &str) -> Result<serde_json::Value> {
    todo!()
}

/// Scan a GraphQL executable document against `rules`, checking every
/// definition: refuses a denied field name, a disallowed operation type, or a
/// document that cannot be read within the bounds. Ports `scanGraphQL` in
/// `src/core/payload.js`.
pub fn scan_graphql(document: &str, rules: &GraphqlRules) -> Result<()> {
    todo!()
}

/// The request a payload rule is checked against. Ports the `input`
/// argument of `evaluatePayload` in `src/core/payload.js`: the JS accepts a
/// view or loose fields read into one; here the caller builds the view with
/// [`crate::request_view::request_view`].
#[derive(Debug, Clone, Copy)]
pub struct PayloadInput<'a> {
    /// The request's one view.
    pub view: &'a RequestView<'a>,
    /// The decided path (`''` when absent); used for the `/graphql` check.
    pub path: &'a str,
}

/// Check every payload rule set (the effective policy's `payload_sets`)
/// against the request. `None` means no rules. An invalid set refuses with
/// `payload_invalid`; every other refusal is `AV_POLICY_DENIED` with the
/// rules named in [`DETAIL`], `request_ambiguous`, or
/// `payload:<kind>:<index>:<constraint>`. Ports `evaluatePayload` in
/// `src/core/payload.js`.
pub fn evaluate_payload(
    sets: Option<&Checked<Vec<PayloadRuleSet>>>,
    input: &PayloadInput<'_>,
) -> Result<()> {
    todo!()
}
