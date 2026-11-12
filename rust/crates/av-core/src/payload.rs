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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::non_null"
    )]
    pub required: Option<bool>,
    /// The field must be absent.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::non_null"
    )]
    pub absent: Option<bool>,
    /// Allowed values: null, booleans, finite numbers or strings of at most
    /// 256 chars; at most 64 of them.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::non_null"
    )]
    pub one_of: Option<Vec<serde_json::Value>>,
    /// Inclusive numeric minimum.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::non_null"
    )]
    pub min: Option<f64>,
    /// Inclusive numeric maximum.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::non_null"
    )]
    pub max: Option<f64>,
    /// Longest string or list.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::non_null"
    )]
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::non_null"
    )]
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::non_null"
    )]
    pub json: Option<OrderedMap<FieldConstraint>>,
    /// Form body constraints by field name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::non_null"
    )]
    pub form: Option<OrderedMap<FieldConstraint>>,
    /// Query constraints by parameter name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::non_null"
    )]
    pub query: Option<OrderedMap<FieldConstraint>>,
    /// Refuse any query parameter the `query` rules do not name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::non_null"
    )]
    pub query_strict: Option<bool>,
    /// GraphQL rules.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::non_null"
    )]
    pub graphql: Option<GraphqlRules>,
    /// Largest body allowed (default [`DEFAULT_MAX_BODY_BYTES`]).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::non_null"
    )]
    pub max_body_bytes: Option<u64>,
}

/// Pure validation of one layer's rule set, given as raw JSON because a
/// stored or proposed set may be any shape. Each problem is
/// `{ field: 'payload', message: 'invalid payload constraint' }`; empty means
/// valid. Ports `validatePayload` in `src/core/payload.js`.
pub fn validate_payload(set: &serde_json::Value) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut bad = || {
        problems.push(Problem {
            field: "payload".into(),
            message: "invalid payload constraint".into(),
        })
    };
    let Some(o) = set.as_object() else {
        bad();
        return problems;
    };
    for k in o.keys() {
        if !RULE_SET_KEYS.contains(&k.as_str()) {
            bad();
        }
    }
    if o.get("max_body_bytes").is_some_and(|v| {
        crate::policy::budget_integer(v)
            .filter(|_| v.is_number())
            .is_none()
    }) {
        bad();
    }
    if o.get("query_strict").is_some_and(|v| !v.is_boolean()) {
        bad();
    }
    for kind in ["json", "form", "query"] {
        let Some(v) = o.get(kind) else {
            continue;
        };
        let Some(map) = v.as_object().filter(|m| m.len() <= 32) else {
            bad();
            continue;
        };
        for (key, c) in map {
            if kind == "json" {
                let b = key.as_bytes();
                if !key.starts_with('/')
                    || key.encode_utf16().count() > 256
                    || key.split('/').any(|x| x == "-")
                    || b.iter()
                        .enumerate()
                        .any(|(i, c)| *c == b'~' && !matches!(b.get(i + 1), Some(b'0' | b'1')))
                {
                    bad();
                }
            }
            let Some(c) = c.as_object() else {
                bad();
                continue;
            };
            for k in c.keys() {
                if !CONSTRAINT_KEYS.contains(&k.as_str()) {
                    bad();
                }
            }
            for k in ["required", "absent"] {
                if c.get(k).is_some_and(|v| !v.is_boolean()) {
                    bad();
                }
            }
            if c.get("required").and_then(|v| v.as_bool()) == Some(true)
                && c.get("absent").and_then(|v| v.as_bool()) == Some(true)
            {
                bad();
            }
            for k in ["min", "max"] {
                if c.get(k).is_some_and(|v| !v.is_number()) {
                    bad();
                }
            }
            if c.get("max_length").is_some_and(|v| {
                crate::policy::budget_integer(v)
                    .filter(|_| v.is_number())
                    .is_none()
            }) {
                bad();
            }
            if c.get("one_of").is_some_and(|v| {
                v.as_array().is_none_or(|a| {
                    a.len() > 64
                        || a.iter().any(|v| {
                            !v.is_null()
                                && !v.is_boolean()
                                && !v.is_number()
                                && !v.as_str().is_some_and(|s| s.encode_utf16().count() <= 256)
                        })
                })
            }) {
                bad();
            }
        }
    }
    if let Some(g) = o.get("graphql") {
        let name = crate::jsre::compile(r"^[_A-Za-z][_0-9A-Za-z]*$").expect("name regex");
        if !g.as_object().is_some_and(|g| {
            g.keys()
                .all(|k| ["operations", "deny_fields"].contains(&k.as_str()))
                && g.get("operations")
                    .and_then(|v| v.as_array())
                    .is_some_and(|a| {
                        a.iter().all(|v| {
                            v.as_str()
                                .is_some_and(|s| ["query", "mutation", "subscription"].contains(&s))
                        })
                    })
                && g.get("deny_fields").is_none_or(|v| {
                    v.as_array().is_some_and(|a| {
                        a.len() <= 64
                            && a.iter()
                                .all(|v| v.as_str().is_some_and(|s| name.is_match(s)))
                    })
                })
        }) {
            bad();
        }
    }
    problems
}

/// Strict JSON: recursive descent that refuses a duplicate key
/// (`payload_duplicate_key`) before any value is lost, nesting past 64
/// (`payload_depth`), and anything else malformed (`payload_unparseable`), all
/// as `AV_POLICY_DENIED`. Ports `parseStrictJson` in `src/core/payload.js`.
pub fn parse_strict_json(text: &str) -> Result<serde_json::Value> {
    let mut p = StrictParser { text, i: 0 };
    let v = p.value(1)?;
    p.ws();
    if p.i != text.len() {
        return Err(payload_fail("payload_unparseable"));
    }
    Ok(v)
}

/// Scan a GraphQL executable document against `rules`, checking every
/// definition: refuses a denied field name, a disallowed operation type, or a
/// document that cannot be read within the bounds. Ports `scanGraphQL` in
/// `src/core/payload.js`.
pub fn scan_graphql(document: &str, rules: &GraphqlRules) -> Result<()> {
    graphql_scan(document, rules)
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
    evaluate(sets, input)
}

fn payload_fail(rule: &str) -> crate::errors::VaultError {
    crate::errors::deny(
        crate::errors::ErrorCode::PolicyDenied,
        DETAIL
            .iter()
            .find(|(r, _)| *r == rule)
            .map_or(DETAIL_FALLBACK, |(_, d)| *d),
        crate::errors::DenyExtra {
            rule: Some(rule.into()),
            ..Default::default()
        },
    )
}
fn ambiguous(why: &str) -> crate::errors::VaultError {
    crate::errors::deny(
        crate::errors::ErrorCode::PolicyDenied,
        AMBIGUOUS
            .iter()
            .find(|(r, _)| *r == why)
            .expect("ambiguity kind")
            .1,
        crate::errors::DenyExtra {
            rule: Some("request_ambiguous".into()),
            hint: Some(AMBIGUOUS_HINT.into()),
            ..Default::default()
        },
    )
}
struct StrictParser<'a> {
    text: &'a str,
    i: usize,
}
impl StrictParser<'_> {
    fn ws(&mut self) {
        while self
            .text
            .as_bytes()
            .get(self.i)
            .is_some_and(|b| b" \t\r\n".contains(b))
        {
            self.i += 1;
        }
    }
    fn string(&mut self) -> Result<String> {
        let start = self.i;
        self.i += 1;
        while let Some(&c) = self.text.as_bytes().get(self.i) {
            self.i += 1;
            if c == b'"' {
                return serde_json::from_str(&self.text[start..self.i])
                    .map_err(|_| payload_fail("payload_unparseable"));
            }
            if c == b'\\' {
                self.i += 1;
            }
        }
        Err(payload_fail("payload_unparseable"))
    }
    fn value(&mut self, depth: usize) -> Result<serde_json::Value> {
        use serde_json::Value as V;
        self.ws();
        let c = self
            .text
            .as_bytes()
            .get(self.i)
            .copied()
            .ok_or_else(|| payload_fail("payload_unparseable"))?;
        if c == b'{' || c == b'[' {
            if depth > MAX_JSON_DEPTH {
                return Err(payload_fail("payload_depth"));
            }
            let object = c == b'{';
            let close = if object { b'}' } else { b']' };
            let mut map = serde_json::Map::new();
            let mut array = Vec::new();
            self.i += 1;
            self.ws();
            if self.text.as_bytes().get(self.i) == Some(&close) {
                self.i += 1;
                return Ok(if object {
                    V::Object(map)
                } else {
                    V::Array(array)
                });
            }
            loop {
                self.ws();
                if object {
                    if self.text.as_bytes().get(self.i) != Some(&b'"') {
                        return Err(payload_fail("payload_unparseable"));
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.text.as_bytes().get(self.i) != Some(&b':') {
                        return Err(payload_fail("payload_unparseable"));
                    }
                    self.i += 1;
                    if map.contains_key(&k) {
                        return Err(payload_fail("payload_duplicate_key"));
                    }
                    map.insert(k, self.value(depth + 1)?);
                } else {
                    array.push(self.value(depth + 1)?);
                }
                self.ws();
                let c = self
                    .text
                    .as_bytes()
                    .get(self.i)
                    .copied()
                    .ok_or_else(|| payload_fail("payload_unparseable"))?;
                self.i += 1;
                if c == close {
                    return Ok(if object {
                        V::Object(map)
                    } else {
                        V::Array(array)
                    });
                }
                if c != b',' {
                    return Err(payload_fail("payload_unparseable"));
                }
            }
        }
        if c == b'"' {
            return self.string().map(V::String);
        }
        let re = crate::jsre::compile(
            r"^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)",
        )
        .expect("JSON scalar");
        let m = re
            .find(&self.text[self.i..])
            .ok_or_else(|| payload_fail("payload_unparseable"))?;
        let start = self.i;
        self.i += m.len();
        let value: V = serde_json::from_str(&self.text[start..self.i])
            .map_err(|_| payload_fail("payload_unparseable"))?;
        if let V::Number(n) = &value {
            let n = n
                .as_f64()
                .ok_or_else(|| payload_fail("payload_unparseable"))?;
            if n.fract() == 0.0 {
                if n >= 0.0 && n < (u64::MAX as f64) {
                    return Ok(V::from(n as u64));
                }
                if n >= i64::MIN as f64 && n < 0.0 {
                    return Ok(V::from(n as i64));
                }
            }
        }
        Ok(value)
    }
}
#[derive(Clone)]
struct GqlToken {
    value: String,
    kind: u8,
}
struct GqlParser {
    tokens: Vec<GqlToken>,
    pos: usize,
    depth: usize,
}
impl GqlParser {
    fn at(&self, v: &str) -> bool {
        self.tokens.get(self.pos).is_some_and(|t| t.value == v)
    }
    fn eat(&mut self, v: &str) -> Result<()> {
        if !self.at(v) {
            return Err(payload_fail("graphql_unparseable"));
        }
        self.pos += 1;
        Ok(())
    }
    fn name(&mut self) -> Result<String> {
        let t = self
            .tokens
            .get(self.pos)
            .filter(|t| t.kind == 0)
            .ok_or_else(|| payload_fail("graphql_unparseable"))?;
        let s = t.value.clone();
        self.pos += 1;
        Ok(s)
    }
    fn value(&mut self, constant: bool, depth: usize) -> Result<()> {
        if depth > 64 {
            return Err(payload_fail("graphql_unparseable"));
        }
        if self.at("$") && !constant {
            self.pos += 1;
            self.name()?;
        } else if self.at("[") {
            self.pos += 1;
            while !self.at("]") {
                self.value(constant, depth + 1)?;
            }
            self.pos += 1;
        } else if self.at("{") {
            self.pos += 1;
            while !self.at("}") {
                self.name()?;
                self.eat(":")?;
                self.value(constant, depth + 1)?;
            }
            self.pos += 1;
        } else if self.tokens.get(self.pos).is_some_and(|t| t.kind <= 2) {
            self.pos += 1;
        } else {
            return Err(payload_fail("graphql_unparseable"));
        }
        Ok(())
    }
    fn args(&mut self) -> Result<()> {
        if !self.at("(") {
            return Ok(());
        }
        self.pos += 1;
        let mut n = 0;
        while !self.at(")") {
            self.name()?;
            self.eat(":")?;
            self.value(false, 0)?;
            n += 1;
        }
        if n == 0 {
            return Err(payload_fail("graphql_unparseable"));
        }
        self.pos += 1;
        Ok(())
    }
    fn directives(&mut self) -> Result<()> {
        while self.at("@") {
            self.pos += 1;
            self.name()?;
            self.args()?;
        }
        Ok(())
    }
    fn type_name(&mut self, depth: usize) -> Result<()> {
        if depth > 64 {
            return Err(payload_fail("graphql_unparseable"));
        }
        if self.at("[") {
            self.pos += 1;
            self.type_name(depth + 1)?;
            self.eat("]")?;
        } else {
            self.name()?;
        }
        if self.at("!") {
            self.pos += 1;
        }
        Ok(())
    }
    fn selection(&mut self) -> Result<()> {
        self.eat("{")?;
        self.depth += 1;
        if self.depth > 64 {
            return Err(payload_fail("graphql_unparseable"));
        }
        let mut n = 0;
        while !self.at("}") {
            if self.at("...") {
                self.pos += 1;
                if self.at("on") {
                    self.pos += 1;
                    self.name()?;
                    self.directives()?;
                    self.selection()?;
                } else if self.at("@") || self.at("{") {
                    self.directives()?;
                    self.selection()?;
                } else {
                    let x = self.name()?;
                    if x == "on" {
                        return Err(payload_fail("graphql_unparseable"));
                    }
                    self.directives()?;
                }
            } else {
                self.name()?;
                if self.at(":") {
                    self.pos += 1;
                    self.name()?;
                }
                self.args()?;
                self.directives()?;
                if self.at("{") {
                    self.selection()?;
                }
            }
            n += 1;
        }
        if n == 0 {
            return Err(payload_fail("graphql_unparseable"));
        }
        self.pos += 1;
        self.depth -= 1;
        Ok(())
    }
}
fn graphql_scan(document: &str, rules: &GraphqlRules) -> Result<()> {
    if document.len() > MAX_GRAPHQL_BYTES {
        return Err(payload_fail("graphql_unparseable"));
    }
    let mut tokens = Vec::new();
    let mut i = 0;
    let token=crate::jsre::compile(r"^(?:[_A-Za-z][_0-9A-Za-z]*|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|\.\.\.|[!$():=@\[\]{|}])").expect("GraphQL token");
    while i < document.len() {
        let c = document[i..].chars().next().unwrap();
        if c.is_whitespace() || c == ',' || c == '\u{feff}' {
            i += c.len_utf8();
            continue;
        }
        if c == '#' {
            while i < document.len() && !b"\r\n".contains(&document.as_bytes()[i]) {
                i += 1;
            }
            continue;
        }
        if c == '"' {
            let start = i;
            let mut closed = false;
            if document[i..].starts_with("\"\"\"") {
                i += 3;
                while i < document.len() {
                    if document[i..].starts_with("\\\"\"\"") {
                        i += 4;
                        continue;
                    }
                    if document[i..].starts_with("\"\"\"") {
                        i += 3;
                        closed = true;
                        break;
                    }
                    let c = document[i..].chars().next().unwrap();
                    if (c as u32) < 32 && !"\t\r\n".contains(c) {
                        return Err(payload_fail("graphql_unparseable"));
                    }
                    i += c.len_utf8();
                }
            } else {
                i += 1;
                while i < document.len() {
                    let x = document.as_bytes()[i];
                    i += 1;
                    if x == b'"' {
                        closed = true;
                        break;
                    }
                    if x == b'\\' {
                        i += 1;
                    } else if x < 32 {
                        return Err(payload_fail("graphql_unparseable"));
                    }
                }
                if i > document.len()
                    || serde_json::from_str::<String>(&document[start..i]).is_err()
                {
                    return Err(payload_fail("graphql_unparseable"));
                }
            }
            if !closed {
                return Err(payload_fail("graphql_unparseable"));
            }
            tokens.push(GqlToken {
                value: String::new(),
                kind: 2,
            });
        } else {
            let m = token
                .find(&document[i..])
                .ok_or_else(|| payload_fail("graphql_unparseable"))?;
            let v = m.as_str();
            i += m.len();
            let kind = if v.as_bytes()[0].is_ascii_alphabetic() || v.starts_with('_') {
                0
            } else if v.as_bytes()[0].is_ascii_digit() || v.starts_with('-') {
                1
            } else {
                3
            };
            if kind == 0
                && rules
                    .deny_fields
                    .as_ref()
                    .is_some_and(|fields| fields.iter().any(|f| f == v))
            {
                return Err(payload_fail("payload:graphql:deny_field"));
            }
            tokens.push(GqlToken {
                value: v.into(),
                kind,
            });
        }
        if tokens.len() > MAX_GRAPHQL_TOKENS {
            return Err(payload_fail("graphql_unparseable"));
        }
    }
    let mut p = GqlParser {
        tokens,
        pos: 0,
        depth: 0,
    };
    let mut operations = 0;
    while p.pos < p.tokens.len() {
        if p.at("fragment") {
            p.pos += 1;
            if p.name()? == "on" {
                return Err(payload_fail("graphql_unparseable"));
            }
            p.eat("on")?;
            p.name()?;
            p.directives()?;
            p.selection()?;
            continue;
        }
        let mut op = "query".to_owned();
        if !p.at("{") {
            op = p.name()?;
            if !["query", "mutation", "subscription"].contains(&op.as_str()) {
                return Err(payload_fail("graphql_unparseable"));
            }
            if p.tokens.get(p.pos).is_some_and(|t| t.kind == 0) {
                p.name()?;
            }
            if p.at("(") {
                p.pos += 1;
                let mut n = 0;
                while !p.at(")") {
                    p.eat("$")?;
                    p.name()?;
                    p.eat(":")?;
                    p.type_name(0)?;
                    if p.at("=") {
                        p.pos += 1;
                        p.value(true, 0)?;
                    }
                    p.directives()?;
                    n += 1;
                }
                if n == 0 {
                    return Err(payload_fail("graphql_unparseable"));
                }
                p.pos += 1;
            }
            p.directives()?;
        }
        let op = match op.as_str() {
            "query" => GraphqlOperation::Query,
            "mutation" => GraphqlOperation::Mutation,
            _ => GraphqlOperation::Subscription,
        };
        if !rules.operations.contains(&op) {
            return Err(payload_fail("payload:graphql:operation"));
        }
        operations += 1;
        p.selection()?;
    }
    if operations == 0 {
        return Err(payload_fail("graphql_unparseable"));
    }
    Ok(())
}
fn element(p: &crate::request_view::QueryParam, key: &str) -> bool {
    if p.raw_name == key {
        return true;
    }
    let normalized = crate::jsre::compile("(?i)%5b|%5d")
        .expect("brackets")
        .replace_all(&p.raw_name, |c: &crate::jsre::Captures<'_>| {
            if c[0].eq_ignore_ascii_case("%5b") {
                "["
            } else {
                "]"
            }
        });
    crate::request_view::list_base(&normalized) == Some(key)
}
fn check_duplicates(list: &[crate::request_view::QueryParam]) -> Result<()> {
    let mut names = std::collections::HashSet::new();
    for p in list {
        if !names.insert(&p.name) && crate::request_view::list_base(&p.name).is_none() {
            return Err(payload_fail("payload_duplicate_key"));
        }
    }
    Ok(())
}
fn respelled(
    rules: &OrderedMap<FieldConstraint>,
    list: &[crate::request_view::QueryParam],
) -> Result<()> {
    for (key, _) in &rules.0 {
        let want = crate::request_view::folded_names(key)[0].clone();
        for p in list {
            if !element(p, key) && crate::request_view::folded_names(&p.name).contains(&want) {
                return Err(ambiguous("spelling"));
            }
        }
    }
    Ok(())
}
fn constraint(
    kind: &str,
    key: &str,
    index: usize,
    c: &FieldConstraint,
    value: Option<&serde_json::Value>,
) -> Result<()> {
    let no = |name: &str| {
        crate::errors::deny(
            crate::errors::ErrorCode::PolicyDenied,
            format!(
                "{} {key} {}",
                WHERE.iter().find(|(k, _)| *k == kind).unwrap().1,
                BROKE.iter().find(|(k, _)| *k == name).unwrap().1
            ),
            crate::errors::DenyExtra {
                rule: Some(format!("payload:{kind}:{index}:{name}")),
                ..Default::default()
            },
        )
    };
    if c.absent == Some(true) && value.is_some() {
        return Err(no("absent"));
    }
    if c.required == Some(true) && value.is_none() {
        return Err(no("required"));
    }
    let Some(v) = value else {
        return Ok(());
    };
    if let Some(allowed) = &c.one_of {
        let same = |a: &serde_json::Value, b: &serde_json::Value| {
            if a.is_number() && b.is_number() {
                a.as_f64() == b.as_f64()
            } else {
                a == b
            }
        };
        if !allowed.iter().any(|a| same(a, v)) {
            return Err(no("one_of"));
        }
    }
    if c.min.is_some_and(|min| v.as_f64().is_none_or(|n| n < min)) {
        return Err(no("min"));
    }
    if c.max.is_some_and(|max| v.as_f64().is_none_or(|n| n > max)) {
        return Err(no("max"));
    }
    if let Some(max) = c.max_length {
        let len = v
            .as_str()
            .map(|s| s.encode_utf16().count())
            .or_else(|| v.as_array().map(Vec::len));
        if len.is_none_or(|n| n as u64 > max) {
            return Err(no("max_length"));
        }
    }
    Ok(())
}
fn body_text(body: Option<&[u8]>) -> Result<&str> {
    let text = std::str::from_utf8(body.unwrap_or_default())
        .map_err(|_| payload_fail("payload_unparseable"))?;
    Ok(text.strip_prefix('\u{feff}').unwrap_or(text))
}
fn evaluate(sets: Option<&Checked<Vec<PayloadRuleSet>>>, input: &PayloadInput<'_>) -> Result<()> {
    let Some(sets) = sets else {
        return Ok(());
    };
    let Checked::Valid(sets) = sets else {
        return Err(payload_fail("payload_invalid"));
    };
    if sets.is_empty() {
        return Ok(());
    }
    let view = input.view;
    let bytes = view.body.map_or(0, <[u8]>::len);
    for set in sets {
        if !validate_payload(&serde_json::to_value(set).expect("rules")).is_empty() {
            return Err(payload_fail("payload_invalid"));
        }
        if bytes as u64 > set.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES) {
            return Err(payload_fail("payload_size"));
        }
    }
    if view.semicolon {
        return Err(ambiguous("semicolon"));
    }
    let ct = &view.media_type;
    let is_json = ct == "application/json"
        || (ct.starts_with("application/") && ct.ends_with("+json") && !ct[12..].contains('/'));
    let is_form = ct == "application/x-www-form-urlencoded";
    let mut json = None;
    let mut form_list = None;
    for set in sets {
        if let Some(rules) = &set.query {
            check_duplicates(&view.params)?;
            respelled(rules, &view.params)?;
        }
        if let Some(form_rules) = set.form.as_ref().filter(|_| bytes > 0 && is_form) {
            let text = body_text(view.body)?;
            if text.contains(';') {
                return Err(ambiguous("form_semicolon"));
            }
            let list = form_list
                .get_or_insert_with(|| crate::request_view::query_params(text, Default::default()));
            check_duplicates(list)?;
            respelled(form_rules, list)?;
        }
        if set.query_strict == Some(true) {
            check_duplicates(&view.params)?;
            for (i, p) in view.params.iter().enumerate() {
                if !set
                    .query
                    .as_ref()
                    .is_some_and(|r| r.0.iter().any(|(key, _)| element(p, key)))
                {
                    return Err(payload_fail(&format!("payload:query:{i}:strict")));
                }
            }
        }
        for (kind, rules) in [
            ("json", &set.json),
            ("form", &set.form),
            ("query", &set.query),
        ] {
            let Some(rules) = rules else {
                continue;
            };
            if kind == "json" && bytes > 0 {
                if !is_json {
                    return Err(payload_fail("payload_content_type"));
                }
                if json.is_none() {
                    json = Some(parse_strict_json(body_text(view.body)?)?);
                }
            }
            if kind == "form" && bytes > 0 {
                if !is_form {
                    return Err(payload_fail("payload_content_type"));
                }
                if form_list.is_none() {
                    let text = body_text(view.body)?;
                    if text.contains(';') {
                        return Err(ambiguous("form_semicolon"));
                    }
                    let list = crate::request_view::query_params(text, Default::default());
                    check_duplicates(&list)?;
                    form_list = Some(list);
                }
            }
            if kind == "query" {
                check_duplicates(&view.params)?;
            }
            for (index, (key, c)) in rules.0.iter().enumerate() {
                if kind != "json" {
                    let list = if kind == "query" {
                        view.params.as_slice()
                    } else {
                        form_list.as_deref().unwrap_or_default()
                    };
                    let values: Vec<_> = list.iter().filter(|p| element(p, key)).collect();
                    if values.is_empty() {
                        constraint(kind, key, index, c, None)?;
                    }
                    for v in values {
                        constraint(
                            kind,
                            key,
                            index,
                            c,
                            Some(&serde_json::Value::String(v.value.clone())),
                        )?;
                    }
                    continue;
                }
                let mut value = json.as_ref();
                for k in key[1..]
                    .split('/')
                    .map(|k| k.replace("~1", "/").replace("~0", "~"))
                {
                    if let Some(o) = value.and_then(|v| v.as_object()) {
                        if o.keys()
                            .any(|x| *x != k && x.to_lowercase() == k.to_lowercase())
                        {
                            return Err(ambiguous("spelling"));
                        }
                    }
                    value = value.and_then(|v| {
                        if let Some(a) = v.as_array() {
                            if k == "0"
                                || (!k.starts_with('0')
                                    && !k.is_empty()
                                    && k.bytes().all(|b| b.is_ascii_digit()))
                            {
                                k.parse::<usize>().ok().and_then(|i| a.get(i))
                            } else {
                                None
                            }
                        } else {
                            v.as_object().and_then(|o| o.get(&k))
                        }
                    });
                }
                constraint(kind, key, index, c, value)?;
            }
        }
        if let Some(rules) = &set.graphql {
            let mut docs = Vec::new();
            check_duplicates(&view.params)?;
            if let Some(p) = view.params.iter().find(|p| p.name == "query") {
                docs.push(p.value.clone());
            }
            if bytes > 0 && ct == "application/graphql" {
                docs.push(body_text(view.body)?.into());
            } else if bytes > 0 && is_form {
                let text = body_text(view.body)?;
                if text.contains(';') {
                    return Err(ambiguous("form_semicolon"));
                }
                let list = form_list.get_or_insert_with(|| {
                    crate::request_view::query_params(text, Default::default())
                });
                check_duplicates(list)?;
                if let Some(p) = list.iter().find(|p| p.name == "query") {
                    docs.push(p.value.clone());
                }
            } else if bytes > 0 && is_json {
                if json.is_none() {
                    json = Some(parse_strict_json(body_text(view.body)?)?);
                }
                let data = json.as_ref().unwrap();
                let entries: Vec<_> = if let Some(a) = data.as_array() {
                    if a.is_empty() {
                        return Err(payload_fail("graphql_unreadable"));
                    }
                    a.iter().collect()
                } else {
                    vec![data]
                };
                for entry in entries {
                    if let Some(query) = entry.get("query").and_then(|v| v.as_str()) {
                        docs.push(query.into());
                    } else if entry.is_object()
                        && entry.get("query").is_none()
                        && entry["extensions"]["persistedQuery"].is_object()
                    {
                        return Err(payload_fail("graphql_persisted"));
                    } else if data.is_array() || (entry.is_object() && entry.get("query").is_some())
                    {
                        return Err(payload_fail("graphql_unreadable"));
                    }
                }
            }
            let path = input.path.split('?').next().unwrap_or("");
            if docs.is_empty() && (path.ends_with("/graphql") || path.ends_with("/graphql/")) {
                return Err(payload_fail("graphql_unreadable"));
            }
            for doc in docs {
                scan_graphql(&doc, rules)?;
            }
        }
    }
    Ok(())
}
