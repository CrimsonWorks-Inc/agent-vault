//! The one reading of a request that the gateway enforces. Ports
//! `src/core/request-view.js`.
//!
//! The view reads a request as the union of what common upstreams accept: a
//! query split on `&` and `;`, names decoded once, method-override names
//! folded as PHP and Rack fold them. Every check reads this view.
//!
//! `isView` is not ported: in Rust a [`RequestView`] and a [`RequestInput`]
//! are different types.

/// Headers a framework may honour in place of the request-line method. Ports
/// `METHOD_OVERRIDE_HEADERS` in `src/core/request-view.js`.
pub const METHOD_OVERRIDE_HEADERS: &[&str] = &[
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

/// Query and body fields (by folded name) a framework may honour in place of
/// the request-line method. Ports `METHOD_OVERRIDE_FIELDS` (module-private)
/// in `src/core/request-view.js`.
pub const METHOD_OVERRIDE_FIELDS: &[&str] = &[
    "_method",
    "__method",
    "x_http_method_override",
    "x_http_method",
    "x_method_override",
];

/// The names a field may be read as (PHP, Rack and qs foldings, lowercased,
/// ` ` `.` `-` folded to `_`), de-duplicated in insertion order. Ports
/// `foldedNames` in `src/core/request-view.js`.
pub fn folded_names(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for base in [
        name,
        name.split('\0')
            .next()
            .unwrap_or("")
            .trim_start_matches(' '),
    ] {
        let n = base.to_lowercase().replace([' ', '.', '-'], "_");
        let a = n.split('[').next().unwrap_or("").to_owned();
        let b = n.replace('[', "_");
        let c = n
            .trim_start_matches(['[', ']'])
            .split(['[', ']'])
            .next()
            .unwrap_or("")
            .to_owned();
        for v in [a, b, c] {
            if !out.contains(&v) {
                out.push(v);
            }
        }
    }
    out
}

/// The base of a bracket-syntax name (`expand[]`, `items[0][price]` →
/// `expand`, `items`), or `None` for any other name. Ports `listBase` in
/// `src/core/request-view.js`.
pub fn list_base(name: &str) -> Option<&str> {
    let start = name.find('[')?;
    let base = &name[..start];
    if base.is_empty() || base.contains(']') {
        return None;
    }
    let mut tail = &name[start..];
    while !tail.is_empty() {
        tail = tail.strip_prefix('[')?;
        let end = tail.find(']')?;
        if tail[..end].contains('[') {
            return None;
        }
        tail = &tail[end + 1..];
    }
    Some(base)
}

/// True when any folding of `name` is a method-override field. Ports
/// `isOverrideField` in `src/core/request-view.js`.
pub fn is_override_field(name: &str) -> bool {
    folded_names(name)
        .iter()
        .any(|n| METHOD_OVERRIDE_FIELDS.contains(&n.as_str()))
}

/// A JSON key its readers do not agree on: empty, a control or non-ASCII
/// character, or a space at either end. Ports `isStrayKey` in
/// `src/core/request-view.js`.
pub fn is_stray_key(name: &str) -> bool {
    name.is_empty()
        || name.bytes().any(|b| !(0x20..=0x7e).contains(&b))
        || name.starts_with(' ')
        || name.ends_with(' ')
}

/// A query/form/multipart name its readers do not agree on: a stray key, or
/// one not starting with `[A-Za-z0-9_.$-]`. Ports `isStrayName` in
/// `src/core/request-view.js`.
pub fn is_stray_name(name: &str) -> bool {
    is_stray_key(name)
        || !name
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b"_.$-".contains(b))
}

/// Which separators split a query. Ports the `separator` argument of
/// `queryParams` in `src/core/request-view.js` (default `/[&;]/`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuerySeparator {
    /// Split on `&` and `;`, as Rack does (the JS default).
    #[default]
    AmpersandOrSemicolon,
    /// Split on `&` only, as the WHATWG parser does.
    Ampersand,
}

/// One `name=value` pair. Ports the `{ rawName, name, value }` objects
/// returned by `queryParams` in `src/core/request-view.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryParam {
    /// The name as written, before decoding (`rawName`).
    pub raw_name: String,
    /// The name decoded as `URLSearchParams` does (`+` is a space).
    pub name: String,
    /// The value decoded the same way (`''` when there is no `=`).
    pub value: String,
}

/// Every `name=value` pair in a query or form body, in order, repeats kept,
/// empty pairs skipped. Ports `queryParams` in `src/core/request-view.js`.
pub fn query_params(raw: &str, separator: QuerySeparator) -> Vec<QueryParam> {
    raw.split(|c| c == '&' || (separator == QuerySeparator::AmpersandOrSemicolon && c == ';'))
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (raw_name, value) = pair.split_once('=').unwrap_or((pair, ""));
            QueryParam {
                raw_name: raw_name.into(),
                name: form_decode(raw_name),
                value: form_decode(value),
            }
        })
        .collect()
}

/// The loose fields a view is read from. Ports the
/// `{ method = 'GET', query = '', headers = [], body = null, contentType }`
/// argument of `requestView` in `src/core/request-view.js`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestInput<'a> {
    /// Request-line method (`GET` when absent).
    pub method: Option<&'a str>,
    /// Query, with or without its leading `?`.
    pub query: Option<&'a str>,
    /// Header pairs in order, repeats kept. A request with secrets already
    /// injected must never be read into a view.
    pub headers: &'a [(String, String)],
    /// Request body.
    pub body: Option<&'a [u8]>,
    /// Explicit Content-Type; when `None` the first `content-type` header is
    /// used.
    pub content_type: Option<&'a str>,
}

/// Methods asked for by override headers and fields. Ports the `overrides`
/// object of the value returned by `requestView` in
/// `src/core/request-view.js`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MethodOverrides {
    /// Methods asked for in override headers, uppercased, in order, unique.
    pub headers: Vec<String>,
    /// Values of override fields wherever a framework reads one (query, form,
    /// multipart, top-level JSON), every copy.
    pub fields: Vec<String>,
}

/// The request as the gateway reads it. Pure; nothing here refuses. Ports
/// the frozen object returned by `requestView` in `src/core/request-view.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestView<'a> {
    /// Request-line method, uppercased.
    pub method: String,
    /// The query exactly as it will be sent, without its `?`.
    pub query: String,
    /// `query_params(query, AmpersandOrSemicolon)`.
    pub params: Vec<QueryParam>,
    /// The query separates a pair with `;`.
    pub semicolon: bool,
    /// The query holds a character a URL cannot carry as written.
    pub unsendable: bool,
    /// Some field name is one its readers do not agree on (`strayName`).
    pub stray_name: bool,
    /// Headers, as given.
    pub headers: &'a [(String, String)],
    /// Body, as given.
    pub body: Option<&'a [u8]>,
    /// The Content-Type (`''` when none) (`contentType`).
    pub content_type: String,
    /// Content-Type lowercased, without parameters (`mediaType`).
    pub media_type: String,
    /// Override methods found.
    pub overrides: MethodOverrides,
}

/// Read a request into its one view. Ports `requestView` in
/// `src/core/request-view.js`.
pub fn request_view<'a>(input: &RequestInput<'a>) -> RequestView<'a> {
    let query = input
        .query
        .unwrap_or("")
        .strip_prefix('?')
        .unwrap_or(input.query.unwrap_or(""))
        .to_owned();
    let params = query_params(&query, Default::default());
    let content_type = input
        .content_type
        .or_else(|| {
            input
                .headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.as_str())
        })
        .unwrap_or("")
        .to_owned();
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let mut overrides = MethodOverrides::default();
    for (n, v) in input.headers {
        if METHOD_OVERRIDE_HEADERS.contains(&n.to_lowercase().as_str()) {
            for m in v.split(',') {
                let m = m.trim().to_uppercase();
                if !m.is_empty() && !overrides.headers.contains(&m) {
                    overrides.headers.push(m);
                }
            }
        }
    }
    let mut names = Vec::new();
    let mut keys = Vec::new();
    let mut read = |params: Vec<QueryParam>| {
        for p in params {
            if is_override_field(&p.name) {
                overrides.fields.push(p.value);
            }
            names.push(p.name);
        }
    };
    read(both_readings(&query));
    if let Some(body) = input.body.filter(|b| !b.is_empty()) {
        let text = String::from_utf8_lossy(body);
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        if media_type == "application/x-www-form-urlencoded" {
            read(both_readings(text));
        } else if media_type == "multipart/form-data" {
            let re = regex::Regex::new("(?i)content-disposition:").expect("disposition");
            let end_re = regex::Regex::new(r"\r?\n\r?\n").expect("end");
            let fold = regex::Regex::new(r";[ \t]*\r?\n|\r?\n[ \t]+").expect("fold");
            let name = regex::Regex::new(r#"(?i);\s*name\*?\s*=\s*(?:"([^"]*)"|([^;]*))"#)
                .expect("part name");
            let value_end = regex::Regex::new(r"\r?\n--").expect("delimiter");
            for m in re.find_iter(text) {
                let rest = &text[m.end()..];
                let end = end_re.find(rest);
                let disposition = fold.replace_all(
                    end.map_or(rest, |m| &rest[..m.start()]),
                    |c: &regex::Captures<'_>| if c[0].starts_with(';') { "; " } else { " " },
                );
                let disposition = disposition.split(['\r', '\n']).next().unwrap_or("");
                let value = end
                    .and_then(|m| {
                        let tail = &rest[m.end()..];
                        value_end.find(tail).map(|e| tail[..e.start()].to_owned())
                    })
                    .unwrap_or_default();
                read(
                    name.captures_iter(disposition)
                        .map(|c| QueryParam {
                            raw_name: String::new(),
                            name: c
                                .get(1)
                                .map_or_else(|| c.get(2).unwrap().as_str().trim(), |m| m.as_str())
                                .into(),
                            value: value.clone(),
                        })
                        .collect(),
                );
            }
        } else if media_type.ends_with("/json") || media_type.ends_with("+json") {
            if let Some(fields) = top_json_fields(text) {
                for (k, v) in fields {
                    keys.push(k.clone());
                    if is_override_field(&k) {
                        overrides.fields.push(
                            v.as_str()
                                .map(str::to_owned)
                                .unwrap_or_else(|| serde_json::to_string(&v).expect("JSON")),
                        );
                    }
                }
            }
        }
    }
    let unsendable = query.contains(['#', '\t', '\n', '\r'])
        || query.as_bytes().last().is_some_and(|b| *b <= 0x20);
    let stray_name = names.iter().any(|n| is_stray_name(n)) || keys.iter().any(|n| is_stray_key(n));
    RequestView {
        method: input
            .method
            .filter(|s| !s.is_empty())
            .unwrap_or("GET")
            .to_uppercase(),
        semicolon: query.contains(';'),
        query,
        params,
        unsendable,
        stray_name,
        headers: input.headers,
        body: input.body,
        content_type,
        media_type,
        overrides,
    }
}

pub(crate) fn form_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={s}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}
fn both_readings(raw: &str) -> Vec<QueryParam> {
    let mut p = query_params(raw, Default::default());
    if raw.contains(';') {
        p.extend(query_params(raw, QuerySeparator::Ampersand));
    }
    p
}
fn top_json_fields(text: &str) -> Option<Vec<(String, serde_json::Value)>> {
    struct Fields;
    impl<'de> serde::de::Visitor<'de> for Fields {
        type Value = Vec<(String, serde_json::Value)>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut fields = Vec::new();
            while let Some(pair) = map.next_entry()? {
                fields.push(pair);
            }
            Ok(fields)
        }
    }
    use serde::de::Deserializer;
    let mut de = serde_json::Deserializer::from_str(text);
    let fields = (&mut de).deserialize_map(Fields).ok()?;
    de.end().ok()?;
    Some(fields)
}
