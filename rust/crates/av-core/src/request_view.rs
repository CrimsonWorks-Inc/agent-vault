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
    todo!()
}

/// The base of a bracket-syntax name (`expand[]`, `items[0][price]` →
/// `expand`, `items`), or `None` for any other name. Ports `listBase` in
/// `src/core/request-view.js`.
pub fn list_base(name: &str) -> Option<&str> {
    todo!()
}

/// True when any folding of `name` is a method-override field. Ports
/// `isOverrideField` in `src/core/request-view.js`.
pub fn is_override_field(name: &str) -> bool {
    todo!()
}

/// A JSON key its readers do not agree on: empty, a control or non-ASCII
/// character, or a space at either end. Ports `isStrayKey` in
/// `src/core/request-view.js`.
pub fn is_stray_key(name: &str) -> bool {
    todo!()
}

/// A query/form/multipart name its readers do not agree on: a stray key, or
/// one not starting with `[A-Za-z0-9_.$-]`. Ports `isStrayName` in
/// `src/core/request-view.js`.
pub fn is_stray_name(name: &str) -> bool {
    todo!()
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
    todo!()
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
    todo!()
}
