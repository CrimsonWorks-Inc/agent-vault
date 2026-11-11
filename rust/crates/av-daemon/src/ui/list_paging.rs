//! Paged, searchable list answers for the UI (U3): the paging request,
//! sealed cursors, and the list specs. Ports `src/ui/list-paging.js`.

use serde_json::Value;

/// Page size when none is asked for. Ports `LIMIT_DEFAULT` in
/// `src/ui/list-paging.js`.
pub const LIMIT_DEFAULT: usize = 25;
/// Largest page. Ports `LIMIT_MAX` in `src/ui/list-paging.js`.
pub const LIMIT_MAX: usize = 200;
/// Cursor MAC length. Ports `MAC_BYTES` (module-private) in
/// `src/ui/list-paging.js`.
pub const MAC_BYTES: usize = 16;
/// Longest cursor accepted. Ports `CURSOR_MAX_CHARS` (module-private) in
/// `src/ui/list-paging.js`.
pub const CURSOR_MAX_CHARS: usize = 2048;

/// A paging refusal, answered with 400 and `code` (`AV_BAD_LIMIT` or
/// `AV_BAD_CURSOR`). Ports `class PagingError` in `src/ui/list-paging.js`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct PagingError {
    /// `AV_BAD_LIMIT` or `AV_BAD_CURSOR`.
    pub code: &'static str,
    /// Human detail.
    pub message: String,
}

impl PagingError {
    /// Ports `new PagingError(code, message)` in `src/ui/list-paging.js`.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        todo!()
    }

    /// HTTP status, always 400. Ports `PagingError.status` in `src/ui/list-paging.js`.
    pub fn status(&self) -> u16 {
        todo!()
    }

    /// `{ code, detail }`. Ports `PagingError.problem` in `src/ui/list-paging.js`.
    pub fn problem(&self) -> Value {
        todo!()
    }
}

/// A parsed paging request. Ports the `{ limit, cursor, q }` result of
/// `pagingOf` in `src/ui/list-paging.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paging {
    /// Page size, 1..=[`LIMIT_MAX`].
    pub limit: usize,
    /// Sealed cursor, if continuing.
    pub cursor: Option<String>,
    /// Lower-cased, trimmed search text ("" for none).
    pub q: String,
}

/// The paging request in a query string (`(name, value)` pairs, repeated
/// names kept), or `None` when the caller did not ask for a page. Ports
/// `pagingOf(params)` in `src/ui/list-paging.js`.
pub fn paging_of(params: &[(String, String)]) -> Result<Option<Paging>, PagingError> {
    todo!()
}

/// An opened cursor. Ports the `{ dir, key }` result of `Cursors.open` in
/// `src/ui/list-paging.js`.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenedCursor {
    /// `next` or `prev`.
    pub dir: String,
    /// The sort key to continue from.
    pub key: Vec<Value>,
}

/// HMAC-sealed list cursors under a per-process key. Ports `class Cursors`
/// in `src/ui/list-paging.js`.
pub struct Cursors {
    _private: (),
}

impl Cursors {
    /// A fresh random 32-byte key. Ports `new Cursors()` in
    /// `src/ui/list-paging.js`.
    pub fn new() -> Self {
        todo!()
    }

    /// A cursor under a given key (tests). Ports `new Cursors(key)` in
    /// `src/ui/list-paging.js`.
    pub fn with_key(key: av_core::secret::Key32) -> Self {
        todo!()
    }

    /// Seal a cursor for this list, filters, direction and key. Ports
    /// `Cursors.seal(list, filters, dir, key)` in `src/ui/list-paging.js`.
    pub fn seal(&self, list: &str, filters: &Value, dir: &str, key: &[Value]) -> String {
        todo!()
    }

    /// Open and check a cursor. Ports `Cursors.open(text, list, filters)` in
    /// `src/ui/list-paging.js`.
    pub fn open(
        &self,
        text: &str,
        list: &str,
        filters: &Value,
    ) -> Result<OpenedCursor, PagingError> {
        todo!()
    }
}

impl Default for Cursors {
    fn default() -> Self {
        Self::new()
    }
}

/// How one list sorts and searches. Ports the entries of `LISTS` in
/// `src/ui/list-paging.js`.
pub struct ListSpec {
    /// The list's name (bound into cursors).
    pub name: &'static str,
    /// Sort key of an item at an index.
    pub key: fn(&Value, usize) -> Vec<Value>,
    /// Sort direction per key position (1 ascending, -1 descending).
    pub dirs: &'static [i8],
    /// Searchable values of an item.
    pub fields: fn(&Value) -> Vec<Value>,
}

/// The list specs, by JS key (`credentials`, `sessions`, `pending`,
/// `templates`, `listeners`, `tripwireRules`, `detailGrants`,
/// `reportSessions`, `reportCredentials`). Ports `LISTS` in
/// `src/ui/list-paging.js`.
pub fn list_spec(name: &str) -> Option<&'static ListSpec> {
    todo!()
}

/// The audit page's searchable fields. Ports `AUDIT_FIELDS(r)` in
/// `src/ui/list-paging.js`.
pub fn audit_fields(record: &Value) -> Vec<Value> {
    todo!()
}

/// Whether any searchable field contains `q`. Ports
/// `matches(item, fields, q)` in `src/ui/list-paging.js`.
pub fn matches(item: &Value, fields: fn(&Value) -> Vec<Value>, q: &str) -> bool {
    todo!()
}

/// Compare two sort keys, one direction per position. Ports
/// `compareKeys(a, b, dirs)` in `src/ui/list-paging.js`.
pub fn compare_keys(a: &[Value], b: &[Value], dirs: &[i8]) -> std::cmp::Ordering {
    todo!()
}

/// One page of a list, with `next`/`prev` cursors. Ports
/// `pageList(items, spec, paging, filters, cursors)` in
/// `src/ui/list-paging.js`.
pub fn page_list(
    items: &[Value],
    spec: &ListSpec,
    paging: &Paging,
    filters: &Value,
    cursors: &Cursors,
) -> Result<Value, PagingError> {
    todo!()
}

/// A list route's answer as one page; `within` names the list inside an
/// object answer and `drop` removes keys beside it. Ports
/// `pageAnswer(shown, spec, paging, { within, drop, filters }, cursors)` in
/// `src/ui/list-paging.js`.
pub fn page_answer(
    shown: &Value,
    spec: &ListSpec,
    paging: &Paging,
    within: Option<&str>,
    drop: &[&str],
    filters: &Value,
    cursors: &Cursors,
) -> Result<Value, PagingError> {
    todo!()
}
