//! Substitution sites: where a placeholder may appear in a request. Ports
//! `src/core/sites.js`.
//!
//! A credential field declares where its value may be substituted, and
//! nowhere else is ever substituted. The request path is deliberately not a
//! site.

use serde::{Deserialize, Serialize};

/// The closed vocabulary of site kinds. Ports `SITE_KINDS` in
/// `src/core/sites.js`.
pub const SITE_KINDS: &[&str] = &["header", "basic", "query", "json", "form", "url", "proxy"];

/// The placeholder text `describeSite` uses when none is given. Ports the
/// default argument of `describeSite` in `src/core/sites.js`.
pub const DEFAULT_PLACEHOLDER_HINT: &str = "<placeholder>";

/// A site kind. Ports the `kind` values of `SITE_KINDS` in
/// `src/core/sites.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiteKind {
    /// `header:<name>[:<scheme>]`
    Header,
    /// `basic:user` | `basic:pass`
    Basic,
    /// `query:<key>`
    Query,
    /// `json:/<pointer>`
    Json,
    /// `form:<field>`
    Form,
    /// `url:userinfo` (L4 connectors only)
    Url,
    /// `proxy:userinfo`
    Proxy,
}

/// A parsed site. Ports the object returned by `parseSite` in
/// `src/core/sites.js` (`{ spec, kind, name, scheme }`, `{ spec, kind, part }`,
/// `{ spec, kind, key }` or `{ spec, kind, pointer }`, by kind).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Site {
    /// The site string as written, e.g. `header:authorization:Bearer`.
    pub spec: String,
    /// The kind.
    pub kind: SiteKind,
    /// Header name, lowercased (`header` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Auth scheme, matched case-insensitively (`header` only; `None` when
    /// the site names no scheme).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// `user`/`pass` for `basic`, `userinfo` for `url` and `proxy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part: Option<String>,
    /// Parameter or field name (`query` and `form`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// RFC 6901 pointer (`json`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
}

/// A site string that does not parse. Ports the plain `Error`s thrown by
/// `parseSite` in `src/core/sites.js`; the message is the JS message, e.g.
/// `unknown site kind: <spec>`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidSite(pub String);

/// Parse a site string into a descriptor. Ports `parseSite` in
/// `src/core/sites.js`.
pub fn parse_site(spec: &str) -> Result<Site, InvalidSite> {
    todo!()
}

/// Parse every site string, failing on the first bad one. Ports `parseSites`
/// in `src/core/sites.js`.
pub fn parse_sites<S: AsRef<str>>(specs: &[S]) -> Result<Vec<Site>, InvalidSite> {
    todo!()
}

/// True when any declared site writes into the request body (`json` or
/// `form`). Ports `hasBodySite` in `src/core/sites.js`.
pub fn has_body_site(sites: &[Site]) -> bool {
    todo!()
}

/// Human- and agent-readable usage for a site, e.g.
/// `Authorization: Bearer <placeholder>`. Pass [`DEFAULT_PLACEHOLDER_HINT`]
/// for the JS default. Ports `describeSite` in `src/core/sites.js`.
pub fn describe_site(site: &Site, placeholder: &str) -> String {
    todo!()
}
