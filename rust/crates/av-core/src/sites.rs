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
    let (kind, rest) = spec.split_once(':').unwrap_or((spec, ""));
    let mut site = Site {
        spec: spec.into(),
        kind: SiteKind::Header,
        name: None,
        scheme: None,
        part: None,
        key: None,
        pointer: None,
    };
    let invalid = |message: &str| InvalidSite(format!("{message}: {spec}"));
    match kind {
        "header" => {
            let (name, scheme) = rest
                .split_once(':')
                .map_or((rest, None), |(n, s)| (n, Some(s.to_owned())));
            if name.is_empty() {
                return Err(invalid("header site needs a name"));
            }
            site.name = Some(name.to_lowercase());
            site.scheme = scheme;
        }
        "basic" => {
            if rest != "user" && rest != "pass" {
                return Err(invalid("basic site must be user or pass"));
            }
            site.kind = SiteKind::Basic;
            site.part = Some(rest.into());
        }
        "query" | "form" => {
            if rest.is_empty() {
                return Err(invalid(&format!("{kind} site needs a key")));
            }
            site.kind = if kind == "query" {
                SiteKind::Query
            } else {
                SiteKind::Form
            };
            site.key = Some(rest.into());
        }
        "json" => {
            if !rest.starts_with('/') {
                return Err(invalid("json site needs an RFC 6901 pointer"));
            }
            site.kind = SiteKind::Json;
            site.pointer = Some(rest.into());
        }
        "url" | "proxy" => {
            if rest != "userinfo" {
                return Err(invalid(&format!("{kind} site must be userinfo")));
            }
            site.kind = if kind == "url" {
                SiteKind::Url
            } else {
                SiteKind::Proxy
            };
            site.part = Some(rest.into());
        }
        _ => return Err(invalid("unknown site kind")),
    }
    Ok(site)
}

/// Parse every site string, failing on the first bad one. Ports `parseSites`
/// in `src/core/sites.js`.
pub fn parse_sites<S: AsRef<str>>(specs: &[S]) -> Result<Vec<Site>, InvalidSite> {
    specs.iter().map(|s| parse_site(s.as_ref())).collect()
}

/// True when any declared site writes into the request body (`json` or
/// `form`). Ports `hasBodySite` in `src/core/sites.js`.
pub fn has_body_site(sites: &[Site]) -> bool {
    sites
        .iter()
        .any(|s| matches!(s.kind, SiteKind::Json | SiteKind::Form))
}

/// Human- and agent-readable usage for a site, e.g.
/// `Authorization: Bearer <placeholder>`. Pass [`DEFAULT_PLACEHOLDER_HINT`]
/// for the JS default. Ports `describeSite` in `src/core/sites.js`.
pub fn describe_site(site: &Site, placeholder: &str) -> String {
    match site.kind {
        SiteKind::Header => {
            let name = site
                .name
                .as_deref()
                .unwrap_or("")
                .split('-')
                .map(|p| {
                    let mut c = p.chars();
                    c.next().map_or(String::new(), |x| {
                        x.to_uppercase().collect::<String>() + c.as_str()
                    })
                })
                .collect::<Vec<_>>()
                .join("-");
            match site.scheme.as_deref().filter(|s| !s.is_empty()) {
                Some(s) => format!("{name}: {s} {placeholder}"),
                None => format!("{name}: {placeholder}"),
            }
        }
        SiteKind::Basic => {
            if site.part.as_deref() == Some("user") {
                format!("Authorization: Basic base64({placeholder}:x)")
            } else {
                format!("Authorization: Basic base64(x:{placeholder})")
            }
        }
        SiteKind::Query => format!("?{}={placeholder}", site.key.as_deref().unwrap_or("")),
        SiteKind::Form => format!(
            "form field {}={placeholder}",
            site.key.as_deref().unwrap_or("")
        ),
        SiteKind::Json => format!("JSON body at {}", site.pointer.as_deref().unwrap_or("")),
        SiteKind::Url => "connection string username field".into(),
        SiteKind::Proxy => "proxy userinfo".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sites_and_descriptions() {
        for (spec, description) in [
            (
                "header:authorization:Bearer",
                "Authorization: Bearer <placeholder>",
            ),
            ("basic:user", "Authorization: Basic base64(<placeholder>:x)"),
            ("basic:pass", "Authorization: Basic base64(x:<placeholder>)"),
            ("query:key", "?key=<placeholder>"),
            ("form:field", "form field field=<placeholder>"),
            ("json:/a/~1", "JSON body at /a/~1"),
            ("url:userinfo", "connection string username field"),
            ("proxy:userinfo", "proxy userinfo"),
        ] {
            let site = parse_site(spec).unwrap();
            assert_eq!(describe_site(&site, DEFAULT_PLACEHOLDER_HINT), description);
        }
        for bad in [
            "path:/",
            "header:",
            "basic:password",
            "query:",
            "json:x",
            "url:password",
        ] {
            assert!(parse_site(bad).is_err());
        }
        assert!(has_body_site(&parse_sites(&["json:/x"]).unwrap()));
        assert!(!has_body_site(&parse_sites(&["header:x"]).unwrap()));
    }
}
