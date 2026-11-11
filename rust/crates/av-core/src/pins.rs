//! SPKI pin lists: the pure parts of `src/connectors/pinning.js`. The TLS
//! handshake and chain checks live in av-daemon.

/// The one pin format: `sha256/` and the base64 of a 32-byte digest. Ports
/// `PIN_RE` in `src/connectors/pinning.js`.
pub const PIN_PATTERN: &str = "^sha256/[A-Za-z0-9+/]{43}=$";

/// Most pins a host may list. Ports `MAX_PINS` (module-private) in
/// `src/connectors/pinning.js`.
pub const MAX_PINS: usize = 4;

/// Whether a value is usable as a pin list. Ports the
/// `'none' | 'pinned' | 'invalid'` returned by `pinListState` in
/// `src/connectors/pinning.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinListState {
    /// `null`, absent or `[]`.
    None,
    /// 1..=4 well-formed pins.
    Pinned,
    /// Anything else; refused.
    Invalid,
}

/// Classify a pin list. Ports `pinListState` in `src/connectors/pinning.js`.
pub fn pin_list_state(pins: Option<&serde_json::Value>) -> PinListState {
    let Some(pins) = pins.filter(|v| !v.is_null()) else {
        return PinListState::None;
    };
    let Some(pins) = pins.as_array() else {
        return PinListState::Invalid;
    };
    if pins.is_empty() {
        return PinListState::None;
    }
    if pins.len() > MAX_PINS {
        return PinListState::Invalid;
    }
    let re = regex::Regex::new(PIN_PATTERN).expect("pin pattern");
    if pins
        .iter()
        .all(|v| v.as_str().is_some_and(|s| re.is_match(s)))
    {
        PinListState::Pinned
    } else {
        PinListState::Invalid
    }
}

/// The stored pins for a host. Ports the `null | false | array` returned by
/// `pinsFor` in `src/connectors/pinning.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinLookup {
    /// No pins for this host (JS `null`).
    NoPins,
    /// The table or an entry has the wrong shape (JS `false`); refused.
    Malformed,
    /// Every pin listed under any key naming this host, joined (entries are
    /// checked by [`pin_list_state`]).
    Found(Vec<serde_json::Value>),
}

/// The stored pin list for `host` (a URL host without IPv6 brackets) from a
/// credential's `pins` table; keys are read as the URL parser reads a host
/// and keys naming the same host are joined. Ports `pinsFor` in
/// `src/connectors/pinning.js` (`cred.pins` is passed directly).
pub fn pins_for(table: Option<&serde_json::Value>, host: &str) -> PinLookup {
    let Some(table) = table.filter(|v| !v.is_null()) else {
        return PinLookup::NoPins;
    };
    let Some(table) = table.as_object() else {
        return PinLookup::Malformed;
    };
    let mut found = Vec::new();
    for (key, value) in table {
        if url_host_of(key).as_deref() != Some(host) || value.is_null() {
            continue;
        }
        let Some(pins) = value.as_array() else {
            return PinLookup::Malformed;
        };
        found.extend(pins.iter().cloned());
    }
    if found.is_empty() {
        PinLookup::NoPins
    } else {
        PinLookup::Found(found)
    }
}

/// The host the URL parser gives `key`, without IPv6 brackets, or `None` if
/// it names no host. A bare IPv6 address is bracketed first. Ports
/// `urlHostOf` in `src/connectors/pinning.js`.
pub fn url_host_of(key: &str) -> Option<String> {
    let bare = key.trim();
    let host = if bare.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{bare}]")
    } else {
        crate::policy::host_only(key)
    };
    if host.is_empty() {
        return None;
    }
    url::Url::parse(&format!("https://{host}/"))
        .ok()
        .and_then(|u| u.host_str().map(|_| url_identity(&u)))
}

/// The URL's host as a certificate names it: no IPv6 brackets. Ports
/// `urlIdentity` in `src/connectors/pinning.js`.
pub fn url_identity(url: &url::Url) -> String {
    url.host_str()
        .unwrap_or("")
        .trim_start_matches('[')
        .trim_end_matches(']')
        .into()
}

/// Whether a Host header value names the URL's host and port: case-blind,
/// and the scheme's default port may be written or omitted. Ports
/// `hostHeaderMatches` in `src/connectors/pinning.js` (a non-string value is
/// `false` there; here the caller passes only strings).
pub fn host_header_matches(value: &str, url: &url::Url) -> bool {
    let given = value.to_lowercase();
    let host = url.host_str().unwrap_or("");
    let authority = if let Some(port) = url.port() {
        format!("{host}:{port}")
    } else {
        host.into()
    };
    if given == authority {
        return true;
    }
    url.port().is_none()
        && match url.scheme() {
            "https" => given == format!("{host}:443"),
            "http" => given == format!("{host}:80"),
            _ => false,
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn malformed_pin_tables_never_mean_unpinned() {
        let pin = format!("sha256/{}=", "A".repeat(43));
        assert_eq!(pin_list_state(Some(&json!([pin]))), PinListState::Pinned);
        assert_eq!(pin_list_state(Some(&json!([]))), PinListState::None);
        assert_eq!(pin_list_state(Some(&json!(null))), PinListState::None);
        for v in [
            json!(false),
            json!(["fake"]),
            json!([null]),
            json!([
                pin.clone(),
                pin.clone(),
                pin.clone(),
                pin.clone(),
                pin.clone()
            ]),
        ] {
            assert_eq!(pin_list_state(Some(&v)), PinListState::Invalid);
        }
        assert_eq!(
            pins_for(
                Some(&json!({"API.Example.com.":[pin.clone()],"api.example.com":[]})),
                "api.example.com"
            ),
            PinLookup::Found(vec![pin.into()])
        );
        assert_eq!(
            pins_for(Some(&json!({"api.example.com":false})), "api.example.com"),
            PinLookup::Malformed
        );
        assert_eq!(
            pins_for(Some(&json!([])), "api.example.com"),
            PinLookup::Malformed
        );
    }
    #[test]
    fn identity_and_host_header() {
        for key in ["::1", "[0:0::1]", "[::1]"] {
            assert_eq!(url_host_of(key).as_deref(), Some("::1"));
        }
        let u = url::Url::parse("https://api.example.com/x").unwrap();
        assert!(host_header_matches("API.Example.Com:443", &u));
        assert!(host_header_matches("api.example.com", &u));
        for value in ["evil.test", "api.example.com:444", " api.example.com"] {
            assert!(!host_header_matches(value, &u));
        }
    }
}
