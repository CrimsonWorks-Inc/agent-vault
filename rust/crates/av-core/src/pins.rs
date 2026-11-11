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
    todo!()
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
    todo!()
}

/// The host the URL parser gives `key`, without IPv6 brackets, or `None` if
/// it names no host. A bare IPv6 address is bracketed first. Ports
/// `urlHostOf` in `src/connectors/pinning.js`.
pub fn url_host_of(key: &str) -> Option<String> {
    todo!()
}

/// The URL's host as a certificate names it: no IPv6 brackets. Ports
/// `urlIdentity` in `src/connectors/pinning.js`.
pub fn url_identity(url: &url::Url) -> String {
    todo!()
}

/// Whether a Host header value names the URL's host and port: case-blind,
/// and the scheme's default port may be written or omitted. Ports
/// `hostHeaderMatches` in `src/connectors/pinning.js` (a non-string value is
/// `false` there; here the caller passes only strings).
pub fn host_header_matches(value: &str, url: &url::Url) -> bool {
    todo!()
}
