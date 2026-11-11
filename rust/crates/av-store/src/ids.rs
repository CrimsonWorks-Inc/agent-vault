//! Ports `src/store/ids.js`: ULID-style identifiers, time-ordered so listings
//! sort naturally, and the prefixed ids of every entity.

/// Crockford base32 alphabet. Ports `CROCKFORD` in `src/store/ids.js`.
pub const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A 26-character ULID for now. Within one millisecond the random part is
/// incremented rather than redrawn, so ids minted in a tight loop stay
/// strictly ordered (process-wide state behind a mutex). Ports `ulid()` in
/// `src/store/ids.js`.
pub fn ulid() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    ulid_at(now)
}

/// The last millisecond and random part handed out, so ids minted within one
/// millisecond increment instead of redrawing.
static LAST: std::sync::Mutex<(u64, Option<[u8; 10]>)> = std::sync::Mutex::new((0, None));

/// A ULID for the given epoch milliseconds (for tests). Ports `ulid(now)` in
/// `src/store/ids.js`.
pub fn ulid_at(now_ms: u64) -> String {
    let mut time = [0u8; 10];
    let mut t = now_ms;
    for slot in time.iter_mut().rev() {
        *slot = CROCKFORD[(t % 32) as usize];
        t /= 32;
    }
    let random = {
        let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
        match last.1 {
            Some(mut r) if last.0 == now_ms => {
                // Increment as a big-endian number, carrying; all-255 wraps.
                let mut i = r.len();
                while i > 0 && r[i - 1] == 255 {
                    r[i - 1] = 0;
                    i -= 1;
                }
                if i > 0 {
                    r[i - 1] += 1;
                }
                last.1 = Some(r);
                r
            }
            _ => {
                let mut r = [0u8; 10];
                // The OS random source failing is not something an id can
                // recover from; fall back to the clock rather than panic.
                if getrandom::fill(&mut r).is_err() {
                    r[..8].copy_from_slice(&now_ms.to_be_bytes());
                }
                *last = (now_ms, Some(r));
                r
            }
        }
    };
    let mut out = String::with_capacity(26);
    out.extend(time.iter().map(|&c| c as char));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for byte in random {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((acc >> bits) & 31) as usize] as char);
        }
    }
    out.truncate(26);
    out
}

/// Entity id prefixes and constructors. Ports the `id` object in
/// `src/store/ids.js`.
pub mod id {
    /// Ports the `ws_` prefix of `id.workspace` in `src/store/ids.js`.
    pub const WORKSPACE: &str = "ws_";
    /// Ports the `cred_` prefix of `id.credential` in `src/store/ids.js`.
    pub const CREDENTIAL: &str = "cred_";
    /// Ports the `ses_` prefix of `id.session` in `src/store/ids.js`. (The
    /// vault keys sessions by `ph.newSid()`, not this.)
    pub const SESSION: &str = "ses_";
    /// Ports the `gr_` prefix of `id.grant` in `src/store/ids.js`.
    pub const GRANT: &str = "gr_";
    /// Ports the `ph_` prefix of `id.placeholder` in `src/store/ids.js`.
    pub const PLACEHOLDER: &str = "ph_";
    /// Ports the `ap_` prefix of `id.approval` in `src/store/ids.js`.
    pub const APPROVAL: &str = "ap_";
    /// Ports the `req_` prefix of `id.request` in `src/store/ids.js`.
    pub const REQUEST: &str = "req_";
    /// Ports the `sr_` prefix of `id.sessionRequest` in `src/store/ids.js`.
    pub const SESSION_REQUEST: &str = "sr_";
    /// Ports the `cl_` prefix of `id.client` in `src/store/ids.js`.
    pub const CLIENT: &str = "cl_";
    /// Ports the `sp_` prefix of `id.scrubPattern` in `src/store/ids.js`.
    pub const SCRUB_PATTERN: &str = "sp_";
    /// Ports the `vlt_` prefix of `id.vault` in `src/store/ids.js`.
    pub const VAULT: &str = "vlt_";

    /// Ports `id.workspace` in `src/store/ids.js`.
    pub fn workspace() -> String {
        [WORKSPACE, &super::ulid()].concat()
    }
    /// Ports `id.credential` in `src/store/ids.js`.
    pub fn credential() -> String {
        [CREDENTIAL, &super::ulid()].concat()
    }
    /// Ports `id.session` in `src/store/ids.js`.
    pub fn session() -> String {
        [SESSION, &super::ulid()].concat()
    }
    /// Ports `id.grant` in `src/store/ids.js`.
    pub fn grant() -> String {
        [GRANT, &super::ulid()].concat()
    }
    /// Ports `id.placeholder` in `src/store/ids.js`.
    pub fn placeholder() -> String {
        [PLACEHOLDER, &super::ulid()].concat()
    }
    /// Ports `id.approval` in `src/store/ids.js`.
    pub fn approval() -> String {
        [APPROVAL, &super::ulid()].concat()
    }
    /// Ports `id.request` in `src/store/ids.js`.
    pub fn request() -> String {
        [REQUEST, &super::ulid()].concat()
    }
    /// Ports `id.sessionRequest` in `src/store/ids.js`.
    pub fn session_request() -> String {
        [SESSION_REQUEST, &super::ulid()].concat()
    }
    /// Ports `id.client` in `src/store/ids.js`.
    pub fn client() -> String {
        [CLIENT, &super::ulid()].concat()
    }
    /// Ports `id.scrubPattern` in `src/store/ids.js`.
    pub fn scrub_pattern() -> String {
        [SCRUB_PATTERN, &super::ulid()].concat()
    }
    /// Ports `id.vault` in `src/store/ids.js`.
    pub fn vault() -> String {
        [VAULT, &super::ulid()].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ulid_is_26_crockford_characters() {
        let u = ulid();
        assert_eq!(u.len(), 26);
        assert!(u.bytes().all(|c| CROCKFORD.contains(&c)), "{u}");
    }

    #[test]
    fn the_time_part_matches_the_js_encoding() {
        // node: ulid(1700000000000).slice(0, 10)
        assert_eq!(&ulid_at(1_700_000_000_000)[..10], "01HF7YAT00");
        assert_eq!(&ulid_at(0)[..10], "0000000000");
    }

    #[test]
    fn ids_in_one_millisecond_stay_strictly_ordered() {
        let ids: Vec<String> = (0..500).map(|_| ulid_at(1_700_000_000_123)).collect();
        for w in ids.windows(2) {
            assert!(w[0] < w[1], "{} !< {}", w[0], w[1]);
        }
    }

    #[test]
    fn ids_sort_by_time() {
        assert!(ulid_at(1_000) < ulid_at(2_000));
    }

    #[test]
    fn every_entity_prefix() {
        assert!(id::workspace().starts_with("ws_"));
        assert!(id::credential().starts_with("cred_"));
        assert!(id::session().starts_with("ses_"));
        assert!(id::grant().starts_with("gr_"));
        assert!(id::placeholder().starts_with("ph_"));
        assert!(id::approval().starts_with("ap_"));
        assert!(id::request().starts_with("req_"));
        assert!(id::session_request().starts_with("sr_"));
        assert!(id::client().starts_with("cl_"));
        assert!(id::scrub_pattern().starts_with("sp_"));
        assert!(id::vault().starts_with("vlt_"));
        assert_eq!(id::credential().len(), 5 + 26);
    }
}
