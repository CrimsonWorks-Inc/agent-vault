//! Ports `src/store/ids.js`: ULID-style identifiers, time-ordered so listings
//! sort naturally, and the prefixed ids of every entity.

/// Crockford base32 alphabet. Ports `CROCKFORD` in `src/store/ids.js`.
pub const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A 26-character ULID for now. Within one millisecond the random part is
/// incremented rather than redrawn, so ids minted in a tight loop stay
/// strictly ordered (process-wide state behind a mutex). Ports `ulid()` in
/// `src/store/ids.js`.
pub fn ulid() -> String {
    todo!()
}

/// A ULID for the given epoch milliseconds (for tests). Ports `ulid(now)` in
/// `src/store/ids.js`.
pub fn ulid_at(now_ms: u64) -> String {
    todo!()
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
        todo!()
    }
    /// Ports `id.credential` in `src/store/ids.js`.
    pub fn credential() -> String {
        todo!()
    }
    /// Ports `id.session` in `src/store/ids.js`.
    pub fn session() -> String {
        todo!()
    }
    /// Ports `id.grant` in `src/store/ids.js`.
    pub fn grant() -> String {
        todo!()
    }
    /// Ports `id.placeholder` in `src/store/ids.js`.
    pub fn placeholder() -> String {
        todo!()
    }
    /// Ports `id.approval` in `src/store/ids.js`.
    pub fn approval() -> String {
        todo!()
    }
    /// Ports `id.request` in `src/store/ids.js`.
    pub fn request() -> String {
        todo!()
    }
    /// Ports `id.sessionRequest` in `src/store/ids.js`.
    pub fn session_request() -> String {
        todo!()
    }
    /// Ports `id.client` in `src/store/ids.js`.
    pub fn client() -> String {
        todo!()
    }
    /// Ports `id.scrubPattern` in `src/store/ids.js`.
    pub fn scrub_pattern() -> String {
        todo!()
    }
    /// Ports `id.vault` in `src/store/ids.js`.
    pub fn vault() -> String {
        todo!()
    }
}
