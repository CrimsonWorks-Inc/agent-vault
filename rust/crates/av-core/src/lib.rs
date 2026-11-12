//! av-core: pure logic with no I/O. Ports `src/core/*` (see rust/PLAN.md,
//! "Module map"), plus the I/O-free parts of `src/connectors/profiles.js`,
//! `src/connectors/pinning.js` and `src/ui/webauthn.js` that the store needs.
#![forbid(unsafe_code)]

pub mod base32;
pub mod canon;
pub mod detect;
pub mod errors;
pub mod model_usage;
pub mod operation;
pub mod payload;
pub mod pins;
pub mod placeholder;
pub mod policy;
pub mod profiles;
pub mod request_view;
pub mod scrub;
pub mod secret;
pub mod sites;
pub mod substitute;

pub use errors::{deny, DenyExtra, ErrorCode, Exit, VaultError};
