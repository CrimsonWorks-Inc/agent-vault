//! Connector profiles. Ports `src/connectors/profiles.js`.
//!
//! Everything in `profiles.js` is pure data and pure functions (`PROFILES`,
//! `getProfile`, `listProfiles`, `defaultSites`, `defaultField`,
//! `extractHealth`), so it lives in `av_core::profiles` and will be
//! re-exported here (`pub use av_core::profiles::*`) once that module is
//! settled. Nothing daemon-specific is left to declare.
