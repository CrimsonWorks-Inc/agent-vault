//! Ports of the JavaScript store tests (see rust/crates/av-store/PORTED.md).
//!
//! The JS tests replace `Date.now` to move the clock; here `util::at` fixes
//! this thread's clock. The JS tests edit records in memory to corrupt them;
//! here the tests write the row through the connection instead.

mod helpers;

mod activity;
mod audit_witness;
mod backup;
mod factors;
mod hygiene;
mod integrity;
mod invariants;
mod key_material;
mod ledger;
mod migrate;
mod notify;
mod passphrase;
mod pending;
mod pins;
mod review_r2;
mod review_r3;
mod rotate;
mod scrub;
mod slice_a;
mod store_fixes;
mod templates;
