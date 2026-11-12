//! av-store: the SQLite vault, key handling, audit log and backups. Ports
//! `src/store/*`, `src/pending.js` and `src/client-state.js` (rust/PLAN.md,
//! "Module map" and "Storage contract").
//!
//! `unsafe` is denied crate-wide and allowed only in [`mlock`], a small
//! commented wrapper around `mlock(2)` for the VMK.
#![deny(unsafe_code)]

pub mod activity;
pub mod audit;
pub mod backup;
pub mod client_state;
pub mod crypto;
pub mod db;
pub mod error;
pub mod ids;
pub mod migrate;
#[allow(unsafe_code)]
pub mod mlock;
pub mod model;
pub mod pending;
mod rows;
pub mod schema;
mod util;
pub mod vault;

#[cfg(test)]
mod tests;
