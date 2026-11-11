//! Policy layers, intersection, host/path matching and evaluation. Ports
//! `src/core/policy.js`.

use serde::{Deserialize, Serialize};

/// One policy layer (credential ceiling, workspace, session or grant), as
/// stored in the vault and accepted by `validate`/`intersect`. Ports the
/// policy object shape used throughout `src/core/policy.js`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Policy {}
