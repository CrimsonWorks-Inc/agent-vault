//! Substitution sites: where a placeholder may appear in a request. Ports
//! `src/core/sites.js`.

use serde::{Deserialize, Serialize};

/// A parsed site. Ports the object returned by `parseSite` in
/// `src/core/sites.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Site {}
