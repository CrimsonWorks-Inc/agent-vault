//! A grant's runtime state: its rolling-quota window (`grant.quota_state`)
//! and its spend counters and in-flight reservations (`grant.spend`). The JS
//! keeps both on the stored grant record and saves them (`durable: false`),
//! so they survive a restart.
//!
//! av-store does not persist them yet: the coordinator approved
//! `Vault::grant_runtime` / `Vault::set_grant_runtime` (two nullable JSON
//! columns on `grants`), which the store worker adds. Until it lands they are
//! kept here, in memory, and this file is the one place that changes when
//! it does. The restart tests are written and `#[ignore]`d until then.

use std::collections::HashMap;

use av_store::vault::Vault;
use serde_json::Value;

/// Mirrors the approved av-store type.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GrantRuntime {
    /// `{window_ms, start, count, prev}`.
    pub quota_state: Option<Value>,
    /// `{tokens_used, usd_micros_used, reserved: {<id>: {tokens, usd_micros, at}}}`.
    pub spend: Option<Value>,
}

/// Where runtime state lives until av-store keeps it.
#[derive(Debug, Default)]
pub struct RuntimeStore {
    by_grant: HashMap<String, GrantRuntime>,
}

impl RuntimeStore {
    /// The grant's runtime state (empty when none was ever written).
    pub fn get(&self, _vault: &Vault, grant_id: &str) -> GrantRuntime {
        self.by_grant.get(grant_id).cloned().unwrap_or_default()
    }

    /// Replace the grant's runtime state.
    pub fn set(&mut self, _vault: &mut Vault, grant_id: &str, rt: GrantRuntime) {
        self.by_grant.insert(grant_id.to_string(), rt);
    }

    /// Every grant with runtime state, for the startup sweep.
    pub fn grant_ids(&self) -> Vec<String> {
        self.by_grant.keys().cloned().collect()
    }
}
