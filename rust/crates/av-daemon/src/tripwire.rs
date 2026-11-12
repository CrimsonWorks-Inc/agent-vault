//! Tripwires (F16): a run of suspicious denials ends the session that made
//! them. Ports `src/daemon/tripwire.js`.

use std::collections::HashMap;

use av_store::model::{QuarantineBy, SessionState};
use av_store::vault::QuarantineOptions;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::pipeline::ApprovalFilter;
use crate::state::{Core, StoreResult};
use crate::util::{as_integer, now_ms};

/// One tripwire rule. Ports the rule objects of `DEFAULT_RULES` in
/// `src/daemon/tripwire.js` (and the shape `POST /v1/tripwires` stores).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TripwireRule {
    /// Rule id.
    pub id: String,
    /// `AV_*` codes that count, or absent when `rule_prefix` is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codes: Option<Vec<String>>,
    /// Denial rule-name prefix that counts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_prefix: Option<String>,
    /// Denials within the window that trip it.
    pub threshold: u32,
    /// Window in seconds.
    pub window_s: u32,
    /// `revoke_session`, `quarantine_credential` or `panic`.
    pub action: String,
}

/// The rules used when tripwires are on and none were saved: `(id, codes,
/// rule_prefix, threshold, window_s, action)`. Ports `DEFAULT_RULES`.
#[allow(clippy::type_complexity)]
pub const DEFAULT_RULES: [(&str, &[&str], Option<&str>, u32, u32, &str); 4] = [
    ("replay", &["AV_PH_REPLAY"], None, 1, 600, "revoke_session"),
    (
        "bad_location",
        &["AV_BAD_LOCATION"],
        None,
        3,
        600,
        "revoke_session",
    ),
    (
        "cross_session",
        &["AV_PH_CROSS_SESSION", "AV_PH_WRONG_CONNECTOR"],
        None,
        3,
        600,
        "revoke_session",
    ),
    (
        "deny_paths",
        &[],
        Some("deny_paths:"),
        5,
        600,
        "revoke_session",
    ),
];

/// [`DEFAULT_RULES`] as rule values.
pub fn default_rules() -> Vec<TripwireRule> {
    DEFAULT_RULES
        .iter()
        .map(
            |(id, codes, prefix, threshold, window_s, action)| TripwireRule {
                id: id.to_string(),
                codes: prefix
                    .is_none()
                    .then(|| codes.iter().map(|c| c.to_string()).collect()),
                rule_prefix: prefix.map(str::to_string),
                threshold: *threshold,
                window_s: *window_s,
                action: action.to_string(),
            },
        )
        .collect()
}

/// [`DEFAULT_RULES`] as the JSON the JS returns (key order as written).
pub fn default_rules_json() -> Value {
    Value::Array(
        DEFAULT_RULES
            .iter()
            .map(|(id, codes, prefix, threshold, window_s, action)| match prefix {
                None => json!({"id": id, "codes": codes, "threshold": threshold, "window_s": window_s, "action": action}),
                Some(p) => json!({"id": id, "rule_prefix": p, "threshold": threshold, "window_s": window_s, "action": action}),
            })
            .collect(),
    )
}

/// One authenticated denial fed to [`Core::tw_observe`]. Ports the
/// `{ sessionId, credentialId, code, rule, preflight }` argument.
#[derive(Debug, Clone, Default)]
pub struct Observation {
    /// Session that made the request ("" for none).
    pub session_id: String,
    /// Credential it was for.
    pub credential_id: Option<String>,
    /// `AV_*` code of the denial.
    pub code: String,
    /// Rule name of the denial.
    pub rule: Option<String>,
    /// Preflight denials are never counted.
    pub preflight: bool,
}

/// Per-session denial counters. Ports the private `#counts` of
/// `class Tripwires`.
#[derive(Debug, Default)]
pub struct TripwireState {
    counts: HashMap<String, HashMap<String, Vec<i64>>>,
    /// What the last tripwire panic did (`this.lastPanic`).
    pub last_panic: Option<Value>,
}

impl Core {
    /// `Tripwires.reset(sessionId)`.
    pub fn tw_reset(&mut self, session_id: &str) {
        self.tw.counts.remove(session_id);
    }

    /// `Tripwires.observe(...)`: count one denial, and fire the rule that
    /// trips. Returns the rule that fired.
    pub fn tw_observe(
        &mut self,
        o: &Observation,
    ) -> Result<Option<Value>, av_core::errors::VaultError> {
        let settings = self.vault.get_settings().v()?;
        let t = settings.get("tripwires").cloned().unwrap_or(Value::Null);
        if t.get("enabled") != Some(&Value::Bool(true))
            || o.session_id.is_empty()
            || o.preflight
            || self.vault.locked()
        {
            return Ok(None);
        }
        let session = self.vault.session(&o.session_id).v()?;
        if !session.is_some_and(|s| s.state == SessionState::Active) {
            self.tw_reset(&o.session_id);
            return Ok(None);
        }
        let tracked: Vec<String> = self.tw.counts.keys().cloned().collect();
        for sid in tracked {
            let live = self
                .vault
                .session(&sid)
                .v()?
                .is_some_and(|s| s.state == SessionState::Active);
            if !live {
                self.tw_reset(&sid);
            }
        }
        let now = now_ms();
        let rules = match t.get("rules") {
            Some(Value::Array(r)) => r.clone(),
            _ => default_rules_json().as_array().cloned().unwrap_or_default(),
        };
        for item in rules {
            if !item.is_object() {
                continue;
            }
            let threshold = item.get("threshold").and_then(as_integer);
            let window_s = item.get("window_s").and_then(as_integer);
            let (Some(threshold), Some(window_s)) = (threshold, window_s) else {
                continue;
            };
            if !(1..=1000).contains(&threshold) || !(10..=86400).contains(&window_s) {
                continue;
            }
            let by_code = item
                .get("codes")
                .and_then(Value::as_array)
                .is_some_and(|c| c.iter().any(|x| x.as_str() == Some(o.code.as_str())));
            let by_rule = item
                .get("rule_prefix")
                .and_then(Value::as_str)
                .filter(|p| !p.is_empty())
                .is_some_and(|p| o.rule.as_deref().is_some_and(|r| r.starts_with(p)));
            if !by_code && !by_rule {
                continue;
            }
            let id = crate::util::js_string(item.get("id").unwrap_or(&Value::Null));
            let counts = self.tw.counts.entry(o.session_id.clone()).or_default();
            let mut stamps: Vec<i64> = counts
                .get(&id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|at| now - at < window_s * 1000)
                .collect();
            stamps.push(now);
            let n = stamps.len();
            let keep = stamps[n.saturating_sub(threshold as usize)..].to_vec();
            counts.insert(id.clone(), keep);
            if (n as i64) < threshold {
                continue;
            }
            let cred = match &o.credential_id {
                Some(c) => self.vault.credential(c).v()?,
                None => None,
            };
            let action = item
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let record = json!({
                "rule_id": item.get("id").cloned().unwrap_or(Value::Null),
                "session_id": o.session_id,
                "credential_slug": cred.as_ref().map(|c| c.slug.clone()),
                "count": (n as i64).min(threshold),
                "window_s": window_s,
                "action": item.get("action").cloned().unwrap_or(Value::Null),
            });
            match action.as_str() {
                "revoke_session" => {
                    self.vault
                        .revoke_session(&o.session_id, &format!("tripwire:{id}"))
                        .v()?;
                    self.pl_deny_approvals(
                        &ApprovalFilter {
                            session_id: Some(o.session_id.clone()),
                            ..Default::default()
                        },
                        "tripwire",
                    )?;
                    self.tw_reset(&o.session_id);
                }
                "quarantine_credential" => {
                    let Some(cred) = cred else { continue };
                    self.vault
                        .set_quarantine(
                            &cred.slug,
                            QuarantineOptions {
                                by: QuarantineBy::Tripwire,
                                rule_id: Some(id.clone()),
                                reason: None,
                            },
                        )
                        .v()?;
                    self.pl_deny_approvals(
                        &ApprovalFilter {
                            credential_id: Some(cred.id.clone()),
                            ..Default::default()
                        },
                        "quarantined",
                    )?;
                }
                "panic" => {
                    let result = self.pl_panic(None, false)?;
                    self.tw.last_panic = Some(result);
                    self.audit("tripwire.fired", record)?;
                    return Ok(Some(item));
                }
                _ => continue,
            }
            self.audit("tripwire.fired", record)?;
            return Ok(Some(item));
        }
        Ok(None)
    }
}
