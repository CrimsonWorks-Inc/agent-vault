//! Terse construction of the JS `deny(code, detail, { rule, hint, ... })`.

use av_core::errors::{deny, DenyExtra, ErrorCode, VaultError};
use serde_json::Value;

pub use av_core::errors::ErrorCode as C;

/// `deny(code, detail)`.
pub fn d(code: ErrorCode, detail: impl Into<String>) -> VaultError {
    deny(code, detail, DenyExtra::default())
}

/// `deny(code, detail, { rule })`.
pub fn dr(code: ErrorCode, detail: impl Into<String>, rule: &str) -> VaultError {
    d(code, detail).rule(rule)
}

/// The optional extras, chained.
pub trait DenyExt: Sized {
    /// `rule`.
    fn rule(self, rule: &str) -> Self;
    /// `hint`.
    fn hinted(self, hint: impl Into<String>) -> Self;
    /// `next`.
    fn next(self, next: Value) -> Self;
    /// `retryAfter`.
    fn retry(self, s: u64) -> Self;
    /// `refunded`.
    fn refunded(self, b: bool) -> Self;
    /// `factors`.
    fn factors(self, f: Vec<String>) -> Self;
}

impl DenyExt for VaultError {
    fn rule(mut self, rule: &str) -> Self {
        self.extra.rule = Some(rule.to_string());
        self
    }
    fn hinted(mut self, hint: impl Into<String>) -> Self {
        self.extra.hint = Some(hint.into());
        self
    }
    fn next(mut self, next: Value) -> Self {
        self.extra.next = Some(next);
        self
    }
    fn retry(mut self, s: u64) -> Self {
        self.extra.retry_after = Some(s);
        self
    }
    fn refunded(mut self, b: bool) -> Self {
        self.extra.refunded = Some(b);
        self
    }
    fn factors(mut self, f: Vec<String>) -> Self {
        self.extra.factors = Some(f);
        self
    }
}

/// `err.rule` as the JS reads it (`undefined` when unset or empty).
pub fn rule_of(e: &VaultError) -> Option<&str> {
    e.extra.rule.as_deref().filter(|s| !s.is_empty())
}

/// What the caller is told about a fault: the JS `#guard` sentence.
pub const FAULT_DETAIL: &str = "the request could not be handled";

/// The internal error every JS handler turns a non-`VaultError` into. The
/// text says what went wrong inside (a store error can quote stored data),
/// so it goes to stderr only, cut at 400 characters as `onProcessFault`
/// does; the caller and the audit log see the generic sentence and the
/// class.
pub fn internal(detail: impl Into<String>) -> VaultError {
    let text: String = detail.into().chars().take(400).collect();
    eprintln!("agent-vault: handler error: {text}");
    d(C::Internal, FAULT_DETAIL)
}

/// Whether `e` is a fault ([`internal`]) rather than a deliberate refusal.
pub fn is_fault(e: &VaultError) -> bool {
    e.code == C::Internal && e.detail == FAULT_DETAIL
}
