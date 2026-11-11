//! The "something is waiting" signal: the SSE stream the CLI's `watch` reads
//! and the optional webhook. Ports `src/daemon/notify.js`.
//!
//! `redactStored`, which the JS re-exports from here, lives in
//! `av_core::scrub` and is not re-declared.

use serde_json::Value;

use crate::VaultRef;

/// Stream subscribers held at once. Ports `MAX_SUBSCRIBERS` in
/// `src/daemon/notify.js`.
pub const MAX_SUBSCRIBERS: usize = 8;

/// SSE keep-alive comment interval. Ports `KEEPALIVE_MS` (module-private) in
/// `src/daemon/notify.js`.
pub const KEEPALIVE_MS: u64 = 15_000;

/// Least time between webhook posts. Ports `WEBHOOK_INTERVAL_MS`
/// (module-private) in `src/daemon/notify.js`.
pub const WEBHOOK_INTERVAL_MS: u64 = 30_000;

/// Least time between `notify test` posts. Ports `TEST_INTERVAL_MS`
/// (module-private) in `src/daemon/notify.js`.
pub const TEST_INTERVAL_MS: u64 = 30_000;

/// Least time between audit records of webhook failures. Ports
/// `FAILURE_RECORD_MS` (module-private) in `src/daemon/notify.js`.
pub const FAILURE_RECORD_MS: u64 = 5 * 60_000;

/// Webhook request timeout. Ports `WEBHOOK_TIMEOUT_MS` (module-private) in
/// `src/daemon/notify.js`.
pub const WEBHOOK_TIMEOUT_MS: u64 = 5_000;

/// Largest webhook body. Ports `MAX_PAYLOAD_BYTES` (module-private) in
/// `src/daemon/notify.js`.
pub const MAX_PAYLOAD_BYTES: usize = 2048;

/// Most item ids in one webhook body. Ports `MAX_IDS` (module-private) in
/// `src/daemon/notify.js`.
pub const MAX_IDS: usize = 10;

/// Longest headline sent. Ports `MAX_HEADLINE` (module-private) in
/// `src/daemon/notify.js`.
pub const MAX_HEADLINE: usize = 200;

/// Item kinds the stream carries. Ports `KINDS` (module-private) in
/// `src/daemon/notify.js`.
pub const KINDS: [&str; 2] = ["request", "session"];

/// Strip controls and bidi characters from a headline and cap its length.
/// Ports `cleanHeadline(text)` in `src/daemon/notify.js`.
pub fn clean_headline(text: &str) -> String {
    todo!()
}

/// The webhook body for these waiting items at this detail level
/// (`minimal` or `headline`). Ports
/// `webhookPayload(items, detail, { event })` in `src/daemon/notify.js`.
pub fn webhook_payload(items: &[Value], detail: &str, event: &str) -> Value {
    todo!()
}

/// Options for [`Notifier::new`]. Ports the options object of
/// `new Notifier(vault, { fetchImpl, snapshot })` in `src/daemon/notify.js`.
#[derive(Default)]
pub struct NotifierOptions {
    /// What is waiting right now, sent first to a new subscriber. Ports
    /// `snapshot`.
    pub snapshot: Option<Box<dyn Fn() -> Vec<Value> + Send + Sync>>,
}

/// The pending-item notifier. Ports `class Notifier` in
/// `src/daemon/notify.js`.
pub struct Notifier {
    _private: (),
}

impl Notifier {
    /// Ports `new Notifier(vault, opts)` in `src/daemon/notify.js`.
    pub fn new(vault: VaultRef, opts: NotifierOptions) -> Self {
        todo!()
    }

    /// Something new is waiting: tell every subscriber and schedule the
    /// webhook. Ports `Notifier.pending(event)` in `src/daemon/notify.js`.
    pub fn pending(&self, event: &Value) {
        todo!()
    }

    /// Add a stream subscriber; the receiver yields SSE frames (snapshot
    /// first). Refused past [`MAX_SUBSCRIBERS`] or once closed. Ports
    /// `Notifier.subscribe(res)` in `src/daemon/notify.js`.
    pub fn subscribe(&self) -> av_core::errors::Result<tokio::sync::mpsc::Receiver<String>> {
        todo!()
    }

    /// Post a test event to the configured webhook. Ports
    /// `Notifier.test()` in `src/daemon/notify.js`.
    pub async fn test(&self) -> av_core::errors::Result<Value> {
        todo!()
    }

    /// End every stream and cancel the pending webhook. Ports
    /// `Notifier.close()` in `src/daemon/notify.js`.
    pub fn close(&self) {
        todo!()
    }
}
